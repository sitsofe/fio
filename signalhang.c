/* Program that demonstrates a hang in pthread_cond_signal() when using
 * winpthreads (at least versions 5.0.2-7.2.0). On Windows compile with
 * x86_64-w64-mingw32-gcc -g -O3 -static -pthread signalhang.c -o signalhang
 * on Linux compile with
 * gcc -g -O3 -lrt -pthread signalhang.c -o signalhang
 *
 * Extra compilation options:
 * -DDETECT_DEADLOCK=1 : Print a message and trigger an assert if it looks like
 *                       threads have become deadlocked
 * -DLOGGING=1 : Print logging information when wakes are done. "hits" is
 *               incremented when a wake is done and there were two more other
 *               threads waiting on the condition variable.
 * -DNDEBUG : Disable all return code checking asserts and don't trigger an
 *            assert after the deadlock is detected when using
 *            DETECT_DEADLOCK=1
 *
 * Usage:
 * ./signalhang [THREAD_COUNT]
 * Program will print a done line with some stats on success or hang on
 * deadlock. It is easy to loop runs until a failure (especially when using
 * DETECT_DEADLOCK=1) by using the shell. For example:
 * PS C:\> $LASTEXITCODE=0; While ($LASTEXITCODE -eq 0) { .\signalhang.exe 4 }
 * or
 * $ rc=0; while [[ rc -eq 0 ]]; do ./signalhang 4; rc=$?; done
 *
 * Deadlock does not occur when any of the following are true:
 * - Running on native Linux with glibc
 * - When the call to pthread_cond_signal() is moved inside the
 *   pthread_mutex_lock()/pthread_mutex_unlock() region
 * The following make deadlock less likely:
 * - Binding threads to the same single CPU
 * - Using less than 4 threads
 * The following make deadlock more likely:
 * - More threads
 * - Turning logging on
 * - Calling sched_yield() between mutex_down()/mutex_up()
 * - Binding threads to different CPUs
 */

#ifndef LOGGING
#define LOGGING 0 // setting to 1 increases deadlock probability
#endif
#ifndef DETECT_DEADLOCK
#define DETECT_DEADLOCK 0 // setting to 1 enables self deadlock detection
#endif
#define MAX_MISSED_HEARTBEATS 10 // the max missed heartbeats with deadlock detection

#ifdef _WIN32
#include <windows.h>
#else
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) if ((x) != 0) assert(0)

#if LOGGING
#define log(x, ...) fprintf(stderr, x, ##__VA_ARGS__)
#else
#define log(x, ...) do {} while (0)
#endif

enum {
	MUTEX_LOCKED = 0,
	MUTEX_UNLOCKED = 1
};

struct sh_mutex {
	uint64_t max_iterations;
	uint64_t max_hits;
	uint64_t iteration;
	uint64_t hits;
	int value;
	int waiters;
	pthread_mutex_t lock;
	pthread_cond_t cond;
};

struct sh_thread {
	struct sh_mutex *mutex;
	int id;
        int *alive;
        unsigned int *no_heartbeat;
};

static void mutex_down(struct sh_mutex *mutex) {
	CHECK(pthread_mutex_lock(&mutex->lock));
	while (mutex->value == MUTEX_LOCKED) {
		mutex->waiters++;
		CHECK(pthread_cond_wait(&mutex->cond, &mutex->lock));
		mutex->waiters--;
	}
	mutex->value = MUTEX_LOCKED;
	CHECK(pthread_mutex_unlock(&mutex->lock));
}

static void mutex_up(struct sh_mutex *mutex) {
	int do_wake = 0;
	uint64_t iteration;
	uint64_t hits;

	CHECK(pthread_mutex_lock(&mutex->lock));
	if (mutex->value == MUTEX_LOCKED && mutex->waiters)
		do_wake = mutex->waiters;
	mutex->value = MUTEX_UNLOCKED;
	iteration = mutex->iteration;
	if (do_wake && mutex->waiters > 1)
		mutex->hits++;
	hits = mutex->hits;
	CHECK(pthread_mutex_unlock(&mutex->lock));

	if (do_wake) {
		log("doing wake (waiters=%d, iteration=%" PRId64 ", hits=%" PRId64 ")...\n", do_wake, iteration, hits);
		CHECK(pthread_cond_signal(&mutex->cond));
	}
}

static int cpu_bind(int cpu) {
#ifdef _WIN32
	DWORD_PTR mask;

	mask = 1 << cpu;

	if (SetThreadAffinityMask(GetCurrentThread(), mask) == 0) {
		log("GetLastError=%ld\n", GetLastError());
		assert(0);
	}
#else
	cpu_set_t cpuset;
	pthread_t thread;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);

	thread = pthread_self();
	CHECK(pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset));
#endif
	return 0;
}

static int get_online_cpus(void) {
	int cpus;
#ifdef _WIN32
	SYSTEM_INFO sysinfo;

	GetSystemInfo(&sysinfo);
	cpus = sysinfo.dwNumberOfProcessors;
#else
	cpus = sysconf(_SC_NPROCESSORS_ONLN);
#endif
	return cpus;
}

static void *contend_lock_thread(void *data) {
	struct sh_thread *thread_data = (struct sh_thread*) data;
	struct sh_mutex	*mutex = thread_data->mutex;
	int cpu;

	//cpu = 0; // bind all threads to the first CPU
	//cpu = thread_data->id % 2; // bind each thread to ONE of the first 2 CPUs
	cpu = thread_data->id % get_online_cpus(); // bind threads to individual CPUs
	CHECK(cpu_bind(cpu));
	while (1) {
		uint64_t iteration, hits;

		mutex_down(mutex);
		mutex->iteration++;
		iteration = mutex->iteration;
		hits = mutex->hits;
		sched_yield(); // increase deadlock probability
		mutex_up(mutex);
		if (iteration >= mutex->max_iterations || hits >= mutex->max_hits)
			break;
#if DETECT_DEADLOCK
		__sync_lock_release(thread_data->no_heartbeat);
#endif
	}

	log("finishing thread %d\n", thread_data->id);
        __sync_sub_and_fetch(thread_data->alive, 1);
	return NULL;
}

int main(int argv, char **argc) {
	struct sh_mutex mutex;
	pthread_t *threads = NULL;
	struct sh_thread *threads_data = NULL;
	int thread_count = 0;
	int alive;
        unsigned int no_heartbeat;

	memset(&mutex, 0, sizeof(struct sh_mutex));

	CHECK(pthread_cond_init(&mutex.cond, NULL));
	CHECK(pthread_mutex_init(&mutex.lock, NULL));
	mutex.value = MUTEX_UNLOCKED;

	if (argv > 1) {
		thread_count = atoi(argc[1]);
	} else
		thread_count = 8;

	mutex.max_iterations = 100000000;
	mutex.max_hits = 100000;

	no_heartbeat = 1;
	alive = thread_count;

	threads = malloc(sizeof(pthread_t) * thread_count);
	threads_data = malloc(sizeof(struct sh_thread) * thread_count);
	for (int i = 0; i < thread_count; i++) {
		threads_data[i].id = i;
		threads_data[i].mutex = &mutex;
                threads_data[i].alive = &alive;
                threads_data[i].no_heartbeat = &no_heartbeat;

		CHECK(pthread_create(&threads[i], NULL, contend_lock_thread, &threads_data[i]));
	}

#if DETECT_DEADLOCK
	int missed_heartbeats = 0;
	int missed_heartbeats_ever = 0;
	while (1) {
		int local_alive;
		unsigned int no_new_heartbeat;

		local_alive = __sync_fetch_and_add(&alive, 0);
		if (!local_alive)
			break;

		usleep(500000);
		no_new_heartbeat = __sync_lock_test_and_set(&no_heartbeat, 1);
		if (no_new_heartbeat) {
			missed_heartbeats++;
			missed_heartbeats_ever++;
			fprintf(stderr, "heartbeat missed\n");
			fflush(stderr);

			if (missed_heartbeats >= MAX_MISSED_HEARTBEATS) {
				fprintf(stderr, "deadlock detected! missed_heartbeats=%d alive=%d\n", missed_heartbeats, local_alive);
				fflush(stderr);
#ifdef NDEBUG
				break;
#else
				assert(missed_heartbeats < MAX_MISSED_HEARTBEATS);
#endif
			}
		} else
			missed_heartbeats = 0;
	}
#endif

	for (int i = 0; i < thread_count; i++)
		CHECK(pthread_join(threads[i], NULL));

	if (threads)
		free(threads);
	if (threads_data)
		free(threads_data);

	printf("done: iterations=%" PRId64 ", hits=%" PRId64 "\n", mutex.iteration, mutex.hits);
#if DETECT_DEADLOCK
	printf("      missed_heartbeats_ever=%d\n", missed_heartbeats_ever);
#endif
	return 0;
}
