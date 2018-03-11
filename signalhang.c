/* Program that demonstrates a hang in pthread_cond_signal() when using
 * winpthreads. For Windows compile with
 * x86_64-w64-mingw32-gcc -g -O3 -Wall -static -pthread signalhang.c -o signalhang
 * on Linux compile with
 * gcc -g -O3 -Wall -lrt -pthread signalhang.c -o signalhang
 *
 * Usage:
 * ./signalhang [THREAD_COUNT]
 * e.g.
 * PS C:\> $LASTEXITCODE=0; While ($LASTEXITCODE -eq 0) { signalhang.exe }
 * or
 * $ ok=0; while [[ ok -eq 0 ]]; do ./a.out 4; ok=$?; done
 *
 * NB: Problem does not show:
 * - When 3 or less threads are used
 * - When all the contending threads are bound to the same CPU on native
 *   windows
 */

#define LOGGING 1
#define MAX_STALLED_HEARTBEATS 3

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

#define CHECK(x) assert(x == 0)

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
        unsigned int heartbeat;
};

static void mutex_down(struct sh_mutex *mutex) {
	pthread_mutex_lock(&mutex->lock);
	while (mutex->value == MUTEX_LOCKED) {
		mutex->waiters++;
		pthread_cond_wait(&mutex->cond, &mutex->lock);
		mutex->waiters--;
	}
	mutex->value = MUTEX_LOCKED;
	pthread_mutex_unlock(&mutex->lock);
}

static void mutex_up(struct sh_mutex *mutex) {
	int do_wake = 0;
	uint64_t iteration, hits;

	pthread_mutex_lock(&mutex->lock);
	if (mutex->value == MUTEX_LOCKED && mutex->waiters)
		do_wake = mutex->waiters;
	mutex->value = MUTEX_UNLOCKED;
	iteration = mutex->iteration;
	if (do_wake && mutex->waiters > 1)
		mutex->hits++;
	hits = mutex->hits;
	pthread_mutex_unlock(&mutex->lock);

	if (do_wake) {
		log("doing wake (waiters=%d, iteration=%" PRId64 ", hits=%" PRId64 ")...\n", do_wake, iteration, hits);
		pthread_cond_signal(&mutex->cond);
	}
}

static int cpu_bind(int cpu) {
#ifdef _WIN32
	DWORD_PTR mask;

	mask = 1 << cpu;

	if (SetThreadAffinityMask(GetCurrentThread(), mask) == 0) {
		log("GetLastError=%ld\n", GetLastError());
		assert(1);
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

static void *contend_lock_thread(void *data) {
	struct sh_thread *thread_data = (struct sh_thread*) data;
	struct sh_mutex	*mutex = thread_data->mutex;
	int cpu;

	//cpu = 0; // bind all threads to the first CPU
	cpu = thread_data->id % 2; // bind thread to ONE of the first 2 CPUs
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
		__sync_fetch_and_add(&heartbeat, 0);
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
        int stalled_heartbeat;
        unsigned int heartbeat, old_heartbeat;

	memset(&mutex, 0, sizeof(struct sh_mutex));

	CHECK(pthread_cond_init(&mutex.cond, NULL));
	CHECK(pthread_mutex_init(&mutex.lock, NULL));
	mutex.value = MUTEX_UNLOCKED;

	/* NB: Problem does not show with thread_count < 4 */
	if (argv > 1) {
		thread_count = atoi(argc[1]);
	} else
		thread_count = 8;

	mutex.max_iterations = 100000000;
	mutex.max_hits = 10000;

	heartbeat = 0;
	alive = thread_count;

	threads = malloc(sizeof(pthread_t) * thread_count);
	threads_data = malloc(sizeof(struct sh_thread) * thread_count);
	for (int i = 0; i < thread_count; i++) {
		threads_data[i].id = i;
		threads_data[i].mutex = &mutex;
                threads_data[i].alive = &alive;

		CHECK(pthread_create(&threads[i], NULL, contend_lock_thread, &threads_data[i]));
	}

	stalled_heartbeat = 0;
	old_heartbeat = 0;
	while (1) {
		int local_alive;
		unsigned int new_heartbeat;

		sleep(1);
		local_alive = __sync_fetch_and_add(&alive, 0);
		if (local_alive) {
			new_heartbeat = __sync_fetch_and_add(&heartbeat, 0);
			if (old_heartbeat == new_heartbeat) {
				stalled_heartbeat++;
				log("heartbeat missed\n");
			} else {
				stalled_heartbeat = 0;
				old_heartbeat = new_heartbeat;
			}

			if (stalled_heartbeat >= MAX_STALLED_HEARTBEATS) {
				fprintf(stderr, "deadlock detected! stalled_heartbeat=%d alive=%d\n", stalled_heartbeat, local_alive);
#ifdef NDEBUG
				break;
#else
				assert(stalled_heartbeat < MAX_STALLED_HEARTBEATS);
#endif
			}
		} else
			break;
	}

	for (int i = 0; i < thread_count; i++)
		CHECK(pthread_join(threads[i], NULL));

	if (threads)
		free(threads);
	if (threads_data)
		free(threads_data);

	printf("iterations done=%" PRId64 ", hits=%" PRId64 "\n", mutex.iteration, mutex.hits);
	return 0;
}
