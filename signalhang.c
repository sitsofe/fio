/* Program that demonstrates a hang in pthread_cond_signal when using
 * winpthreads. Compile with
 * x86_64-w64-mingw32-gcc -g -O3 -Wall -static -pthread signal_hang.c
 */

#ifdef _WIN32
#include <windows.h>
#else
#define _GNU_SOURCE
#endif
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x, msg) \
	if (x != 0) { \
		printf("%s failed\n", msg); \
		goto err; \
	}

#define LOGGING 0
#if LOGGING
#define log(x, ...) log(x, ##__VA_ARGS__)
#else
#define log(x, ...) do {} while (0)
#endif

enum {
	MUTEX_LOCKED = 0,
	MUTEX_UNLOCKED = 1
};

struct sh_mutex {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	int value;
	int waiters;
	uint64_t max_iterations;
	uint64_t max_hits;
	uint64_t iteration;
	uint64_t hits;
	pthread_barrier_t barrier;
};

struct sh_thread {
	int id;
	struct sh_mutex *mutex;
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
		goto err;
	}
#else
	cpu_set_t cpuset;
	pthread_t thread;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);

	thread = pthread_self();
	if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset) != 0)
		goto err;

#endif
	return 0;
err:
	log("setting affinity failed\n");
	return 1;
}

static void *contend_lock_thread(void *data) {
	struct sh_thread *thread_data = (struct sh_thread*) data;
	struct sh_mutex	*mutex = thread_data->mutex;
	int cpu;

	//cpu = 0;                 // bind all to the first CPU
	cpu = thread_data->id % 2; // round-robin to first 2 CPUs
	CHECK(cpu_bind(cpu), "cpu_bind");
	//pthread_barrier_wait(&mutex->barrier);
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
	}

	log("finishing thread %d\n", thread_data->id);
	return NULL;
err:
	exit(1);
}

int main(int argv, char **argc) {
	struct sh_mutex mutex;
	pthread_t *threads = NULL;
	struct sh_thread *threads_data = NULL;
	int thread_count = 0;

	memset(&mutex, 0, sizeof(struct sh_mutex));

	CHECK(pthread_cond_init(&mutex.cond, NULL), "pthread_cond_init");
	CHECK(pthread_mutex_init(&mutex.lock, NULL), "pthread_mutex_init");
	mutex.value = MUTEX_UNLOCKED;

	if (argv > 1) {
		thread_count = atoi(argc[1]);
	} else
		thread_count = 8;

	mutex.max_iterations = 100000000;
	mutex.max_hits = 10000;

	CHECK(pthread_barrier_init(&mutex.barrier, NULL, thread_count), "pthread_barrier_init");

	threads = malloc(sizeof(pthread_t) * thread_count);
	threads_data = malloc(sizeof(struct sh_thread) * thread_count);
	for (int i = 0; i < thread_count; i++) {
		threads_data[i].id = i;
		threads_data[i].mutex = &mutex;
		CHECK(pthread_create(&threads[i], NULL, contend_lock_thread, &threads_data[i]), "pthread_create");
	}

	for (int i = 0; i < thread_count; i++) {
		CHECK(pthread_join(threads[i], NULL), "pthread_join");
	}

	if (threads)
		free(threads);
	if (threads_data)
		free(threads_data);

	printf("iterations done: %" PRId64 "\n", mutex.iteration);
	return 0;
err:
	perror("last error was");
	return 1;
}
