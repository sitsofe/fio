/* Program that demonstrates a hang in pthread_cond_signal when using
 * winpthreads. Compile with
 * x86_64-w64-mingw32-gcc -O3 -Wall -static -pthread signal_hang.c
 */

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
	uint64_t iteration;
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
	uint64_t iteration;

	pthread_mutex_lock(&mutex->lock);
	if (mutex->value == MUTEX_LOCKED && mutex->waiters)
		do_wake = mutex->waiters;
	mutex->value = MUTEX_UNLOCKED;
	iteration = mutex->iteration;
	pthread_mutex_unlock(&mutex->lock);

	if (do_wake) {
		fprintf(stderr, "doing wake (waiters=%d, iteration=%" PRId64 ")...\n", do_wake, iteration);
		pthread_cond_signal(&mutex->cond);
	}
}

static void *contend_lock_thread(void *data) {
	struct sh_thread *thread_data = (struct sh_thread*) data;
	struct sh_mutex	*mutex = thread_data->mutex;

	while (1) {
		uint64_t iteration;

		mutex_down(mutex);
		mutex->iteration++;
		iteration = mutex->iteration;
		usleep(5);
		mutex_up(mutex);
		if (iteration >= mutex->max_iterations)
			break;
	}

	fprintf(stderr, "finishing thread %d\n", thread_data->id);
	return NULL;
}

int main(void) {
	struct sh_mutex mutex;
	struct sh_thread *threads_data = NULL;
	pthread_t *threads = NULL;
	int thread_count;

	CHECK(pthread_cond_init(&mutex.cond, NULL), "pthread_cond_init");
	CHECK(pthread_mutex_init(&mutex.lock, NULL), "pthread_mutex_init");
	mutex.value = MUTEX_UNLOCKED;
	mutex.iteration = 0;
	mutex.waiters = 0;

	/* Change these to make the test longer */
	thread_count = 50;
	mutex.max_iterations = 10000;

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
