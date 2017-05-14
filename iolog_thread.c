#include "fio.h"
#include "smalloc.h"
#include "iolog.h"

struct iolog_data {
	volatile int exit;
	volatile int reset;
	volatile int do_stat;
	struct thread_data *td;
	pthread_cond_t cond;
	pthread_mutex_t lock;
	pthread_t thread;
	struct fio_mutex *startup_mutex;
	FILE *f;
	bool is_blktrace;
	int need_swap;
	bool back;
};

#if 0
void iolog_thread_destroy(void)
{
	pthread_cond_destroy(&iolog_data->cond);
	pthread_mutex_destroy(&iolog_data->lock);
	sfree(iolog_data);
}

void iolog_reset(void)
{
	if (!iolog_data)
		return;

	pthread_mutex_lock(&iolog_data->lock);

	if (!iolog_data->reset) {
		iolog_data->reset = 1;
		pthread_cond_signal(&iolog_data->cond);
	}

	pthread_mutex_unlock(&iolog_data->lock);
}

bool iolog_should_exit(void)
{
	if (!iolog_data)
		return true;

	return iolog_data->exit;
}
#endif

void iolog_thread_exit(struct iolog_data *id)
{
	void *ret;

	pthread_mutex_lock(&id->lock);
	id->exit = 1;
	pthread_cond_signal(&id->cond);
	pthread_mutex_unlock(&id->lock);

	pthread_join(id->thread, &ret);
}

static int iolog_stream_read(struct iolog_data *id) {
	struct thread_data *td = id->td;
	int ret;

	ret = read_opened_iolog(td, id->is_blktrace, id->need_swap, id->f,
			true, true, id->back);

	pthread_mutex_lock(&td->io_log_lock);
	if (ret == 2)
		td->io_log_swap_state = SWAP_READY;
	else if (ret == 0) {
		td->io_log_swap_state = SWAP_READY_FINAL;
		fclose(id->f);
	} else {
		td->io_log_swap_state = SWAP_READY_FINAL;
		fclose(id->f);
	}
	pthread_mutex_unlock(&td->io_log_lock);
	pthread_cond_signal(&td->io_log_read_cond);
	dprint(FD_COMPRESS, "iolog_stream_read: ret=%d, waking after fill\n", ret);

	return ret;
}

static int iolog_stream_init(struct iolog_data *id) {
	struct thread_data *td = id->td;
	int ret;

	ret = open_iolog(td, &id->is_blktrace, &id->need_swap, &id->f, true);
	dprint(FD_COMPRESS, "iolog_stream_init: f=%p\n", id->f);
	id->back = true;
	if (ret == 2) {
		iolog_stream_read(id);

		if (ret == 2)
			td->io_log_swap_state = SWAP_READY;
		else if (ret == 0) {
			td->io_log_swap_state = SWAP_READY_FINAL;
			fclose(id->f);
		} else {
			td->io_log_swap_state = SWAP_READY_FINAL;
			fclose(id->f);
		}
	} else
		td->io_log_swap_state = SWAP_EXHAUSTED;

	return ret;
}

static void *iolog_thread_main(void *data)
{
	struct iolog_data *id = data;
	struct thread_data *td = id->td;
	struct timeval tv, last_du, last_ss;
	int ret = 0;

	gettimeofday(&tv, NULL);
	memcpy(&last_du, &tv, sizeof(tv));
	memcpy(&last_ss, &tv, sizeof(tv));

	td->io_log_swap_state = SWAP_EMPTY;
	if (iolog_stream_init(id) <= 0)
		id->exit = 1;
	fio_mutex_up(id->startup_mutex);
	log_err("fio: iolog_thread started...\n");

	// Fill ipos until log is finished
	while (!id->exit) {
		struct timespec ts;
		bool refill = false;

		// Check what state we're in
		pthread_mutex_lock(&td->io_log_lock);
		if (!id->exit &&
		    (td->io_log_swap_state != SWAP_EMPTY &&
		     td->io_log_swap_state != SWAP_EMPTY_WAITING)) {

			gettimeofday(&tv, NULL);
			ts.tv_sec = tv.tv_sec;
			ts.tv_nsec = tv.tv_usec * 1000;
			timespec_add_msec(&ts, 100);
			// Go to sleep on condition
			dprint(FD_COMPRESS, "iolog_thread_main: sleeping on io_log_fill_cond\n");
			pthread_cond_timedwait(&td->io_log_fill_cond, &td->io_log_lock, &ts);
		} else
			refill = true;
		pthread_mutex_unlock(&td->io_log_lock);

		if (refill) {
			// Fill back buffer
			ret = iolog_stream_read(id);
			// Check whether this is last fill or whether we should
			// exit
			if (ret != 2)
				iolog_thread_exit(id);
		}
		// TODO: If someone is waiting log message
	}

	pthread_mutex_lock(&td->io_log_lock);
	if (td->io_log_swap_state == SWAP_EMPTY ||
	    td->io_log_swap_state == SWAP_EMPTY_WAITING)
		td->io_log_swap_state = SWAP_EXHAUSTED;
	else if (td->io_log_swap_state == SWAP_READY)
		td->io_log_swap_state = SWAP_READY_FINAL;
	pthread_mutex_unlock(&td->io_log_lock);

	pthread_cond_signal(&td->io_log_read_cond);

	dprint(FD_COMPRESS, "iolog_thread: exiting (%d)\n", td->io_log_swap_state);
	return NULL;
}

int iolog_thread_create(struct thread_data *td)
{
	struct iolog_data *id;
	struct fio_mutex *mutex;
	int ret;

	td->io_log_swap_state = SWAP_EXHAUSTED;

	mutex = fio_mutex_init(FIO_MUTEX_LOCKED);
	if (!mutex)
		return 1;

	id = smalloc(sizeof(*id));

	id->td = td;

	ret = mutex_cond_init_pshared(&id->lock, &id->cond);
	if (ret)
		goto err;

	id->startup_mutex = mutex;

	ret = pthread_create(&id->thread, NULL, iolog_thread_main, id);
	if (ret) {
		log_err("Can't create iolog thread: %s\n", strerror(ret));
		goto err;
	}

	dprint(FD_MUTEX, "wait on iolog startup_mutex\n");
	fio_mutex_down(mutex);
	dprint(FD_MUTEX, "done waiting on iolog startup_mutex\n");
err:
	fio_mutex_remove(mutex);
	return ret;
}
