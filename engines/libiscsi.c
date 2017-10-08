/*
 * libiscsi engine
 *
 * IO engine using libiscsi
 *
 * Based off libiscsi's iscsi-perf by Peter Lieven
 *
 * TODO:
 * Rename reconnect_retries to retry and enumerate it to be none, login,
 * transport, scsi_temporary, scsi_permenant, all
 * Does td->terminate needs some sort of barrier?
 * Add fsync (and fdatasync?) support by sending CACHE SYNCHRONIZE
 * Add trim support by sending UNMAP/WRITE SAME(16)
 * Fix io_submit_mode=offload hang
 * Config check to see if platform has poll
 * Use iscsi_set_timeout around more of the _sync commands?
 * Add a note that we only work with targets that implement the (16) commands
 * What's the correct way to update time (RE update_ts_cache)?
 * Add documentation comment here
 * Run through clang
 * Add multipath failover support
 *
 */
#include <errno.h>
#include <poll.h>
#include <iscsi/iscsi.h>
#include <iscsi/scsi-lowlevel.h>

#include "../fio.h"
#include "../optgroup.h"

enum libiscsi_protocol {
	FIO_LIBISCSI_ISCSI = 0,
	FIO_LIBISCSI_ISER
};

enum libiscsi_retry {
	FIO_LIBISCSI_RETRY_NONE = 0,
	FIO_LIBISCSI_RETRY_TRANSPORT,
	FIO_LIBISCSI_RETRY_NOT_READY,
	FIO_LIBISCSI_RETRY_ALL
};

#define retry_transport(retry)  ((retry) & FIO_LIBISCSI_RETRY_TRANSPORT)
#define retry_notready(retry)  ((retry) & FIO_LIBISCSI_RETRY_NOT_READY)

struct libiscsi_options {
	struct thread_data *td;
	char *initiator;
	enum libiscsi_protocol protocol;
	unsigned int header_digest;
	unsigned int iscsi_retry;
	int busy_poll;
	int64_t timeout_grace;
};

static struct fio_option options[] = {
	{
		.name           = "busy_poll",
		.lname          = "Busy poll",
		.type           = FIO_OPT_STR_SET,
		.help           = "Busy poll for completions instead of sleeping",
		.off1           = offsetof(struct libiscsi_options, busy_poll),
		.category       = FIO_OPT_C_ENGINE,
		.group          = FIO_OPT_G_LIBISCSI,
	},
	{
		.name           = "timeout_grace",
		.lname          = "Timeout grace",
		.type           = FIO_OPT_STR_VAL_TIME,
		.help           = "Max time to wait after timeout or termination before aborting (-1 to wait forever). Unspecified, unit is usec",
		.def            = "1s",
		.is_time         = 1,
		.off1           = offsetof(struct libiscsi_options, timeout_grace),
		.category       = FIO_OPT_C_ENGINE,
		.group          = FIO_OPT_G_LIBISCSI,
	},
	{
		.name		= "iscsi_protocol",
		.lname		= "Default libiscsi protocol",
		.type		= FIO_OPT_STR,
		.help		= "Protocol libiscsi should use when unspecified within the filename",
		.def		= "iscsi",
		.off1		= offsetof(struct libiscsi_options, protocol),
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_LIBISCSI,
		.posval	= {
			  { .ival = "iscsi",
			    .oval = FIO_LIBISCSI_ISCSI,
			    .help = "Use iSCSI as the default protocol",
			  },
			  { .ival = "iser",
			    .oval = FIO_LIBISCSI_ISER,
			    .help = "Use iSER as the default protocol",
			  },
		},
	},
	{
		.name		= "initiator",
		.lname		= "Initiator name",
		.type		= FIO_OPT_STR_STORE,
		.help		= "iSCSI initiator name",
		.def		= "iqn.2010-11.libiscsi:fio",
		.off1		= offsetof(struct libiscsi_options, initiator),
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_LIBISCSI,
	},
	{
		.name		= "iscsi_retry",
		.lname		= "Failing operations to retry",
		.type		= FIO_OPT_STR,
		.help		= "Which category of operations to infinitely retry if they fail",
		.def		= "none",
		.off1		= offsetof(struct libiscsi_options, iscsi_retry),
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_LIBISCSI,
		.posval	= {
			  { .ival = "none",
			    .oval = FIO_LIBISCSI_RETRY_NONE,
			    .help = "Do not repeatedly retry any failing operations",
			  },
			  { .ival = "transport",
			    .oval = FIO_LIBISCSI_RETRY_TRANSPORT,
			    .help = "Infinitely retry failing transport operations",
			  },
			  { .ival = "notready",
			    .oval = FIO_LIBISCSI_RETRY_NOT_READY,
			    .help = "Retry NOT_READY SCSI errors",
			  },
			  { .ival = "all",
			    .oval = FIO_LIBISCSI_RETRY_TRANSPORT | FIO_LIBISCSI_RETRY_NOT_READY,
			    .help = "Infinitely retry all retryable errors",
			  },
		},

	},
	{
		.name		= "headerdigest",
		.lname		= "libiscsi header digest",
		.type		= FIO_OPT_STR,
		.help		= "Control PDU header digest checksumming",
		.def		= "none",
		.off1		= offsetof(struct libiscsi_options, header_digest),
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_LIBISCSI,
		.posval	= {
			  { .ival = "none",
			    .oval = ISCSI_HEADER_DIGEST_NONE,
			    .help = "Disable header digest checking",
			  },
			  { .ival = "crc32c",
			    .oval = ISCSI_HEADER_DIGEST_CRC32C,
			    .help = "Enable header digest checking",
			  },
			  { .ival = "crc32c-none",
			    .oval = ISCSI_HEADER_DIGEST_CRC32C_NONE,
			    .help = "Express a preference for header digest checking",
			  },
			  { .ival = "none-crc32c",
			    .oval = ISCSI_HEADER_DIGEST_NONE_CRC32C,
			    .help = "Express a preference for disabling header digest checking",
			  },
		},
	},
	{
		.name = NULL,
	},
};

struct libiscsi_data {
	struct io_u **io_us_completed;
	struct io_u **io_us_events;
	struct pollfd *pfds;
	unsigned int iscsi_retry;

	int queued;

	int capacity;
	int completed;
	int read;
};

struct libiscsi_file_data {
	struct iscsi_context *iscsi;
	uint32_t lun;
	uint32_t blocksize;
	uint64_t num_blocks;
	int fd;
	int busy;
};

struct fio_libiscsi_iou {
	struct io_u *io_u;
	int io_complete;
	struct libiscsi_file_data *ifd;
	struct libiscsi_data *id;
	struct scsi_iovec iovec;
	struct scsi_task *task;
};

static struct io_u *fio_libiscsi_event(struct thread_data *td, int event)
{
	struct libiscsi_data *id = td->io_ops_data;

	dprint(FD_IO, "%s\n", __FUNCTION__);
	dprint(FD_IO, "libiscsi: return event=%d\n", event);

	return id->io_us_events[event];
}

static inline void __update_ts_cache(struct thread_data *td)
{
	fio_gettime(&td->ts_cache, NULL);
}

static inline void update_ts_cache(struct thread_data *td)
{
	if ((++td->ts_cache_nr & td->ts_cache_mask) == td->ts_cache_mask)
		__update_ts_cache(td);
}

void fio_libiscsi_complete(struct fio_libiscsi_iou *fli) {
	int index;

	dprint(FD_IO, "%s\n", __FUNCTION__);

	if (!fli->io_complete) {
		return;
	}

	fli->io_complete = 0;
	index = (fli->id->read + fli->id->completed) % fli->id->capacity;
	(fli->id->completed)++;
	dprint(FD_IO, "libiscsi: ring index=%d\n", index);
	fli->id->io_us_completed[index] = fli->io_u;
	fli->id->queued--;
	fli->task = NULL;
	dprint(FD_IO, "libiscsi: complete io_u=%p completed=%d\n", fli->io_u,
			fli->id->completed);
}

static int fio_libiscsi_getevents(struct thread_data *td, unsigned int min,
			    unsigned int max, const struct timespec *t)
{
	struct libiscsi_data *id = td->io_ops_data;
	struct libiscsi_options *o = td->eo;
	struct fio_file *f;
	struct libiscsi_file_data *ifd;

	bool busy_poll = o->busy_poll || min == 0;
	int which_events;
	bool any_which_events;
	int io_events = 0;
	int i;
	int ret;
	bool errors;
	uint64_t timeout;
	bool in_terminate_grace = false;

	/*
	 * Switching between the ramp time state only happens outside this
	 * function
	 */
	if (o->timeout_grace < 0)
		timeout = 0;
	else if (td->o.timeout && in_ramp_time(td))
		timeout = td->o.ramp_time + td->o.timeout;
	else
		timeout = td->o.timeout;

	dprint(FD_IO, "%s\n", __FUNCTION__);
	do {
		any_which_events = false;
		for_each_file(td, f, i) {
			if (fio_file_open(f)) {
				ifd = FILE_ENG_DATA(f);

				which_events = iscsi_which_events(ifd->iscsi);
				any_which_events = any_which_events || which_events;

				if (!busy_poll) {
					id->pfds[i].fd = iscsi_get_fd(ifd->iscsi);
				}
				id->pfds[i].events = which_events;
			} else {
				id->pfds[i].fd = -1;
				id->pfds[i].events = 0;
			}
		}

		if (!busy_poll && any_which_events && !td->terminate) {
			ret = poll(id->pfds, td->o.nr_files, 1000);
			if (ret < 0 && errno != EINTR) {
				td_verror(td, errno, "poll");
				break;
			}
		}

		errors = false;
		for_each_file(td, f, i) {
			if (!fio_file_open(f))
				continue;

			ifd = FILE_ENG_DATA(f);
			/* Pump libiscsi (note: this reconnects too) */
			ret = iscsi_service(ifd->iscsi, id->pfds[i].events);
			if (ret < 0 && !retry_transport(o->iscsi_retry)) {
				log_err("libiscsi_getevents: iscsi_service failed: %s\n",
						iscsi_get_error(ifd->iscsi));
				td_verror(td, ret, "iscsi_service");
				errors = true;
			}
			ifd->busy = iscsi_out_queue_length(ifd->iscsi);
		}

		/* Check for changes */
		if (id->completed > max) {
			io_events = max;
			break;
		} else if (id->completed >= min) {
			io_events = id->completed;
			break;
		} else if (errors) {
			log_err("libiscsi_getevents: aborting on error\n");
			break;
		} else if (td->terminate && (o->timeout_grace > -1) && !in_terminate_grace) {
			in_terminate_grace = true;
			dprint(FD_IO, "libiscsi_getevents: entering grace "
					"period due to terminate\n");
			__update_ts_cache(td);
			timeout = utime_since(&td->epoch, &td->ts_cache)
				+ o->timeout_grace;
		} else if (timeout) {
			update_ts_cache(td);
			if (utime_since(&td->epoch, &td->ts_cache) >= timeout) {
				if (!in_terminate_grace) {
					dprint(FD_IO, "libiscsi_getevents: entering grace period due to timeout\n");
					in_terminate_grace = true;
					timeout = utime_since(&td->epoch, &td->ts_cache) +
						o->timeout_grace;
				} else {
					dprint(FD_IO, "libiscsi_getevents: aborting on grace timeout\n");
					td_verror(td, ETIMEDOUT, "fio_libiscsi_getevents");
					break;
				}
			}
		}

		if (!any_which_events)
			usleep(100000);
	} while (true);

	for (i = 0; i < io_events; i++) {
		id->io_us_events[i] = id->io_us_completed[id->read];
		id->read = (id->read + 1);
		if (id->read == id->capacity)
			id->read = 0;
	}
	id->completed -= io_events;

	dprint(FD_IO, "libiscsi_getevents: found %d event(s)\n", io_events);
	return io_events;
}

static void fio_libiscsi_io_u_free(struct thread_data *td, struct io_u *io_u)
{
	struct fio_libiscsi_iou *fli = io_u->engine_data;

	if (fli) {
		if (fli->io_complete)
			log_err("libiscsi_io_u_free: incomplete IO found.\n");
		io_u->engine_data = NULL;
		free(fli);
	}
}

static int fio_libiscsi_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	struct fio_libiscsi_iou *fli;

	dprint(FD_IO, "%s\n", __FUNCTION__);

	fli = malloc(sizeof(struct fio_libiscsi_iou));
	if (!fli) {
		td_verror(td, errno, "malloc");
		return 1;
	}
	fli->io_u = io_u;
	fli->io_complete = 0;
	io_u->engine_data = fli;

	return 0;
}

static bool retry_task(enum libiscsi_retry iscsi_retry, int status,
		enum scsi_sense_key sense_key)
{
	bool scsi_busy, scsi_check, soft_error, retryable_hard_error;

	scsi_busy = (status == SCSI_STATUS_TASK_SET_FULL ||
		     status == SCSI_STATUS_BUSY);
	scsi_check = status == SCSI_STATUS_CHECK_CONDITION;
	soft_error = sense_key == SCSI_SENSE_UNIT_ATTENTION;
	retryable_hard_error = ((sense_key == SCSI_SENSE_HARDWARE_ERROR ||
				sense_key == SCSI_SENSE_NOT_READY) &&
			        retry_notready(iscsi_retry));

	return (scsi_busy ||
		(scsi_check && (soft_error || retryable_hard_error)) );
}

static void libiscsi_cb_common(struct iscsi_context *iscsi, int status,
		struct fio_libiscsi_iou *fli, struct io_u *io_u,
		const char *cmd_name)
{
	if (status == SCSI_STATUS_GOOD) {
		dprint(FD_IO, "libiscsi_cb_common: %s good\n", cmd_name);
		fli->io_complete = 1;
		io_u->error = 0;
	} else if (status == SCSI_STATUS_CANCELLED) {
		dprint(FD_IO, "libiscsi_cb_common: %s cancelled\n", cmd_name);
		fli->io_complete = 1;
		io_u->error = 1;
		io_u->resid = io_u->xfer_buflen;
	} else {
		log_err("libiscsi: %s failed with error %s\n", cmd_name, iscsi_get_error(iscsi));
		fli->io_complete = 1;
		io_u->error = 1;
		io_u->resid = io_u->xfer_buflen;
	}
}

static void read_cb(struct iscsi_context *iscsi, int status, void
		*command_data, void *private_data)
{
	struct fio_libiscsi_iou *fli = (struct fio_libiscsi_iou *)private_data;
	struct libiscsi_data *id = fli->id;
	struct libiscsi_file_data *ifd = fli->ifd;
	struct io_u *io_u = fli->io_u;
	struct scsi_task *task = command_data, *task2 = NULL;
	struct scsi_read16_cdb *read16_cdb = NULL;

	dprint(FD_IO, "%s\n", __FUNCTION__);
	read16_cdb = scsi_cdb_unmarshall(task, SCSI_OPCODE_READ16);
	if (read16_cdb == NULL) {
		log_err("libiscsi: READ16 unmarshall failed\n");
		fli->io_complete = 1;
		io_u->error = 1;
		io_u->resid = io_u->xfer_buflen;
		goto out;
	}

	if (retry_task(id->iscsi_retry, status, task->sense.key)) {
		task2 = iscsi_read16_task(iscsi, ifd->lun,
				read16_cdb->lba, read16_cdb->transfer_length *
				ifd->blocksize, ifd->blocksize, 0, 0, 0, 0, 0,
				read_cb, fli);
		if (task2 == NULL) {
			log_err("READ16 retry failed\n");
			fli->io_complete = 1;
			io_u->error = 1;
			io_u->resid = io_u->xfer_buflen;

			goto out;
		}
		scsi_task_set_iov_in(task2, &fli->iovec, 1);
		fli->task = task2;
	} else {
		libiscsi_cb_common(iscsi, status, fli, io_u, "READ16");
	}
out:
	fio_libiscsi_complete(fli);
	scsi_free_scsi_task(task);
}

static void write_cb(struct iscsi_context *iscsi, int status, void
		*command_data, void *private_data)
{
	struct fio_libiscsi_iou *fli = (struct fio_libiscsi_iou *)private_data;
	struct libiscsi_data *id = fli->id;
	struct libiscsi_file_data *ifd = fli->ifd;
	struct io_u *io_u = fli->io_u;
	struct scsi_task *task = command_data, *task2 = NULL;
	struct scsi_write16_cdb *write16_cdb = NULL;

	dprint(FD_IO, "%s\n", __FUNCTION__);
	write16_cdb = scsi_cdb_unmarshall(task, SCSI_OPCODE_WRITE16);
	if (write16_cdb == NULL) {
		log_err("libiscsi: WRITE16 unmarshall failed\n");
		fli->io_complete = 1;
		io_u->error = 1;
		io_u->resid = io_u->xfer_buflen;
		goto out;
	}

	if (retry_task(id->iscsi_retry, status, task->sense.key)) {
		task2 = iscsi_write16_task(iscsi, ifd->lun,
				write16_cdb->lba, io_u->xfer_buf, write16_cdb->transfer_length *
				ifd->blocksize, ifd->blocksize, 0, 0, 0,
				0, 0, write_cb, fli);
		if (task2 == NULL) {
			log_err("libiscsi: sending WRITE16 retry failed\n");
			fli->io_complete = 1;
			io_u->error = 1;
			io_u->resid = io_u->xfer_buflen;

			goto out;
		}
		fli->task = task2;
	} else {
		libiscsi_cb_common(iscsi, status, fli, io_u, "WRITE16");
	}

out:
	fio_libiscsi_complete(fli);
	scsi_free_scsi_task(task);
}

static int fio_libiscsi_queue(struct thread_data *td, struct io_u *io_u)
{
	struct libiscsi_file_data *ifd = FILE_ENG_DATA(io_u->file);
	struct libiscsi_data *id = td->io_ops_data;
	struct scsi_task *task;
	struct fio_libiscsi_iou *fli = io_u->engine_data;
	uint64_t lba;
	int ret;

	dprint(FD_IO, "%s op %s\n", __FUNCTION__, io_ddir_name(io_u->ddir));

	fio_ro_check(td, io_u);

	// FIXME: Following is incorrect because it would allow io_us_completed
	// to grow greater than the iodepth.
	// Should it be id->queued + id->completed (essentially I/Os in
	// flight)?
	// >= rather > on batch?
	if (id->queued == td->o.iodepth || ifd->busy > td->o.iodepth_batch) {
		return FIO_Q_BUSY;
	}

	fli->ifd = ifd;
	fli->id = id;

	lba = io_u->offset / ifd->blocksize;

	if (io_u->xfer_buflen & (ifd->blocksize - 1) ||
	    io_u->offset & (ifd->blocksize - 1)) {
		log_err("libiscsi_queue: IO not sector aligned\n");
		ret = EINVAL;
	} else if (io_u->ddir == DDIR_READ) {
		fli->iovec.iov_base = io_u->xfer_buf;
		fli->iovec.iov_len = io_u->xfer_buflen;
		task = iscsi_read16_task(ifd->iscsi, ifd->lun, lba,
				io_u->buflen, ifd->blocksize, 0, 0, 0, 0, 0,
				read_cb, fli);

		if (task == NULL) {
			log_err("libiscsi_queue: sending READ16 failed\n");
			ret = 1;
		} else {
			scsi_task_set_iov_in(task, &fli->iovec, 1);
			ret = 0;
		}
	} else if (io_u->ddir == DDIR_WRITE) {
		task = iscsi_write16_task(ifd->iscsi, ifd->lun, lba,
				io_u->xfer_buf, io_u->buflen, ifd->blocksize,
				0, 0, 0, 0, 0, write_cb, fli);

		if (task == NULL) {
			log_err("libiscsi_queue: sending WRITE16 failed\n");
			ret = 1;
		} else
			ret = 0;
	} else if (io_u->ddir == DDIR_TRIM)
		ret = EINVAL;
	else if (io_u->ddir == DDIR_SYNC)
		ret = EINVAL;
	else
		ret = EINVAL;

	if (ret) {
		log_err("libiscsi_queue: failed.\n");
		io_u->error = ret;
		td_verror(td, io_u->error, "xfer");
		return FIO_Q_COMPLETED;
	} else {
		fli->task = task;
		id->queued++;
		return FIO_Q_QUEUED;
	}
}

static int fio_libiscsi_cancel(struct thread_data *td, struct io_u *io_u)
{
	struct fio_libiscsi_iou *fli = io_u->engine_data;
	int ret;

	dprint(FD_IO, "%s: cancelling IO\n", __FUNCTION__);

	if (fli->task)
		ret = iscsi_scsi_cancel_task(fli->ifd->iscsi, fli->task);
	else {
		dprint(FD_IO, "%s: to-cancel IO had no libiscsi task\n",
				__FUNCTION__);
		ret = 0;
	}

	return ret;
}

static void fio_libiscsi_cleanup(struct thread_data *td)
{
	struct libiscsi_data *id = td->io_ops_data;

	dprint(FD_IO, "%s\n", __FUNCTION__);

	if (id) {
		dprint(FD_IO, "libiscsi: freeing libiscsi_data\n");
		if (id->io_us_completed)
			free(id->io_us_completed);
		if (id->io_us_events)
			free(id->io_us_events);
		if (id->pfds)
			free(id->pfds);

		free(id);
	}
	td->io_ops_data = NULL;
}

static int fio_libiscsi_connect(enum libiscsi_protocol protocol,
		char *file_name, char *initiator, unsigned int header_digest,
		bool retry, volatile int *terminate, struct
		iscsi_context **iscsi, uint32_t *lun) {
	struct iscsi_context *new_context = NULL;
	struct iscsi_url *iscsi_url = NULL;
	char url[255];
	int ret;
	int attempts;

	if (strncmp(file_name, "iscsi://", 8) != 0 &&
			strncmp(file_name, "iser://", 7) != 0) {
		ret = snprintf(url, 255, "%s://%s", protocol ==
				FIO_LIBISCSI_ISCSI ? "iscsi" : "iser",
				file_name);
	} else {
		ret = snprintf(url, 255, "%s", file_name);
	}

	if (ret < 0 || ret >= 255) {
		log_err("libiscsi: Failed to construct valid URL\n");
		ret = 1;
		goto cleanup;
	}
	dprint(FD_IO, "libiscsi: constructed URL %s\n", url);

	new_context = iscsi_create_context(initiator);
	if (new_context == NULL) {
		log_err("libiscsi: Failed to create context\n");
		ret = 1;
		goto cleanup;
	}
	dprint(FD_IO, "libiscsi: got context\n");

	iscsi_url = iscsi_parse_full_url(new_context, url);

	if (!iscsi_url) {
		log_err("libiscsi: Failed to parse iSCSI URL %s\n",
				iscsi_get_error(new_context));
		ret = 1;
		goto cleanup;
	}
	dprint(FD_IO, "libiscsi: portal=%s, target=%s\n", iscsi_url->portal,
			iscsi_url->target);

	iscsi_set_session_type(new_context, ISCSI_SESSION_NORMAL);
	iscsi_set_header_digest(new_context, header_digest);
	iscsi_set_reconnect_max_retries(new_context, 0);
	/* FIXME: Set timeout? */

	dprint(FD_IO, "libiscsi: attempting login (retry=%s)\n",
			retry ? "yes" : "no");

	attempts = 0;
	ret = iscsi_full_connect_sync(new_context, iscsi_url->portal,
			iscsi_url->lun);
	while (ret != 0 && !*terminate && retry) {
		dprint(FD_IO, "libiscsi: login failed, ret=%d\n", ret);
		usleep(100000);
		dprint(FD_IO, "libiscsi: attempting re-login\n");
		iscsi_logout_sync(new_context);
		iscsi_disconnect(new_context);
		ret = iscsi_full_connect_sync(new_context, iscsi_url->portal,
				iscsi_url->lun);
		attempts++;
	}
	if (ret != 0) {
		log_err("libiscsi: login failed: %s\n",
				iscsi_get_error(new_context));
		goto cleanup;
	}

	if (retry)
		iscsi_set_reconnect_max_retries(new_context, -1);

	*lun = iscsi_url->lun;
	dprint(FD_IO, "libiscsi: iscsi_url->lun=%d\n", iscsi_url->lun);

	*iscsi = new_context;
	ret = 0;

cleanup:
	if (iscsi_url) {
		iscsi_destroy_url(iscsi_url);
	}
	if (ret != 0 && new_context) {
		iscsi_destroy_context(new_context);
	}

	return ret;
}

static int fio_libiscsi_init(struct thread_data *td)
{
	struct libiscsi_data *id = NULL;
	int ret;


	dprint(FD_IO, "libiscsi: api version=%d\n", LIBISCSI_API_VERSION);

	/* FIXME: Use malloc instead of calloc? */
	id = calloc(1, sizeof(struct libiscsi_data));
	if (!id) {
		return -ENOMEM;
	}
	td->io_ops_data = id;

	id->io_us_completed = malloc(td->o.iodepth * sizeof(struct io_u *));
	id->io_us_events = malloc(td->o.iodepth * sizeof(struct io_u *));
	id->pfds = malloc(td->o.nr_files * sizeof(struct pollfd));

	if (!id->io_us_completed || !id->io_us_events || !id->pfds) {
		log_err("libiscsi: out of memory\n");
		ret = -ENOMEM;
		goto cleanup;
	}

	id->iscsi_retry = ((struct libiscsi_options *) td->eo)->iscsi_retry;

	/* Initialise ring */
	id->capacity = td->o.iodepth;
	id->read = 0;
	id->completed = 0;

	return 0;

cleanup:
	return ret;
}

static int fio_libiscsi_readcapacity(struct iscsi_context *iscsi,
		uint32_t lun, uint32_t *blocksize, uint64_t *num_blocks)
{
	struct scsi_task *task = NULL;
	struct scsi_readcapacity16 *rc16;
	int ret = 0;

	task = iscsi_readcapacity16_sync(iscsi, lun);
	if (task == NULL || task->status != SCSI_STATUS_GOOD) {
		log_err("libiscsi: sending READCAPACITY16 failed: %s\n",
				iscsi_get_error(iscsi));
		ret = 1;
		goto cleanup;
	}

	rc16 = scsi_datain_unmarshall(task);
	if (rc16 == NULL) {
		log_err("libiscsi: READCAPACITY16 unmarshall failed\n");
		ret = 1;
		goto cleanup;
	}

	*blocksize = rc16->block_length;
	*num_blocks = rc16->returned_lba + 1;

	ret = 0;

cleanup:
	if (task)
		scsi_free_scsi_task(task);

	return ret;
}

static int fio_libiscsi_open_file(struct thread_data *td, struct fio_file *f)
{
	struct libiscsi_file_data *ifd;
	struct libiscsi_options *o = td->eo;
	int ret;

	dprint(FD_FILE, "%s\n", __FUNCTION__);

	/* FIXME: Use malloc instead of calloc? */
	ifd = calloc(1, sizeof(*ifd));
	if (!ifd) {
		log_err("libiscsi: out of memory\n");
		ret = 1;
		goto cleanup;
	}

	if (fio_libiscsi_connect(o->protocol, f->file_name, o->initiator,
				o->header_digest, retry_transport(o->iscsi_retry),
				&td->terminate, &ifd->iscsi, &ifd->lun) != 0) {
		log_err("libiscsi: failed to connect to target\n");
		ret = 1;
		goto cleanup;
	}

	if (fio_libiscsi_readcapacity(ifd->iscsi, ifd->lun, &ifd->blocksize,
				&ifd->num_blocks) != 0) {
		ret = 1;
		goto cleanup;
	}

	FILE_SET_ENG_DATA(f, ifd);
	ret = 0;

cleanup:
	return ret;
}

static int fio_libiscsi_close_file(struct thread_data *td, struct fio_file *f)
{
	struct libiscsi_file_data *ifd = FILE_ENG_DATA(f);
	struct libiscsi_options *o = td->eo;
	int ret = 0;

	FILE_SET_ENG_DATA(f, NULL);

	if (ifd && ifd->iscsi) {
#if 0
		struct libiscsi_data *id = td->io_ops_data;

		// FIXME: Should never be non-zero because cancellation would
		// have kicked in making it 0
		if (id->queued) {
			log_err("libiscsi: aborting outstanding IO\n");
			iscsi_task_mgmt_abort_task_set_sync(ifd->iscsi, ifd->lun);
		}
#endif

		/*
		 * Don't retry logging out as we can become stuck when we're
		 * not logged in...
		 */
		iscsi_set_reconnect_max_retries(ifd->iscsi, 0);
		// TODO: Have an explicit login/logout timeout?
		iscsi_set_timeout(ifd->iscsi, o->timeout_grace / (uint64_t) 1000000);
		ret = iscsi_logout_sync(ifd->iscsi);

		dprint(FD_IO, "libiscsi: freeing libiscsi_file_data\n");
		iscsi_destroy_context(ifd->iscsi);
		free(ifd);
	}

	return ret;
}

static int fio_libiscsi_get_file_size(struct thread_data *td, struct fio_file *f)
{
	struct libiscsi_file_data *ifd = FILE_ENG_DATA(f);
	struct libiscsi_options *o = td->eo;
	struct iscsi_context *iscsi = NULL;

	int ret;
	bool new_connection;
	uint32_t lun;
	uint32_t blocksize;
	uint64_t num_blocks;

	dprint(FD_FILE, "libiscsi: get file size for %s\n", f->file_name);

	if (fio_file_size_known(f))
		return 0;

	if (ifd) {
		new_connection = false;
		iscsi = ifd->iscsi;
		lun = ifd->lun;
	} else {
		new_connection = true;

		dprint(FD_FILE, "libiscsi: iscsi_retry=%d\n", o->iscsi_retry);
		if (fio_libiscsi_connect(o->protocol, f->file_name,
		    o->initiator, o->header_digest, retry_transport(o->iscsi_retry),
		    &td->terminate, &iscsi, &lun) != 0) {
			ret = 1;
			goto cleanup;
		}
	}

	dprint(FD_IO, "libiscsi: iscsi=%p lun=%d\n", iscsi, lun);

	if (fio_libiscsi_readcapacity(iscsi, lun, &blocksize,
				&num_blocks) != 0) {
		ret = 1;
		goto cleanup;
	}

	f->real_file_size = blocksize * num_blocks;
	fio_file_set_size_known(f);

	dprint(FD_FILE, "libiscsi: LUN size=%" PRId64 " bytes\n",
			f->real_file_size);

	ret = 0;

cleanup:
	if (new_connection && iscsi) {
		iscsi_set_reconnect_max_retries(iscsi, 0);
		iscsi_logout_sync(iscsi);
		iscsi_destroy_context(iscsi);
	}

	return ret;
}

static struct ioengine_ops ioengine = {
	.name		= "libiscsi",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_libiscsi_init,
	.cancel		= fio_libiscsi_cancel,
	.cleanup	= fio_libiscsi_cleanup,
	.queue		= fio_libiscsi_queue,
	.open_file	= fio_libiscsi_open_file,
	.close_file	= fio_libiscsi_close_file,
	.get_file_size	= fio_libiscsi_get_file_size,
	.getevents	= fio_libiscsi_getevents,
	.event		= fio_libiscsi_event,
	.io_u_init	= fio_libiscsi_io_u_init,
	.io_u_free	= fio_libiscsi_io_u_free,
	.options	= options,
	.option_struct_size = sizeof(struct libiscsi_options),
	.flags		= FIO_DISKLESSIO | FIO_NOEXTEND | FIO_RAWIO,
};

static void fio_init fio_libiscsi_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_libiscsi_unregister(void)
{
	unregister_ioengine(&ioengine);
}
