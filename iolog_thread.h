#ifndef FIO_IOLOG_THREAD_H
#define FIO_IOLOG_THREAD_H
enum swap_states {
	SWAP_EMPTY		= 0,
	SWAP_EMPTY_WAITING, // Empty back buffer and consumer is waiting
	SWAP_READY,         // Back buffer is ready
	SWAP_READY_FINAL,   // Final back buffer is ready (no more will be produced)
	SWAP_EXHAUSTED,     // No back buffer and none can be produced
};
extern int iolog_thread_create(struct thread_data *td);

#endif
