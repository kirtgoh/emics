/*
 * rts.h - many-core run-time support interfaces
 *
 */

#ifndef SSMP_H
#define SSMP_H

typedef	int	Lock;
typedef int	Barrier;
typedef	int	Sema;

extern	void	init_lock (Lock *lock_ptr);
extern	void	init_barrier (Barrier *barrier_ptr);
extern	void	init_sema (Sema *sema_ptr, int initial_sema_count);

extern	void	lock (Lock lock_id);
extern	void	unlock (Lock lock_id);

extern	void	barrier (Barrier barrier_id, int num_threads);

extern	void	sema_wait (Sema sema_id);
extern	void	sema_signal (Sema sema_id);

extern	void	create_thread (void (*function_ptr)(void));

extern	int	get_my_thread_id (void);

#endif /* SSMP_H */
