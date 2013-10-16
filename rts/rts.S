/*
 * runtime.S - runtime library code for SimpleScalar multiprocessor support
 *
 */

/* include #defines for system call codes specific to multiprocessing */
//#include "mpsyscalls.h"


	.text

/*---------------------------------------------------------------------*/

        .align  2
        .globl  lock

        .ent    lock
lock:
        li      $2, 4300/*SS_MP_ACQUIRE_LOCK*/
        syscall
        jr      $31

        .end    lock

/*---------------------------------------------------------------------*/

	.align  2
        .globl  unlock

        .ent    unlock
unlock:
        li      $2, 4301/*SS_MP_RELEASE_LOCK*/
        syscall
        jr      $31

        .end    unlock

/*---------------------------------------------------------------------*/

	.align  2
        .globl  init_lock

        .ent    init_lock
init_lock:
        li      $2, 4302/*SS_MP_INIT_LOCK*/
        syscall
        jr      $31

        .end    init_lock

/*---------------------------------------------------------------------*/

        .align  2
        .globl  barrier

        .ent    barrier
barrier:
        li      $2, 4303/*SS_MP_BARRIER*/
        syscall
        jr      $31

        .end	barrier

/*---------------------------------------------------------------------*/

        .align  2
        .globl  init_barrier

        .ent    init_barrier
init_barrier:
        li      $2, 4304/*SS_MP_INIT_BARRIER*/
        syscall
        jr      $31

        .end	init_barrier

/*---------------------------------------------------------------------*/

        .align  2
        .globl  get_my_thread_id

        .ent    get_my_thread_id
get_my_thread_id:
        li      $2, 4305/*SS_MP_THREAD_ID*/
        syscall
        jr      $31

        .end    get_my_thread_id

/*---------------------------------------------------------------------*/
/*
/        .align  2
        .globl  get_cycle

        .ent    get_cycle
get_cycle:
        li      $2, SS_MP_GET_CYCLE
        syscall
        jr      $31

        .end    get_cycle*/
/*---------------------------------------------------------------------*/

	.text
        .align  2
        .globl  create_thread

        .ent    create_thread
create_thread:
        la      $5, thread_wrapper
	li	$2, 4306/*SS_MP_CREATE_THREAD*/
        syscall
        jr      $31

        .end    create_thread

/*---------------------------------------------------------------------*/

	.text
        .align  2
        .globl  thread_wrapper

        .ent    thread_wrapper
thread_wrapper:
	move	$25, $4
	jalr	$31, $4			# call user-supplied function
        li      $2, 4307/*SS_MP_EXIT_THREAD*/	# and then terminate
        syscall				# thread exits, no return here
        jr      $0			# THIS SHOULD NEVER BE EXECUTED !!!

        .end    thread_wrapper

/*---------------------------------------------------------------------*/

        .align  2
        .globl  sema_wait

        .ent    sema_wait
sema_wait:
        li      $2, 4308/*SS_MP_SEMA_WAIT*/
        syscall
        jr      $31

        .end    sema_wait

/*---------------------------------------------------------------------*/

	.align  2
        .globl  sema_signal

        .ent    sema_signal
sema_signal:
        li      $2, 4309/*SS_MP_SEMA_SIGNAL*/
        syscall
        jr      $31

        .end    sema_signal

/*---------------------------------------------------------------------*/

	.align  2
        .globl  init_sema

        .ent    init_sema
init_sema:
        li      $2, 4310/*SS_MP_INIT_SEMA*/
        syscall
        jr      $31

        .end    init_sema
