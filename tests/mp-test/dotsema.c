/*
 * dotsema.c - computes dot product in parallel and uses semaphore for synch
 *
 * This file is used in conjunction with the SimpleScalar tool suite
 * originally written by Todd M. Austin for the Multiscalar Research Project
 * at the University of Wisconsin-Madison.
 *
 * The file was created by Naraig Manjikian at Queen's University,
 * Kingston, Ontario, Canada.
 *
 * Copyright (C) 2000 by Naraig Manjikian
 *
 * This source file is distributed "as is" in the hope that it will be
 * useful.  The tool set comes with no warranty, and no author or
 * distributor accepts any responsibility for the consequences of its
 * use. 
 * 
 * Everyone is granted permission to copy, modify and redistribute
 * this tool set under the following conditions:
 * 
 *    This source code is distributed for non-commercial use only. 
 *    Please contact the maintainer for restrictions applying to 
 *    commercial use.
 *
 *    Permission is granted to anyone to make or distribute copies
 *    of this source code, either as received or modified, in any
 *    medium, provided that all copyright notices, permission and
 *    nonwarranty notices are preserved, and that the distributor
 *    grants the recipient permission for further redistribution as
 *    permitted by this document.
 *
 *    Permission is granted to distribute this file in compiled
 *    or executable form under the same conditions that apply for
 *    source code, provided that either:
 *
 *    A. it is accompanied by the corresponding machine-readable
 *       source code,
 *    B. it is accompanied by a written offer, with no time limit,
 *       to give anyone a machine-readable copy of the corresponding
 *       source code in return for reimbursement of the cost of
 *       distribution.  This written offer must permit verbatim
 *       duplication by anyone, or
 *    C. it is distributed by someone who received only the
 *       executable form, and is accompanied by a copy of the
 *       written offer of source code that they received concurrently.
 *
 * In other words, you are welcome to use, share and improve this
 * source file.  You are forbidden to forbid anyone else to use, share
 * and improve what you give them.
 */

#include <stdio.h>
#include <stdlib.h>

#include "rts.h"

#define MAX_THREADS 8

int	NUM_THREADS = 1;    /* number of threads to use */
int	N = 100;            /* number of elements in each vector */

/* Shared variables when using threads */

#define NMAX 10000

double	a[NMAX], b[NMAX];
double	dot_product;

Lock	the_lock;
Sema	the_sema;	/* this semaphore and the following count variable */
int	arrival_count;	/*  are used to implement a "barrier" */

extern  char	*optarg;	/* this is a global variable set by the */
				/* 'getopt()' library function */
void    ParallelFunction ()
{
        int     thread_id = get_my_thread_id ();
        int     i, start, end;
        double  local_sum;

        /* Compute the start/end of the array range for this thread. */
        start = thread_id * N / NUM_THREADS;
        if (thread_id == NUM_THREADS - 1)
                end = N - 1;    /* last thread; go to end of arrays */
        else
                end = (thread_id + 1) * N / NUM_THREADS - 1;

        /* Compute the partial dot product using a local variable */
        local_sum = 0.0;
        for (i = start; i <= end; i++)
                local_sum += a[i] * b[i];

        /* After computing the partial sum, add it atomically to the total. */
        lock (the_lock);
        dot_product += local_sum;
	unlock (the_lock);
	
	/* now perform a "barrier" using a semaphore */
	lock (the_lock);
	++arrival_count;
	if (arrival_count == NUM_THREADS)
	{
	    for (i = 0; i < NUM_THREADS - 1; i++) /* unblock other threads */
		sema_signal (the_sema);
	    arrival_count = 0;			/* then reset the count */
	    unlock (the_lock);			/* and finally free the lock */
	}
	else
	{
	    unlock (the_lock);		/* _FIRST_ free the lock */
	    sema_wait (the_sema);	/* and then block ourselves */
	}

        /* Parallel phase complete; threads will terminate and die
           (except for main program thread). */
}

int	main(int argc, char **argv)
{
	int             c, i;

	/* get command line parameters */
	while ((c = getopt(argc, argv, "n:p:h")) != -1)
	    switch (c)
	    {
		case 'n':
		    N = atoi(optarg);
		    if (N > NMAX)
		    {
			fprintf (stderr, "Error: N is too large (max = %d)\n",
				 NMAX);
			return 1;
		    }
		    break;
		case 'p':
		    NUM_THREADS = atoi(optarg);
		    if (NUM_THREADS > MAX_THREADS)
		    {
			fprintf (stderr, "Error: too many threads (max = %d)\n",
				 MAX_THREADS);
			return 1;
		    }
		    break;
		case 'h':
		default:
		    fprintf(stderr, "DOT - OPTIONS\n");
		    fprintf(stderr, "\tp - Number of processors\n");
		    fprintf(stderr, "\tn - Number of elements in vectors\n");
		    fprintf(stderr, "\th - Help\n");
		    return 0;
	    }

        /* Initialize the two vectors with some interesting values. */
        for (i = 0; i < N; i++)
                a[i] = b[i] = (double) 1.0/(i+1);

	/* initialize synchronization variables */
	init_sema (&the_sema, 0);	/* first sema_wait will block */
	init_lock (&the_lock);

	/* create the threads */
	for (i = 1; i < NUM_THREADS; i++) /* create NUM_THREADS-1 threads */
	    create_thread (ParallelFunction);
        ParallelFunction ();	/* invoke function directly for thread 0 */

        /* When we return here, all threads have completed after synchronizing
           on the barrier. The main program can print the result. */
        printf ("The dot product is: %f\n", dot_product);

	return 0;
}
