/* loader.h - program loader interfaces */

#ifndef LOADER_H
#define LOADER_H

#include <stdio.h>

#include "host.h"
//#include "misc.h"
#include "mips.h"
#include "regs.h"
#include "memory.h"

/*
 * This module implements program loading.  The program text (code) and
 * initialized data are first read from the program executable.  Next, the
 * program uninitialized data segment is initialized to all zero's.  Finally,
 * the program stack is initialized with command line arguments and
 * environment variables.  The format of the top of stack when the program
 * starts execution is as follows:
 *
 * 0x7fffffff    +----------+
 *               | unused   |
 * 0x7fffc000    +----------+
 *               | envp     |
 *               | strings  |
 *               +----------+
 *               | argv     |
 *               | strings  |
 *               +----------+
 *               | envp     |
 *               | array    |
 *               +----------+
 *               | argv     |
 *               | array    |
 *               +----------+
 *               | argc     |
 * regs_R[29]    +----------+
 * (stack ptr)
 *
 * NOTE: the start of envp is computed in crt0.o (C startup code) using the
 * value of argc and the computed size of the argv array, the envp array size
 * is not specified, but rather it is NULL terminated, so the startup code
 * has to scan memory for the end of the string.
 */

/*
 * program segment ranges, valid after calling ld_load_prog()
 */

/* program text (code) segment base */
extern md_addr_t ld_text_base;

/* program text (code) size in bytes */
extern unsigned int ld_text_size;

/* program initialized data segment base */
extern md_addr_t ld_data_base;

/* program initialized ".data" and uninitialized ".bss" size in bytes */
extern unsigned int ld_data_size;

/* top of the data segment */
extern md_addr_t ld_brk_point;

/* program stack segment base (highest address in stack) */
extern md_addr_t ld_stack_base;

/* program initial stack size */
extern unsigned int ld_stack_size;

/* lowest address accessed on the stack */
extern md_addr_t ld_stack_min;

extern md_addr_t tls_base;

/* program file name */
extern char *ld_prog_fname;

/* program entry point (initial PC) */
extern md_addr_t ld_prog_entry;

/* program environment base address address */
extern md_addr_t ld_environ_base;

/* target executable endian-ness, non-zero if big endian */
extern int ld_target_big_endian;

/* register simulator-specific statistics */
void
ld_reg_stats(struct stat_sdb_t *sdb);	/* stats data base */

/* load program text and initialized data into simulated virtual memory
   space and initialize program segment range variables */
void
ld_load_prog(char *fname,		/* program to load */
	     int argc, char **argv,	/* simulated program cmd line args */
	     char **envp,		/* simulated program environment */
	     struct regs_t *regs,	/* registers to initialize for load */
	     struct mem_t *mem,		/* memory space to load prog into */
	     int zero_bss_segs);	/* zero uninit data segment? */

#endif /* LOADER_H */
