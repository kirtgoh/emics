/* regs.h - architected register state interfaces */

#ifndef REGS_H
#define REGS_H

#include "host.h"
//#include "misc.h"
#include "mips.h"

/*
 * This module implements the SimpleScalar architected register state, which
 * includes integer and floating point registers and miscellaneous registers.
 * The architected register state is as follows:
 *
 * Integer Register File:                  Miscellaneous Registers:
 * (aka general-purpose registers, GPR's)
 *
 *   +------------------+                  +------------------+
 *   | $r0 (src/sink 0) |                  | PC               | Program Counter
 *   +------------------+                  +------------------+
 *   | $r1              |                  | HI               | Mult/Div HI val
 *   +------------------+                  +------------------+
 *   |  .               |                  | LO               | Mult/Div LO val
 *   |  .               |                  +------------------+
 *   |  .               |
 *   +------------------+
 *   | $r31             |
 *   +------------------+
 *
 * Floating point Register File:
 *    single-precision:  double-precision:
 *   +------------------+------------------+  +------------------+
 *   | $f0              | $f1 (for double) |  | FCC              | FP codes
 *   +------------------+------------------+  +------------------+
 *   | $f1              |
 *   +------------------+
 *   |  .               |
 *   |  .               |
 *   |  .               |
 *   +------------------+------------------+
 *   | $f30             | $f31 (for double)|
 *   +------------------+------------------+
 *   | $f31             |
 *   +------------------+
 *
 * The floating point register file can be viewed as either 32 single-precision
 * (32-bit IEEE format) floating point values $f0 to $f31, or as 16
 * double-precision (64-bit IEEE format) floating point values $f0 to $f30.
 */

struct regs_t {
  md_gpr_t regs_R;		/* (signed) integer register file */
  md_fpr_t regs_F;		/* floating point register file */
  md_ctrl_t regs_C;		/* control register file */
  md_addr_t regs_PC;		/* program counter */
  md_addr_t regs_NPC;		/* next-cycle program counter */
  md_addr_t regs_TPC;
};

struct regs_t regs[NUM_CORES];

/* create a register file */
struct regs_t *regs_create(void);

/* initialize architected register state */
void
regs_init(int pid, md_addr_t init_stack, md_addr_t entry, struct regs_t *regs);		/* register file to initialize */

/* dump all architected register state values to output stream STREAM */
void
regs_dump(struct regs_t *regs,		/* register file to display */
	  FILE *stream);		/* output stream */

/* destroy a register file */
void
regs_destroy(struct regs_t *regs);	/* register file to release */

#endif /* REGS_H */
