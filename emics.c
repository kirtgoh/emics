/* sim-safe.c - sample functional simulator implementation 
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "host.h"
#include "misc.h"
#include "mips.h"
#include "regs.h"
#include "memory.h"
#include "loader.h"
#include "syscall.h"
#include "options.h"
#include "stats.h"
#include "sim.h"
//#include "mpcache.h"

/*
 * This file implements a functional simulator.  This functional simulator is
 * the simplest, most user-friendly simulator in the simplescalar tool set.
 * Unlike sim-fast, this functional simulator checks for all instruction
 * errors, and the implementation is crafted for clarity rather than speed.
 */

/* simulated registers */
//static struct regs_t regs[NUM_CORES];

/* simulated memory */
static struct mem_t *mem = NULL;

/* track number of refs */
static counter_t sim_num_refs = 0;

/* maximum number of inst's to execute */
static unsigned int max_insts;

/* we count instructions executed by each process, and also the
   number of cycles from beginning to end (note that processes may
   not be in existence or active during part of the total number of
   cycles) */
unsigned int    sim_num_instructions[NUM_CORES];
unsigned int    sim_num_cycles = 0;

extern  int     active[NUM_CORES];

/* the following is made volatile because it may be changed externally
   during execution, and it is the upper bound of a 'for' loop (see below) */
extern  volatile int    num_created_threads;

/* cache parameters with default values
   (cache size is in kilobytes, line size is in bytes) */
static  int     L1_size =8,   L1_line_size = 16;
static  int     L2_size =256, L2_line_size = 16;

#ifdef GRAPHICS
static  int     graphics_flag;  /* flag to select graphics */
static  int     graphics_speed; /* animation speed (1 to 10) */
#endif /* GRAPHICS */

/* macro for computing log base 2; the 'log_base2' function that
   is already defined in misc.c expects exact powers of 2;
   this macro works for any number */
//#define log2_base(x) ((int)(log(x)/log(2)))
/* return log of a number to the base 2 */
int
log2_base(int n)
{
  int power = 0;
  if (n <= 0 || (n & (n-1)) != 0)
    panic("log2_base() only works for positive power of two values");
  while (n >>= 1)
    power++;
  return power;
}



/* register simulator-specific options */
void
sim_reg_options(struct opt_odb_t *odb)
{
  opt_reg_header(odb, 
"sim-safe: This simulator implements a functional simulator.  This\n"
"functional simulator is the simplest, most user-friendly simulator in the\n"
"simplescalar tool set.  Unlike sim-fast, this functional simulator checks\n"
"for all instruction errors, and the implementation is crafted for clarity\n"
"rather than speed.\n"
		 );
  opt_reg_int (odb, "-L1", "Level 1 cache size (kbytes)",
               &L1_size, /* default */8, /* print */TRUE, NULL);

  opt_reg_int (odb, "-L1line", "Level 1 line size (bytes)",
               &L1_line_size, /* default */16, /* print */TRUE, NULL);

  opt_reg_int (odb, "-L2", "Level 2 cache size (kbytes)",
               &L2_size, /* default */256, /* print */TRUE, NULL);

  opt_reg_int (odb, "-L2line", "Level 2 line size (bytes)",
               &L2_line_size, /* default */16, /* print */TRUE, NULL);


  /* instruction limit */
  opt_reg_uint(odb, "-max:inst", "maximum number of inst's to execute",
	       &max_insts, /* default */0,
	       /* print */TRUE, /* format */NULL);
#ifdef GRAPHICS  
  opt_reg_flag(odb, "-graphics", "graphical display of coherence",
               &graphics_flag, /* default */FALSE, /* print */TRUE, NULL);

  opt_reg_int (odb, "-speed", "animation speed (1 to 10)",
               &graphics_speed, /* default */10, /* print */TRUE, NULL);
#endif /* GRAPHICS */


}

/* check simulator-specific option values */
void
sim_check_options(struct opt_odb_t *odb, int argc, char **argv)
{
 /* verify that L1 and L2 cache capacities are powers of 2 */
    if ((1 << log2_base(L1_size)) != L1_size)
        fatal("The L1 cache size of %d kbytes is not a power of 2.", L1_size);
    if ((1 << log2_base(L2_size)) != L2_size)
        fatal("The L2 cache size of %d kbytes is not a power of 2.", L2_size);

    /* verify that L1 cache capacity is no larger than L2 cache capacity */
    if (L1_size > L2_size)
        fatal ("The L1 cache size of %d kbytes is larger than"
               "\n\tthe L2 cache size of %d kbytes.", L1_size, L2_size);

    /* verify that L1 and L2 line sizes are powers of 2 */
    if ((1 << log2_base(L1_line_size)) != L1_line_size)
        fatal("The L1 line size of %d bytes is not a power of 2.",
              L1_line_size);
    if ((1 << log2_base(L2_line_size)) != L2_line_size)
        fatal("The L2 line size of %d bytes is not a power of 2.",
              L2_line_size);

    /* verify that L2 line size is greater than or equal to L1 line size */
    if (L2_line_size < L1_line_size)
        fatal ("The L2 line size of %d bytes is smaller than"
               "\n\tthe L1 line size of %d bytes.", L2_line_size,L1_line_size);

#ifdef GRAPHICS
    /* check validity of animation speed parameter */
    if (graphics_speed < 1 || graphics_speed > 10)
        fatal("The animation speed must be 1 (slowest) to 10 (fastest).");
#endif /* GRAPHICS */


}


/* register simulator-specific statistics */
void
sim_reg_stats(struct stat_sdb_t *sdb)
{
  stat_reg_counter(sdb, "sim_num_insn",
		   "total number of instructions executed",
		   &sim_num_insn, sim_num_insn, NULL);
  stat_reg_counter(sdb, "sim_num_refs",
		   "total number of loads and stores executed",
		   &sim_num_refs, 0, NULL);
  stat_reg_int(sdb, "sim_elapsed_time",
	       "total simulation time in seconds",
	       &sim_elapsed_time, 0, NULL);
  stat_reg_formula(sdb, "sim_inst_rate",
		   "simulation speed (in insts/sec)",
		   "sim_num_insn / sim_elapsed_time", NULL);

  stat_reg_uint(sdb, "sim_num_cycles",
                "total number of execution cycles",
                &sim_num_cycles, 0, NULL);


  stat_reg_int(sdb, "sim_elapsed_time",
               "total simulation time in seconds",
               (int *)&sim_elapsed_time, 0, NULL);

  ld_reg_stats(sdb);
  mem_reg_stats(mem, sdb);
}

/* initialize the simulator */
void
sim_init(void)
{
  sim_num_refs = 0;

  /* allocate and initialize register file */
  //regs_init(&regs);

  /* initialize address spaces */
  regs_init(0,                          /* pid 0 is first to run */
            (md_addr_t) NULL,        /* init_stack_ptr (unused for pid 0) */
            (md_addr_t) NULL, &regs[0]);       /* entry_ptr (unused for pid 0) */

  /* allocate and initialize memory space */
  mem = mem_create("mem");
  mem_init(mem);
  /* initialize multiprocessor cache simulator */
#ifdef GRAPHICS  
  MPCacheInit (L1_line_size, L1_size * 1024,
               L2_line_size, L2_size * 1024,
               graphics_flag, graphics_speed);
#else
#endif /* GRAPHICS */


}

/* load program into simulated state */
void
sim_load_prog(char *fname,		/* program to load */
	      int argc, char **argv,	/* program arguments */
	      char **envp)		/* program environment */
{
  /* load program text and data, set up environment, memory, and regs */
  ld_load_prog(fname, argc, argv, envp, &regs[0], mem, TRUE);

  /* initialize the DLite debugger */
  //dlite_init(md_reg_obj, dlite_mem_obj, dlite_mstate_obj);
}

/* print simulator-specific configuration information */
void
sim_aux_config(FILE *stream)		/* output stream */
{
  /* nothing currently */
}

/* dump simulator-specific auxiliary simulator statistics */
void
sim_aux_stats(FILE *stream)		/* output stream */
{
  /* nada */
}

/* un-initialize simulator-specific state */
void
sim_uninit(void)
{
  /* nada */
}


/*
 * configure the execution engine
 */

/*
 * precise architected register accessors
 */

/* next program counter */
#define SET_NPC(EXPR)		(regs[pid].regs_NPC = (EXPR))

/* target program counter */
#undef  SET_TPC
#define SET_TPC(PC)     { regs[pid].regs_TPC = (PC); }

/* current program counter */
#define CPC			(regs[pid].regs_PC)

/* general purpose registers */
#define GPR(N)			(regs[pid].regs_R[N])
#define SET_GPR(N,EXPR)		(regs[pid].regs_R[N] = (EXPR))

#if defined(TARGET_PISA) || defined(TARGET_MIPS)

/* floating point registers, L->word, F->single-prec, D->double-prec */
#define FPR_L(N)		(regs[pid].regs_F.l[(N)])
#define SET_FPR_L(N,EXPR)	(regs[pid].regs_F.l[(N)] = (EXPR))
#define FPR_F(N)		(regs[pid].regs_F.f[(N)])
#define SET_FPR_F(N,EXPR)	(regs[pid].regs_F.f[(N)] = (EXPR))
#define FPR_D(N)		(regs[pid].regs_F.d[(N) >> 1])
#define SET_FPR_D(N,EXPR)	(regs[pid].regs_F.d[(N) >> 1] = (EXPR))

/* miscellaneous register accessors */
#define SET_HI(EXPR)		(regs[pid].regs_C.hi = (EXPR))
#define HI			(regs[pid].regs_C.hi)
#define SET_LO(EXPR)		(regs[pid].regs_C.lo = (EXPR))
#define LO			(regs[pid].regs_C.lo)
#define FCC			(regs[pid].regs_C.fcc)
#define SET_FCC(EXPR)		(regs[pid].regs_C.fcc = (EXPR))

#elif defined(TARGET_ALPHA)

/* floating point registers, L->word, F->single-prec, D->double-prec */
#define FPR_Q(N)		(regs[pid].regs_F.q[N])
#define SET_FPR_Q(N,EXPR)	(regs[pid].regs_F.q[N] = (EXPR))
#define FPR(N)			(regs[pid].regs_F.d[(N)])
#define SET_FPR(N,EXPR)		(regs[pid].regs_F.d[(N)] = (EXPR))

/* miscellaneous register accessors */
#define FPCR			(regs[pid].regs_C.fpcr)
#define SET_FPCR(EXPR)		(regs[pid].regs_C.fpcr = (EXPR))
#define UNIQ			(regs[pid].regs_C.uniq)
#define SET_UNIQ(EXPR)		(regs[pid].regs_C.uniq = (EXPR))

#else
#error No ISA target defined...
#endif

/* precise architected memory state accessor macros */
#define READ_BYTE(SRC, FAULT)						\
  ((FAULT) = md_fault_none, addr = (SRC), MEM_READ_BYTE(mem, addr))
#define READ_HALF(SRC, FAULT)						\
  ((FAULT) = md_fault_none, addr = (SRC), MEM_READ_HALF(mem, addr))
#define READ_WORD(SRC, FAULT)						\
  ((FAULT) = md_fault_none, addr = (SRC), MEM_READ_WORD(mem, addr))
#ifdef HOST_HAS_QWORD
#define READ_QWORD(SRC, FAULT)						\
  ((FAULT) = md_fault_none, addr = (SRC), MEM_READ_QWORD(mem, addr))
#endif /* HOST_HAS_QWORD */

#define WRITE_BYTE(SRC, DST, FAULT)					\
  ((FAULT) = md_fault_none, addr = (DST), MEM_WRITE_BYTE(mem, addr, (SRC)))
#define WRITE_HALF(SRC, DST, FAULT)					\
  ((FAULT) = md_fault_none, addr = (DST), MEM_WRITE_HALF(mem, addr, (SRC)))
#define WRITE_WORD(SRC, DST, FAULT)					\
  ((FAULT) = md_fault_none, addr = (DST), MEM_WRITE_WORD(mem, addr, (SRC)))
#ifdef HOST_HAS_QWORD
#define WRITE_QWORD(SRC, DST, FAULT)					\
  ((FAULT) = md_fault_none, addr = (DST), MEM_WRITE_QWORD(mem, addr, (SRC)))
#endif /* HOST_HAS_QWORD */

/* system call handler macro */
#define SYSCALL(INST)	sys_syscall(&regs[pid], mem_access, mem, INST, TRUE, pid)

/* start simulation, program loaded, processor precise state initialized */
void
sim_main(void)
{
  md_inst_t inst;
  register md_addr_t addr;
  enum md_opcode op;
  register int is_write, pid;
  enum md_fault_type fault;

  fprintf(stderr, "sim: ** starting functional simulation **\n");

  active[0] = 1;
  num_created_threads = 1;


  /* check for DLite debugger entry condition */
  //if (dlite_check_break(regs[pid].regs_PC, /* !access */0, /* addr */0, 0, 0))
    //dlite_main(regs[pid].regs_PC - sizeof(md_inst_t),
//	       regs[pid].regs_PC, sim_num_insn, &regs, mem);

  while (TRUE)
    {
      /* keep an instruction count */
      sim_num_insn++;

      for (pid = 0; pid < num_created_threads; pid++)
      {
        if(!active[pid])
          continue;

        /* set up initial default next PC */
        regs[pid].regs_NPC = regs[pid].regs_PC + sizeof(md_inst_t);

        /* maintain $r0 semantics */
        regs[pid].regs_R[MD_REG_ZERO] = 0;
#ifdef TARGET_ALPHA
        regs[pid].regs_F.d[MD_REG_ZERO] = 0.0;
#endif /* TARGET_ALPHA */

	++sim_num_instructions[pid];

      /* get the next instruction to execute */
      MD_FETCH_INST(inst, mem, regs[pid].regs_PC);



      /* set default reference address and access mode */
      addr = 0; is_write = FALSE;

      /* set default fault - none */
      fault = md_fault_none;

      /* decode the instruction */
      MD_SET_OPCODE(op, inst);

      /* pass memory events only to multiprocr cache simulator
         and send base+offset address _before_ executing instruction
         because simulating "lw $reg,0($reg)" modifies base register */
#ifdef TARGET_MIPS
      /* if the instruction is in the delay slot, change the NPC */
      if (is_jump[pid] == 1)
      {
        SET_NPC(regs[pid].regs_TPC);
        is_jump[pid] = 0;
      }

      /* if previous branch likely instruction is not taken,skip this
       * instruction
       */
      if (is_annulled[pid]) {
        is_annulled[pid] = 0;
        /* execute next instruction */
        regs[pid].regs_PC = regs[pid].regs_NPC;
        regs[pid].regs_NPC += sizeof(md_inst_t);
        continue;
      }
#endif

      /* execute the instruction */
      switch (op)
	{
#define DEFINST(OP,MSK,NAME,OPFORM,RES,FLAGS,O1,O2,I1,I2,I3)		\
	case OP:							\
          SYMCAT(OP,_IMPL);						\
          break;
#define DEFLINK(OP,MSK,NAME,MASK,SHIFT)					\
        case OP:							\
          panic("attempted to execute a linking opcode");
#define CONNECT(OP)
#define DECLARE_FAULT(FAULT)						\
	  { fault = (FAULT); break; }
#include "mips.def"
	default:
          printf("inst is 0x%x,regs_PC is 0x%x\n",inst,regs[pid].regs_PC);
	  panic("attempted to execute a bogus opcode");
      }

      if (fault != md_fault_none)
	fatal("fault (%d) detected @ 0x%08p", fault, regs[pid].regs_PC);

      if (verbose)
	{
	  myfprintf(stderr, "pid %d, %10n [xor: 0x%08x] @ 0x%08p: ",pid,
		    sim_num_insn, md_xor_regs(&regs), regs[pid].regs_PC);
	  md_print_insn(inst, regs[pid].regs_PC, stderr);
 //	if (pid == 0)
		myfprintf(stderr, "ra is 0x%x, func is 0x%x",regs[pid].regs_R[31],regs[pid].regs_R[25]);
	  if (MD_OP_FLAGS(op) & F_MEM)
	    myfprintf(stderr, "  mem: 0x%08p ", addr);
	  //  myfprintf(stderr, " REG's value is 0x%x", GPR(RT));
	  fprintf(stderr, "\n");
	  /* fflush(stderr); */
	}

      if (MD_OP_FLAGS(op) & F_MEM)
	{
	  sim_num_refs++;
	  if (MD_OP_FLAGS(op) & F_STORE)
	    is_write = TRUE;
	}

      /* go to the next instruction */
      regs[pid].regs_PC = regs[pid].regs_NPC;
      regs[pid].regs_NPC += sizeof(md_inst_t);

      /* finish early? */
      if (max_insts && sim_num_insn >= max_insts)
	return;
    }
}
}
