/* host.h - host-dependent definitions and interfaces */


#ifndef HOST_H
#define HOST_H

/* make sure host compiler supports ANSI-C */
#ifndef __STDC__ /* an ansi C compiler is required */
#error The SimpleScalar simulators must be compiled with an ANSI C compiler.
#endif /* __STDC__ */

/* enable inlining here, if supported by host compiler */
#undef INLINE
#if defined(__GNUC__)
#define INLINE		inline
#else
#define INLINE
#endif

/* bind together two symbols, at preprocess time */
#ifdef __GNUC__
/* this works on all GNU GCC targets (that I've seen...) */
#define SYMCAT(X,Y)	X##Y
#define ANSI_SYMCAT
#else /* !__GNUC__ */
#ifdef OLD_SYMCAT
#define SYMCAT(X,Y)	X/**/Y
#else /* !OLD_SYMCAT */
#define SYMCAT(X,Y)	X##Y
#define ANSI_SYMCAT
#endif /* OLD_SYMCAT */
#endif /* __GNUC__ */

/* host-dependent canonical type definitions */
typedef int bool_t;			/* generic boolean type */
typedef unsigned char byte_t;		/* byte - 8 bits */
typedef signed char sbyte_t;
typedef unsigned short half_t;		/* half - 16 bits */
typedef signed short shalf_t;
typedef unsigned int word_t;		/* word - 32 bits */
typedef signed int sword_t;
typedef float sfloat_t;			/* single-precision float - 32 bits */
typedef double dfloat_t;		/* double-precision float - 64 bits */

/* qword defs, note: not all targets support qword types */
#if defined(__GNUC__) || defined(__SUNPRO_C) || defined(__CC_C89) || defined(__CC_XLC)
#define HOST_HAS_QWORD
typedef unsigned long long qword_t;	/* qword - 64 bits */
typedef signed long long sqword_t;
#ifdef ANSI_SYMCAT
#define ULL(N)		N##ULL		/* qword_t constant */
#define LL(N)		N##LL		/* sqword_t constant */
#else /* OLD_SYMCAT */
#define ULL(N)		N/**/ULL	/* qword_t constant */
#define LL(N)		N/**/LL		/* sqword_t constant */
#endif
#elif defined(__alpha)
#define HOST_HAS_QWORD
typedef unsigned long qword_t;		/* qword - 64 bits */
typedef signed long sqword_t;
#ifdef ANSI_SYMCAT
#define ULL(N)		N##UL		/* qword_t constant */
#define LL(N)		N##L		/* sqword_t constant */
#else /* OLD_SYMCAT */
#define ULL(N)		N/**/UL		/* qword_t constant */
#define LL(N)		N/**/L		/* sqword_t constant */
#endif
#elif defined(_MSC_VER)
#define HOST_HAS_QWORD
typedef unsigned __int64 qword_t;	/* qword - 64 bits */
typedef signed __int64 sqword_t;
#define ULL(N)		((qword_t)(N))
#define LL(N)		((sqword_t)(N))
#else /* !__GNUC__ && !__alpha */
#undef HOST_HAS_QWORD
#endif

/* statistical counter types, use largest counter type available */
#ifdef HOST_HAS_QWORD
typedef sqword_t counter_t;
typedef sqword_t tick_t;		/* NOTE: unsigned breaks caches */
#else /* !HOST_HAS_QWORD */
typedef dfloat_t counter_t;
typedef dfloat_t tick_t;
#endif /* HOST_HAS_QWORD */

#ifdef __svr4__
#define setjmp	_setjmp
#define longjmp	_longjmp
#endif

#endif /* HOST_H */
