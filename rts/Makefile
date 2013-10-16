#
# Makefile.runtimelib - multiprocessor simulator run-time library makefile
#

# >>>> IMPORTANT NOTES:
#
# Building the run-time library requires that the 'simpletools'
# including GCC and the assembler for SimpleScalar have been
# properly installed.

# This Makefile.runtimelib is normally invoked from the main Makefile
# and hence assumes that the SS_BIN_PATH variable is defined appropriately.

SS_BIN_PATH=/opt/crosstool/gcc-3.4.5-glibc-2.3.6/mipsel-unknown-linux-gnu/bin
CC = $(SS_BIN_PATH)/mipsel-unknown-linux-gnu-gcc
AS = $(SS_BIN_PATH)/mipsel-unknown-linux-gnu-as
AR = $(SS_BIN_PATH)/mipsel-unknown-linux-gnu-ar
LD = $(SS_BIN_PATH)/mipsel-unknown-linux-gnu-ld
RANLIB = $(SS_BIN_PATH)/mipsel-unknown-linux-gnu-ranlib


all: librts.a

runtime.o: rts.S
	$(COMPILE.S) -o $@ rts.S -I../

librts.a: runtime.o
	$(AR) $(ARFLAGS) $@ runtime.o

clean:
	rm -f runtime.o runtime.a
