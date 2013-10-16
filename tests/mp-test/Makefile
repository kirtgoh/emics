SSMP_LIB_PATH = ../rts
SSMP_INC_PATH = ../rts

CC = mipsel-unknown-linux-gnu-gcc 
AS = mipsel-unknonw-linux-gnu-as
AR = mipsel-unknown-linux-gnu-ar
LD = mipsel-unknown-linux-gnu-ld
RANLIB = mipsel-unknown-linux-gnu-ranlib


#--- optimization flags and include paths for C compiler

CFLAGS = -O2 -I$(SSMP_INC_PATH) -static

#--- library inclusion

LIBS = -L$(SSMP_LIB_PATH) -lrts

#--- rules to create executables

all: dotbar.ss dotsema.ss dotm4.ss

DOTBAR_OBJS = dotbar.o

dotbar.ss: $(DOTBAR_OBJS)
	$(CC) -o $@ $(DOTBAR_OBJS) $(LIBS) -static

DOTSEMA_OBJS = dotsema.o

dotsema.ss: $(DOTSEMA_OBJS)
	$(CC) -o $@ $(DOTSEMA_OBJS) $(LIBS)

dotm4.c: dotm4.c.m4
	m4 $(M4_MACROS) dotm4.c.m4 > $@

DOTM4_OBJS = dotm4.o

dotm4.ss: $(DOTM4_OBJS)
	$(CC) -o $@ $(DOTM4_OBJS) $(LIBS)

clean:
	rm -f *.o *~ dotbar.ss dotsema.ss dotm4.ss

#--- rule to execute test programs

tests: all
	$(SIM_DIR)/$(SIM_BIN) -d dotbar.ss -p8 -n10000
	$(SIM_DIR)/$(SIM_BIN) -d dotsema.ss -p8 -n10000
	$(SIM_DIR)/$(SIM_BIN) -d dotm4.ss -p8 -n10000
