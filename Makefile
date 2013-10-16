CC = gcc
#CFLAGS = -O0 -g
OEXT = o
EEXT = mips
RM = rm -f
PROG = emics 
OBJS = main.$(OEXT) options.$(OEXT) misc.$(OEXT) loader.$(OEXT) memory.$(OEXT) \
	stats.$(OEXT) mips.$(OEXT) emics.$(OEXT) syscall.$(OEXT) eval.$(OEXT) \
	regs.$(OEXT)

.PHONY: all
all: $(PROG)

$(PROG): $(OBJS)
	$(CC) -o $(PROG) $(CFLAGS) $(OBJS) -lm

.PHONY: run
run: $(PROG)
	$(DARSIM) $(PROG) --concurrency 1

.PHONY: clean
clean:
	$(RM) *.s *.o $(PROG)

#main.$(OEXT): common.h manage_queue.h proc_pkt.h entity_manage.h timer.h
#manage_queue.$(OEXT):  manage_queue.h
#proc_pkt.$(OEXT): common.h proc_pkt.h entity_manage.h manage_queue.h
#entity_manage.$(OEXT): entity_manage.h
mips.$(OEXT): mips.h
