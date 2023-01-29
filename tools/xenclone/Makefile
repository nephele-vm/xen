XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

XENSTORE_SRC=$(CURDIR)/../xenstore

#TODO uncomment CFLAGS += -Werror
# Include configure output (config.h)
CFLAGS += -include $(XEN_ROOT)/tools/config.h
CFLAGS += $(CFLAGS_libxenevtchn)
CFLAGS += $(CFLAGS_libxengnttab)
CFLAGS += $(CFLAGS_libxenctrl)
#TODO CFLAGS += $(CFLAGS_xeninclude)
CFLAGS += $(CFLAGS_libxenstore)
CFLAGS += -I$(XENSTORE_SRC) # for hashtable.h and list.h
CFLAGS += -DHASHTABLE_DONT_FREE_KEY=1
ifeq ($(debug),y)
CFLAGS += -DXENCLONED_DEBUG=1
else
CFLAGS += -O3
endif

CONFIG_XENCLONED_INSTRUMENT_FUNCTIONS=n
ifeq ($(CONFIG_XENCLONED_INSTRUMENT_FUNCTIONS),y)
PROFILING_DIR=$(CURDIR)/../profiling
CFLAGS += -I$(PROFILING_DIR)
CFLAGS += -finstrument-functions
CFLAGS += -I$(XEN_ROOT)/tools/xenstore
CFLAGS += -DLIB_PROFILING=1
CFLAGS += -DPROFILE_TRIGGER_INIT_VALUE=1
CFLAGS += -DINSTRUMENTED_LIB_PATH=\"/root/dist/xen/sbin/xencloned\"
OBJS += $(PROFILING_DIR)/trace_func.o
OBJS += $(PROFILING_DIR)/trace_func_hash.o
OBJS += hashtable.o
endif

ifeq ($(local),y)
#TODO remove paths
OVS_SRC=/home/wolf/nfv/dev/UPSTREAM/ovs.git
APPEND_LDFLAGS+=-L$(OVS_SRC)/utilities/.libs/
APPEND_LDFLAGS+=-L$(OVS_SRC)/dist/ovs/lib
else
OVS_SRC=/root/dev/ovs
APPEND_LDFLAGS+=-L/root/dist/ovs/lib
endif
CFLAGS += -I$(OVS_SRC)/include
CFLAGS += -I$(OVS_SRC)/lib
CFLAGS += -I$(OVS_SRC)/utilities
#APPEND_LDFLAGS+=-lovsctl -lopenvswitch -lofproto -lssl -lcrypto -latomic -lrt -lm
APPEND_LDFLAGS+=-ludev -lpthread

OBJS += 9pfs.o
OBJS += bond.o
OBJS += cache.o
OBJS += clone.o
OBJS += console.o
OBJS += hashtable.o
OBJS += hmap.o
OBJS += mem.o
OBJS += netif.o
OBJS += network.o
OBJS += os.o
OBJS += ovs.o
OBJS += profile.o
OBJS += qemu.o
OBJS += udev.o
OBJS += utils.o
OBJS += vif.o
OBJS += vbd.o
OBJS += xencloned.o
OBJS += xenstore.o
OBJS += xs.o

# Everything to be installed
TARGETS_ALL := xencloned

.PHONY: all build
all build: $(TARGETS_ALL)

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS_ALL) *~ $(DEPS_RM)

.PHONY: distclean
distclean: clean

.PHONY: install
install: all
	$(INSTALL_PROG) xencloned $(DESTDIR)$(sbindir)


xencloned: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS_libxenevtchn) $(LDLIBS_libxengnttab) $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxenstore) $(LDLIBS_libxentoollog) $(APPEND_LDFLAGS)

hashtable.o: $(XENSTORE_SRC)/hashtable.c
	$(CC) $(CFLAGS) -c -o $@ $<


-include $(DEPS_INCLUDE)
