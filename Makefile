CFLAGS += -std=gnu11 \
	-I/usr/include/vyatta-dataplane \
	$(shell pkg-config --cflags libdpdk) \
	$(shell pkg-config --cflags opennsl) \
	$(shell pkg-config --cflags vyatta-dpdk-swport) \
	-D_REENTRANT -fPIC -m64 -Werror -Wall -Wmissing-declarations -march=corei7

LDFLAGS += -Wl,--as-needed -Wl,--version-script=fal_opennsl.sym \
	-L/usr/lib/x86_64-linux-gnu \
	$(shell pkg-config --libs libdpdk) \
	$(shell pkg-config --libs opennsl) \
	$(shell pkg-config --libs vyatta-dpdk-swport) \
	-lrte_net_ixgbe \
	-linih

CFILES := \
	fal_opennsl.c \
	fal_opennsl_id_mgr.c \
	fal_opennsl_l2.c \
	fal_opennsl_l3.c \
	fal_opennsl_dpp.c \
	pmd/rte_eth_opennslsw.c

OFILES := $(patsubst %.c,%.o,$(CFILES))
NAME := libfal-opennsl.so.1

all: $(NAME)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

pmd/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(NAME): $(OFILES)
	$(CC) -pthread $(CFLAGS) -o $@ $(OFILES) \
            -shared -Wl,-soname,$@ $(LDFLAGS)

test-%: %.c
	$(CC) $(CFLAGS) -DTEST $< -o $@

%.ok: %
	./$< && touch $@

TEST_FILES := \
	fal_opennsl_id_mgr.c

test: $(TEST_FILES:%.c=test-%.ok)

clean:
	rm -f *.o
	rm -f pmd/*.o
	rm -f $(NAME)
	rm -f *.ok
	rm -f $(TEST_FILES:%.c=test-%)
