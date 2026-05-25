CC       ?= gcc
CFLAGS   ?= -Wall -Wextra -Wpedantic -std=c11 -O2 -g
INCLUDES := -Iinclude

# Load balancer capacity (defaults match prior hard-coded values)
IKE_LB_MAX_SESSIONS  ?= 65536
IKE_LB_MAX_BACKENDS  ?= 32
IKE_LB_SESSION_TIMEOUT ?= 3600

LB_CPPFLAGS := -DIKE_LB_MAX_SESSIONS=$(IKE_LB_MAX_SESSIONS) \
               -DIKE_LB_MAX_BACKENDS=$(IKE_LB_MAX_BACKENDS) \
               -DIKE_LB_SESSION_TIMEOUT=$(IKE_LB_SESSION_TIMEOUT)
LIB_SRCS := src/ike_msg.c src/ike_crypto.c src/ike_session.c src/ike_lb_session.c src/ike_lb_pcap.c
LIB_OBJS := $(LIB_SRCS:.c=.o)

BIN_DIR  := bin
TEST_BIN := $(BIN_DIR)/test_ike_msg
TEST_LB  := $(BIN_DIR)/test_ike_lb
TEST_PROP := $(BIN_DIR)/test_proposals
SERVER   := $(BIN_DIR)/ikev2-server
CLIENT   := $(BIN_DIR)/ikev2-client
IKE_LB   := $(BIN_DIR)/ike-lb

# Set IKEV2_NO_SSL=1 to build without OpenSSL (stub DH for testing only)
ifdef IKEV2_NO_SSL
CFLAGS  += -DIKEV2_NO_SSL
LDFLAGS ?=
else
LDFLAGS ?= -lssl -lcrypto
endif

.PHONY: all clean test test-all test-e2e-pcap test-e2e-multi test-interop-real run-server run-client run-lb dirs show-config submission-docs record

all: dirs $(SERVER) $(CLIENT) $(IKE_LB) $(TEST_BIN) $(TEST_LB) $(TEST_PROP)

dirs:
	@mkdir -p $(BIN_DIR)

$(SERVER): src/server_main.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ src/server_main.c $(LIB_OBJS) $(LDFLAGS)

$(CLIENT): src/client_main.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ src/client_main.c $(LIB_OBJS) $(LDFLAGS)

$(IKE_LB): src/ike_lb_main.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(LB_CPPFLAGS) $(INCLUDES) -o $@ src/ike_lb_main.c $(LIB_OBJS) $(LDFLAGS)
	@echo "ike-lb built with MAX_SESSIONS=$(IKE_LB_MAX_SESSIONS) MAX_BACKENDS=$(IKE_LB_MAX_BACKENDS) TIMEOUT=$(IKE_LB_SESSION_TIMEOUT)s"

$(TEST_BIN): tests/test_ike_msg.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_ike_msg.c $(LIB_OBJS) $(LDFLAGS)

$(TEST_LB): tests/test_ike_lb.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_ike_lb.c $(LIB_OBJS) $(LDFLAGS)

$(TEST_PROP): tests/test_proposals.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_proposals.c $(LIB_OBJS) $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) $(LB_CPPFLAGS) $(INCLUDES) -c -o $@ $<

show-config:
	@echo "IKE_LB_MAX_SESSIONS=$(IKE_LB_MAX_SESSIONS)"
	@echo "IKE_LB_MAX_BACKENDS=$(IKE_LB_MAX_BACKENDS)"
	@echo "IKE_LB_SESSION_TIMEOUT=$(IKE_LB_SESSION_TIMEOUT)"

submission-docs:
	python3 scripts/generate_submission_docs.py

record:
	@chmod +x scripts/record_demo.sh scripts/make_recording_html.sh
	./scripts/record_demo.sh
	./scripts/make_recording_html.sh
	@echo "Recording: docs/output/demo_recording.log"
	@echo "HTML:      docs/output/demo_recording.html"
	@echo "Script:    docs/output/demo_session.script"

test: $(TEST_BIN) $(TEST_LB) $(TEST_PROP)
	./$(TEST_BIN)
	./$(TEST_LB)
	./$(TEST_PROP)

test-all:
	@chmod +x scripts/run_tests.sh scripts/run_e2e_tcpdump.sh scripts/run_multi_session_e2e.sh scripts/analyze_ike_pcap.sh
	./scripts/run_tests.sh

test-e2e-pcap:
	@chmod +x scripts/run_e2e_tcpdump.sh scripts/analyze_ike_pcap.sh
	./scripts/run_e2e_tcpdump.sh

test-e2e-multi:
	@chmod +x scripts/run_multi_session_e2e.sh
	./scripts/run_multi_session_e2e.sh

test-interop-real:
	@chmod +x scripts/run_interop_real.sh
	@echo "Requires: sudo, strongswan (swanctl). Optional: openiked (iked)."
	@echo "Log: docs/output/interop_real.log"
	sudo ./scripts/run_interop_real.sh

run-server: $(SERVER)
	./$(SERVER)

run-client: $(CLIENT)
	./$(CLIENT) 127.0.0.1 5000

clean:
	rm -f src/*.o $(BIN_DIR)/*
