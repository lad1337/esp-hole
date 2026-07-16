# Plain-cc host test harness — no ESP-IDF, no hardware. `make` alone builds
# and runs it.
CC ?= cc
CFLAGS := -std=c11 -Wall -Wextra -Wsign-compare -I../include

SRCS := host_main.c ../parse.c ../normalize.c ../hash.c ../generate.c sha256_host.c
BIN  := host_test

SCALE_SRCS := scale_test.c ../parse.c ../normalize.c ../hash.c ../generate.c sha256_host.c
SCALE_BIN  := scale_test
DATA_DIR   := data

.PHONY: test scale-test scale-data clean

test: $(BIN)
	./$(BIN)

$(BIN): $(SRCS) ../include/*.h
	$(CC) $(CFLAGS) -o $@ $(SRCS)

# Not part of `make test`: hits the network and reports real timing/memory
# numbers on the actual configured blocklist sources (see
# generator/config.example.json) — the M2 milestone's "before any hardware
# is touched" scale check. Per-source fetch failures are non-fatal, matching
# the generator's own fault tolerance (scale_test.c warns and skips missing
# files rather than failing).
scale-data:
	mkdir -p $(DATA_DIR)
	curl -sL --fail -o $(DATA_DIR)/stevenblack.txt \
		https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts || true
	curl -sL --fail -o $(DATA_DIR)/oisd.txt \
		https://big.oisd.nl/domainswild || true
	curl -sL --fail -o $(DATA_DIR)/adguard.txt \
		https://raw.githubusercontent.com/AdguardTeam/AdguardSDNSFilter/master/Filters/filter.txt || true

scale-test: $(SCALE_BIN) scale-data
	./$(SCALE_BIN) $(DATA_DIR)/*.txt

$(SCALE_BIN): $(SCALE_SRCS) ../include/*.h
	$(CC) $(CFLAGS) -o $@ $(SCALE_SRCS)

clean:
	rm -f $(BIN) $(SCALE_BIN)
	rm -rf $(DATA_DIR)
