# Wrappers around idf.py (firmware, two targets) and the Go generator.
#
# Requires an ESP-IDF v6.x environment sourced in your shell first, e.g.:
#   source ~/.espressif/tools/activate_idf_v6.0.2.sh
# `idf.py` itself is a shell *function* the activation script defines, which
# a Make recipe's non-interactive subshell won't inherit — so instead of
# calling `idf.py` directly, we call the real script via IDF_PATH and
# IDF_PYTHON_ENV_PATH, the actual exported env vars that script also sets.
#
# PORT=/dev/tty... overrides the auto-detected serial port for flash/monitor.

ifndef IDF_PATH
$(error IDF_PATH is not set. Source your ESP-IDF environment first, e.g.: \
  source ~/.espressif/tools/activate_idf_v6.0.2.sh)
endif

BUILD_DIR_ESP32   := build
BUILD_DIR_ESP32P4 := build.esp32p4
SDKCONFIG_ESP32   := sdkconfig
SDKCONFIG_ESP32P4 := sdkconfig.esp32p4

IDF_PY := $(IDF_PYTHON_ENV_PATH)/bin/python $(IDF_PATH)/tools/idf.py

IDF32   := $(IDF_PY) -B $(BUILD_DIR_ESP32)   -D SDKCONFIG=$(SDKCONFIG_ESP32)
IDF32P4 := $(IDF_PY) -B $(BUILD_DIR_ESP32P4) -D SDKCONFIG=$(SDKCONFIG_ESP32P4)

ifdef PORT
PORT_ARG := -p $(PORT)
endif

.PHONY: help \
        build build-p4 \
        flash flash-p4 \
        monitor monitor-p4 \
        flash-monitor flash-monitor-p4 \
        menuconfig menuconfig-p4 \
        clean clean-p4 fullclean fullclean-p4 \
        generator-build generator-test generator-run \
        docker-build docker-up docker-down

help:
	@echo "Firmware (plain ESP32 + external LAN8720):"
	@echo "  make build             idf.py build"
	@echo "  make flash             idf.py flash (PORT=/dev/tty... to override)"
	@echo "  make monitor           idf.py monitor"
	@echo "  make flash-monitor     idf.py flash monitor"
	@echo "  make menuconfig        idf.py menuconfig"
	@echo "  make clean / fullclean"
	@echo ""
	@echo "Firmware (ESP32-P4-Function-EV-Board, onboard IP101):"
	@echo "  make build-p4 / flash-p4 / monitor-p4 / flash-monitor-p4 / menuconfig-p4"
	@echo "  make clean-p4 / fullclean-p4"
	@echo ""
	@echo "Go generator (generator/):"
	@echo "  make generator-build   go build ./..."
	@echo "  make generator-test    go test ./..."
	@echo "  make generator-run     go run . -config config.json -oneshot"
	@echo "  make docker-build      docker compose build"
	@echo "  make docker-up         docker compose up -d --build"
	@echo "  make docker-down       docker compose down"

## --- ESP32 + external LAN8720 ---------------------------------------------

build:
	$(IDF32) build

flash:
	$(IDF32) $(PORT_ARG) flash

monitor:
	$(IDF32) $(PORT_ARG) monitor

flash-monitor:
	$(IDF32) $(PORT_ARG) flash monitor

menuconfig:
	$(IDF32) menuconfig

clean:
	$(IDF32) clean

fullclean:
	$(IDF32) fullclean

## --- ESP32-P4-Function-EV-Board (onboard IP101) ---------------------------
## First build sets the target explicitly; harmless (and fast) on later runs.

build-p4:
	$(IDF32P4) set-target esp32p4
	$(IDF32P4) build

flash-p4: build-p4
	$(IDF32P4) $(PORT_ARG) flash

monitor-p4:
	$(IDF32P4) $(PORT_ARG) monitor

flash-monitor-p4: build-p4
	$(IDF32P4) $(PORT_ARG) flash monitor

menuconfig-p4:
	$(IDF32P4) set-target esp32p4
	$(IDF32P4) menuconfig

clean-p4:
	$(IDF32P4) clean

fullclean-p4:
	$(IDF32P4) fullclean

## --- Go generator (generator/) ---------------------------------------------

generator-build:
	cd generator && go build ./...

generator-test:
	cd generator && go test ./...

generator-run:
	cd generator && go run . -config config.json -oneshot

docker-build:
	docker compose build

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down
