# Wrappers around idf.py for both firmware roles (sinkhole + generator-node).
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

BUILD_DIR := build
SDKCONFIG := sdkconfig

IDF_PY := $(IDF_PYTHON_ENV_PATH)/bin/python $(IDF_PATH)/tools/idf.py

# sdkconfig.local, if present, is an untracked (gitignored) extra defaults
# layer merged in on top of sdkconfig.defaults — for machine-specific
# overrides (e.g. CONFIG_SINKHOLE_MANIFEST_URL pointed at your LAN IP) that
# must survive `set-target`/fullclean regenerating sdkconfig, but shouldn't be
# committed. Listing SDKCONFIG_DEFAULTS explicitly like this replaces idf.py's
# auto-detected defaults chain, so the real defaults file is named here even
# when the local one is absent.
SDKCONFIG_LOCAL := $(wildcard sdkconfig.local)
SDKCONFIG_DEFAULTS := sdkconfig.defaults$(if $(SDKCONFIG_LOCAL),;sdkconfig.local,)

IDF := $(IDF_PY) -B $(BUILD_DIR) -D SDKCONFIG=$(SDKCONFIG) -D SDKCONFIG_DEFAULTS="$(SDKCONFIG_DEFAULTS)"

# generator-node/ is a separate ESP-IDF project (its own role — see CLAUDE.md's
# "Firmware roles" — not a build variant of the sinkhole firmware above), so it
# gets its own build dir/sdkconfig and the same gitignored-local-overrides
# mechanism, just rooted under generator-node/. `-C generator-node` anchors
# idf.py/CMake's own relative-path resolution there, so SDKCONFIG/
# SDKCONFIG_DEFAULTS below are relative to generator-node/, not the repo root
# (unlike BUILD_DIR_GEN, which idf.py resolves relative to the invoking CWD).
BUILD_DIR_GEN := generator-node/build
SDKCONFIG_GEN := sdkconfig
SDKCONFIG_LOCAL_GEN := $(wildcard generator-node/sdkconfig.local)
SDKCONFIG_DEFAULTS_GEN := sdkconfig.defaults$(if $(SDKCONFIG_LOCAL_GEN),;sdkconfig.local,)
IDFGEN := $(IDF_PY) -C generator-node -B $(BUILD_DIR_GEN) -D SDKCONFIG=$(SDKCONFIG_GEN) -D SDKCONFIG_DEFAULTS="$(SDKCONFIG_DEFAULTS_GEN)"

ifdef PORT
PORT_ARG := -p $(PORT)
endif

.PHONY: help ports \
        build flash monitor flash-monitor menuconfig clean fullclean \
        build-gen flash-gen monitor-gen flash-monitor-gen menuconfig-gen clean-gen fullclean-gen

help:
	@echo "  make ports             list connected USB serial ports"
	@echo ""
	@echo "Firmware (ESP32-P4-Function-EV-Board, onboard IP101):"
	@echo "  make build             idf.py build"
	@echo "  make flash             idf.py flash (PORT=/dev/tty... to override)"
	@echo "  make monitor           idf.py monitor"
	@echo "  make flash-monitor     idf.py flash monitor"
	@echo "  make menuconfig        idf.py menuconfig"
	@echo "  make clean / fullclean"
	@echo ""
	@echo "Generator-node firmware (generator-node/, same board, different role):"
	@echo "  make build-gen / flash-gen / monitor-gen / flash-monitor-gen / menuconfig-gen"
	@echo "  make clean-gen / fullclean-gen"

ports:
	$(IDF_PYTHON_ENV_PATH)/bin/python -m serial.tools.list_ports -v

## --- ESP32-P4-Function-EV-Board (onboard IP101) ----------------------------
## `set-target` (which unconditionally fullcleans + regenerates sdkconfig,
## even when the target is unchanged) only runs when sdkconfig is missing or
## older than sdkconfig.defaults/sdkconfig.local — real Make prerequisite
## tracking, not just an existence check, so editing sdkconfig.local still
## triggers a regenerate (defaults are only applied to *missing* Kconfig
## symbols, never re-applied over an already-set value any other way) while
## an unrelated `make flash` stays a fast incremental ninja build.

$(SDKCONFIG): sdkconfig.defaults $(SDKCONFIG_LOCAL)
	$(IDF) set-target esp32p4

build: $(SDKCONFIG)
	$(IDF) build

flash: build
	$(IDF) $(PORT_ARG) flash

monitor:
	$(IDF) $(PORT_ARG) monitor

flash-monitor: build
	$(IDF) $(PORT_ARG) flash monitor

menuconfig: $(SDKCONFIG)
	$(IDF) menuconfig

clean:
	$(IDF) clean

fullclean:
	$(IDF) fullclean

## --- Generator-node firmware (generator-node/) -----------------------------
## Same reasoning as above.

generator-node/$(SDKCONFIG_GEN): generator-node/sdkconfig.defaults $(SDKCONFIG_LOCAL_GEN)
	$(IDFGEN) set-target esp32p4

build-gen: generator-node/$(SDKCONFIG_GEN)
	$(IDFGEN) build

flash-gen: build-gen
	$(IDFGEN) $(PORT_ARG) flash

monitor-gen:
	$(IDFGEN) $(PORT_ARG) monitor

flash-monitor-gen: build-gen
	$(IDFGEN) $(PORT_ARG) flash monitor

menuconfig-gen: generator-node/$(SDKCONFIG_GEN)
	$(IDFGEN) menuconfig

clean-gen:
	$(IDFGEN) clean

fullclean-gen:
	$(IDFGEN) fullclean
