# Makefile for m2crypto

# Use ?= to allow overriding from the command line (e.g., `make PYTHON=python3.11`)
PYTHON ?= python3
PIP = $(PYTHON) -mpip

# --- Source File Dependencies ---
# Find all relevant source files recursively in the src/ directory.
# The wheel will be rebuilt only if any of these files are modified.
SRC_FILES := $(shell find src -name '*.py' -o -name '*.i' -o -name '*.h')

# --- Build Artifacts ---
# Directory for the wheel file and the sentinel file.
DIST_DIR = dist

# A sentinel file to track when the wheel was last built successfully.
# This avoids rebuilding if source files haven't changed.
WHEEL_SENTINEL = $(DIST_DIR)/.wheel_built

# Parse src/M2Crypto/__init__.py to get the current version of the package we work on
# Depends on blackening of that file to have all values covered by doublequotes
CUR_VERSION = $(shell awk -F'"' '/^__version__/ { print $$2 }' src/M2Crypto/__init__.py)
ifeq ($(CUR_VERSION),)
    $(error Cannot extract version from src/M2Crypto/__init__.py)
endif

# Find the most recently built wheel file in the dist directory.
LATEST_WHEEL := $(firstword $(wildcard dist/[mM]2[Cc]rypto-$(CUR_VERSION)*.whl))
LATEST_TAR := $(firstword $(wildcard dist/[mM]2[Cc]rypto-$(CUR_VERSION)*.tar.gz))

# The directory where the package is installed for testing.
BUILD_LIB_DIR = $(shell find build -maxdepth 1 -type d -name "lib.*")

# Phony targets are actions, not files. Declaring them prevents conflicts
# with files of the same name and improves performance.
.PHONY: all wheel install check clean help

# The default 'all' target now runs the full build and test cycle.
all: check ## Build the wheel (if needed), install it locally, and run tests.

# The 'wheel' target is a simple alias for the sentinel file.
# Running `make wheel` will trigger the build only if source files have changed.
wheel: $(WHEEL_SENTINEL) ## Build the wheel package if source files have changed.

# This is the core build rule. It runs if the sentinel file is missing
# or if any of the SRC_FILES are newer than it.
$(WHEEL_SENTINEL): $(SRC_FILES)
	rm -rf build
	@mkdir -p $(DIST_DIR)
	$(PIP) wheel \
		--verbose \
		--no-cache-dir \
		--no-clean \
		--no-build-isolation \
		--wheel-dir $(DIST_DIR)/ \
		--editable .
	@touch $@

# 'install' depends on the wheel being created first.
install: wheel ## Install the wheel into the local 'build' directory.
	@if [ -z "$(LATEST_WHEEL)" ]; then \
		echo "Error: No wheel file found in dist/. Run 'make wheel' first."; \
		exit 1; \
	fi
	@echo "Installing $(LATEST_WHEEL)..."
	$(PIP) install \
		--verbose \
		--upgrade \
		--target "$(BUILD_LIB_DIR)" \
		--no-compile \
		--ignore-installed \
		--no-deps \
		--no-index \
		"$(LATEST_WHEEL)"

sdist: $(SRC_FILES)
	$(PYTHON) setup.py sdist
	$(PYTHON) -mtwine check --strict $(LATEST_TAR)
	$(PYTHON) -mpyroma --quiet --min=10 $(LATEST_TAR)

# 'check' depends on the package being installed locally.
check: install ## Run the unit tests.
	@if [ -z "$(BUILD_LIB_DIR)" ]; then \
		echo "Error: Build library directory not found. Run 'make install' first."; \
		exit 1; \
	fi
	PYTHONPATH="$(BUILD_LIB_DIR)" $(PYTHON) -m unittest -v tests.alltests.suite

# 'clean' is a manual operation to remove all generated files.
clean: ## Remove all generated files and build artifacts.
	rm -rf build src/m2crypto.egg-info $(LATEST_WHEEL) $(LATEST_TAR) $(WHEEL_SENTINEL)
	rm -f src/SWIG/_m2crypto_wrap.c
	find . -type d -name "__pycache__" -exec rm -r {} +

# A self-documenting 'help' target.
help: ## Show this help message.
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'