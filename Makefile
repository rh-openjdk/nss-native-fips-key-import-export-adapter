# SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

NAME         := nssadapter
SRC_DIR      := src
TST_DIR      := test
BIN_DIR      := bin
OUTPUT       := $(BIN_DIR)/lib$(NAME).so
DBG_SENTINEL := $(BIN_DIR)/_built_in_debug_mode_

JAVA          = java
CC            = gcc
DEVEL_PKGS    = nss nss-softokn
LIB_DIR       = $(shell pkg-config --variable=libdir nss-softokn)
SHARED_LIBS   = pthread softokn3 nss3
STATIC_LIBS   = freebl
CFLAGS        = -shared -fPIC -fvisibility=hidden -Wl,--exclude-libs,ALL       \
                $(addprefix -l,$(SHARED_LIBS))                                 \
                $(strip $(shell pkg-config --cflags $(DEVEL_PKGS)))            \
                -Wpedantic -Wall -Wextra -Wconversion -Werror
REL_CFLAGS    = -O3
DBG_CFLAGS    = -Wno-error=unused-variable -Wno-error=unused-parameter -DDEBUG \
                -O0 -g

# https://clang.llvm.org/docs/ClangFormatStyleOptions.html
CLANG_FORMAT_STYLE = {                                                         \
    BasedOnStyle: LLVM,                                                        \
    IndentWidth: 4,                                                            \
    AlignArrayOfStructures: Left,                                              \
    AlignConsecutiveMacros: AcrossEmptyLines,                                  \
    AllowShortFunctionsOnASingleLine: Inline,                                  \
    InsertNewlineAtEOF: true,                                                  \
}
CLANG_FORMAT_IGNORED_FILES = $(SRC_DIR)/nss_lowkey_imported.c                  \
                             $(SRC_DIR)/sensitive_attributes.h
# Reasons for exclusion:
#   nss_lowkey_imported.c  <- copy and pasted content from NSS
#   sensitive_attributes.h <- this file is wrongly formatted


#
# Build
#

SRC_FILES = $(sort $(wildcard $(SRC_DIR)/*.h) $(wildcard $(SRC_DIR)/*.c))
ifeq ($(wildcard $(DBG_SENTINEL)),$(DBG_SENTINEL))
  PREVIOUS_BUILD_MODE = debug
  CLEAN_IF_PREVIOUS_BUILD_MODE_IS_DEBUG = clean
else
  PREVIOUS_BUILD_MODE = release
  CLEAN_IF_PREVIOUS_BUILD_MODE_IS_RELEASE = clean
endif

.PHONY: release ## Build in RELEASE mode (default)
release: CFLAGS += $(REL_CFLAGS)
release: $(CLEAN_IF_PREVIOUS_BUILD_MODE_IS_DEBUG) $(OUTPUT)

.PHONY: debug ## Build in DEBUG mode
debug: CFLAGS += $(DBG_CFLAGS)
debug: CREATE_DBG_SENTINEL_IF_NEEDED = touch $(DBG_SENTINEL)
debug: $(CLEAN_IF_PREVIOUS_BUILD_MODE_IS_RELEASE) $(OUTPUT)

.PHONY: rebuild ## Force a rebuild in the previous mode (RELEASE if not built)
rebuild: clean $(PREVIOUS_BUILD_MODE)

.PHONY: clean ## Remove binaries and artifacts
clean:
	rm -rf $(BIN_DIR)


$(BIN_DIR):
	@mkdir $(BIN_DIR)

$(OUTPUT): $(BIN_DIR) $(SRC_FILES)
	@$(CREATE_DBG_SENTINEL_IF_NEEDED)
	$(CC) $(CFLAGS) $(filter %.c, $+) $(addprefix $(LIB_DIR)/lib,              \
	                                    $(addsuffix .a,$(STATIC_LIBS))) -o $@


#
# Utilities
#

.PHONY: format ## Automatically format the source code (requires 'clang-format')
format:
	@clang-format --verbose -i --style='$(CLANG_FORMAT_STYLE)'                 \
	    $(filter-out $(CLANG_FORMAT_IGNORED_FILES),$(SRC_FILES)) ||            \
	    echo "NOTE: in RHEL/Fedora, 'clang-format' is provided"                \
	         "by the 'clang-tools-extra' package." 1>&2

.PHONY: info ## Show built binary information (build mode, linkage and symbols)
info: $(PREVIOUS_BUILD_MODE)
	@echo
	@test -f $(DBG_SENTINEL) && echo "Built in DEBUG mode" ||                  \
	                            echo "Built in RELEASE mode"
	@echo
	ldd $(OUTPUT)
	@echo
	nm --dynamic --radix=x $(OUTPUT)
	@echo

.PHONY: -test
-test:
	$(JAVA)c -d $(BIN_DIR) $(TST_DIR)/Main.java
	$(JAVA) -cp $(BIN_DIR) Main $(TEST_ARGUMENT)

.PHONY: test ## Run the test suite, usage: make test [JAVA=/path/to/java]
test: TEST_ARGUMENT = $(OUTPUT)
test: $(PREVIOUS_BUILD_MODE) -test

.PHONY: test-data ## Run the test suite in data generation mode (honours JAVA)
test-data: TEST_ARGUMENT = --data-generation
test-data: -test

.PHONY: help ## Display this message
help:
	@echo '$(shell tput bold)Available make targets:$(shell tput sgr0)'
	@sed -ne 's/^\.PHONY:\s*\([a-zA-Z0-9_\-]*\)\s*##\s*\(.*\)/                 \
	  $(shell tput setaf 6)\1$(shell tput sgr0)$(shell printf "\x1E")\2/p'     \
	  $(MAKEFILE_LIST) | column -c2 -t -s$(shell printf "\x1E")
