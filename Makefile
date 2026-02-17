# SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

NAME         := nssadapter
VERSION      := 0.1.1
NAME_VER     := $(NAME) v$(VERSION)
SRC_DIR      := src
TST_DIR      := test
BIN_DIR      := bin
OUTPUT       := $(BIN_DIR)/lib$(NAME).so
DBG_SENTINEL := $(BIN_DIR)/_built_in_debug_mode_

CC            = gcc
DEVEL_PKGS    = nss nss-softokn
LIB_DIR       = $(shell pkg-config --variable=libdir nss-softokn)
SHARED_LIBS   = pthread softokn3 nss3
STATIC_LIBS   = freebl
SHR_CFLAGS    = -shared -fPIC -fvisibility=hidden -DNAME_VER='"$(NAME_VER)"'   \
                $(strip $(shell pkg-config --cflags $(DEVEL_PKGS)))            \
                -Wpedantic -Wall -Wextra -Wconversion -Werror
DBG_CFLAGS    = -Wno-error=unused-variable -Wno-error=unused-parameter -DDEBUG \
                -fanalyzer -O0 -g
SHR_LDFLAGS   = -Wl,--exclude-libs,ALL $(addprefix -l,$(SHARED_LIBS))

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

SRC_FILES = $(sort $(shell find $(SRC_DIR) -type f))
TST_FILES = $(sort $(shell find $(TST_DIR) -type f))
EXTRA_FILES = README.md LICENSE Makefile
ifeq ($(wildcard $(DBG_SENTINEL)),$(DBG_SENTINEL))
  PREVIOUS_BUILD_MODE = debug
  CLEAN_IF_PREVIOUS_BUILD_MODE_IS_DEBUG = clean
else
  PREVIOUS_BUILD_MODE = release
  CLEAN_IF_PREVIOUS_BUILD_MODE_IS_RELEASE = clean
endif

.PHONY: release ## Build the library in RELEASE mode (default)
release: BLD_CFLAGS = $(SHR_CFLAGS) $(CFLAGS)
release: BLD_LDFLAGS = $(SHR_LDFLAGS) $(LDFLAGS)
release: $(CLEAN_IF_PREVIOUS_BUILD_MODE_IS_DEBUG) $(OUTPUT)

.PHONY: debug ## Build the library in DEBUG mode
debug: BLD_CFLAGS = $(SHR_CFLAGS) $(DBG_CFLAGS) $(CFLAGS)
debug: BLD_LDFLAGS = $(SHR_LDFLAGS) $(LDFLAGS)
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
	$(CC) $(BLD_CFLAGS) $(filter %.c, $+) $(BLD_LDFLAGS) \
	      $(addprefix $(LIB_DIR)/lib,$(addsuffix .a,$(STATIC_LIBS))) -o $@


DIST_FILE = $(NAME)-$(VERSION).tar.xz
.PHONY: dist ## Build a source tarball
dist: $(DIST_FILE)
$(DIST_FILE): $(SRC_FILES) $(TST_FILES) $(EXTRA_FILES)

.PHONY: distclean ## Remove the source tarball(s)
distclean:
	rm -f $(NAME)-*.tar.xz

# More info in the tar manual, in "8.4 Making tar Archives More Reproducible":
# https://www.gnu.org/software/tar/manual/html_section/Reproducibility.html
ifneq ($(wildcard ./.git),)
  # Use the last commit committer's timestamp. Timestamps are specified with @:
  # https://www.gnu.org/software/tar/manual/html_section/Date-input-formats.html
  SOURCE_EPOCH = $(shell git log -1 --format=tformat:@%ct)
  # Issue a warning when the repository contains uncommitted changes
  _WARN_TEXT = creating a tarball with uncommitted changes (check "git status")
  WORKTREE_WARN = $(if $(shell git status --porcelain),WARNING: $(_WARN_TEXT),)
else
  # Not in a git repository, fall-back to this file's mtime, please note that
  # this reproduces the same tarball from an extracted tarball. We can directly
  # pass a file path to --mtime as long as it starts with '/' or '.':
  # https://www.gnu.org/software/tar/manual/html_section/create-options.html
  SOURCE_EPOCH = $(realpath $(lastword $(MAKEFILE_LIST)))
endif
TARFLAGS = --sort=name --format=posix --mtime=$(SOURCE_EPOCH)                  \
           --pax-option=exthdr.name=%d/PaxHeaders/%f                           \
           --pax-option=delete=atime,delete=ctime                              \
           --numeric-owner --owner=0 --group=0 --mode=go+u,go-w
%.tar.xz:
	@test -z '$(WORKTREE_WARN)' || echo                                        \
	  '$(shell tput setaf 3)$(WORKTREE_WARN)$(shell tput sgr0)' 1>&2
	@rm --recursive --force dist-tmp # Hard-code to prevent accidents
	@mkdir --parents dist-tmp/$*
	cp --parents $^ dist-tmp/$*
	LC_ALL=C tar --create --xz --file=$@ --directory=dist-tmp $(TARFLAGS) $*
	@rm --recursive --force dist-tmp


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

ifndef JAVA_HOME
  JAVA_HOME = $(realpath $(dir $(realpath $(shell command -v javac)))..)
endif
ifndef CENTOS_VERSION
  CENTOS_VERSION = 9
endif
ifndef JDK_VERSION
  JDK_VERSION = 21
endif
.PHONY: -test
-test:
	$(JAVA_HOME)/bin/javac -d $(BIN_DIR) $(TST_DIR)/Main.java
	$(JAVA_HOME)/bin/java -cp $(BIN_DIR) Main $(TEST_ARGUMENT)

.PHONY: test-exec ## Locally run the test suite (system must be in FIPS mode), parameters: [JAVA_HOME]
test-exec: TEST_ARGUMENT = $(OUTPUT)
test-exec: $(PREVIOUS_BUILD_MODE) -test

.PHONY: test-data ## Locally run the test suite in data generation mode, parameters: [JAVA_HOME]
test-data: TEST_ARGUMENT = --data-generation
test-data: -test

.PHONY: test ## Run the test suite inside a CentOS Stream container, parameters: [CENTOS_VERSION] [JDK_VERSION]
test:
	@bash $(TST_DIR)/containerized_test.sh $(CENTOS_VERSION) $(JDK_VERSION)

.PHONY: github-release ## Create a release tag for the current VERSION and publish it to GitHub, parameters: [REMOTE_NAME]
ifndef REMOTE_NAME
  REMOTE_NAME = origin
endif
github-release: $(DIST_FILE)
	@bash .github/tag_and_upload_release.sh                                    \
	  "$(NAME_VER)" "$(VERSION)" "$(REMOTE_NAME)" "$(DIST_FILE)"

.PHONY: help ## Display this message
help:
	@echo '$(shell tput bold)Available make targets:$(shell tput sgr0)'
	@sed -ne 's/^\.PHONY:\s*\([a-zA-Z0-9_\-]*\)\s*##\s*\(.*\)/                 \
	  $(shell tput setaf 6)\1$(shell tput sgr0)$(shell printf "\x1E")\2/p'     \
	  $(MAKEFILE_LIST) | column -c2 -t -s$(shell printf "\x1E")
