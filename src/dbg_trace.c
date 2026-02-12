// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#include "dbg_trace.h"
#include "nssadapter.h"
#include <err.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define DEBUG_ENV_VAR     "NSS_ADAPTER_DEBUG"
#define DISABLED_OPT      "no"
#define ENABLED_OPT       "yes"
#define ENABLED_COLOR_OPT "color"

#define STATUS_DISABLED   (0)
#define STATUS_ENABLED    (1 << 0)
#define STATUS_COLOR      (1 << 1)

#ifdef DEBUG
#define STATUS_DEFAULT (STATUS_ENABLED | STATUS_COLOR)
#else
#define STATUS_DEFAULT (STATUS_DISABLED)
#endif

static FILE *dbg_file = NULL;
static pthread_mutex_t dbg_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned char dbg_status = STATUS_DEFAULT;

// If 'text' startswith 'prefix' (case insensitive), returns the length of
// 'prefix', otherwise zero. NOTE: 'prefix' must be a compile-time string
// literal.
#define __skip_prefix(text, prefix)                                            \
    (strncasecmp((text), (prefix), sizeof(prefix) - 1) ? 0                     \
                                                       : (sizeof(prefix) - 1))

void dbg_initialize() {
    const char *var = getenv(DEBUG_ENV_VAR);
    if (var != NULL) {
        size_t offset = 0;
        if (__skip_prefix(var, DISABLED_OPT)) {
            dbg_status = STATUS_DISABLED;
        } else if ((offset = __skip_prefix(var, ENABLED_OPT))) {
            dbg_status = STATUS_ENABLED;
        } else if ((offset = __skip_prefix(var, ENABLED_COLOR_OPT))) {
            dbg_status = STATUS_ENABLED | STATUS_COLOR;
        }
        if (offset > 0 && strlen(var + offset) > 0 && var[offset] == ':') {
            const char *file_path = var + offset + 1;
            dbg_file = fopen(file_path, "a");
            if (dbg_file == NULL) {
                dbg_status = STATUS_DISABLED;
                warn(DEBUG_ENV_VAR " file '%s'", file_path);
            }
        }
    }
    if (dbg_file == NULL) {
        dbg_file = stderr;
    }
    dbg_trace(NAME_VER);
}

inline bool dbg_is_enabled() {
    return dbg_status & STATUS_ENABLED;
}

void dbg_finalize() {
    if (dbg_file != NULL && dbg_file != stderr) {
        fclose(dbg_file);
    }
    pthread_mutex_destroy(&dbg_mutex);
}

inline FILE *__dbg_file() {
    return dbg_file;
}

inline void __dbg_lock() {
    pthread_mutex_lock(&dbg_mutex);
}

inline void __dbg_unlock() {
    pthread_mutex_unlock(&dbg_mutex);
}

// Generates an ANSI terminal escape sequence.
#define __ansi_attrs(attrs) "\033[" attrs "m"

void __dbg_trace_header(const char *file, const unsigned int line,
                        const char *func) {
    struct timeval tv;
    char datetime[24];
    const char *cyan;
    const char *red;
    const char *green;
    const char *magenta;
    const char *yellow;
    const char *reset;
    if (dbg_status & STATUS_COLOR) {
        cyan = __ansi_attrs("36");
        red = __ansi_attrs("31");
        green = __ansi_attrs("32");
        magenta = __ansi_attrs("35");
        yellow = __ansi_attrs("33");
        reset = __ansi_attrs();
    } else {
        cyan = red = green = magenta = yellow = reset = "";
    }
    gettimeofday(&tv, NULL);
    strftime(datetime, sizeof(datetime), "%F %T", gmtime(&tv.tv_sec));
    fprintf(dbg_file,
            "%s%s.%06ld%s (tid %s%lu%s): %s%s%s:%s%d%s, %s%s()%s: ", cyan,
            datetime, tv.tv_usec, reset, red, syscall(SYS_gettid), reset, green,
            file, reset, magenta, line, reset, yellow, func, reset);
}

inline void __dbg_trace_footer() {
    fputc('\n', dbg_file);
    fflush(dbg_file);
}

bool __dbg_should_dump_attr_value(UNUSED CK_ATTRIBUTE_TYPE type) {
    return true
#ifndef DEBUG
// Do not dump attribute value if sensitive.
#define for_each_sensitive_attr(idx, sensitive_attr_type)                      \
    &&type != sensitive_attr_type
#include "sensitive_attributes.h"
#undef for_each_sensitive_attr
#endif
        ;
}

// Logs a simple hex-dump like representation of the input buffer.
void __dbg_trace_hex(const unsigned char *const buf, size_t len) {
    if (buf != NULL && len > 0) {
        fprintf(dbg_file, "\n ");
        for (size_t n = 0; n < len; n++) {
            if (n != 0 && n % 8 == 0) {
                fprintf(dbg_file, n % 32 == 0 ? "\n " : "  ");
            }
            fprintf(dbg_file, " %02X", buf[n]);
        }
    }
}
