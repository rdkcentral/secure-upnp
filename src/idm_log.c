/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2016 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * @file idm_log.c
 * @brief IDM logging implementation — single shared fd for idm_client and idm_server.
 */
#ifndef _GNU_SOURCE
 #define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include "idm_log.h"

static FILE *idm_log_fp = NULL;
static pthread_mutex_t idm_log_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Rate-limit fopen() failure reports: log at most once every 60 seconds */
static time_t idm_log_fopen_fail_last = 0;

/**
 * idm_log_reopen — return the current log fd, reopening if rdklogger has
 * rotated the file (detected via inode mismatch).
 */
static FILE *idm_log_reopen(void)
{
    struct stat st_fd, st_file;
    /* Check if open fd still points to the same file as the named path */
    if (idm_log_fp)
    {
        int stale = (fstat(fileno(idm_log_fp), &st_fd) != 0 ||
                     stat(IDM_LOG_FILE, &st_file) != 0 ||
                     st_fd.st_ino != st_file.st_ino ||
                     st_fd.st_dev != st_file.st_dev ||
                     st_fd.st_mode != st_file.st_mode);
        if (stale)
        {
            fclose(idm_log_fp);
            idm_log_fp = NULL;
        }
    }
    if (!idm_log_fp)
    {
        idm_log_fp = fopen(IDM_LOG_FILE, "a");
        if (!idm_log_fp)
        {
            /* Report fopen failure via stderr, rate-limited to once per 60s */
            time_t now = time(NULL);
            if (now - idm_log_fopen_fail_last >= 60)
            {
                idm_log_fopen_fail_last = now;
                fprintf(stderr,
                        "IDM: fopen(%s) failed: %s\n",
                        IDM_LOG_FILE, strerror(errno));
            }
        }
    }
    return idm_log_fp;
}

/**
 * idm_consolelog — write one timestamped log line (with automatic newline).
 * Called via the IDM_LOG_INFO() macro which supplies __func__ and __LINE__.
 * Callers should not include a trailing "\n" in fmt.
 */
void idm_consolelog(const char *func, int line, const char *level,
                    const char *fmt, ...)
{
    pthread_mutex_lock(&idm_log_mutex);
    FILE *out = idm_log_reopen();
    if (!out)
    {
        pthread_mutex_unlock(&idm_log_mutex);
        return;
    }

    /* Timestamp: YYMMDD-HH:MM:SS.uuuuuu */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm_info;
    localtime_r(&tv.tv_sec, &tm_info);
    char ts[32];
    strftime(ts, sizeof(ts), "%y%m%d-%H:%M:%S", &tm_info);
    long tid = (long)syscall(SYS_gettid);

    fprintf(out, "%s.%06ld [mod=INTERDEVICEMANAGER, lvl=%s] [tid=%ld] %s %d - ",
            ts, (long)tv.tv_usec, level, tid, func, line);

    va_list args;
    va_start(args, fmt);
    vfprintf(out, fmt, args);
    va_end(args);
    fputc('\n', out);
    fflush(out);
    pthread_mutex_unlock(&idm_log_mutex);
}
