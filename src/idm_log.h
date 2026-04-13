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
 * @file idm_log.h
 * @brief IDM logging interface — shared between idm_client.c and idm_server.c.
 *
 * All writes go to /rdklogs/logs/Consolelog.txt.0.
 * Log rotation is handled externally by rdklogger; the open file descriptor
 * is transparently reopened after rotation via inode comparison.
 */

#ifndef IDM_LOG_H
#define IDM_LOG_H

#define IDM_LOG_FILE "/rdklogs/logs/Consolelog.txt.0"

/**
 * IDM_LOG_INFO(fmt, ...) — write a timestamped INFO line to Consolelog.txt.0.
 * IDM_LOG_ERR(fmt, ...) — write a timestamped ERROR line.
 *
 * A newline is appended automatically; do not include a trailing "\n" in fmt.
 * Format matches the standard RDK log pattern:
 *   YYMMDD-HH:MM:SS.uuuuuu [mod=INTERDEVICEMANAGER, lvl=<LEVEL>] [tid=NNN] func line - message
 */
#define IDM_LOG_INFO(fmt, ...) \
    idm_consolelog(__func__, __LINE__, "INFO", fmt, ##__VA_ARGS__)

#define IDM_LOG_ERR(fmt, ...) \
    idm_consolelog(__func__, __LINE__, "ERROR", fmt, ##__VA_ARGS__)

void idm_consolelog(const char *func, int line, const char *level,
                    const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

#endif /* IDM_LOG_H */
