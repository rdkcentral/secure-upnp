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
 * @brief IDM logging macros backed by rdklogger.
 *
 * Uses RDK_LOG() with the "LOG.RDK.INTERDEVICEMANAGER" log4c category —
 * identical to the module used by the interdevicemanager binary — which
 * routes all output to /rdklogs/logs/InterDeviceManager.txt.
 * Timestamps, log rotation, and level filtering are handled by rdklogger.
 *
 * Link with -lrdkloggers (declared in libupnpidm_la_LIBADD).
 */

#ifndef IDM_LOG_H
#define IDM_LOG_H

#include "rdk_debug.h"

#define IDM_LOG_MODULE "LOG.RDK.INTERDEVICEMANAGER"

/**
 * IDM_LOG_INFO(fmt, ...) — INFO-level entry in InterDeviceManager.txt.
 * IDM_LOG_ERR(fmt, ...)  — ERROR-level entry in InterDeviceManager.txt.
 *
 * A newline is appended automatically; do not include a trailing "\n" in fmt.
 * Each line is prefixed with (function:line) matching the CcspTraceInfo
 * convention used by the interdevicemanager component.
 */
#define IDM_LOG_INFO(fmt, ...) \
    RDK_LOG(RDK_LOG_INFO,  IDM_LOG_MODULE, \
            "(%s:%d) " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

#define IDM_LOG_ERR(fmt, ...) \
    RDK_LOG(RDK_LOG_ERROR, IDM_LOG_MODULE, \
            "(%s:%d) " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

#endif /* IDM_LOG_H */
