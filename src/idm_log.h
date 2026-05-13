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
 * @brief IDM logging macros — thin wrappers over CcspTraceInfo/CcspTraceError.
 *
 * Uses the same ccsp_trace.h API as the interdevicemanager binary.
 * pComponentName is supplied by the interdevicemanager binary that links
 * libupnpidm.la; CcspTraceGetRdkLogModule() maps it to
 * "LOG.RDK.INTERDEVICEMANAGER", routing all output to InterDeviceManager.txt.
 *
 * Link with -lrdkloggers -lccsp_common (declared in libupnpidm_la_LIBADD).
 */

#ifndef IDM_LOG_H
#define IDM_LOG_H

#include "ccsp_trace.h"

/**
 * IDM_LOG_INFO(fmt, ...) — INFO-level entry; matches CcspTraceInfo convention.
 * IDM_LOG_ERR(fmt, ...)  — ERROR-level entry; matches CcspTraceError convention.
 *
 * Format prefix "(%s:%d) " injects __func__ and __LINE__ automatically,
 * identical to the pattern used throughout the interdevicemanager source.
 * Do not include a trailing "\n" in fmt — it is appended by the macro.
 */
#define IDM_LOG_INFO(fmt, ...) \
    CcspTraceInfo(("(%s:%d) " fmt "\n", __func__, __LINE__, ##__VA_ARGS__))

#define IDM_LOG_ERR(fmt, ...) \
    CcspTraceError(("(%s:%d) " fmt "\n", __func__, __LINE__, ##__VA_ARGS__))

#endif /* IDM_LOG_H */
