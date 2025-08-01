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
#ifndef RDK_SAFECLIB_H_
#define RDK_SAFECLIB_H_

#ifndef SAFEC_DUMMY_API
#include "safe_str_lib.h"
#include "safe_mem_lib.h"
#endif

#define RDK_SAFECLIB_ERR(rc)  printf("safeclib error at %s %s:%d rc = %d", __FILE__, __FUNCTION__, __LINE__, rc)

#define ERR_CHK(rc)                                             \
    if(rc !=EOK) {                                              \
        RDK_SAFECLIB_ERR(rc);                                   \
    }

#ifdef SAFEC_DUMMY_API
typedef int errno_t;
#define EOK 0

#define strcpy_s(dst,max,src) EOK; \
 strcpy(dst,src);
#define strncpy_s(dst,max,src,len)  EOK; \
 strncpy(dst,src,len);
#define memset_s(dst,max_1,c,max) EOK; \
 memset(dst,c,max);

errno_t strcmp_s(const char *,int,const char *,int *);
#endif

#endif /* RDK_SAFECLIB_H_ */

