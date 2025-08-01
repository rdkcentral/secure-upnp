/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2021 RDK Management
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

#ifndef _MEDIA_BROWSER_PRIVATE_H_
#define _MEDIA_BROWSER_PRIVATE_H_

#include <libgupnp/gupnp-control-point.h>
#include <safec_lib.h>
#define RBUS_XUPNP_SERVICE_PROVIDER "rbus.xupnp.dlna"
#define XUPNP_SERVICE_CONTENT_DIR "urn:schemas-upnp-org:service:ContentDirectory:1"
#define XUPNP_DEVICE_MEDIASERVER_CONTROL_URN "urn:schemas-upnp-org:device:MediaServer:1"


#define BROWSE_MODE_CHILD_NODE "BrowseDirectChildren"
#define BROWSE_MODE_META_DATA "BrowseMetadata"

GUPnPControlPoint* *cp_media_rndr;
GMutex * locker;

typedef struct _mediaServerCfg {
    char * friendlyname;
    char * udn;
    GUPnPServiceInfo * browserService;
}mediaServerCfg;

extern GList* msList; // Defined in mediaserver.c

void init_rpc_iface(); //For intializing RPC communications
void close_rpc_iface(); // To cleanup RPC communications.
bool browse_remote_dir_with_udn(const char * server_udn, const char * path_id, int start_index, 
        int max_entries,  int *totalCount, char **results);
void init_media_browser();
void close_media_browser();

#endif //_MEDIA_BROWSER_PRIVATE_H_