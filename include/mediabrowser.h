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

#ifndef _XUPNP_MEDIABROWSER_H
#define _XUPNP_MEDIABROWSER_H

#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif

#define METHOD_DISCOVER_MEDIA_DEVICES_SIZE "Device.Methods.dlna.getDiscoveredDevicesSize()"
#define METHOD_GET_MEDIA_DEVICE_AT "Device.Methods.dlna.getDiscoveredDeviceAt()"
#define METHOD_BROWSE_CONTENT_ON_MEDIA_SERVER "Device.Methods.dlna.browseContentOnServer()"

/**
 *  This method initializes the RPC communication between rdkservice and xupnp dlna counter part
 *  return true if the RPC initialization succeeds , false otherwise.
 * */
bool InitializeRPC();

/**
 * Returns a count of discovered servers
 * 
 * param size OUT count of servers present in the array
 * 
 * return true if the  RPC call succeeds, false otherwise
 */
bool getDiscoveredMediaServers(int * size);


/**
 * Returns a list of discovered servers
 * 
 * param index IN the index for device for which information is requested, starts from 0.
 * param friendlyName OUT will provide the name of the server 
 * param udn OUT the device unique id 
 * param error OUT sets to one if an error occured.
 * 
 * return true if the  RPC call succeeds, false otherwise
 */
bool getDiscoveredMediaServerAt(int index, char **friendlyName, char ** udn,int * error);

/**
 * Returns the contents from the specified directory. This method can be repeatedly invoked on the 
 *      same directory if the max_entries is less than total content size, by givign appropriate 
 *      starting point.
 * 
 * param server IN  server the server object representing media server
 * param path_id IN the path id representing the directory for which the content 
 *                  is requested, if NULL, root directory is assumed
 * param start_index IN starting index of contents, 
 *                  zero if calling first time, 
 * param max_entries IN the maximum number of entries expected in result
 * param total_count OUT total number of items present.
 * param content_list OUT content list in xml format with meta-data information.
 *                  Refer "ContentDirectory:1 Service Template Version 1.01" for more details.
 * param error OUT sets to one if an error occured, 0 otherwise.
 * 
 * return true if the RPC call succeeds, false otherwise
 */

bool browseContentOnServer(const char * server_udn, const char * path_id, int start_index, 
        int max_entries, int *total_count, char ** content_list, int * error);

/**
 * Clean up the IPC communication channel between rdkservice and xupnp dlna counter part
 * */
void cleanup();
#ifdef __cplusplus
}
#endif

#endif //_XUPNP_MEDIABROWSER_H