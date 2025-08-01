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
 * @file idm_client.h
 * @brief This source file contains functions  that will run as task for maintaining the device list.
 */
typedef struct _gwyDeviceData {
    GString* serial_num;
    GString* gwyipv6;
    GString* bcastmacaddress;
    GString* receiverid;
    GUPnPServiceInfo* sproxy;
    GUPnPServiceInfo* sproxy_i;
    GString* clientip;
} GwyDeviceData;
GList* xdevlist= NULL;
GMainContext *main_context;
GUPnPControlPoint *cp_bgw,*cp;
GString *ownSerialNo;
#define ACCOUNTID_SIZE 30
#define SSL_FILE_LEN 128
gboolean init_gwydata(GwyDeviceData* gwydata);
gboolean getserialnum(GString* ownSerialNo);
gboolean discovery_interval_configuration(guint seconds,guint loss_detection_window);
char certFile[SSL_FILE_LEN];
char keyFile[SSL_FILE_LEN];
char caFile[SSL_FILE_LEN];
#define MAC_ADDR_SIZE 18
#define IPv4_ADDR_SIZE 16
#define IPv6_ADDR_SIZE 128
#define BOOL unsigned char
BOOL getAccountId(char *outValue);
typedef struct {
    char Ipv4[IPv4_ADDR_SIZE];
    char Ipv6[IPv6_ADDR_SIZE];
    char mac[MAC_ADDR_SIZE];
} device_info_t;

unsigned int sleep_seconds=0;
typedef struct _discovery_config_t{
    gchar interface[32];
    unsigned int port;
    unsigned int discovery_interval;
    unsigned int loss_detection_window;
    gchar base_mac[32];
    char sslCert[SSL_FILE_LEN];
    char sslKey[SSL_FILE_LEN];
    char sslCA[SSL_FILE_LEN];
#ifdef ENABLE_HW_CERT_USAGE
    char sslSeCert[SSL_FILE_LEN];
    char sslPassCodeFile[SSL_FILE_LEN];
    char sslSeCAFile[SSL_FILE_LEN];
#endif
}discovery_config_t;

GMutex *mutex;
int (*callback)(device_info_t*,uint,uint);
int idm_server_start(char*interface, char * mac);

void free_server_memory();
