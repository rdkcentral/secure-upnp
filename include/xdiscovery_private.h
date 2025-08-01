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

#ifndef XDISCOVERY_PRIVATE_H_
#define XDISCOVERY_PRIVATE_H_

#ifdef G_LOG_DOMAIN
#undef G_LOG_DOMAIN
#endif
#define G_LOG_DOMAIN "XUPNP"
#define XUPNP_RESCAN_INTERVAL 22000000
#define XDISC_SERVICE "urn:schemas-upnp-org:service:DiscoverFriendlies:1"
#define XDISC_SERVICE_IDENTITY "urn:schemas-upnp-org:service:X1Identity:1"
#define XDISC_SERVICE_MEDIA "urn:schemas-upnp-org:service:X1MediaConfiguration:1"
#define XDISC_SERVICE_GW_CFG "urn:schemas-upnp-org:service:X1GatewayConfiguration:1"
#define XDISC_SERVICE_QAM_CFG "urn:schemas-upnp-org:service:X1QamConfiguration:1"
#define XDISC_SERVICE_TIME "urn:schemas-upnp-org:service:X1Time:1"
#define XDISC_SERVICE_PROTECTION "urn:schemas-upnp-org:service:DeviceProtection:1"

#define MAX_ENTRIES 1024
#define MAX_OVERFLOW 1024
#define MAX_BUF_SIZE 2048
#define MAC_ADDRESS_SIZE 20

#ifdef BROADBAND
typedef enum { DP_SUCCESS=0, DP_INVALID_MAC, DP_COLLISION, DP_WLIST_ERROR} dp_wlist_ss_t;
typedef enum { FIFO_OK=0, FIFO_FULL=1, FIFO_EMPTY=2} fstat_t;

#define DEF_FIFO(name, max_size, type) \
    typedef struct fname1 { \
          type entries[max_size]; \
          unsigned int tail; \
          unsigned int size;\
    } fname1_t; \
    fname1_t name;     

#define INIT_FIFO(name, max_size) \
{ \
    name.tail = max_size;\
    name.size = max_size; \
}

#define ENQUEUE_FIFO(name, value, ret) \
{ \
   if (name.tail > 0) { \
      name.tail--; \
      name.entries[name.tail] = value; \
      ret = FIFO_OK; \
   } \
   else { \
      ret = FIFO_FULL; \
   } \
} \

#define DEQUEUE_FIFO(name, value, ret) \
{ \
   if (name.tail != name.size) {\
       value = name.entries[name.tail]; \
       name.tail++; \
       ret = FIFO_OK; \
   } \
   else { \
       ret = FIFO_EMPTY; \
   } \
}

typedef struct dp_wlist {
     long ipaddr;
     char macaddr[MAC_ADDRESS_SIZE];
     short ofb_index;
}dp_wlist_t;
#endif

struct ProxyMapping {
    GUPnPDeviceProxy *proxy;
    GUPnPServiceProxyAction *action;
    GSource *timeout_src;
};

typedef struct _gwyDeviceData {
    GString* serial_num;
    gboolean isgateway;
    gboolean requirestrm;
    GString* gwyip;
    GString* gwyipv6;
    GString* gatewaystbip;
    GString* ipv6prefix;
    GString* devicename;
    GString* bcastmacaddress;
    GString* hostmacaddress;
    GString* recvdevtype;
    GString* devicetype;
    GString* buildversion;
    GString* dsgtimezone;
    gint rawoffset;
    gint dstoffset;
    gint dstsavings;
    gboolean usesdaylighttime;
    GString* baseurl;
    GString* basetrmurl;
    GString* playbackurl;
    GString* dataGatewayIPaddress;
    GString* dnsconfig;
    GString* etchosts;
    GString* systemids;
    GString* receiverid;
    gboolean devFoundFlag;
    gboolean isRouteSet;
    gboolean isOwnGateway;
    gboolean isDevRefactored;
    GUPnPServiceInfo* sproxy;
    GUPnPServiceInfo* sproxy_i;
    GUPnPServiceInfo* sproxy_m;
    GUPnPServiceInfo* sproxy_g;
    GUPnPServiceInfo* sproxy_q;
    GUPnPServiceInfo* sproxy_t;
    GString* modelclass;
    GString* modelnumber;
    GString* deviceid;
    GString* hardwarerevision;
    GString* softwarerevision;
    GString* managementurl;
    GString* make;
    GString* accountid;
    GString* ipSubNet;
    GString* clientip;
} GwyDeviceData;

GList* xdevlist= NULL;
//const char* host_ip = "eth0";
const guint host_port = 50759;

GMutex *mutex;
GMutex *devMutex;
GCond *cond;
GMainContext *main_context;
GUPnPContext *context;
GUPnPContext *upnpContextDeviceProtect;
GUPnPControlPoint* cp, *cp_client, *cp_gw, *cp_bgw;
GString* outputfilename;
GString* outputcontents;
GString* ipMode;
FILE *logoutfile;
GString *ownSerialNo;
char ipaddress[INET6_ADDRSTRLEN];
gchar *bcastmac;

typedef struct
{
    gchar *discIf,*gwIf;
    gchar *gwSetupFile,*logFile,*outputJsonFile,*disCertFile, *disCertPath, *disKeyFile, *disKeyPath;
    gchar *disSeCertFile, *disPassCodeFile, *disSeCAFile;
    gboolean enableGwSetup;
    gint GwPriority;
} ConfSettings;

ConfSettings *disConf;


#ifdef USE_XUPNP_TZ_UPDATE
struct _Timezone
{
    char* upnpTZ;
    char* tz;
    char* tzInDst;
} m_timezoneinfo[] =
{
    {"US/Hawaii", "HST11", "HST11HDT,M3.2.0,M11.1.0"},
    {"US/Alaska", "AKST",   "AKST09AKDT,M3.2.0,M11.1.0"},
    {"US/Pacific", "PST08", "PST08PDT,M3.2.0,M11.1.0"},
    {"US/Mountain", "MST07","MST07MDT,M3.2.0,M11.1.0"},
    {"US/Central", "CST06","CST06CDT,M3.2.0,M11.1.0"},
    {"US/Eastern", "EST05","EST05EDT,M3.2.0,M11.1.0"},
};
#endif

void* verify_devices();
gboolean init_gwydata(GwyDeviceData* gwydata);
gboolean sendDiscoveryResult(const char* outfilename);
void delOldItemsFromList(gboolean bDeleteAll);

void xupnp_logger (const gchar *log_domain, GLogLevelFlags log_level,
                   const gchar *message, gpointer user_data);

gboolean verifyDeviceAttributeChanges(GUPnPServiceProxy *, GwyDeviceData *);
static void on_last_change (GUPnPServiceProxy *sproxy, const char  *variable_name, GValue  *value, gpointer user_data);
gboolean readconffile(const char* configfile);
gboolean getserialnum(GString* ownSerialNo);
int getipaddress(const char* ifname, char* ipAddressBuffer, gboolean ipv6Enabled);
char *replace_string(char *src_string, char *sub_string, char *replace_string);
gboolean replace_hn_with_local(GwyDeviceData* gwydata);
gboolean replace_local_device_ip(GwyDeviceData* gwydata);
gboolean checkvalidip( char* ipAddress);
gboolean checkvalidhostname( char* hostname);
void broadcastIPModeChange(void);


#if defined(ENABLE_FEATURE_TELEMETRY2_0)
#include <telemetry_busmessage_sender.h>
#endif


gchar *getmacaddress(const gchar *ifname);

gboolean delete_gwyitem(const char* serial_num);
gboolean process_gw_services(GUPnPServiceProxy *sproxy, GwyDeviceData* gwData);
gboolean free_gwydata(GwyDeviceData* gwydata);
gboolean process_gw_services_identity(GUPnPServiceProxy *sproxy, GwyDeviceData* gwData);
gboolean process_gw_services_media_config(GUPnPServiceProxy *sproxy, GwyDeviceData* gwData);
gboolean process_gw_services_time_config(GUPnPServiceProxy *sproxy, GwyDeviceData* gwData);
gboolean process_gw_services_gateway_config(GUPnPServiceProxy *sproxy, GwyDeviceData* gwData);
gboolean process_gw_services_qam_config(GUPnPServiceProxy *sproxy, GwyDeviceData* gwData);
gboolean processStringRequest(const GUPnPServiceProxy *sproxy ,const char * requestFn, const char * responseFn, gchar ** result, gboolean isInCriticalPath);
#endif /* XDISCOVERY_PRIVATE_H_ */
