/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2018 RDK Management
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
#ifndef BOOL
#define BOOL  unsigned char
#endif
#if defined(USE_XUPNP_IARM_BUS)
#include "libIARM.h"
#endif

#define MAX_DEBUG_MESSAGE 50
typedef struct
{
  gchar *bcastIf, *streamIf, *trmIf, *gwIf, *cvpIf, *ruiPath, *uriOverride, *hostMacIf,  *devCertPath, *devKeyPath;
  gchar *oemFile, *dnsFile, *dsgFile, *diagFile, *hostsFile, *wbFile, *devXmlPath, *devXmlFile, *cvpXmlFile, *logFile, *devPropertyFile,*ipv6FileLocation,*ipv6PrefixFile,*deviceNameFile;
  gchar *devCertFile, *devKeyFile;
  gboolean enableCVP2, useIARM, allowGwy, enableTRM, useGliDiag, disableTuneReady,enableHostMacPblsh,rmfCrshSupp,wareHouseMode;
  gint bcastPort, cvpPort;
} ConfSettings;

ConfSettings *devConf;

GString *url, *trmurl, *videobaseurl, *playbackurl, *gwyip, *gwyipv6, *dnsconfig, *systemids, *serial_num, *lan_ip, *recv_id,*partner_id,*hostmacaddress,*devicetype,*recvdevtype,*buildversion,*ipv6prefix,*gwystbip,*bcastmacaddress,*devicename,*mocaIface,*wifiIface,*fogtsburl,*dataGatewayIPaddress, *eroutermacaddress, *accountid, *make;
GString *trmurlCVP2, *playbackurlCVP2, *gwyipCVP2;
unsigned long channelmap_id, dac_id, plant_id, vodserver_id;
GString *dsgtimezone, *etchosts;
gboolean isgateway, tune_ready, requirestrm, usesDaylightTime;
gint dstOffset, rawOffset, dstSavings;
GString *ruiurl;
FILE *logoutfile;

extern gboolean service_ready;
extern GString *inDevProfile, *uiFilter;

typedef struct _STRING_MAP {
    char *pszKey;
    char *pszValue;
} STRING_MAP;

typedef void (*xupnpEventCallback)(const char*,const char*);
void xupnpEventCallback_register(xupnpEventCallback callback_proc);

#if defined(USE_XUPNP_IARM_BUS)
#define  _IARM_XDEVICE_NAME   "XDEVICE" /*!< Method to Get the Xdevice Info */
static void _sysEventHandler(const char *owner, IARM_EventId_t eventId,
                             void *data, size_t len);
IARM_Result_t _SysModeChange(void *arg);
static void _routesysEventHandler(const char *owner, IARM_EventId_t eventId,
                                  void *data, size_t len);
gboolean XUPnP_IARM_Init(void);
BOOL getRouteData(void);
void getSystemValues(void);
gboolean getFogStatus(void);
//fog
typedef struct _IARM_Bus_FOG_Param_t
{
	bool status; // if true, FOG is active
	int fogVersion;
	char tsbEndpoint[33]; // i.e. http://169.254.228.194:9080/tsb?
} IARM_Bus_Fog_Param_t;
#define IARM_BUS_FOG_NAME "FOG"
#define IARM_BUS_FOG_getCurrentState "getCurrentState"
typedef enum
{
	IARM_BUS_FOG_EVENT_STATUS,
	IARM_BUS_FOG_EVENT_MAX
} FOG_EventId_t;
//netsrvmgr
#define IARM_BUS_NM_SRV_MGR_NAME "NET_SRV_MGR"
#define IARM_BUS_NETSRVMGR_Route_Event "sendCurrentRouteData"
#define IARM_BUS_ROUTE_MGR_API_getCurrentRouteData "getCurrentRouteData"
typedef struct _routeEventData_t {
        char routeIp[46];
        gboolean ipv4;
        char routeIf[10];
} routeEventData_t;
typedef struct _IARM_Bus_RouteSrvMgr_RouteData_Param_t {
    routeEventData_t route;
    bool status;
} IARM_Bus_RouteSrvMgr_RouteData_Param_t;
typedef enum _NetworkManager_Route_EventId_t {
        IARM_BUS_NETWORK_MANAGER_EVENT_ROUTE_DATA=10,
        IARM_BUS_NETWORK_MANAGER_EVENT_ROUTE_MAX,
} IARM_Bus_NetworkManager_Route_EventId_t;
#endif

//#####################
BOOL check_empty(char *str);
BOOL check_null(char *str);
//######################

BOOL xdeviceInit(char *devConfFile, char *devLogFile);

GString *getID( const gchar *id );
gboolean updatesystemids(void);
gboolean parsedevicename(void);
gboolean parseipv6prefix(void);
gboolean readconffile(const char *configfile);
gboolean getetchosts(void);
gboolean parseserialnum(GString *serial_num);
unsigned long getidfromdiagfile(const gchar *diagparam,
                                const gchar *diagfilecontents);
gboolean parsednsconfig(void);
gchar *getmacaddress(const gchar *ifname);
int getipaddress(const char *ifname, char *ipAddressBuffer,
                 gboolean ipv6Enabled);
//BOOL check_empty(char *str);
//BOOL check_null(char *str);
//static char *getStrValueFromMap(char *pszKey, int nPairs, STRING_MAP map[]);
