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
 * @file xdevice.h
 * @brief The header file provides xcal devices APIs.
 */

 /**
 * @defgroup XUPNP_XCALDEV XUPnP XCal-Device
 * The XUPnP XCal-Device moudule is responssible for getting the device discovery information.
 * - Read the xupnp configuration details from configuration file.
 * - Getting the input for different gateway to populate all the service veriables.
 * - It act like a server & whenever requested it will give the services details such as ipv6 ip address,
 * receiver Id, etc.
 * - Once the xcal-device receive the services details, it will create a UPnP object and start publishing the UPnP data.
 * @ingroup XUPNP
 *
 * @defgroup XUPNP_XCALDEV_FUNC XUPnP XCal-Device Functions
 * Describe the details about XCal-Device functional specifications.
 * @ingroup XUPNP_XCALDEV
 */
#ifndef XDEVICE_H
#define XDEVICE_H

#define  _IARM_XDEVICE_NAME   "XDEVICE" /*!< Method to Get the Xdevice Info */
#define MAX_DEBUG_MESSAGE 50

typedef struct
{
  gchar *bcastIf, *streamIf, *trmIf, *gwIf, *cvpIf, *ruiPath, *uriOverride, *hostMacIf;
  gchar *oemFile, *dnsFile, *dsgFile, *diagFile, *hostsFile, *devXmlPath, *devXmlFile, *cvpXmlFile, *logFile, *devPropertyFile,*ipv6FileLocation,*ipv6PrefixFile,*deviceNameFile;
  gboolean enableCVP2, useIARM, allowGwy, enableTRM, useGliDiag, disableTuneReady,enableHostMacPblsh,rmfCrshSupp,wareHouseMode;
  gint bcastPort, cvpPort;
} ConfSettings;

ConfSettings *devConf;
GString *url, *trmurl, *playbackurl, *gwyip, *gwyipv6, *dnsconfig, *systemids, *serial_num, *lan_ip, *recv_id,*partner_id,*hostmacaddress,*devicetype,*recvdevtype,*buildversion,*ipv6prefix,*gwystbip,*bcastmacaddress,*devicename,*mocaIface,*wifiIface,*dataGatewayIPaddress;
GString *trmurlCVP2, *playbackurlCVP2, *gwyipCVP2;
unsigned long channelmap_id, dac_id, plant_id, vodserver_id;
GString *dsgtimezone, *etchosts;
GUPnPRootDevice *dev, *cvpdev;
GUPnPServiceInfo *service, *cvpservice;
GUPnPContext *context, *cvpcontext;

gboolean isgateway, tune_ready, service_ready, requirestrm, usesDaylightTime;
gint dstOffset, rawOffset, dstSavings;
GString *ruiurl, *inDevProfile, *uiFilter;
FILE *logoutfile;



xmlDoc * open_document(const char * file_name);
int set_content(xmlDoc* doc, const char * node_name, const char * new_value);
char * get_content(xmlDoc* doc, const char * node_name);
gboolean getdnsconfig(void);
unsigned long getidfromdiagfile(const gchar *diagparam, const gchar *diagfilecontents);
gboolean updatesystemids(void);
gboolean gettimezone(void);
gboolean getserialnum(GString* serial_num);
gboolean getetchosts(void);
gboolean readconfile(const char*);
gboolean updateuuid(const char*, const char*, const char*);
gboolean getruiurl(void);
void notify_value_change(const char*, const char*);
void notify_value_change_int(const char*, int);
gboolean is_alphanum(const gchar *str);
gchar* getmacaddress(const gchar *if_name);
gboolean readDevFile(const char* );
GString* getID( const gchar* );
int getipaddress(const char* ifname, char* ipAddressBuffer, gboolean ipv6Enabled);
gboolean getipv6prefix(void);
gboolean getdevicename(void);
GString* get_eSTBMAC(void);
void notify_timezone(void);
gboolean getFogStatus(void);
void getRouteData(void);


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

#endif // XDEVICE_H
