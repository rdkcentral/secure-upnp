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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xdevice_library.h>
#include <xdevice_library_private.h>
//#include <libgssdp/gssdp.h>
#include <libsoup/soup.h>
#include <gmodule.h>
#include <stdbool.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <memory.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <glib/gstdio.h>
#include <ctype.h>
#ifdef ENABLE_RFC
#include "rfcapi.h"
#endif
#ifdef CLIENT_XCAL_SERVER
#include "mfrMgr.h"
#endif
#if defined(USE_XUPNP_IARM_BUS)
#include "libIBus.h"
#include "libIARMCore.h"
#include "sysMgr.h"
#include "libIBusDaemon.h"
IARM_Bus_Daemon_SysMode_t sysModeParam;
#endif
#include "rdk_safeclib.h"
#include "secure_wrapper.h"

#define RECEIVER_ID "deviceId"
#define PARTNER_ID "partnerId"
#define SLEEP_INTERVAL 7000000
#define BCAST_PORT  50755
#define DEVICE_PROPERTY_FILE   "/etc/device.properties"
#define GET_DEVICEID_SCRIPT     "/lib/rdk/getDeviceId.sh"
#define DEVICE_NAME_FILE    "/opt/hn_service_settings.conf"
#define LOG_FILE    "/opt/logs/xdevice.log"
#define DEVICE_XML_PATH     "/etc/xupnp/"
#define DEVICE_XML_FILE     "BasicDevice.xml"
#define CLIENT_DEVICE_XML_FILE          "X1Renderer.xml"
#define GW_DEVICE_XML_FILE              "X1VideoGateway.xml"

#define DEVICE_PROPERTY_FILE   "/etc/device.properties"
#define DEVICE_NAME_FILE    "/opt/hn_service_settings.conf"

#define RUIURLSIZE 2048
#define MAX_OUTVALUE 256
#define URLSIZE 512
#define DEVICE_KEY_PATH     "/tmp/"
#define DEVICE_KEY_FILE     "xpki_key"
#define DEVICE_CERT_PATH     "/tmp/"
#define DEVICE_CERT_FILE     "xpki_cert"
#define MAX_FILE_LENGTH      250
BOOL ipv6Enabled = FALSE;
char ipAddressBuffer[INET6_ADDRSTRLEN] = {0};
char stbipAddressBuffer[INET6_ADDRSTRLEN] = {0};

//Raw offset is fixed for a timezone
//in case of 1.3.x this read from java TimeZone object
#define HST_RAWOFFSET  (-11 * 60 * 60 * 1000)
#define AKST_RAWOFFSET (-9  * 60 * 60 * 1000)
#define PST_RAWOFFSET (-8  * 60 * 60 * 1000)
#define MST_RAWOFFSET (-7  * 60 * 60 * 1000)
#define CST_RAWOFFSET (-6  * 60 * 60 * 1000)
#define EST_RAWOFFSET (-5  * 60 * 60 * 1000)

#define COMCAST_PARTNET_KEY "comcast"
#define COX_PARTNET_KEY     "cox"
#define ARRAY_COUNT(array)  (sizeof(array)/sizeof(array[0]))
static STRING_MAP partnerNameMap[] = {
    {COMCAST_PARTNET_KEY, "comcast"},
    {COX_PARTNET_KEY    , "cox"},
};

#if 0
static STRING_MAP friendlyNameMap[] = {
    {COMCAST_PARTNET_KEY, "XFINITY"},
    {COX_PARTNET_KEY    , "Contour"},
};
#endif

static STRING_MAP productNameMap[] = {
    {COMCAST_PARTNET_KEY, "xfinity"},
    {COX_PARTNET_KEY    , "contour"},
};
static STRING_MAP serviceNameMap[] = {
    {COMCAST_PARTNET_KEY, "Comcast XFINITY Guide"},
    {COX_PARTNET_KEY    , "Cox Contour Guide"},
};
static STRING_MAP serviceDescriptionMap[] = {
    {COMCAST_PARTNET_KEY, "Comcast XFINITY Guide application"},
    {COX_PARTNET_KEY    , "Cox Contour Guide application"},
};
static STRING_MAP gatewayNameMap[] = {
    {COMCAST_PARTNET_KEY, "Comcast Gateway"},
    {COX_PARTNET_KEY    , "Cox Gateway"},
};

static struct TZStruct
{
    char* inputTZ;
    char* javaTZ;
    int rawOffset;
    gboolean usesDST;
} tzStruct[] =
{
    {"HST11", "US/Hawaii", HST_RAWOFFSET, 1},
    {"HST11HDT,M3.2.0,M11.1.0", "US/Hawaii", HST_RAWOFFSET, 1},
    {"AKST", "US/Alaska", AKST_RAWOFFSET, 1},
    {"AKST09AKDT", "US/Alaska", AKST_RAWOFFSET, 1},
    {"PST08", "US/Pacific", PST_RAWOFFSET, 1},
    {"PST08PDT,M3.2.0,M11.1.0", "US/Pacific", PST_RAWOFFSET, 1},
    {"MST07","US/Mountain", MST_RAWOFFSET, 1},
    {"MST07MDT,M3.2.0,M11.1.0","US/Mountain", MST_RAWOFFSET, 1},
    {"CST06", "US/Central", CST_RAWOFFSET, 1},
    {"CST06CDT,M3.2.0,M11.1.0", "US/Central", CST_RAWOFFSET, 1},
    {"EST05", "US/Eastern", EST_RAWOFFSET, 1},
    {"EST05EDT,M3.2.0,M11.1.0", "US/Eastern", EST_RAWOFFSET, 1}
};

xupnpEventCallback eventCallback;

static GString *get_uri_value();

void xupnpEventCallback_register(xupnpEventCallback callback_func)
{
    eventCallback=callback_func;
}

void mapTimeZoneToJavaFormat(char* payload)
{
    int i = 0;
    int len = sizeof(tzStruct)/sizeof( struct TZStruct );
//	dstOffset = 3600000;
    for (; i < len; i++ )
    {
        if (g_strcmp0(tzStruct[i].inputTZ, payload) == 0)
        {

            g_string_assign(dsgtimezone, tzStruct[i].javaTZ);
            if(dstOffset != 1)
            {
                notify_timezone();
            }
            rawOffset = tzStruct[i].rawOffset;
            usesDaylightTime= tzStruct[i].usesDST;
            break;
        }
    }
}

/**
 * @brief Generic function to notify the change in the time zone.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
void notify_timezone(void)
{
    if ((g_strcmp0(g_strstrip(dsgtimezone->str),"US/Mountain") == 0) && (dstOffset == 0))
    {
        g_string_assign(dsgtimezone,"US/Arizona");
        g_message("XUPnP: changing timezone  timezone= %s  dst offset = %d \n",dsgtimezone->str,dstOffset);
    }
    else if ((g_strcmp0(g_strstrip(dsgtimezone->str),"US/Central") == 0) && (dstOffset == 0))
    {
        g_string_assign(dsgtimezone,"Canada/Saskatchewan");
        g_message("XUPnP: changing timezone  timezone= %s  dst offset = %d \n",dsgtimezone->str,dstOffset);
    }
//        	else if ((g_strcmp0(g_strstrip(dsgtimezone->str),"US/Hawaii") == 0) && (dstOffset == 60))  //we wont get dstoffset as 60 for hawaii but just to be safe.
    //      	{
    //            	g_message("XUPnP: changing dstoffset  timezone= %s  dst offset = %d \n",dsgtimezone->str,dstOffset);
    //          	dstOffset=0;
    //	}
    (*eventCallback)("TimeZone", dsgtimezone->str);
}

gboolean getserialnum(GString* serial_num)
{
#ifndef CLIENT_XCAL_SERVER
    GError                  *error=NULL;
    gboolean                result = FALSE;
    gchar* udhcpcvendorfile = NULL;
    
    result = g_file_get_contents ("//etc//udhcpc.vendor_specific", &udhcpcvendorfile, NULL, &error);
    if (result == FALSE && error != NULL) {
        g_warning("Problem in reading /etc/udhcpcvendorfile file %s", error->message);
    }
    else
    {
        /* reset result = FALSE to identify serial number from udhcpcvendorfile contents */
        result = FALSE;
        gchar **tokens = g_strsplit_set(udhcpcvendorfile," \n\t\b\0", -1);
        guint toklength = g_strv_length(tokens);
        guint loopvar=0;
        for (loopvar=0; loopvar<toklength; loopvar++)
        {
            //g_print("Token is %s\n",g_strstrip(tokens[loopvar]));
            if (g_strrstr(g_strstrip(tokens[loopvar]), "SUBOPTION4"))
            {
                if ((loopvar+1) < toklength )
                {
                    g_string_assign(serial_num, g_strstrip(tokens[loopvar+2]));
                }
                result = TRUE;
                break;
            }
        }
        g_strfreev(tokens);
    }
    //diagid=1000;

    if(error)
    {
        /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
        g_clear_error(&error);
    }

    return result;
#else
    bool bRet;
    IARM_Bus_MFRLib_GetSerializedData_Param_t param;
    IARM_Result_t iarmRet = IARM_RESULT_IPCCORE_FAIL;
    errno_t rc = -1;
    rc = memset_s(&param, sizeof(param), 0, sizeof(param));
    ERR_CHK(rc); 
    param.type = mfrSERIALIZED_TYPE_SERIALNUMBER;
    iarmRet = IARM_Bus_Call(IARM_BUS_MFRLIB_NAME, IARM_BUS_MFRLIB_API_GetSerializedData, &param, sizeof(param));
    if(iarmRet == IARM_RESULT_SUCCESS)
    {
        if(param.buffer && param.bufLen)
        {
	    g_message( " serialized data %s  \n",param.buffer );
            g_string_assign(serial_num,param.buffer);
            bRet = true;
        }
        else
        {
	    g_message( " serialized data is empty  \n" );
            bRet = false;
        }
    }
    else
    {
        bRet = false;
	g_message("IARM CALL failed  for mfrtype \n");
    }
    return bRet;
#endif

}

/**
 * @brief This function is used to get the IP address based on IPv6 or IPv4 is enabled.
 *
 * @param[in] ifname Name of the network interface.
 * @param[out] ipAddressBuffer Character buffer to hold the IP address.
 * @param[in] ipv6Enabled Flag to check whether IPV6 is enabled
 *
 * @return Returns an integer value '1' if successfully gets the IP address else returns '0'.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
static char *getStrValueFromMap(char *pszKey, int nPairs, STRING_MAP map[])
{
    int i = 0;
    for (i = 0; i < nPairs; i++) {
        int nKeyLen = strlen(map[i].pszKey);
        if (0 == strncasecmp(map[i].pszKey, pszKey, nKeyLen)) return map[i].pszValue;
    }
    // By default return value in entry 0;
    return map[0].pszValue;
}

/**
 * @brief This function is used to retrieve the information from the device file.
 *
 * @param[in] deviceFile Name of the device configuration file.
 *
 * @return Returns TRUE if successfully reads the device file else returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
gboolean readDevFile(const char *deviceFile)
{
    GError                  *error=NULL;
    gboolean                result = FALSE;
    gchar* devfilebuffer = NULL;
    gchar counter=0;

    if (deviceFile == NULL)
    {
        g_message("device properties file not found");
        return result;
    }

    result = g_file_get_contents (deviceFile, &devfilebuffer, NULL, &error);
    if (result == FALSE)
    {
        g_message("No contents in device properties");
    }
    else
    {
        /* reset result = FALSE to identify device properties from devicefile contents */
        result = FALSE;
        gchar **tokens = g_strsplit_set(devfilebuffer,",='\n'", -1);
        guint toklength = g_strv_length(tokens);
        guint loopvar=0;
        for (loopvar=0; loopvar<toklength; loopvar++)
        {
            if (g_strrstr(g_strstrip(tokens[loopvar]), "DEVICE_TYPE"))
            {
                if ((loopvar+1) < toklength )
                {
                    counter++;
                    g_string_assign(recvdevtype, g_strstrip(tokens[loopvar+1]));
                }
                if (counter == 7)
                {
                    result = TRUE;
                    break;
                }
            }
            else if(g_strrstr(g_strstrip(tokens[loopvar]), "BUILD_VERSION"))
            {
                if ((loopvar+1) < toklength )
                {
                    counter++;
                    g_string_assign(buildversion, g_strstrip(tokens[loopvar+1]));
                }
                if (counter == 7)
                {
                    result = TRUE;
                    break;
                }
            }
            else if(g_strrstr(g_strstrip(tokens[loopvar]), "BOX_TYPE"))
            {
                if ((loopvar+1) < toklength )
                {
                    counter++;
                    g_string_assign(devicetype, g_strstrip(tokens[loopvar+1]));
                }
                if (counter == 7)
                {
                    result = TRUE;
                    break;
                }
            }
#if !defined (NO_MOCA_FEATURE_SUPPORT)
            if (g_strrstr(g_strstrip(tokens[loopvar]), "MOCA_INTERFACE"))
            {
                if ((loopvar+1) < toklength )
                {
                    counter++;
                    g_string_assign(mocaIface, g_strstrip(tokens[loopvar+1]));
                }
                if (counter == 7)
                {
                    result = TRUE;
                    break;
                }
            }
#endif
            if (g_strrstr(g_strstrip(tokens[loopvar]), "WIFI_INTERFACE"))
            {
                if ((loopvar+1) < toklength )
                {
                    counter++;
                    g_string_assign(wifiIface, g_strstrip(tokens[loopvar+1]));
                }
                if (counter == 7)
                {
                    result = TRUE;
                    break;
                }
            }
            if (g_strrstr(g_strstrip(tokens[loopvar]), "MODEL_NUM"))
            {
                if ((loopvar+1) < toklength )
                {
                    counter++;
                    g_string_assign(modelnumber, g_strstrip(tokens[loopvar+1]));
                }
                if (counter == 7)
                {
                    result = TRUE;
                    break;
                }
            }
            if (g_strrstr(g_strstrip(tokens[loopvar]), "MFG_NAME"))
            {
                if ((loopvar+1) < toklength )
                {
                    counter++;
                    g_string_assign(make, g_strstrip(tokens[loopvar+1]));
                }
                if (counter == 7)
                {
                    result = TRUE;
                    break;
                }
            }


        }
        g_strfreev(tokens);
    }
    if(result == FALSE)
    {
	g_message("RECEIVER_DEVICETYPE  and BUILD_VERSION  not found in %s",deviceFile);
    }

    if(error)
    {
        /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
        g_clear_error(&error);
    }

    //diagid=1000;
    return result;
}

int xPKI_check_rfc()
{
#ifdef ENABLE_RFC
    RFC_ParamData_t param = {0};
    errno_t rc       = -1;
    int     ind      = -1;
    WDMP_STATUS status = getRFCParameter("XUPNP","Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.UPnPxPKI.Enable",&param);

    if (status == WDMP_SUCCESS)
    {
       rc = strcmp_s(param.value,sizeof(param.value),"true",&ind);
       if ((ind == 0) && (rc == EOK))
       {
           g_message("New Device xPKI rfc_enabled and xcal is running with new certs");
           return 1;
       }
       else
       {
           g_message("Running xcal-device with old certs");
       }
    }
    else
    {
       g_message("getRFCParameter Failed : %s\n", getRFCErrorString(status));
    }
#else
    g_message("Not built with RFC support.");
#endif
    return 0;
}

int check_rfc()
{
#ifdef ENABLE_RFC
    RFC_ParamData_t param = {0};

    WDMP_STATUS status = getRFCParameter("XUPNP","Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.UPnP.Refactor.Enable",&param);

    if (status == WDMP_SUCCESS)
    {
       if (!strncmp(param.value, "true", strlen("true")))
       {
           g_message("New Device Refactoring rfc_enabled");
           return 1;
       }
       else
       {
           g_message("Running older xcal");
       }
    }
    else
    {
       g_message("getRFCParameter Failed : %s\n", getRFCErrorString(status));
    }
#else
    g_message("Not built with RFC support.");
#endif
    return 0;
}

static GString *get_compatible_uis_icon(int nSize, int nDepth, const char * pszImageType, const char * pszImageExt)
{
    GString * icon = g_string_new(NULL);
    g_string_printf(icon,
                    "<icon>"
                    "<mimetype>image/%s</mimetype>"
                    "<width>%d</width>"
                    "<height>%d</height>"
                    "<depth>%d</depth> <url>http://syndeo.xcal.tv/app/x2rui/dlna/%s/%s_%d.%s</url>"
                    "</icon>",
                    pszImageType,
                    nSize,
                    nSize,
                    nDepth,
                    getPartnerName(),
                    getProductName(),
                    nSize,
                    pszImageExt
                   );

    return icon;
}

static GString *get_compatible_uis_icon_list()
{
    GString * icon1 = get_compatible_uis_icon( 48, 32,  "png", "png");
    GString * icon2 = get_compatible_uis_icon(120, 32,  "png", "png");
    GString * icon3 = get_compatible_uis_icon( 48, 32, "jpeg", "jpg");
    GString * icon4 = get_compatible_uis_icon(120, 32, "jpeg", "jpg");

    GString * iconList = g_string_new(NULL);
    g_string_printf(iconList,
                    "<iconList>"
                    "%s"
                    "%s"
                    "%s"
                    "%s"
                    "</iconList>",
                    icon1->str,
                    icon2->str,
                    icon3->str,
                    icon4->str
                   );

    g_string_free(icon1, TRUE);
    g_string_free(icon2, TRUE);
    g_string_free(icon3, TRUE);
    g_string_free(icon4, TRUE);

    return iconList;
}

/**
 * @brief Supporting function for checking the content of given string is numeric or not.
 *
 * @param[in] str String for which the contents need to be verified.
 *
 * @return Returns TRUE if successfully checks the string is numeric else returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
gboolean is_num(const gchar *str)
{

    unsigned int i=0;
    gboolean isnum = TRUE;
    for (i = 0; i < strlen(str); i++) {
        if (!g_ascii_isdigit(str[i])) {
            isnum = FALSE;
            break;
        }
    }
    return isnum;
}

#if defined(USE_XUPNP_IARM_BUS)
/**
 * @brief This function is used to get the IP address based on IPv6 or IPv4 is enabled.
 *
 * @param[in] ifname Name of the network interface.
 * @param[out] ipAddressBuffer Character buffer to hold the IP address.
 * @param[in] ipv6Enabled Flag to check whether IPV6 is enabled
 *
 * @return Returns an integer value '1' if successfully gets the IP address else returns '0'.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
BOOL getRouteData(void)
{
    errno_t rc = -1; 
    IARM_Result_t iarmRet = IARM_RESULT_IPCCORE_FAIL;
    IARM_Bus_RouteSrvMgr_RouteData_Param_t param;
    param.status = false;//CID:28886- Initialize param
     rc = memset_s(&param, sizeof(param), 0, sizeof(param));
     ERR_CHK(rc); 
    iarmRet = IARM_Bus_Call(IARM_BUS_NM_SRV_MGR_NAME,
                  IARM_BUS_ROUTE_MGR_API_getCurrentRouteData, &param, sizeof(param));
    if (iarmRet == IARM_RESULT_SUCCESS )
    {
        if (param.status) {
            g_string_assign(dataGatewayIPaddress, param.route.routeIp);
            g_message("getRouteData: route IP for the device %s ",
                  dataGatewayIPaddress->str);
            return TRUE;
        } else {
            g_message("route data not available");
            return FALSE;
        }
    }
    else
    {
        g_message("IARM failure in getting route data");
        return FALSE;
    }
}

/**
 * @brief This fuction is used to query the existing system values from IARM System manager.
 *
 * The system values could be,
 * - Channel Map Id
 * - Plant Id
 * - DAC Id
 * - VOD server Id
 * - Time Zone
 * - Serial number of tuner, and so on.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
void getSystemValues(void)
{
    IARM_Bus_SYSMgr_GetSystemStates_Param_t param;
    IARM_Bus_Call(IARM_BUS_SYSMGR_NAME, IARM_BUS_SYSMGR_API_GetSystemStates,
                  &param, sizeof(param));
    if (param.channel_map.state == 2) {
        if (strlen(param.channel_map.payload) > 0
                && is_num(param.channel_map.payload) == TRUE) {
            channelmap_id = strtoul(param.channel_map.payload, NULL, 10);
            g_message("Channel map id available. Value %lu", channelmap_id);
        }
    }
    if (param.dac_id.state == 2) {
        if (strlen(param.dac_id.payload) > 0
                && is_num(param.dac_id.payload) == TRUE) {
            dac_id = strtoul(param.dac_id.payload, NULL, 10);
            g_message("dac id available. Value %lu", dac_id);
        }
    }
    if (param.plant_id.state == 2) {
        if (strlen(param.plant_id.payload) > 0
                && is_num(param.plant_id.payload) == TRUE) {
            plant_id = strtoul(param.plant_id.payload, NULL, 10);
            g_message("plant id available. Value %lu", plant_id);
        }
    }
    if (param.vod_ad.state == 2) {
        if (strlen(param.vod_ad.payload) > 0
                && is_num(param.vod_ad.payload) == TRUE) {
            vodserver_id = strtoul(param.vod_ad.payload, NULL, 10);
            g_message("vod ad available. Value %lu", vodserver_id);
        }
    }
    if (param.time_zone_available.state == 2) {
        if (strlen(param.time_zone_available.payload) > 0
                /*&& is_alphanum(param.time_zone_available.payload) == TRUE*/) {
            g_message("Timezone is available. Value %s",
                      param.time_zone_available.payload);
            //g_string_assign(dsgtimezone, param.time_zone_available.payload);
            mapTimeZoneToJavaFormat ((char *)param.time_zone_available.payload);
            g_message("dsgtimezone: %s", dsgtimezone->str);
            g_message("rawOffset: %d", rawOffset);
        }
    }
    if (param.dst_offset.state == 2) {
        if (strlen(param.dst_offset.payload) > 0) {
            dstOffset = atoi(param.dst_offset.payload);
        }
        dstSavings = (dstOffset * 60000);
        g_message("dstSavings: %d", dstSavings);
        if (g_strcmp0(g_strstrip(dsgtimezone->str), NULL) != 0) {
            notify_timezone();
        }
    }
    if (tune_ready != param.TuneReadyStatus.state) {
        tune_ready = param.TuneReadyStatus.state;
//        notify_value_change("PlaybackUrl", playbackurl->str);
	(*eventCallback)("PlaybackUrl", playbackurl->str);	
    }
    g_message("Tune Ready: %d\n", tune_ready);
    if (param.stb_serial_no.payload != NULL) {
        g_string_assign(serial_num, param.stb_serial_no.payload);
        g_message("Serial no: %s\n", serial_num->str);
    } else
        g_message("Serial no is NULL\n");
    /*      if (param.lan_ip.state == 1)
            g_string_assign(lan_ip, param.lan_ip.payload);
          if (param.time_zone_available.state == 1)
          {
              g_string_assign(dsgtimezone, param.time_zone_available.payload);
          }
    */
    /*   else if(propertyNames.at(i) == SYSTEM_MOCA) {
         property["value"] = param.moca.state;
         property["error"] = param.moca.error;
       }
    */
    return;
}
#endif

#if defined(USE_XUPNP_IARM_BUS)
/**
 * @brief This function is used to get the IP address based on IPv6 or IPv4 is enabled.
 *
 * @param[in] ifname Name of the network interface.
 * @param[out] ipAddressBuffer Character buffer to hold the IP address.
 * @param[in] ipv6Enabled Flag to check whether IPV6 is enabled
 *
 * @return Returns an integer value '1' if successfully gets the IP address else returns '0'.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
static void _sysEventHandler(const char *owner, IARM_EventId_t eventId,
                             void *data, size_t len)
{
    if (data == NULL)
	return ;
   
    /* Only handle state events */
    errno_t rc       = -1;
    int     ind      = -1;
    
    rc = strcmp_s(IARM_BUS_SYSMGR_NAME,strlen(IARM_BUS_SYSMGR_NAME),owner,&ind);
    ERR_CHK(rc); 
    
    if ((eventId != IARM_BUS_SYSMGR_EVENT_SYSTEMSTATE)
            || (ind != 0) || (rc != EOK))
    {
      return;
    }
    IARM_Bus_SYSMgr_EventData_t *sysEventData = (IARM_Bus_SYSMgr_EventData_t *)
            data;
    IARM_Bus_SYSMgr_SystemState_t stateId =
        sysEventData->data.systemStates.stateId;
    switch (stateId) {
    case IARM_BUS_SYSMGR_SYSSTATE_TUNEREADY:
	if ( sysEventData != NULL)
	{
        	if (tune_ready != sysEventData->data.systemStates.state) {
            	tune_ready = sysEventData->data.systemStates.state;
            	if (devConf->rmfCrshSupp == TRUE) {
                	if (tune_ready == TRUE) {
//                    gupnp_root_device_set_available (dev, TRUE);
                    	g_message(" Start publishing %d ", tune_ready);
                    	if (devConf->useGliDiag == FALSE) {
                        	updatesystemids();
				(*eventCallback)("SystemIds", systemids->str);
                   	}
		      (*eventCallback)("PlaybackUrl", playbackurl->str);
                } else {
//                    gupnp_root_device_set_available (dev, FALSE);
                    g_message(" Stop publishing %d ", tune_ready);
                }
            	} else {
                	if (devConf->useGliDiag == FALSE) {
                    		updatesystemids();
				(*eventCallback)("SystemIds", systemids->str);
                	}
			(*eventCallback)("PlaybackUrl", playbackurl->str);
            	}
            	g_message("Tune Ready Update Received: %d", tune_ready);
        	}
	}
        break;
    case IARM_BUS_SYSMGR_SYSSTATE_STB_SERIAL_NO:
	if(sysEventData != NULL)
	{
        	g_string_assign(serial_num, sysEventData->data.systemStates.payload);
        	g_message("Serial Number Update Received: %s", serial_num->str);
	}
        break;
    case IARM_BUS_SYSMGR_SYSSTATE_CHANNELMAP:
	if(sysEventData != NULL)
	{
        	g_message("Received channel map update");
	        if (sysEventData->data.systemStates.error) {
        	    channelmap_id = 0;
            //g_string_assign(channelmap_id, NULL);
        	} else if (sysEventData->data.systemStates.state == 2) {
            	if ((strlen(sysEventData->data.systemStates.payload) > 0) &&
                	is_num(sysEventData->data.systemStates.payload) == TRUE) {
                	channelmap_id = strtoul(sysEventData->data.systemStates.payload, NULL, 10);
                //g_string_assign(channelmap_id, sysEventData->data.systemStates.payload);
                //g_message("Received channel map id: %s", channelmap_id->str);
                	g_message("Received channel map id: %lu", channelmap_id);
                	updatesystemids();
			(*eventCallback)("SystemIds", systemids->str);
            	}
        	}
	}
        break;
    case IARM_BUS_SYSMGR_SYSSTATE_DAC_ID:
        g_message("Received controller id update");
	if(sysEventData != NULL)
	{
        	if (sysEventData->data.systemStates.error) {
            	dac_id = 0;
            //g_string_assign(dac_id, NULL);
        	} else if (sysEventData->data.systemStates.state == 2) {
            	if ((strlen(sysEventData->data.systemStates.payload) > 0) &&
                    (is_num(sysEventData->data.systemStates.payload) == TRUE)) {
                	dac_id = strtoul(sysEventData->data.systemStates.payload, NULL, 10);
                //g_string_assign(dac_id, sysEventData->data.systemStates.payload);
                //g_message("Received controller id: %s", dac_id->str);
                	g_message("Received controller id: %lu", dac_id);
                	updatesystemids();
			(*eventCallback)("SystemIds", systemids->str);
            	}
        	}
	}
        break;
    case IARM_BUS_SYSMGR_SYSSTATE_PLANT_ID:
	if( sysEventData != NULL)
	{
        	g_message("Received plant id update");
        	if (sysEventData->data.systemStates.error) {
            	plant_id = 0;
            //g_string_assign(plant_id, NULL);
        	} else if (sysEventData->data.systemStates.state == 2) {
            	if ((strlen(sysEventData->data.systemStates.payload) > 0) &&
                    is_num(sysEventData->data.systemStates.payload) == TRUE) {
                	plant_id = strtoul(sysEventData->data.systemStates.payload, NULL, 10);
                //g_string_assign(plant_id, sysEventData->data.systemStates.payload);
                //g_message("Received plant id: %s", plant_id->str);
                	g_message("Received plant id: %lu", plant_id);
                	updatesystemids();
			(*eventCallback)("SystemIds", systemids->str);
            	}
        	}
	}
        break;
    case IARM_BUS_SYSMGR_SYSSTATE_VOD_AD:
        if(sysEventData != NULL)
	{
		g_message("Received vod server id update");
        	if (sysEventData->data.systemStates.error) {
            		vodserver_id = 0;
            //g_string_assign(vodserver_id, NULL);
        	} else if (sysEventData->data.systemStates.state == 2) {
            	if ((strlen(sysEventData->data.systemStates.payload) > 0) &&
                    is_num(sysEventData->data.systemStates.payload) == TRUE) {
                	vodserver_id = strtoul(sysEventData->data.systemStates.payload, NULL, 10);
                //g_string_assign(vodserver_id, sysEventData->data.systemStates.payload);
                //g_message("Received vod server id: %s", vodserver_id->str);
                	g_message("Received vod server id: %lu", vodserver_id);
                	updatesystemids();
			(*eventCallback)("SystemIds", systemids->str);
            	}
        	}
	}
        break;
    case IARM_BUS_SYSMGR_SYSSTATE_TIME_ZONE:
	if(sysEventData != NULL)
	{
        	g_message("Received timezone update");
        	if (sysEventData->data.systemStates.error) {
//          g_string_assign(dsgtimezone, NULL);
            	g_message("Time zone error");
        	} else if (sysEventData->data.systemStates.state == 2) {
            	if ((strlen(sysEventData->data.systemStates.payload) > 1)) /*&&
                                      is_alphanum(sysEventData->data.systemStates.payload) == TRUE)*/
            	{
                //If in DST then the TZ string will contain , and . so is alpha num checking will fail
                	mapTimeZoneToJavaFormat ((char *)sysEventData->data.systemStates.payload);
                //g_string_assign(dsgtimezone, sysEventData->data.systemStates.payload);
                	g_message("Received dsgtimezone: %s", dsgtimezone->str);
                	g_message("Received rawOffset: %d", rawOffset);
            	}
        	}
	}
        break;
    case   IARM_BUS_SYSMGR_SYSSTATE_DST_OFFSET :
	if( sysEventData != NULL)
	{
        	if (sysEventData->data.systemStates.error) {
            		g_message("dst offset error ");
        	} else if (sysEventData->data.systemStates.state == 2) {
            		dstOffset = atoi(sysEventData->data.systemStates.payload);
            		dstSavings = (dstOffset * 60000);
            		g_message("Received dstSavings: %d", dstSavings);
            	if (g_strcmp0(g_strstrip(dsgtimezone->str), NULL) != 0) {
                	notify_timezone();
            	}
        	}
	}
        break;
        /*    case IARM_BUS_SYSMGR_SYSSTATE_LAN_IP:
                if (sysEventData->data.systemStates.error)
                {
                  g_string_assign(lan_ip, NULL);
                }
                else if (sysEventData->data.systemStates.state == 1)
                {
                  g_string_assign(lan_ip, sysEventData->data.systemStates.payload);
                }
                break;
            case IARM_BUS_SYSMGR_SYSSTATE_MOCA:
                setPropertyFunc(SYSTEM_MOCA, state, sysEventData->data.systemStates.error);
                break;*/
    default:
        break;
    }
}

/**
 * @brief This function is used to get the system modes (EAS, NORMAL and WAREHOUSE)
 *
 * @param[in] arg Pointer variable of void.
 *
 * @retval IARM_RESULT_SUCCESS By default it return success.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
IARM_Result_t _SysModeChange(void *arg)
{
    IARM_Bus_CommonAPI_SysModeChange_Param_t *param =
        (IARM_Bus_CommonAPI_SysModeChange_Param_t *)arg;
    g_message("Sys Mode Change::New mode --> %d, Old mode --> %d\n",
              param->newMode, param->oldMode);
    sysModeParam = param->newMode;
    return IARM_RESULT_SUCCESS;
}
static void _routesysEventHandler(const char *owner, IARM_EventId_t eventId,
                                  void *data, size_t len)
{
     errno_t rc = -1;  
     int ind = -1; 
     rc = strcmp_s(IARM_BUS_NM_SRV_MGR_NAME,strlen(IARM_BUS_NM_SRV_MGR_NAME),owner,&ind);
     ERR_CHK(rc);
     if ((!ind) && (rc == EOK))
     {
        switch (eventId) {
        case IARM_BUS_NETWORK_MANAGER_EVENT_ROUTE_DATA: {
            routeEventData_t *param = (routeEventData_t *)data;
            if (param->routeIp) {
                if (g_strcmp0(g_strstrip(param->routeIp), dataGatewayIPaddress->str) != 0) {
                    g_string_assign(dataGatewayIPaddress, param->routeIp);
                    g_message("route IP for the device %s ", dataGatewayIPaddress->str);
		    (*eventCallback)("DataGatewayIPaddress",dataGatewayIPaddress->str);
                } else
                    g_message("same route is send %s  %s ", param->routeIp,
                              dataGatewayIPaddress->str);
            } else
                g_message(" route ip is empty");
        }
        break;
        default:
            break;
        }
    }
}
/**
 * @brief Initialize the IARM Bus from UPnP, connecting to the IARM Bus, registering system events,
 * listing system event states and registering system mode changes.
 *
 * @return TRUE if the IARM initializer is successful else returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
BOOL XUPnP_IARM_Init(void)
{
    g_message("<<<<< Iniializing IARM XUPnP >>>>>>>>");
    if (IARM_RESULT_SUCCESS != IARM_Bus_Init(_IARM_XDEVICE_NAME)) {
        g_message("<<<<<<<%s - Failed in IARM Bus IARM_Bus_Init>>>>>>>>",
                  __FUNCTION__);
        return FALSE;
    } else if (IARM_RESULT_SUCCESS != IARM_Bus_Connect()) {
        g_message("<<<<<<<%s Failed in  IARM_Bus_Connect>>>>>>>>", __FUNCTION__);
        return FALSE;
    } else {
        IARM_Bus_RegisterEventHandler(IARM_BUS_SYSMGR_NAME,
                                      IARM_BUS_SYSMGR_EVENT_SYSTEMSTATE, _sysEventHandler);
        IARM_Bus_RegisterEventHandler(IARM_BUS_NM_SRV_MGR_NAME,
                                      IARM_BUS_NETWORK_MANAGER_EVENT_ROUTE_DATA, _routesysEventHandler);
        g_message("<<<<<<<%s - Registered the SYSMGR BUS Events >>>>>>>>",
                  __FUNCTION__);
        IARM_Bus_RegisterCall(IARM_BUS_COMMON_API_SysModeChange, _SysModeChange);
       g_message("<<<<<<<%s - Registering Callback for Warehouse Mode Check >>>>>>>>",
                  __FUNCTION__);
        return TRUE;
    }
}
#endif


/**
 * @brief This function is used to get the IP address based on IPv6 or IPv4 is enabled.
 *
 * @param[in] ifname Name of the network interface.
 * @param[out] ipAddressBuffer Character buffer to hold the IP address.
 * @param[in] ipv6Enabled Flag to check whether IPV6 is enabled
 *
 * @return Returns an integer value '1' if successfully gets the IP address else returns '0'.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
BOOL check_empty(char *str)
{
    if (str[0]) {
        return TRUE;
    }
    return FALSE;
}

BOOL check_null(char *str)
{
    if (str) {
        return TRUE;
    }
    return FALSE;
}
/**
 * @brief This function is used to get the IP address based on IPv6 or IPv4 is enabled.
 *
 * @param[in] ifname Name of the network interface.
 * @param[out] ipAddressBuffer Character buffer to hold the IP address.
 * @param[in] ipv6Enabled Flag to check whether IPV6 is enabled
 *
 * @return Returns an integer value '1' if successfully gets the IP address else returns '0'.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
BOOL getBaseUrl(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc       = -1;
    if ((!check_null(gwyip->str)) || (!check_null(outValue)) || (!check_null(recv_id->str))) {
	g_message("getBaseUrl : NULL string !");
        return result;
    }
    if (check_empty(gwyip->str) && check_empty(recv_id->str)) {
        g_string_printf(url, "http://%s:8080/videoStreamInit?recorderId=%s",
                        gwyip->str, recv_id->str);
        g_print ("The url is now %s.\n", url->str);
	rc =  strcpy_s(outValue,MAX_OUTVALUE,url->str);
        if(rc == EOK)
        {
            result = TRUE;
        }
        else
        {
            ERR_CHK(rc);
        }
    }
    return result;
}
BOOL getPlaybackUrl(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc       = -1;
    if (!check_null(playbackurl->str)){
	g_message("getPlaybackUrl:  NULL string !");
	return result;
    }
    if (check_empty(playbackurl->str))
    {
	rc =  strcpy_s(outValue,URLSIZE, playbackurl->str);
        if(rc == EOK)
        {
            result = TRUE;
        }
        else
        {
            ERR_CHK(rc);
        }
    }
    return result;
}
BOOL getTuneReady()
{
    return tune_ready;
}

BOOL getDisableTuneReadyStatus()
{
    return devConf->disableTuneReady;
}
/**
 * @brief This function is used to get the IP address based on IPv6 or IPv4 is enabled.
 *
 * @param[in] ifname Name of the network interface.
 * @param[out] ipAddressBuffer Character buffer to hold the IP address.
 * @param[in] ipv6Enabled Flag to check whether IPV6 is enabled
 *
 * @return Returns an integer value '1' if successfully gets the IP address else returns '0'.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
BOOL getIpv6Prefix(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc       = -1;
    if  (!check_null(outValue)) {
        g_message("getIpv6Prefix : NULL string !");
        return result;
    }
    if ((parseipv6prefix()) || ((ipv6prefix->str != NULL) && (ipv6prefix->str[0] == '\0'))) {
      rc = strcpy_s(outValue,MAX_OUTVALUE,ipv6prefix->str);
      if(rc == EOK)
      {
          result = TRUE;
      }
      else
      {
          ERR_CHK(rc);
      }
    } else {
        g_message("getIpv6Prefix : No ipv6 prefix  !");
    }
    return result;
}

BOOL getIpSubnet(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc = -1;
    if (!check_null(outValue)) {
        g_message("getIpSubnet : NULL string !");
        return result;
    }
    rc = strcpy_s(outValue,MAX_OUTVALUE, "");
    if(rc == EOK)
    {
        result = TRUE;
    }
    else
    {
        ERR_CHK(rc);
    }
    return result;
}


/**
 * @brief This function is used to get the IP address based on IPv6 or IPv4 is enabled.
 *
 * @param[in] ifname Name of the network interface.
 * @param[out] ipAddressBuffer Character buffer to hold the IP address.
 * @param[in] ipv6Enabled Flag to check whether IPV6 is enabled
 *
 * @return Returns an integer value '1' if successfully gets the IP address else returns '0'.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
BOOL getDeviceName(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc       = -1;
    if (!check_null(outValue)) {
        g_message("getDeviceName : NULL string !");
        return result;
    }
    if (parsedevicename()) {
        rc = strcpy_s(outValue,MAX_OUTVALUE,devicename->str);
        if(rc == EOK)
        {
            result = TRUE;
        }
        else
        {
            ERR_CHK(rc);
        }
    } else {
        g_message("getDeviceName : No Device Name !");
    }
    return result;
}
/**
 * @brief This function is used to get the IP address based on IPv6 or IPv4 is enabled.
 *
 * @param[in] ifname Name of the network interface.
 * @param[out] ipAddressBuffer Character buffer to hold the IP address.
 * @param[in] ipv6Enabled Flag to check whether IPV6 is enabled
 *
 * @return Returns an integer value '1' if successfully gets the IP address else returns '0'.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
BOOL getDeviceType(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc       = -1; 
    if ((!check_null(devicetype->str)) || (!check_null(outValue))) {
        g_message("getDeviceType : NULL string !");
        return result;
    }
    if (check_empty(devicetype->str)) {
         rc = strcpy_s(outValue,MAX_OUTVALUE,devicetype->str);
         if(rc == EOK)
         {
             result = TRUE;
         }
         else
         {
             ERR_CHK(rc);
         }
    } else {
	g_message("getDeviceType : No device type availabel\n");
    }
    return result;
}
/**
 * @brief This function is used to get the IP address based on IPv6 or IPv4 is enabled.
 *
 * @param[in] ifname Name of the network interface.
 * @param[out] ipAddressBuffer Character buffer to hold the IP address.
 * @param[in] ipv6Enabled Flag to check whether IPV6 is enabled
 *
 * @return Returns an integer value '1' if successfully gets the IP address else returns '0'.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
BOOL getBcastMacAddress(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc       = -1;
    if (!check_null(outValue)) {
        g_message("getBcastMacAddress : NULL string !");
        return result;
    }
    if (devConf->bcastIf != NULL ) {
        const gchar *bcastmac = (gchar *)getmacaddress(devConf->bcastIf);
        if (bcastmac) {
            g_message("Broadcast MAC address in  interface: %s  %s \n", devConf->bcastIf,
                      bcastmac);
        } else {
            g_message("failed to retrieve macaddress on interface %s ", devConf->bcastIf);
            return result;
        }
        g_string_assign(bcastmacaddress, bcastmac);
        g_message("bcast mac address is %s", bcastmacaddress->str);
        rc = strcpy_s(outValue,MAX_OUTVALUE,bcastmacaddress->str);
        if(rc == EOK)
        {
            result = TRUE;
        }
        else
        {
            ERR_CHK(rc);
        }
    } else {
	g_message("getBcastMacAddress : Could not get BcastMacaddress\n");
    }
    return result;

}
/**
 * @brief This function is used to get the IP address based on IPv6 or IPv4 is enabled.
 *
 * @param[in] ifname Name of the network interface.
 * @param[out] ipAddressBuffer Character buffer to hold the IP address.
 * @param[in] ipv6Enabled Flag to check whether IPV6 is enabled
 *
 * @return Returns an integer value '1' if successfully gets the IP address else returns '0'.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
BOOL getGatewayStbIp(char *outValue)
{
    BOOL result = FALSE;
    if ((!check_null(gwystbip->str)) || (!check_null(outValue))) {
        g_message("getGatewayStbIp : NULL string !");
        return result;
    }
#ifndef CLIENT_XCAL_SERVER
    errno_t rc       = -1;
    if (check_empty(gwystbip->str)) {
        rc = strcpy_s(outValue,MAX_OUTVALUE,gwystbip->str);
        if(rc == EOK)
        {
            result = TRUE;
        }
        else
        {
            ERR_CHK(rc);
        }
    } else {
	g_message("getGatewayStbIp : Could not get gatewayStbIp\n");
    }
#endif
    return result;
}
/**
 * @brief This function is used to get the IP address based on IPv6 or IPv4 is enabled.
 *
 * @param[in] ifname Name of the network interface.
 * @param[out] ipAddressBuffer Character buffer to hold the IP address.
 * @param[in] ipv6Enabled Flag to check whether IPV6 is enabled
 *
 * @return Returns an integer value '1' if successfully gets the IP address else returns '0'.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
BOOL getGatewayIpv6(char *outValue)
{
    BOOL result = FALSE;
    if ((!check_null(gwyipv6->str)) || (!check_null(outValue))) {
        g_message("getGatewayIpv6 : NULL string !");
        return result;
    }
#ifndef CLIENT_XCAL_SERVER
    errno_t rc       = -1;
    if (check_empty(gwyipv6->str)) {
         rc = strcpy_s(outValue,MAX_OUTVALUE,gwyipv6->str);
         if(rc == EOK)
         {
             result = TRUE;
         }
         else
         {
             ERR_CHK(rc);
         }
    } else {
	g_message("getGatewayIpv6 : Could not get GatewayIpv6\n");
    }
#endif
    return result;
}
/**
 * @brief This function is used to get the IP address based on IPv6 or IPv4 is enabled.
 *
 * @param[in] ifname Name of the network interface.
 * @param[out] ipAddressBuffer Character buffer to hold the IP address.
 * @param[in] ipv6Enabled Flag to check whether IPV6 is enabled
 *
 * @return Returns an integer value '1' if successfully gets the IP address else returns '0'.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
BOOL getGatewayIp(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc       = -1;
    if ((!check_null(gwyip->str)) || (!check_null(outValue))) {
        g_message("getGatewayIp : NULL string !");
        return result;
    }
    if (check_empty(gwyip->str)) {
        rc = strcpy_s(outValue,MAX_OUTVALUE,gwyip->str);
        if(rc == EOK)
        {
            result = TRUE;
        }
        else
        {
            ERR_CHK(rc);
        }
    } else {
	g_message("getGatewayIp : Could not get gatewayIp\n");
    }
    return result;
}
/**
 * @brief This function is used to get the IP address based on IPv6 or IPv4 is enabled.
 *
 * @param[in] ifname Name of the network interface.
 * @param[out] ipAddressBuffer Character buffer to hold the IP address.
 * @param[in] ipv6Enabled Flag to check whether IPV6 is enabled
 *
 * @return Returns an integer value '1' if successfully gets the IP address else returns '0'.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
BOOL getRecvDevType(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc = -1;
    if ((!check_null(recvdevtype->str)) || (!check_null(outValue))) {
        g_message("getRecvDevType : NULL string !");
        return result;
    }
    if (check_empty(recvdevtype->str)) {

         rc = strcpy_s(outValue,MAX_OUTVALUE,recvdevtype->str);
         if(rc == EOK)
         {
             result = TRUE;
         }
         else
         {
             ERR_CHK(rc);
         }
    } else {
	g_message("getRecvDevType : Could not get receiver DeciveType\n");
    }
    return result;
}
BOOL getBuildVersion(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc       = -1;
    if ((!check_null(buildversion->str)) || (!check_null(outValue))) {
        g_message("getBuildVersion : NULL string !");
        return result;
    }
    if (check_empty(buildversion->str)) {
        rc = strcpy_s(outValue,MAX_OUTVALUE,buildversion->str);
        if(rc == EOK)
        {
            result = TRUE;
        }
        else
        {
            ERR_CHK(rc);
        }
    } else {
	g_message("getBuildVersion : Could not get Build Version\n");
    }
    return result;
}
BOOL getHostMacAddress(char *outValue)
{
    BOOL result = FALSE;
    if (!(check_null(hostmacaddress->str)) || (!check_null(outValue))) {
        g_message("getHostMacAddress : NULL string !");
        return result;
    }
#ifndef CLIENT_XCAL_SERVER
    errno_t rc = -1;
    if (devConf->hostMacIf != NULL) {
        const gchar *hostmac = (gchar *)getmacaddress(devConf->hostMacIf);
        if (hostmac) {
            g_message("MAC address in  interface: %s  %s \n", devConf->hostMacIf, hostmac);
        } else {
            g_message("failed to retrieve macaddress on interface %s ",
                      devConf->hostMacIf);
        }
        g_string_assign(hostmacaddress, hostmac);
        g_message("Host mac address is %s", hostmacaddress->str);
        rc = strcpy_s(outValue,MAX_OUTVALUE,hostmacaddress->str);
        if(rc == EOK)
        {
            result = TRUE;
        }
        else
        {
            ERR_CHK(rc);
        }
    } else {
	g_message("getHostMacAddress : Could not get host mac address\n");
    }
#endif
    return result;
}
BOOL getDnsConfig(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc       = -1;
    if (!check_null(outValue)) {
        g_message("getDnsConfig : NULL string !");
        return result;
    }
    if (parsednsconfig()) {
      rc = strcpy_s(outValue,MAX_OUTVALUE,dnsconfig->str);
      if(rc == EOK)
      {
          result = TRUE;
      }
      else
      {
          ERR_CHK(rc);
      }
    } else {
        g_message("getDnsConfig : no dns config !");
    }
    return result;
}
BOOL getSystemsIds(char *outValue)
{
    errno_t rc       = -1;
    BOOL result = FALSE;
    if ((!check_null(systemids->str)) || (!check_null(outValue))) {
        g_message("getSystemsIds : NULL string !");
        return result;
    }
    if (check_empty(systemids->str)) {
	if(updatesystemids()) {
             rc = strcpy_s(outValue,MAX_OUTVALUE, systemids->str);
             if(rc == EOK)
             {
                 result = TRUE;
             }
             else
             {
                 ERR_CHK(rc);
             }
	}
	else
	{
	    result = FALSE;
	}
    } else {
	g_message("getSystemsIds : No systemIds \n");
    }
    return result;
}
gboolean gettimezone(void)
{
    GError                  *error=NULL;
    gboolean                result = FALSE;
    gchar* dsgproxyfile = NULL;

    if (devConf->dsgFile == NULL)
    {
        g_warning("dsg file name not found in config");
        return result;
    }
    result = g_file_get_contents (devConf->dsgFile, &dsgproxyfile, NULL, &error);
    if (result == FALSE && error != NULL) {
        g_warning("Problem in reading dsgproxyfile file %s", error->message);
    }
    else
    {
        /* reset result = FALSE to identify timezone from dsgproxyfile contents */
        result = FALSE;
        gchar **tokens = g_strsplit_set(dsgproxyfile,",=", -1);
        guint toklength = g_strv_length(tokens);
        guint loopvar=0;
        for (loopvar=0; loopvar<toklength; loopvar++)
        {
            //g_print("Token is %s\n",g_strstrip(tokens[loopvar]));
            if (g_strrstr(g_strstrip(tokens[loopvar]), "DSGPROXY_HOST_TIME_ZONE"))
            {
                if ((loopvar+1) < toklength )
                {
                    g_string_assign(dsgtimezone, g_strstrip(tokens[loopvar+1]));
                }
                result = TRUE;
                break;
            }
        }
        g_strfreev(tokens);
    }

    //diagid=1000;

    if(error)
    {
        /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
        g_clear_error(&error);
    }

    return result;
}

BOOL getTimeZone(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc       = -1;
    if ((!check_null(dsgtimezone->str)) || (!check_null(outValue))) {
        g_message("getTimeZone : NULL string !");
        return result;
    }
    if (check_empty(dsgtimezone->str)) {
        rc = strcpy_s(outValue,MAX_OUTVALUE,dsgtimezone->str);
        if(rc == EOK)
        {
            result = TRUE;
        }
        else
        {
            ERR_CHK(rc);
        }
    } else {
	g_message("getTimeZone : No Timezone data\n");
    }
    return result;
}
BOOL getRawOffSet(int *outValue)
{
    *outValue = rawOffset;
    return TRUE;
}
BOOL getDstOffset(int *outValue)
{
    *outValue = dstOffset;
    return TRUE;
}
BOOL getDstSavings(int *outValue)
{
    *outValue = dstSavings;
    return TRUE;
}
BOOL getUsesDayLightTime(BOOL *outValue)
{
    *outValue = usesDaylightTime;
    return TRUE;
}
BOOL getIsGateway(BOOL *outValue)
{
    *outValue = devConf->allowGwy;
    return TRUE;
}
BOOL getHosts(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc = -1;
    if (!check_null(outValue)) {
        g_message("getHosts : NULL string !");
        return result;
    }
    if (getetchosts()) {
       rc = strcpy_s(outValue,RUIURLSIZE,etchosts->str);
       if(rc == EOK)
       {
           result = TRUE;
       }
       else
       {
           ERR_CHK(rc);
       }
    } else {
        g_message("getHosts : No Hosts Data available !");
    }
    return result;
}
BOOL getRequiresTRM(BOOL *outValue)
{
    *outValue = requirestrm;
    return TRUE;
}
BOOL getBcastPort(int *outValue)
{
    *outValue = devConf->bcastPort;
    return TRUE;
}
BOOL getBcastIp(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc = -1;
    if ((!check_null(gwyip->str)) || (!check_null(outValue))) {
        g_message("getBcastIp : NULL string !");
        return result;
    }
    if (check_empty(gwyip->str)) {
       rc = strcpy_s(outValue,MAX_OUTVALUE,gwyip->str);
       if(rc == EOK)
       {
           result = TRUE;
       }
       else
       {
           ERR_CHK(rc);
       }
    } else {
	g_message("getBcastIp : No BcastIp found\n");
    }
    return result;
}
BOOL getBcastIf(char *outValue)
{
    errno_t rc = -1;
    BOOL result = FALSE;
    if (!check_null(outValue)) {
	g_message("getBcastIf : NULL string !");
	return result;
    }
    if(check_null(devConf->bcastIf)) {
	rc = strcpy_s(outValue,MAX_OUTVALUE,devConf->bcastIf);
        if(rc == EOK)
        {
            result = TRUE;
        }
        else
        {
            ERR_CHK(rc);
        }
    }
    else
	g_message("getBcastIf : No Bcast Interface found !");
    return result;
}
BOOL getRUIUrl(char *outValue)
{
    errno_t rc       = -1;
    if (!check_null(outValue)) {
        g_message("getPartnerId : NULL string !");
        return FALSE;
    }
    if ( ruiurl->str != NULL ) {   //previous string needs to be freed
        g_string_free( ruiurl, TRUE);//TRUE means free str allocation too
    }
    if (devConf->ruiPath != NULL) { //use config file string if present
        g_print("getruiurl using xdevice.conf RuiPath=value\n");
        ruiurl = g_string_new(g_strconcat(devConf->ruiPath, NULL));
    } else {                      //otherwise, create with actual values
        GString *urivalue = get_uri_value();
        GString *iconlist = get_compatible_uis_icon_list();
        //create rui url string, needs to be freed with g_free()
        ruiurl = g_string_new(NULL);
        g_string_printf(ruiurl,
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                        "<uilist xmlns=\"urn:schemas-upnp-org:remoteui:uilist-1-0\" "
                        "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"urn:schemas-upnp-org:remoteui:uilist-1-0 CompatibleUIs.xsd\">"
                        "<ui>"
                        "<uiID>1234-9876-1265-8758</uiID>"
                        "<name>%s</name>"               //"<name>Comcast XFINITY Guide</name>"
                        "<description>%s</description>" //"<description>Comcast XFINITY Guide application</description>"
                        "%s"
                        "<fork>true</fork>"
                        "<lifetime>-1</lifetime>"
                        "<protocol shortName=\"DLNA-HTML5-1.0\">"
                        "<uri>"
                        "%s"
                        "</uri>"
                        "</protocol>"
                        "</ui>"
                        "</uilist>",
                        getServiceName(),
                        getServiceDescription(),
                        iconlist->str,
                        urivalue->str
                       );
        g_string_free(urivalue, TRUE);
        g_string_free(iconlist,TRUE);
    }
    rc = strcpy_s(outValue,RUIURLSIZE,ruiurl->str);
    g_print("ruiurl string from getruiurl(): = %s\n",ruiurl->str);
    if(rc == EOK)
    {
        return TRUE;
    }
    else
    {
        ERR_CHK(rc);
        return FALSE;
    }
}
BOOL getSerialNum(char *outValue)
{
     errno_t rc       = -1;
     BOOL result = FALSE;
    if (!check_null(outValue)) {
        g_message("getSerialNum : NULL string !");
        return result;
    }
    if (parseserialnum(serial_num)) {
        rc = strcpy_s(outValue,MAX_OUTVALUE,serial_num->str);
        if(rc == EOK)
        {
            result = TRUE;
        }
        else
        {
            ERR_CHK(rc);
        }
    } else {
        g_message("getSerialNum : No Serial Number Available !");
    }
    return result;
}
BOOL getPartnerId(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc = -1;
    if (!check_null(outValue)) {
        g_message("getPartnerId : NULL string !");
        return result;
    } else {
        partner_id = getID(PARTNER_ID);
        if (check_null(partner_id->str) && check_empty(partner_id->str)) {
           rc =  strcpy_s(outValue,MAX_OUTVALUE,partner_id->str);
           if(rc == EOK)
           {
               result = TRUE;
           }
           else
           {
               ERR_CHK(rc);
           }
        } else {
	    g_message("getPartnerId : No partner Id found\n");
	}
    }
    return result;
}
BOOL getUUID(char *outValue)
{
    BOOL result = FALSE;
    if (!check_null(outValue)) {
        g_message("getUUID : NULL string !");
        return result;
    }
    if (check_empty(recv_id->str)) {
	sprintf(outValue, "uuid:%s", recv_id->str);
        result = TRUE;
    }
    else
    {
	g_message("getUUID : No recv_id for uuid available\n");
    }
    return result;
}
BOOL getReceiverId(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc       = -1;
    if (!check_null(outValue)) {
        g_message("getReceiverId : NULL string !");
        return result;
    }
    recv_id = getID(RECEIVER_ID);
    if (check_null(recv_id->str) && check_empty(recv_id->str)) {
         rc = strcpy_s(outValue,MAX_OUTVALUE,recv_id->str);
         if(rc == EOK)
         {
             result = TRUE;
         }
         else
         {
            ERR_CHK(rc);
         }
    } else {
	g_message("getReceiverId : No recveiverId found\n");
    }
    return result;
}
BOOL getTrmUrl(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc       = -1;
    if (!check_null(outValue)) {
        g_message("getTrmUrl : NULL string !");
        return result;
    }
    if (check_empty(trmurl->str)) {
	rc =strcpy_s(outValue,MAX_OUTVALUE,trmurl->str);
        if(rc == EOK)
        {
            result = TRUE;
        }
        else
        {
            ERR_CHK(rc);
        }
    } else {
	g_message("getTrmUrl : No trmurl found\n");
    }
    return result;
}
BOOL getIsuseGliDiagEnabled()
{
	return devConf->useGliDiag;
}
#ifndef CLIENT_XCAL_SERVER
BOOL getCVPIp(char *outValue)
{
    errno_t rc = -1;
    if (!check_null(outValue)) {
        g_message("getCVPIp : NULL string !");
        return FALSE;
    }
    ipAddressBuffer[0] = '\0';
    int result = getipaddress(devConf->cvpIf, ipAddressBuffer, FALSE);
    if (!result) {
        fprintf(stderr, "Could not locate the ipaddress of CVP2 interface %s\n",
                devConf->cvpIf);
        return FALSE;
    }
    g_message("ipaddress of the CVP2 interface %s\n", ipAddressBuffer);
    rc = strcpy_s(outValue,MAX_OUTVALUE,ipAddressBuffer);
    if(rc == EOK)
    {
       return TRUE;
    }
    else
    {
        ERR_CHK(rc);
        return FALSE;
    }

}
BOOL getCVPIf(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc       = -1;
    if (!check_null(outValue)) {
	g_message("getCVPIf : NULL string !");
	return result;
    }
    if (check_empty(devConf->cvpIf)) {
	rc =strcpy_s(outValue,MAX_OUTVALUE,devConf->cvpIf);
        if(rc == EOK)
        {
            result = TRUE;
        }
        else
        {
            ERR_CHK(rc);
        }
    }
    else
    {
	g_message("getCVPIf : Failed to get the CVP Interface\n");
    }
    return result;
}
BOOL getCVPPort(int *outValue)
{
    BOOL result = FALSE;
    if (!check_null((char *)outValue)) {
        g_message("getCVPPort : NULL string !");
        return result;
    }
    else
    {
	*outValue = devConf->cvpPort;
	result = TRUE;
    }
    return result;	
}
BOOL getCVPXmlFile(char *outValue)
{
    errno_t rc       = -1;
    BOOL result = FALSE;
    if (!check_null(outValue)) {
        g_message("getCVPXmlFile : NULL string !");
        return result;
    }
    if (check_empty(devConf->cvpXmlFile)) {
        rc = strcpy_s(outValue,MAX_OUTVALUE,devConf->cvpXmlFile);
        if(rc == EOK)
        {
            result = TRUE;
        }
        else
        {
            ERR_CHK(rc);
        }
    }
    else
    {
        g_message("getCVPXmlFile : Failed to get the CVP XmlFile\n");
    }
    return result;
}
#endif
BOOL getRouteDataGateway(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc       = -1;
    if (!check_null(outValue)) {
        g_message("getRouteDataGateway : NULL string !");
        return result;
    }
    if (getRouteData()) {
     rc =strcpy_s(outValue,MAX_OUTVALUE,dataGatewayIPaddress->str);
     if(rc == EOK)
     {
         result = TRUE;
     }
     else
     {
         ERR_CHK(rc);
     }
    } else
        g_message("getRouteDataGateway : error getting route data!");
    return result;
}
BOOL getLogFile(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc       = -1;
    if (!check_null(outValue)) {
        g_message("getLogFile : NULL string !");
        return result;
    }
    if (check_empty(devConf->logFile)) {
        rc =  strcpy_s(outValue,MAX_OUTVALUE,devConf->logFile);
        if(rc == EOK)
        {
            result = TRUE;
        }
        else
        {
            ERR_CHK(rc);
        }
    } else
        g_message("getLogFile : Config doesnt have a log file !");
    return result;
}
BOOL getEstbMacAddr(char *outValue)
{
    BOOL result = FALSE;
#ifndef CLIENT_XCAL_SERVER
    errno_t rc       = -1;
    if ((!check_null(devConf->hostMacIf)) || (!check_null(outValue))) {
        g_message("getEstbMacAddr : NULL string !");
        return result;
    }
    if (!check_empty(hostmacaddress->str)) {
        const gchar *hostmac = (gchar *)getmacaddress(devConf->hostMacIf);
        if (hostmac) {
            g_message("MAC address in  interface: %s  %s \n", devConf->hostMacIf, hostmac);
            g_string_assign(hostmacaddress, hostmac);
            result = TRUE;
        } else {
            g_message("failed to retrieve macaddress on interface %s ",
                      devConf->hostMacIf);
            return result;
        }
    }
    rc = strcpy_s(outValue,MAX_OUTVALUE, hostmacaddress->str);
    if(rc == EOK)
    {
        result = TRUE;
    }
    else
    {
        ERR_CHK(rc);
    }
    g_message("Host mac address is %s", hostmacaddress->str);
#endif
    return result;
}
BOOL getDevXmlPath(char *outValue)
{
    BOOL result = FALSE;
     errno_t rc       = -1;
    if ((!check_null(devConf->devXmlPath)) || (!check_null(outValue))) {
        g_message("getDevXmlPath : NULL string !");
        return result;
    }
    if (check_null(devConf->devXmlPath)) {
        rc = strcpy_s(outValue,MAX_OUTVALUE,devConf->devXmlPath);
        if(rc == EOK)
        {
            result = TRUE;
        }
        else
        {
            ERR_CHK(rc);
        }
    } else
        g_message("getDevXmlPath : config has empty xml path !");
    return result;
}

BOOL getDevXmlFile(char *outValue, int refactor)
{
    BOOL result = FALSE;
    if ((!check_null(devConf->devXmlFile)) || (!check_null(outValue))) {
        g_message("getDevXmlFile : NULL string !");
        return result;
    }
    if(!refactor)
    {
        if (check_empty(devConf->devXmlFile)) {
            sprintf(outValue, "%s/%s", devConf->devXmlPath, devConf->devXmlFile);
            result = TRUE;
        } else
            g_message("getDevXmlFile : config has empty xml file !");
    }
    else
    {
#ifndef CLIENT_XCAL_SERVER
        sprintf(outValue, "%s/%s", devConf->devXmlPath,GW_DEVICE_XML_FILE);
#else
	sprintf(outValue, "%s/%s", devConf->devXmlPath,CLIENT_DEVICE_XML_FILE);
#endif
	result = TRUE;
	g_message("getDevXmlFile : refactor path=%s",outValue);
    }
    return result;
}

BOOL getDevKeyPath(char *outValue)
{
    BOOL result = FALSE;
    if ((!check_null(devConf->devKeyPath)) || (!check_null(outValue))) {
        g_message("getDevKeyPath: NULL string !");
        return result;
    }
    if (check_empty(devConf->devKeyPath)) {
          strncpy(outValue,devConf->devKeyPath, MAX_FILE_LENGTH);
          result = TRUE;
    } else
          g_message("getDevKeyPath : config has empty key path !");
    return result;
}

BOOL getDevKeyFile(char *outValue)
{
    BOOL result = FALSE;
    if ((!check_null(devConf->devKeyFile)) || (!check_null(outValue)))  {
        g_message("getDevKeyFile : NULL string !");
        return result;
    }
    if (check_empty(devConf->devKeyFile)) {
        strncpy(outValue,devConf->devKeyFile, MAX_FILE_LENGTH);
        result = TRUE;
    } else
          g_message("getDevKeyFile : config has empty key file !");
    return result;
}

BOOL getDevCertPath(char *outValue)
{
    BOOL result = FALSE;
    if ((!check_null(devConf->devCertPath)) || (!check_null(outValue))) {
        g_message("getDevCertPath: NULL string !");
        return result;
    }
    if (check_empty(devConf->devCertPath)) {
        strncpy(outValue,devConf->devCertPath, MAX_FILE_LENGTH);
        result = TRUE;
    } else
        g_message("getDevCertPath: config has empty path!");
   return result;

}

BOOL getDevCertFile(char *outValue)
{
    BOOL result = FALSE;
    if ((!check_null(devConf->devCertFile)) || (!check_null(outValue))) {
        g_message("getDevCertFile: NULL string !");
        return result;
    }
    if (check_empty(devConf->devCertFile)) {
         strncpy(outValue,devConf->devCertFile,MAX_FILE_LENGTH);
         result = TRUE;
    } else
         g_message("getDevCertFile: config has empty file !");
    return result;
}

BOOL getModelNumber(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc       = -1;
    if ((!check_null(modelnumber->str)) || (!check_null(outValue))) {
        g_message("getModelNumber : NULL string !");
        return result;
    }
    if (check_empty(modelnumber->str)) {
        rc = strcpy_s(outValue,MAX_OUTVALUE,modelnumber->str);
        if(rc == EOK)
        {
            result = TRUE;
        }
        else
        {
            ERR_CHK(rc);
        }
	g_message("getModelNumber : %s",modelnumber->str);
        
    } else
        g_message("getModelNumber : config has empty modelnumber file !");
    return result;
}

BOOL getMake(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc       = -1;
    if ((!check_null(make->str)) || (!check_null(outValue))) {
        g_message("getMake : NULL string !");
        return result;
    }
    if (check_empty(make->str)) {
        rc = strcpy_s(outValue,MAX_OUTVALUE,make->str);
        if(rc == EOK)
        {
            result = TRUE;
        }
        else
        {
            ERR_CHK(rc);
        }
    } else
        g_message("getMake : config has empty device make file !");
    return result;
}
BOOL getAccountId(char *outValue)
{
    BOOL result = FALSE;
    errno_t rc = -1;
    
#ifdef ENABLE_RFC
    RFC_ParamData_t param = {0};

    WDMP_STATUS status = getRFCParameter("XUPNP","Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AccountInfo.AccountID",&param);

    if (status == WDMP_SUCCESS)
    {
	if ((!check_null(param.value)))
	{
	    g_message("getAccountId : NULL string !");
	    return result;
	}
	else
	{
            rc = strcpy_s(outValue,MAX_OUTVALUE,param.value);
            if(rc == EOK)
            {
                result = TRUE;
            }
            else
            {
                ERR_CHK(rc);
            }
	}
    }
    else
    {
       g_message("getAccountId: getRFCParameter Failed : %s\n", getRFCErrorString(status));
    }
#else
    g_message("Not built with RFC support.");
#endif
    return result;
}

BOOL checkCVP2Enabled()
{
    return devConf->enableCVP2;
}

/**
 * @brief Supporting function for checking the given string is alphanumeric.
 *
 * @param[in] str String to be verified.
 *
 * @return Returns TRUE if successfully checks the string is alphanumeric else returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
gboolean is_alphanum(const gchar *str)
{

    unsigned int i=0;
    gboolean isalphanum = TRUE;
    for (i = 0; i < strlen(str); i++) {
        if (!g_ascii_isalnum(str[i])) {
            isalphanum = FALSE;
            break;
        }
    }
    return isalphanum;
}

/**
 * @brief This function is used to retrieve the IPv6 prefix information from dibblers file.
 *
 * @return Returns TRUE if successfully gets the ipv6 prefix value else returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
gboolean getipv6prefix(void)
{
    GError                  *error=NULL;
    gboolean                result = FALSE;
    gchar* prefixfile = NULL;
    guint loopvar=0;
    guint prefixloopvar=0;
    gboolean ifacematch = FALSE;
    gboolean prefixmatch = FALSE;
    gchar **prefixtokens;
    if (devConf->ipv6PrefixFile == NULL)
    {
        g_warning("ipv6PrefixFile file name not found in config");
        return result;
    }
    result = g_file_get_contents (devConf->ipv6PrefixFile, &prefixfile, NULL, &error);
    if (result == FALSE && error != NULL) {
        g_warning("Problem in reading /prefix/prefix file %s", error->message);
    }
    else
    {
        gchar **tokens = g_strsplit_set(prefixfile,"'\n''\0'", -1);
        guint toklength = g_strv_length(tokens);

        while(loopvar < toklength)
        {
            if(ifacematch==FALSE)
            {
                if ((g_strrstr(g_strstrip(tokens[loopvar]), "ifacename")) && (g_strrstr(g_strstrip(tokens[loopvar]), devConf->hostMacIf)))
                {
                    ifacematch=TRUE;
                }
            }
            else
            {
                if(g_strrstr(g_strstrip(tokens[loopvar]), "AddrPrefix"))
                {
                    prefixtokens = g_strsplit_set(tokens[loopvar],"'<''>''='", -1);
                    guint prefixtoklength = g_strv_length(prefixtokens);
                    while(prefixloopvar<prefixtoklength)
                    {
                        if(g_strrstr(g_strstrip(prefixtokens[prefixloopvar]), "/AddrPrefix"))
                        {

                            prefixmatch=TRUE;
                            result=TRUE;
                            g_string_printf(ipv6prefix,"%s",prefixtokens[prefixloopvar-1]);
                            g_message("ipv6 prefix format in the file %s",prefixtokens[prefixloopvar-1]);
                            break;
                        }
                        prefixloopvar++;
                    }
                    g_strfreev(prefixtokens);
                }
                if(prefixmatch == TRUE)
                    break;
            }
            loopvar++;

        }
        g_strfreev(tokens);
        if(prefixmatch == FALSE)
        {
            result=FALSE;
            g_message("No Matching ipv6 prefix in file %s",prefixfile);
        }
    }
    if(error)
    {
        /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
        g_clear_error(&error);
    }
    g_free(prefixfile);
    return result;
}

BOOL xdeviceInit(char *devConfFile, char *devLogFile)
{
    url = g_string_new(NULL);
    trmurl = g_string_new(NULL);
    trmurlCVP2 = g_string_new(NULL);
    playbackurl = g_string_new(NULL);
    playbackurlCVP2 = g_string_new(NULL);
    gwyip = g_string_new(NULL);
    gwyipv6 = g_string_new(NULL);
    gwystbip = g_string_new(NULL);
    ipv6prefix = g_string_new(NULL);
    gwyipCVP2 = g_string_new(NULL);
    dnsconfig = g_string_new(NULL);
    systemids = g_string_new(NULL);
    dsgtimezone = g_string_new(NULL);
    etchosts = g_string_new(NULL);
    serial_num = g_string_new(NULL);
    channelmap_id = dac_id = plant_id = vodserver_id = 0;
    isgateway = TRUE;
    requirestrm = TRUE;
    service_ready = FALSE;
    tune_ready = FALSE;
    ruiurl = g_string_new(NULL);
    inDevProfile = g_string_new(NULL);
    uiFilter = g_string_new(NULL);
    recv_id = g_string_new(NULL);
    partner_id = g_string_new(NULL);
    hostmacaddress = g_string_new(NULL);
    bcastmacaddress = g_string_new(NULL);
    devicename = g_string_new(NULL);
    buildversion = g_string_new(NULL);
    recvdevtype = g_string_new(NULL);
    devicetype = g_string_new(NULL);
#if !defined (NO_MOCA_FEATURE_SUPPORT)
    mocaIface = g_string_new(NULL);
#endif
    wifiIface = g_string_new(NULL);
    modelnumber = g_string_new(NULL);
    make = g_string_new(NULL);
    accountid = g_string_new(NULL);
    dataGatewayIPaddress = g_string_new(NULL);

    dstOffset=1; //dstoffset can be only 0 or 60 so intializing with 1.

    if (! check_null(devConfFile)) {
#ifndef CLIENT_XCAL_SERVER
        g_message("No Configuration file please use /usr/bin/xcal-device /etc/xdevice.conf");
        exit(1);
#endif
    }
#ifndef CLIENT_XCAL_SERVER
    if(readconffile(devConfFile)==FALSE)
    {
	g_message("Unable to find xdevice config, giving up\n");
	exit(1);
    }

#else
    devConf = g_new0(ConfSettings, 1);
#endif
#ifdef CLIENT_XCAL_SERVER
    devConf->bcastPort = 0;
    if (! (devConf->bcastPort))
        devConf->bcastPort = BCAST_PORT;
    if (! (devConf->devPropertyFile))
        devConf->devPropertyFile = g_strdup(DEVICE_PROPERTY_FILE);
    if (! (devConf->deviceNameFile))
        devConf->deviceNameFile = g_strdup(DEVICE_NAME_FILE);
    if (! (devConf->logFile))
        devConf->logFile = g_strdup(LOG_FILE);
    if (! (devConf->devXmlPath))
        devConf->devXmlPath = g_strdup(DEVICE_XML_PATH);
    if (! (devConf->devXmlFile))
        devConf->devXmlFile = g_strdup(DEVICE_XML_FILE);
    if (! (devConf->devKeyFile ))
        devConf->devKeyFile  = g_strdup(DEVICE_KEY_FILE); 
    if (! (devConf->devKeyPath ))
        devConf->devKeyPath  = g_strdup(DEVICE_KEY_PATH); 
    if (! (devConf->devCertFile ))
        devConf->devCertFile = g_strdup(DEVICE_CERT_FILE); 
    if (! (devConf->devCertPath))
        devConf->devCertPath = g_strdup(DEVICE_CERT_PATH); 
    devConf->allowGwy = FALSE;
    devConf->useIARM = TRUE;
    devConf->useGliDiag=TRUE;
#endif
    if (check_null(devLogFile)) {
        logoutfile = g_fopen (devLogFile, "a");
    }
#ifdef ENABLE_LOGFILE
    else if (devConf->logFile) {
        logoutfile = g_fopen (devConf->logFile, "a");
    }
#endif
    else {
        g_message("xupnp not handling the logging");
    }
    if (devConf->devPropertyFile != NULL) {
        if (readDevFile(devConf->devPropertyFile) == TRUE) {
#if !defined (NO_MOCA_FEATURE_SUPPORT)
            g_message("Receiver Type : %s Build Version :  %s Device Type: %s moca %s wifi %s \n",
                      recvdevtype->str, buildversion->str, devicetype->str, mocaIface->str,
                      wifiIface->str);
#else
          g_message("Receiver Type : %s Build Version :  %s Device Type: %s wifi %s \n",
                    recvdevtype->str,buildversion->str,devicetype->str,wifiIface->str);
#endif
        } else {
            g_message(" ERROR in getting Receiver Type : %s Build Version :  %s \n",
                      recvdevtype->str, buildversion->str);
#if !defined (NO_MOCA_FEATURE_SUPPORT)
            g_message("Receiver Type : %s Build Version :  %s Device Type: %s moca %s wifi %s \n",
                      recvdevtype->str, buildversion->str, devicetype->str, mocaIface->str,
                      wifiIface->str);
#else
            g_message("Receiver Type : %s Build Version :  %s Device Type: %s wifi %s \n",
                      recvdevtype->str,buildversion->str,devicetype->str,wifiIface->str);
#endif
        }
    }
    int loop,result,assigned=0;
    for(loop=0;loop<10;loop++)
    {
#ifndef CLIENT_XCAL_SERVER
        if ( access(devConf->ipv6FileLocation, F_OK ) != -1 ){
            ipv6Enabled=TRUE;
        }
        result = getipaddress(devConf->bcastIf, ipAddressBuffer, TRUE);
        if (!result) {
            fprintf(stderr,
                    "In Ipv6 Could not locate the link  local ipv6 address of the broadcast interface %s\n",
                    devConf->bcastIf);
            g_critical("In Ipv6 Could not locate the link local ipv6 address of the broadcast interface %s\n",
                    devConf->bcastIf);
        }
        else {
            assigned=1;
            g_message("ipaddress of the interface %s", ipAddressBuffer);
        }
        g_string_assign(gwyipv6, ipAddressBuffer);
        ipAddressBuffer[0] = '\0';
        result = getipaddress(devConf->bcastIf, ipAddressBuffer, FALSE);
        if (!result) {
            fprintf(stderr,
                    "Could not locate the link local v4 ipaddress of the broadcast interface %s\n",
                    devConf->bcastIf);
            g_critical("Could not locate the link local v4 ipaddress of the broadcast interface %s\n",
                    devConf->bcastIf);
        } else {
            assigned=1;
            g_message("ipaddress of the interface %s", ipAddressBuffer);
            break;
        }
#else
        ipAddressBuffer[0] = '\0';
        result = getipaddress(mocaIface->str, ipAddressBuffer, FALSE);
        if (!result) {
            g_message("Could not locate the ipaddress of the broadcast moca isolation interface %s",
                    mocaIface->str);
            result = getipaddress(wifiIface->str, ipAddressBuffer, FALSE);
            if (!result) {
                g_message("Could not locate the ipaddress of the wifi broadcast interface %s",
                        wifiIface->str);
                g_critical("Could not locate the link local v4 ipaddress of the broadcast interface %s\n",
                        devConf->bcastIf);
            } else {
                devConf->bcastIf = g_strdup(wifiIface->str);
                g_message("ipaddress of the interface %s", ipAddressBuffer);
                assigned=1;
                break;
            }
        } else {
            devConf->bcastIf = g_strdup(mocaIface->str);
            g_message("ipaddress of the interface %s", ipAddressBuffer);
            assigned=1;
            break;
        }
#endif
        sleep(1);
    }
    if(assigned != 0){
        g_message("Starting xdevice service on interface %s ipAddressBuffer= %s", devConf->bcastIf,ipAddressBuffer);
    }
    else{
        g_message("waited 10 seconds for interface to come up so giving up");
        exit(1);
    }
    g_message("Broadcast Network interface: %s\n", devConf->bcastIf);
    g_message("Dev XML File Name: %s\n", devConf->devXmlFile);
    g_message("Use IARM value is: %u\n", devConf->useIARM);
    g_string_assign(gwyip, ipAddressBuffer);

#if defined(USE_XUPNP_IARM_BUS)
    BOOL iarminit = XUPnP_IARM_Init();
    if (iarminit == true) {
        g_message("XUPNP IARM init success");
#ifndef CLIENT_XCAL_SERVER
        getSystemValues();
#endif
    } else {
        //g_print("IARM init failure");
        g_critical("XUPNP IARM init failed");
    }
#endif //#if defined(USE_XUPNP_IARM_BUS)

#ifndef CLIENT_XCAL_SERVER
    if (devConf->hostMacIf != NULL) {
        const gchar *hostmac = (gchar *)getmacaddress(devConf->hostMacIf);
        if (hostmac) {
            g_message("MAC address in  interface: %s  %s \n", devConf->hostMacIf, hostmac);
        } else {
            g_message("failed to retrieve macaddress on interface %s ",
                      devConf->hostMacIf);
        }
        g_string_assign(hostmacaddress, hostmac);
        g_message("Host mac address is %s", hostmacaddress->str);
    }
#endif
    if (devConf->bcastIf != NULL ) {
        const gchar *bcastmac = (gchar *)getmacaddress(devConf->bcastIf);
        if (bcastmac) {
            g_message("Broadcast MAC address in  interface: %s  %s \n", devConf->bcastIf,
                      bcastmac);
        } else {
            g_message("failed to retrieve macaddress on interface %s ", devConf->bcastIf);
        }
        g_string_assign(bcastmacaddress, bcastmac);
        g_message("bcast mac address is %s", bcastmacaddress->str);
    }
    if (devConf->deviceNameFile != NULL) {
	if(parsedevicename()) {
            g_message("Device Name : %s ", devicename->str);
        } else {
            g_message(" ERROR in getting Device Name ");
        }
    }
    //status = FALSE;
    //g_string_assign(recv_id, argv[2]);
    g_message("getting the receiver id from %s", GET_DEVICEID_SCRIPT);
    recv_id = getID(RECEIVER_ID);

    g_string_printf(url, "http://%s:8080/videoStreamInit?recorderId=%s",
                    ipAddressBuffer, recv_id->str);
    g_print ("The url is now %s.\n", url->str);
#ifndef CLIENT_XCAL_SERVER
    if (devConf->enableTRM == FALSE) {
        requirestrm = FALSE;
        g_string_printf(trmurl, NULL);
    } else {
        requirestrm = TRUE;
        g_string_printf(trmurl, "ws://%s:9988", ipAddressBuffer);
    }
#endif
    if (devConf->allowGwy == FALSE) {
        isgateway = FALSE;
    }
#ifndef CLIENT_XCAL_SERVER
    g_string_printf(playbackurl,
                    "http://%s:8080/hnStreamStart?deviceId=%s&DTCP1HOST=%s&DTCP1PORT=5000",
                    ipAddressBuffer, recv_id->str, ipAddressBuffer);
    if (parsednsconfig() == TRUE) {
        g_print("Contents of dnsconfig is %s\n", dnsconfig->str);
    }
    if (updatesystemids() == TRUE) {
        g_message("System ids are %s\n", systemids->str);
    } else {
        g_warning("Error in finding system ids\n");
    }
#if defined(USE_XUPNP_IARM_BUS)
    if ((strlen(g_strstrip(serial_num->str)) < 6)
            || (is_alphanum(serial_num->str) == FALSE)) {
        g_message("Serial Number not yet received.\n");
    }
    g_message("Received Serial Number:%s", serial_num->str);
#else
    if (getserialnum(serial_num) == TRUE) {
        g_print("Serial Number is %s\n", serial_num->str);
    }
#endif
#else
    if (getserialnum(serial_num) == TRUE) {
        g_print("Serial Number is %s\n", serial_num->str);
    }
#endif
#ifndef CLIENT_XCAL_SERVER
    if (getetchosts() == TRUE) {
        g_print("EtcHosts Content is \n%s\n", etchosts->str);
    } else {
        g_print("Error in getting etc hosts\n");
    }
#else
       getRouteData();
#endif
#ifndef CLIENT_XCAL_SERVER
    if (devConf->disableTuneReady == FALSE) {
        while (FALSE == tune_ready) {
            g_message("XUPnP: Tune Ready Not Yet Received.\n");
	    usleep(5000000);
        }
    } else {
        g_message("Tune Ready check is disabled - Setting tune_ready to TRUE");
        tune_ready = TRUE;
    }
    if ((devConf->allowGwy == TRUE) && (ipv6Enabled == TRUE)
            && (devConf->ipv6PrefixFile != NULL)) {
        while (access(devConf->ipv6PrefixFile, F_OK ) == -1 ) {
            g_message("IPv6 Prefix File Not Yet Created. %s ", devConf->ipv6PrefixFile);
            usleep(5000000);
        }
        while (getipv6prefix() == FALSE) {
            g_message(" V6 prefix is not yet updated in file %s ",
                      devConf->ipv6PrefixFile);
            usleep(2000000);
        }
        g_message("IPv6 prefix : %s ", ipv6prefix->str);
    } else {
        g_message("Box is in IPV4 or ipv6 prefix is empty or  Not a gateway  ipv6enabled = %d ipv6PrefixFile = %s allowGwy = %d ",
                  ipv6Enabled, devConf->ipv6PrefixFile, devConf->allowGwy);
    }
    if (devConf->hostMacIf != NULL) {
        result = getipaddress(devConf->hostMacIf, stbipAddressBuffer, ipv6Enabled);
        if (!result) {
            g_message("Could not locate the ipaddress of the host mac interface %s\n",
                      devConf->hostMacIf);
        } else
            g_message("ipaddress of the interface %s\n", stbipAddressBuffer);
        g_string_assign(gwystbip, stbipAddressBuffer);
    }
#endif
    return TRUE;
}

/**
 * @brief This function is used to get the Receiver Id & Partner Id.
 *
 * When box in warehouse mode, the box does not have the receiver Id so the box need to be put the
 * broadcast MAC address as receiver Id.
 *
 * @param[in] id The Device ID node for which the value need to be retrieved. It is also used for
 * getting Partner Id.
 *
 * @return Returns Value of the Device Id on success else NULL.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
GString *getID( const gchar *id )
{
    BOOL isDevIdPresent = FALSE;
    gshort counter =
        0; // to limit the logging if the user doesnt activate for long time
    GString *jsonData = g_string_new(NULL);
    GString *value = g_string_new(NULL);
    while(TRUE)
    {
//    if (IARM_BUS_SYS_MODE_WAREHOUSE == sysModeParam)
#if defined(USE_XUPNP_IARM_BUS)
        if (( devConf->wareHouseMode == TRUE )
                || (IARM_BUS_SYS_MODE_WAREHOUSE == sysModeParam)) {
            const gchar *bcastmac = (gchar *)getmacaddress(devConf->bcastIf);
            g_string_assign(value, bcastmac);
            g_message("In WareHouse Mode recvid  %s bcastmac %s \n ", recv_id->str,
                      bcastmac);
            g_string_free(jsonData, TRUE);
            return value;
        }
#endif //#if defined(USE_XUPNP_IARM_BUS)

        FILE *fp = NULL;
        if((fp = v_secure_popen("r", GET_DEVICEID_SCRIPT)))
        {
            char response[1024] = {0};
            fread(response, 1, sizeof(response)-1, fp);
            int ret = v_secure_pclose(fp);
            if(ret != 0)
                g_message("Error in closing pipe ! : %d \n", ret);

            if ((response[0] == '\0') && (counter < MAX_DEBUG_MESSAGE)) {
                counter ++;
                g_message("No Json string found in Auth url  %s \n" ,
                          response);
            } else {
                g_string_assign(jsonData, response);
                gchar **tokens = g_strsplit_set(jsonData->str, "{}:,\"", -1);
                guint tokLength = g_strv_length(tokens);
                guint loopvar = 0;
                for (loopvar = 0; loopvar < tokLength; loopvar++) {
                    if (g_strrstr(g_strstrip(tokens[loopvar]), id)) {
                        //"deviceId": "T00xxxxxxx" so omit 3 tokens ":" fromDeviceId
                        if ((loopvar + 3) < tokLength ) {
                            g_string_assign(value, g_strstrip(tokens[loopvar + 3]));
                            if (value->str[0] != '\0') {
                                isDevIdPresent = TRUE;
                                break;
                            }
                        }
                    }
                }
                if (!isDevIdPresent) {
                    if (g_strrstr(id, PARTNER_ID)) {
                        g_message("%s not found in Json string in Auth url %s \n ", id, jsonData->str);
                        return value;
                    }
                    if (counter < MAX_DEBUG_MESSAGE ) {
                        counter++;
                        g_message("%s not found in Json string in Auth url %s \n ", id, jsonData->str);
                    }
                } else {
                    g_message("Successfully fetched %s %s \n ", id, value->str);
                    g_string_free(jsonData,TRUE);
                    return value;
                }
                g_strfreev(tokens);
            }
        }
        else
        {
            g_message("The deviceId script %s can't be executed\n", GET_DEVICEID_SCRIPT);
        }


        sleep(5);
    } // end while
    g_string_free(jsonData, TRUE);
    return value;
}

/**
 * @brief This function is used to update the system Ids such as channelMapId, controllerId, plantId
 * and vodServerId.
 *
 * @return Returns TRUE if successfully updates the system ids, else returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
BOOL updatesystemids(void)
{
    if (devConf->useGliDiag == TRUE) {
        g_string_printf(systemids,
                        "channelMapId:%lu;controllerId:%lu;plantId:%lu;vodServerId:%lu",
                        channelmap_id, dac_id, plant_id, vodserver_id);
        return TRUE;
    } else {
        gchar *diagfile = NULL;  //CID:124887 - uninit
        unsigned long diagid = 0;
        BOOL  result = FALSE;
        GError *error = NULL;
        if (devConf->diagFile == NULL) {
            g_warning("diag file name not found in config");
            return result;
        }
        result = g_file_get_contents (devConf->diagFile, &diagfile, NULL, &error);
        if (result == FALSE) {
            g_string_assign(systemids,
                            "channelMapId:0;controllerId:0;plantId:0;vodServerId:0");
        } else {
            diagid = getidfromdiagfile("channelMapId", diagfile);
            g_string_printf(systemids, "channelMapId:%lu;", diagid);
            diagid = getidfromdiagfile("controllerId", diagfile);
            g_string_append_printf(systemids, "controllerId:%lu;", diagid);
            diagid = getidfromdiagfile("plantId", diagfile);
            g_string_append_printf(systemids, "plantId:%lu;", diagid);
            diagid = getidfromdiagfile("vodServerId", diagfile);
            g_string_append_printf(systemids, "vodServerId:%lu", diagid);
        }
        if (error) {
            /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
            g_clear_error(&error);
        }
        return result;
    }
}

/**
 * @brief This function is used to get the device name from /devicename/devicename file.
 *
 * @return Returns TRUE if successfully gets the device name string else returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
BOOL parsedevicename(void)
{
    GError                  *error = NULL;
    BOOL                result = FALSE;
    gchar *devicenamefile = NULL;
    guint loopvar = 0;
    BOOL devicenamematch = FALSE;
    if (devConf->deviceNameFile == NULL) {
        g_warning("device name file name not found in config");
        return result;
    }

    result = g_file_get_contents (devConf->deviceNameFile, &devicenamefile, NULL,
                                  &error);
    if (result == FALSE && error != NULL) {
        g_warning("Problem in reading /devicename/devicename file %s", error->message);
    } else {
        gchar **tokens = g_strsplit_set(devicenamefile, "'=''\n''\0'", -1);
        guint toklength = g_strv_length(tokens);
        while (loopvar < toklength) {
            if (g_strrstr(g_strstrip(tokens[loopvar]), "deviceName")) {
                result = TRUE;
                g_string_printf(devicename, "%s", g_strstrip(tokens[loopvar + 1]));
//                g_message("device name =  %s", devicename->str);
                devicenamematch = TRUE;
                break;
            }
            loopvar++;
        }
        g_strfreev(tokens);
        if (devicenamematch == FALSE) {
            g_message("No Matching  devicename in file %s", devicenamefile);
        }
	else
	{
	    if(strstr(devicename->str,"\"")||strstr(devicename->str,"\\"))
            {
                char *ptr = NULL;
                ptr = g_strescape(devicename->str,"\b\n");
                if(ptr)
                {
                    g_string_printf(devicename,"%s",ptr);
                    g_free(ptr);
                }
            }
	    g_message("device name =  %s",devicename->str);
	}
    }
    if (error) {
        /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
        g_clear_error(&error);
    }
    g_free(devicenamefile);
    return result;
}

/**
 * @brief This function is used to retrieve the IPv6 prefix information from dibblers file.
 *
 * @return Returns TRUE if successfully gets the ipv6 prefix value else returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
BOOL parseipv6prefix(void)
{
    GError                  *error = NULL;
    BOOL                result = FALSE;
    gchar *prefixfile = NULL;
    guint loopvar = 0;
    guint prefixloopvar = 0;
    BOOL ifacematch = FALSE;
    BOOL prefixmatch = FALSE;
    gchar **prefixtokens;
    if (devConf->ipv6PrefixFile == NULL) {
        g_warning("ipv6PrefixFile file name not found in config");
        return result;
    }
    result = g_file_get_contents (devConf->ipv6PrefixFile, &prefixfile, NULL,
                                  &error);
    if (result == FALSE && error != NULL) {
        g_warning("Problem in reading /prefix/prefix file %s", error->message);
    } else {
        gchar **tokens = g_strsplit_set(prefixfile, "'\n''\0'", -1);
        guint toklength = g_strv_length(tokens);
        while (loopvar < toklength) {
            if (ifacematch == FALSE) {
                if ((g_strrstr(g_strstrip(tokens[loopvar]), "ifacename"))
                        && (g_strrstr(g_strstrip(tokens[loopvar]), devConf->hostMacIf))) {
                    ifacematch = TRUE;
                }
            } else {
                if (g_strrstr(g_strstrip(tokens[loopvar]), "AddrPrefix")) {
                    prefixtokens = g_strsplit_set(tokens[loopvar], "'<''>''='", -1);
                    guint prefixtoklength = g_strv_length(prefixtokens);
                    while (prefixloopvar < prefixtoklength) {
                        if (g_strrstr(g_strstrip(prefixtokens[prefixloopvar]), "/AddrPrefix")) {
                            prefixmatch = TRUE;
                            result = TRUE;
                            g_string_printf(ipv6prefix, "%s", prefixtokens[prefixloopvar - 1]);
                            g_message("ipv6 prefix format in the file %s",
                                      prefixtokens[prefixloopvar - 1]);
                            break;
                        }
                        prefixloopvar++;
                    }
                    g_strfreev(prefixtokens);
                }
                if (prefixmatch == TRUE)
                    break;
            }
            loopvar++;
        }
        g_strfreev(tokens);
        if (prefixmatch == FALSE) {
            result = FALSE;
            g_message("No Matching ipv6 prefix in file %s", prefixfile);
        }
    }
    if (error) {
        /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
        g_clear_error(&error);
    }
    g_free(prefixfile);
    return result;
}
/*
* isVidiPathEnabled()
* If /opt/vidiPathEnabled does not exist, indicates VidiPath is NOT enabled.
* If /opt/vidiPathEnabled exists, VidiPath is enabled.
*/
#ifndef CLIENT_XCAL_SERVER
#define VIDIPATH_FLAG "/opt/vidiPathEnabled"
static int isVidiPathEnabled()
{
    if (access(VIDIPATH_FLAG, F_OK) == 0)
        return 1; //vidipath enabled
    return 0;     //vidipath not enabled
}
#endif
/**
 * @brief This function is used to retrieve the data from the device configuration file
 *
 * @param[in] configfile Device configuration file name.
 *
 * @return Returns TRUE if successfully reads the configuration else returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
BOOL readconffile(const char *configfile)
{
    GKeyFile *keyfile = NULL;
    GKeyFileFlags flags;
    GError *error = NULL;
    /* Create a new GKeyFile object and a bitwise list of flags. */
    keyfile = g_key_file_new ();
    flags = G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS;
    /* Load the GKeyFile from keyfile.conf or return. */
    if (!g_key_file_load_from_file (keyfile, configfile, flags, &error)) {
        if (error) {
            g_message (error->message);
            /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
            g_clear_error(&error);
        }
        if (keyfile) {
            g_key_file_free(keyfile);
        }
        return FALSE;
    }
    //g_message("Starting with Settings %s\n", g_key_file_to_data(keyfile, NULL,
    //          NULL));
    devConf = g_new0(ConfSettings, 1);
    /*
    # Names of all network interfaces used for publishing
    [Network]
    BCastIf=eth1
    BCastPort=50755
    StreamIf=eth1
    TrmIf=eth1
    GwIf=eth1
    CvpIf=eth1
    CvpPort=50753
    HostMacIf=wan
    */
    /* Read in data from the key file from the group "Network". */
    devConf->bcastIf = g_key_file_get_string             (keyfile, "Network",
                       "BCastIf", NULL);
    devConf->bcastPort = g_key_file_get_integer          (keyfile, "Network",
                         "BCastPort", NULL);
#ifndef CLIENT_XCAL_SERVER
    devConf->streamIf = g_key_file_get_string             (keyfile, "Network",
                        "StreamIf", NULL);
    devConf->trmIf = g_key_file_get_string             (keyfile, "Network",
                     "TrmIf", NULL);
    devConf->gwIf = g_key_file_get_string             (keyfile, "Network", "GwIf",
                    NULL);
    devConf->cvpIf = g_key_file_get_string             (keyfile, "Network",
                     "CvpIf", NULL);
    devConf->cvpPort = g_key_file_get_integer          (keyfile, "Network",
                       "CvpPort", NULL);
    devConf->hostMacIf = g_key_file_get_string             (keyfile, "Network",
                         "HostMacIf", NULL);
#endif
    /*
    # Paths and names of all input data files
    [DataFiles]
    OemFile=//etc//udhcpc.vendor_specific
    DnsFile=//etc//resolv.dnsmasq
    DsgFile=//tmp//dsgproxy_slp_attributes.txt
    DiagFile=//tmp//mnt/diska3//persistent//usr//1112//703e//diagnostics.json
    HostsFile=//etc//hosts
    DevXmlPath=/opt/xupnp/
    DevXmlFile=BasicDevice.xml
    LogFile=/opt/logs/xdevice.log
    AuthServerUrl=http://localhost:50050/device/generateAuthToken
    DevPropertyFile=/etc/device.properties
    Ipv6FileLocation=/tmp/stb_ipv6
    Ipv6PrefixFile=/tmp/stb_ipv6
    DeviceNameFile=/opt/hn_service_settings.conf
    */
    /* Read in data from the key file from the group "DataFiles". */
#ifndef CLIENT_XCAL_SERVER
    devConf->oemFile = g_key_file_get_string             (keyfile, "DataFiles",
                       "OemFile", NULL);
    devConf->dnsFile = g_key_file_get_string          (keyfile, "DataFiles",
                       "DnsFile", NULL);
    devConf->dsgFile = g_key_file_get_string             (keyfile, "DataFiles",
                       "DsgFile", NULL);
    devConf->diagFile = g_key_file_get_string             (keyfile, "DataFiles",
                        "DiagFile", NULL);
    devConf->devXmlPath = g_key_file_get_string             (keyfile, "DataFiles",
                          "DevXmlPath", NULL);
    devConf->devXmlFile = g_key_file_get_string             (keyfile, "DataFiles",
                          "DevXmlFile", NULL);
    devConf->cvpXmlFile = g_key_file_get_string             (keyfile, "DataFiles",
                          "CvpXmlFile", NULL);
    devConf->logFile = g_key_file_get_string             (keyfile, "DataFiles",
                       "LogFile", NULL);
    devConf->ipv6FileLocation = g_key_file_get_string          (keyfile,
                                "DataFiles", "Ipv6FileLocation", NULL);
    devConf->ipv6PrefixFile = g_key_file_get_string          (keyfile, "DataFiles",
                              "Ipv6PrefixFile", NULL);
    devConf->devCertFile = g_key_file_get_string             (keyfile, "DataFiles",
                                  "DevCertFile", NULL);
    devConf->devKeyFile = g_key_file_get_string             (keyfile,  "DataFiles",
                                   "DevKeyFile", NULL);
    devConf->devCertPath = g_key_file_get_string             (keyfile, "DataFiles",
                                  "DevCertPath", NULL);
    devConf->devKeyPath = g_key_file_get_string             (keyfile, "DataFiles",
                                 "DevKeyPath", NULL);
#endif
    devConf->deviceNameFile = g_key_file_get_string          (keyfile, "DataFiles",
                              "DeviceNameFile", NULL);
    devConf->devPropertyFile = g_key_file_get_string          (keyfile,
                               "DataFiles", "DevPropertyFile", NULL);
    /*
    # Enable/Disable feature flags
    [Flags]
    EnableCVP2=false
    UseIARM=true
    AllowGwy=true
    EnableTRM=true
    UseGliDiag=true
    DisableTuneReady=true
    enableHostMacPblsh=true
    wareHouseMode=true
    rmfCrshSupp=false
     */
    devConf->useIARM = g_key_file_get_boolean          (keyfile, "Flags",
                       "UseIARM", NULL);
    devConf->allowGwy = g_key_file_get_boolean             (keyfile, "Flags",
                        "AllowGwy", NULL);
#ifndef CLIENT_XCAL_SERVER
    devConf->enableCVP2 = isVidiPathEnabled();
    devConf->ruiPath = g_key_file_get_string (keyfile, "Rui", "RuiPath" , NULL);
    if (devConf->ruiPath == NULL ) { //only use overrides if ruiPath is not present
        devConf->uriOverride = g_key_file_get_string (keyfile, "Rui", "uriOverride",
                               NULL);
    } else {
        devConf->uriOverride = NULL;
    }
    devConf->enableTRM = g_key_file_get_boolean             (keyfile, "Flags",
                         "EnableTRM", NULL);
    devConf->useGliDiag = g_key_file_get_boolean             (keyfile, "Flags",
                          "UseGliDiag", NULL);
    devConf->disableTuneReady = g_key_file_get_boolean             (keyfile,
                                "Flags", "DisableTuneReady", NULL);
    devConf->enableHostMacPblsh = g_key_file_get_boolean             (keyfile,
                                  "Flags", "EnableHostMacPblsh", NULL);
    devConf->rmfCrshSupp = g_key_file_get_boolean             (keyfile, "Flags",
                           "rmfCrshSupp", NULL);
    devConf->wareHouseMode = g_key_file_get_boolean             (keyfile, "Flags",
                             "wareHouseMode", NULL);
#endif
    g_key_file_free(keyfile);
#ifndef CLIENT_XCAL_SERVER
    if ((devConf->bcastIf == NULL) || (devConf->bcastPort == 0)
            || (devConf->devXmlPath == NULL) ||
            (devConf->devXmlFile == NULL)) {
        g_warning("Invalid or no values found for mandatory parameters\n");
        return FALSE;
    }
#endif
    return TRUE;
}

/*-----------------------------
* Creates a XML escaped string from input
*/
static void xmlescape(gchar *instr, GString *outstr)
{
    for (; *instr; instr++)
    {
        switch (*instr)
        {
        case '&':
            g_string_append_printf(outstr,"%s","&amp;");
            break;
        case '\"':
            g_string_append_printf(outstr,"%s","&guot;");
            break;
        case '\'':
            g_string_append_printf(outstr,"%s","&apos;");
            break;
        case '<':
            g_string_append_printf(outstr,"%s","&lt;");
            break;
        case '>':
            g_string_append_printf(outstr,"%s","&gt;");
            break;
        default:
            g_string_append_printf(outstr,"%c",*instr);
            break;
        }
    }
}

/*-----------------------------
* Creates a URI escaped string from input using RFC 2396 reserved chars
* The output matches what javascript encodeURIComponent() generates
*/
static void uriescape(unsigned char *instr, GString *outstr)
{
    int i;
    char unreserved[256] = {0};               //array of unreserved chars or 0 flag

    for (i = 0; i < 256; ++i)                 //init unreserved chars
    {
        unreserved[i] = isalnum(i) || i == '-' || i == '_' || i == '.' || i == '!' || i == '~'
                        || i == '*' || i == '\'' || i == '(' || i == ')'
                        ? i : 0;
    }

    for (; *instr; instr++)                  //escape the input string to the output string
    {
        if (unreserved[*instr])                //if defined as unreserved
            g_string_append_printf(outstr,"%c",*instr);
        else
            g_string_append_printf(outstr,"%%%02X",*instr);
    }
}

/*-----------------------------
* Returns pointer to string of eSTBMAC without ':' chars
* Uses global hostmacaddress GString for address value
* Returned string must be g_string_free() if not NULL
*/

/**
 * @brief This function is used to get the MAC address of the eSTB. It uses global hostmacaddress
 * GString to get the address value.
 *
 * @return Returned string must be g_string_free() if not NULL.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
GString* get_eSTBMAC(void)
{
    if (hostmacaddress != NULL && hostmacaddress->len == 17)//length of address with ':' chars
    {
        GString* addr = g_string_new(NULL);

        int i = 0;
        for (i = 0; i < hostmacaddress->len; ++i)
        {
            if (i != 2 && i != 5 && i != 8 && i != 11 && i != 14 )//positions of ':' char
            {
                addr = g_string_append_c(addr,(hostmacaddress->str)[i]);
            }
        }
        return g_string_ascii_up(addr);
    }
    return NULL;
}

/*-----------------------------
* Initialize ipAddressBufferCVP2 with ip address at devConf->cvp2If
*/
static void initIpAddressBufferCVP2( char *ipAddressBufferCVP2)
{
    int result = getipaddress(devConf->cvpIf, ipAddressBufferCVP2, FALSE);

    if (!result)
    {
        fprintf(stderr,"Could not locate the ipaddress of CVP2 interface %s\n", devConf->cvpIf);
    }

    g_message("ipaddress of the CVP2 interface %s\n", ipAddressBufferCVP2);
    g_string_assign(gwyipCVP2, ipAddressBufferCVP2);
}


/*-----------------------------
* Creates the escaped rui <uri> element value
*/
static GString *get_uri_value()
{
    //create a unique udn value
    //struct timeval now;
    //int rc = gettimeofday(&now,NULL);
    GTimeVal timeval;
    g_get_current_time(&timeval);
    double t = timeval.tv_sec + (timeval.tv_usec /
                                 1000000.0); //number of seconds and microsecs since epoch
    char udnvalue[25];
    snprintf(udnvalue, 25, "%s%f", "CVP-", t);
    //get current ip address for CVP2
    char ipAddressBufferCVP2[INET6_ADDRSTRLEN];
    initIpAddressBufferCVP2(ipAddressBufferCVP2);
    //init uri parameters with current ip address
    g_string_printf(trmurlCVP2, "ws://%s:9988", ipAddressBufferCVP2);
    g_string_printf(playbackurlCVP2,
                    "http://%s:8080/hnStreamStart?deviceId=%s&DTCP1HOST=%s&DTCP1PORT=5000",
                    ipAddressBufferCVP2, recv_id->str, ipAddressBufferCVP2);
    //initialize urivalue from xdevice.conf if present
    gchar *urilink;
    if (devConf->uriOverride != NULL)
        urilink = devConf->uriOverride;
    else
        urilink = "http://syndeo.xcal.tv/app/x2rui/rui.html";
    //g_print("before g_strconcat urilink: %s\n",urilink);
    //parse the systemids
    //systemids-str must have the following format
    //channelMapId:%lu;controllerId:%lu;plantId:%lu;vodServerId:%lu
    g_print("systemids->str: %s\n", systemids->str);
    GString *channelMapId = NULL;
    char *pId = "channelMapId:";
    char *pChannelMapId = strstr(systemids->str, pId);
    if (pChannelMapId != NULL) {
        pChannelMapId += strlen(pId);
        size_t len = strcspn(pChannelMapId, ";");
        channelMapId = g_string_new_len(pChannelMapId, len);
    }
    if (channelMapId == NULL)
        channelMapId = g_string_new("0");
    GString *controllerId = NULL;
    pId = "controllerId:";
    char *pControllerId = strstr(systemids->str, pId);
    if (pControllerId != NULL) {
        pControllerId += strlen(pId);
        size_t len = strcspn(pControllerId, ";");
        controllerId = g_string_new_len(pControllerId, len);
    }
    if (controllerId == NULL)
        controllerId = g_string_new("0");
    GString *plantId = NULL;
    pId = "plantId:";
    char *pPlantId = strstr(systemids->str, pId);
    if (pPlantId != NULL) {
        pPlantId += strlen(pId);
        size_t len = strcspn(pPlantId, ";");
        plantId = g_string_new_len(pPlantId, len);
    }
    if (plantId == NULL)
        plantId = g_string_new("0");
    GString *vodServerId = NULL;
    pId = "vodServerId:";
    char *pVodServerId = strstr(systemids->str, pId);
    if (pVodServerId != NULL) {
        pVodServerId += strlen(pId);
        size_t len = strcspn(pVodServerId, ";");
        vodServerId = g_string_new_len(pVodServerId, len);
    }
    if (vodServerId == NULL)
        vodServerId = g_string_new("0");
    GString *eSTBMAC = get_eSTBMAC();
    if (eSTBMAC == NULL) {
        eSTBMAC = g_string_new("UNKNOWN");
    }
    gchar *gw_value = g_strconcat(
                          "{"
                          "\"deviceType\":\"DMS\","
                          "\"friendlyName\":\"" , getGatewayName(),     "\","
                          "\"receiverID\":\""   , recv_id->str,         "\","
                          "\"udn\":\""          , udnvalue,             "\","
                          "\"gatewayIP\":\""    , gwyipCVP2->str,       "\","
                          "\"baseURL\":\""      , playbackurlCVP2->str, "\","
                          "\"trmURL\":\""       , trmurlCVP2->str,      "\","
                          "\"channelMapId\":\"" , channelMapId->str,    "\","
                          "\"controllerId\":\"" , controllerId->str,    "\","
                          "\"plantId\":\""      , plantId->str,         "\","
                          "\"vodServerId\":\""  , vodServerId->str,     "\","
                          "\"eSTBMAC\":\""      , eSTBMAC->str,         "\""
                          "}", NULL );
    g_string_free(eSTBMAC, TRUE);
    g_string_free(channelMapId, TRUE);
    g_string_free(controllerId, TRUE);
    g_string_free(plantId, TRUE);
    g_string_free(vodServerId, TRUE);
    //gchar *gw_value = "a&b\"c\'d<e>f;g/h?i:j@k&l=m+n$o,p{}q'r_s-t.u!v~x*y(z)"; //test string with reserved chars
    //g_print("gw_value string before escape = %s\n",gw_value);
    GString *gwescapededstr = g_string_sized_new(strlen(gw_value) *
                              3);//x3, big enough for all of the chars to be escaped
    uriescape(gw_value, gwescapededstr);
    g_free(gw_value);
    //g_print("gw_value string after URI escape = %s\n",gwescapededstr->str);
    gchar *uri = g_strconcat( urilink, "?partner=", getPartnerId(partner_id->str), "&gw=",
                              gwescapededstr->str, NULL );
    g_string_free(gwescapededstr, TRUE);
    GString *xmlescapedstr = g_string_sized_new(strlen(uri) *
                             2);//x2 should be big enough
    xmlescape(uri, xmlescapedstr);
    g_free(uri);
    //g_print("uri string after XML escape = %s\n",xmlescapedstr->str);
    return xmlescapedstr;
}

/**
 * @brief This function is used to get the hosts IP information from hosts configuration file "/etc/hosts".
 *
 * @return Returns TRUE if successfully gets the hosts else returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
BOOL getetchosts(void)
{
    GError                  *error = NULL;
    BOOL                result = FALSE;
    gchar *etchostsfile = NULL;
    gchar *hostsFile;
    if ( ipv6Enabled == TRUE )
        hostsFile = g_strdup("//etc//xi-xconf-hosts.list");
    else
        hostsFile = g_strdup("//etc//hosts");
    result = g_file_get_contents (hostsFile, &etchostsfile, NULL, &error);
    if (result == FALSE && error != NULL) {
        g_warning("Problem in reading %s file %s", hostsFile, error->message);
    } else {
        gchar **tokens = g_strsplit_set(etchostsfile, "\n\0", -1);
        //etchosts->str = g_strjoinv(";", tokens);
        guint toklength = g_strv_length(tokens);
        guint loopvar = 0;
        if ((toklength > 0) && (strlen(g_strstrip(tokens[0])) > 0) &&
                (g_strrstr(g_strstrip(tokens[0]), "127.0.0.1") == NULL)) {
            g_string_printf(etchosts, "%s", gwyip->str);
            g_string_append_printf(etchosts, "%s", " ");
            g_string_append_printf(etchosts, "%s;", g_strstrip(tokens[0]));
        } else {
            g_string_assign(etchosts, "");
        }
        for (loopvar = 1; loopvar < toklength; loopvar++) {
            //g_print("Token is %s\n",g_strstrip(tokens[loopvar]));
            //Do not send localhost 127.0.0.1 mapping
            if (g_strrstr(g_strstrip(tokens[loopvar]), "127.0.0.1") == NULL) {
                if (strlen(g_strstrip(tokens[loopvar])) > 0) {
                    g_string_append_printf(etchosts, "%s", gwyip->str);
                    g_string_append_printf(etchosts, "%s", " ");
                    g_string_append_printf(etchosts, "%s;", g_strstrip(tokens[loopvar]));
                }
            }
        }
        g_strfreev(tokens);
    }
    //diagid=1000;
    //g_print("Etc Hosts contents are %s", etchosts->str);
    g_free(hostsFile);
    if (error) {
        /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
        g_clear_error(&error);
    }
    return result;
}

/**
 * @brief This function is used to get the serial number of the device from the vendor specific file.
 *
 * @param[out] serial_num Manufacturer serial number
 *
 * @return Returns TRUE if successfully gets the serial number else, returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
BOOL parseserialnum(GString *serial_num)
{
#ifndef CLIENT_XCAL_SERVER
    GError                  *error = NULL;
    BOOL                result = FALSE;
    gchar *udhcpcvendorfile = NULL;
    result = g_file_get_contents ("//etc//udhcpc.vendor_specific",
                                  &udhcpcvendorfile, NULL, &error);
    if (result == FALSE && error != NULL) {
        g_warning("Problem in reading /etc/udhcpcvendorfile file %s", error->message);
    } else {
        /* reset result = FALSE to identify serial number from udhcpcvendorfile contents */
        result = FALSE;
        gchar **tokens = g_strsplit_set(udhcpcvendorfile, " \n\t\b\0", -1);
        guint toklength = g_strv_length(tokens);
        guint loopvar = 0;
        for (loopvar = 0; loopvar < toklength; loopvar++) {
            //g_print("Token is %s\n",g_strstrip(tokens[loopvar]));
            if (g_strrstr(g_strstrip(tokens[loopvar]), "SUBOPTION4")) {
                if ((loopvar + 1) < toklength ) {
                    g_string_assign(serial_num, g_strstrip(tokens[loopvar + 2]));
                }
                result = TRUE;
                break;
            }
        }
        g_strfreev(tokens);
    }
    //diagid=1000;
    if (error) {
        /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
        g_clear_error(&error);
    }
    return result;
#else
    bool bRet;
    IARM_Bus_MFRLib_GetSerializedData_Param_t param;
    IARM_Result_t iarmRet = IARM_RESULT_IPCCORE_FAIL;
    errno_t rc = -1;
    rc = memset_s(&param, sizeof(param), 0, sizeof(param));
    ERR_CHK(rc);
    param.type = mfrSERIALIZED_TYPE_SERIALNUMBER;
    iarmRet = IARM_Bus_Call(IARM_BUS_MFRLIB_NAME,
                            IARM_BUS_MFRLIB_API_GetSerializedData, &param, sizeof(param));
    if (iarmRet == IARM_RESULT_SUCCESS) {
        if (param.buffer && param.bufLen) {
            g_message( " serialized data %s  \n", param.buffer );
            g_string_assign(serial_num, param.buffer);
            bRet = true;
        } else {
            g_message( " serialized data is empty  \n" );
            bRet = false;
        }
    } else {
        bRet = false;
        g_message(  "IARM CALL failed  for mfrtype \n");
    }
    return bRet;
#endif
}

/**
 * @brief This function is used to get the system Id information from the diagnostic file.
 *
 * @param[in] diagparam Parameter for which value(system Id) need to be retrieved from the diagnostic file.
 * @param[in] diagfilecontents The diagnostic filename
 *
 * @return Returns value of the system Id.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
unsigned long getidfromdiagfile(const gchar *diagparam,
                                const gchar *diagfilecontents)
{
    unsigned long diagid = 0;
    gchar **tokens = g_strsplit_set(diagfilecontents, ":,{}", -1);
    guint toklength = g_strv_length(tokens);
    guint loopvar = 0;
    for (loopvar = 0; loopvar < toklength; loopvar++) {
        if (g_strrstr(g_strstrip(tokens[loopvar]), diagparam)) {
            if ((loopvar + 1) < toklength )
                diagid = strtoul(tokens[loopvar + 1], NULL, 10);
        }
    }
    g_strfreev(tokens);
    return diagid;
}

/**
 * @brief This function is used to get the DNS value from DNS mask configuration file.
 *
 * @return Returns TRUE if successfully gets the DNS configuration, else returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
BOOL parsednsconfig(void)
{
    GError                  *error = NULL;
    BOOL                result = FALSE;
    gchar *dnsconfigfile = NULL;
    GString *strdnsconfig = g_string_new(NULL);
    if (devConf->dnsFile == NULL) {
        g_warning("dnsconfig file name not found in config");
        return result;
    }
    result = g_file_get_contents (devConf->dnsFile, &dnsconfigfile, NULL, &error);
    if (result == FALSE) {
        g_warning("Problem in reading dnsconfig file %s", error->message);
    } else {
        gchar **tokens = g_strsplit_set(dnsconfigfile, "\n\0", -1);
        //etchosts->str = g_strjoinv(";", tokens);
        guint toklength = g_strv_length(tokens);
        guint loopvar = 0;
        BOOL firsttok = TRUE;
        for (loopvar = 0; loopvar < toklength; loopvar++) {
            if ((strlen(g_strstrip(tokens[loopvar])) > 0)) {
                //          g_message("Token is %s\n",g_strstrip(tokens[loopvar]));
                if (firsttok == FALSE) {
                    g_string_append_printf(strdnsconfig, "%s;", g_strstrip(tokens[loopvar]));
                } else {
                    g_string_printf(strdnsconfig, "%s;", g_strstrip(tokens[loopvar]));
                    firsttok = FALSE;
                }
            }
        }
        g_string_assign(dnsconfig, strdnsconfig->str);
        g_string_free(strdnsconfig, TRUE);
        g_message("DNS Config is %s", dnsconfig->str);
        g_strfreev(tokens);
    }
    if (error) {
        /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
        g_clear_error(&error);
    }
    return result;
}

/**
 * @brief This function is used to get the mac address of the target device.
 *
 * @param[in] ifname Name of the network interface.
 *
 * @return Returns the mac address of the interface given.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
gchar *getmacaddress(const gchar *ifname)
{
    int fd;
    struct ifreq ifr;
    unsigned char *mac;
    GString *data = g_string_new("00:00:00:00:00:00");
    errno_t rc = -1;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0){//CID:18597-Resolve negative returns issue
        return data->str;
    }
    ifr.ifr_addr.sa_family = AF_INET;
    rc = strcpy_s(ifr.ifr_name ,IFNAMSIZ - 1,ifname);
    ERR_CHK(rc);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    //display mac address
    //g_print("Mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    g_string_printf(data, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[0], mac[1], mac[2],
                    mac[3], mac[4], mac[5]);
    return data->str;
}

/**
 * @brief This function is used to get the IP address based on IPv6 or IPv4 is enabled.
 *
 * @param[in] ifname Name of the network interface.
 * @param[out] ipAddressBuffer Character buffer to hold the IP address.
 * @param[in] ipv6Enabled Flag to check whether IPV6 is enabled
 *
 * @return Returns an integer value '1' if successfully gets the IP address else returns '0'.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
int getipaddress(const char *ifname, char *ipAddressBuffer,gboolean ipv6Enabled)
{
    struct ifaddrs *ifAddrStruct = NULL;
    struct ifaddrs *ifa = NULL;
    void *tmpAddrPtr = NULL;
    getifaddrs(&ifAddrStruct);
    errno_t rc       = -1;
    int     ind      = -1;
    //char addressBuffer[INET_ADDRSTRLEN] = NULL;
    int found = 0;
    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ipv6Enabled == TRUE) {
            // check it is IP6
            // is a valid IP6 Address
            rc = strcmp_s(ifa->ifa_name,strlen(ifa->ifa_name),ifname,&ind);
            ERR_CHK(rc);

            if (((!ind) && (rc == EOK)) && (ifa ->ifa_addr->sa_family == AF_INET6)) {
                tmpAddrPtr = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
                inet_ntop(AF_INET6, tmpAddrPtr, ipAddressBuffer, INET6_ADDRSTRLEN);
                //if (strcmp(ifa->ifa_name,"eth0")==0trcmp0(g_strstrip(devConf->mocaMacIf),ifname) == 0)
                if (((g_strcmp0(g_strstrip(devConf->bcastIf), ifname) == 0)
                        && (IN6_IS_ADDR_LINKLOCAL(tmpAddrPtr)))
                        || ((!(IN6_IS_ADDR_LINKLOCAL(tmpAddrPtr)))
                            && (g_strcmp0(g_strstrip(devConf->hostMacIf), ifname) == 0))) {
                    found = 1;
                    break;
                }
            }
        } else {
            if (ifa ->ifa_addr->sa_family == AF_INET) { // check it is IP4
                // is a valid IP4 Address
                tmpAddrPtr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
                inet_ntop(AF_INET, tmpAddrPtr, ipAddressBuffer, INET_ADDRSTRLEN);
                //if (strcmp(ifa->ifa_name,"eth0")==0)
                rc = strcmp_s(ifa->ifa_name,strlen(ifa->ifa_name),ifname,&ind);
                ERR_CHK(rc);
                if((!ind) && (rc == EOK)) {
                    found = 1;
                    break;
                }
            }
        }
    }
    if (ifAddrStruct != NULL) freeifaddrs(ifAddrStruct);
    return found;
}

static char * getPartnerName()
{
        getPartnerId(partner_id->str);
        return getStrValueFromMap(partner_id->str, ARRAY_COUNT(partnerNameMap), partnerNameMap);
}

#if 0
static char * getFriendlyName()
{
        getPartnerId(partner_id->str);
        return getStrValueFromMap(partner_id->str, ARRAY_COUNT(friendlyNameMap), friendlyNameMap);
}
#endif

static char * getProductName()
{
        getPartnerId(partner_id->str);
        return getStrValueFromMap(partner_id->str, ARRAY_COUNT(productNameMap), productNameMap);
}
static char * getServiceName()
{
        getPartnerId(partner_id->str);
        return getStrValueFromMap(partner_id->str, ARRAY_COUNT(serviceNameMap), serviceNameMap);
}
static char * getServiceDescription()
{
        getPartnerId(partner_id->str);
        return getStrValueFromMap(partner_id->str, ARRAY_COUNT(serviceDescriptionMap), serviceDescriptionMap);
}
static char * getGatewayName()
{
        getPartnerId(partner_id->str);
        return getStrValueFromMap(partner_id->str, ARRAY_COUNT(gatewayNameMap), gatewayNameMap);
}
