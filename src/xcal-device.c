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
 * @file xcal-device.c
 * @brief This source file contains the APIs for xcal device initializer.
 */
#include <libgupnp/gupnp.h>
//#include <libgssdp/gssdp.h>
#include <stdio.h>
#include <stdlib.h>
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

#include "xdevice.h"
#include "rdk_safeclib.h"
#ifdef CLIENT_XCAL_SERVER
#include "mfrMgr.h"
#endif
#ifdef ENABLE_BREAKPAD
#include "breakpadWrapper.h"
#endif

#ifdef ENABLE_SD_NOTIFY
#include <systemd/sd-daemon.h>
#endif


#if defined(USE_XUPNP_IARM_BUS)
#include "libIBus.h"
#include "libIARMCore.h"
#include "sysMgr.h"
#include "libIBusDaemon.h"

#define G_VALUE_INIT {0,{{0}}}

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
static  GMainLoop *main_loop;

IARM_Bus_Daemon_SysMode_t sysModeParam;
//Event Handler for SYSMGR Events

//Raw offset is fixed for a timezone
//in case of 1.3.x this read from java TimeZone object
#define HST_RAWOFFSET  (-11 * 60 * 60 * 1000)
#define AKST_RAWOFFSET (-9  * 60 * 60 * 1000)
#define PST_RAWOFFSET (-8  * 60 * 60 * 1000)
#define MST_RAWOFFSET (-7  * 60 * 60 * 1000)
#define CST_RAWOFFSET (-6  * 60 * 60 * 1000)
#define EST_RAWOFFSET (-5  * 60 * 60 * 1000)
gboolean ipv6Enabled=FALSE;

#ifdef SAFEC_DUMMY_API
//adding strcmp_s defination
errno_t strcmp_s(const char * d,int max ,const char * src,int *r)
{
  *r= strcmp(d,src);
  return EOK;
}
#endif


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

static void mapTimeZoneToJavaFormat(char* payload)
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

#define COMCAST_PARTNET_KEY "comcast"
#define COX_PARTNET_KEY     "cox"

typedef struct _STRING_MAP
{
    char * pszKey;
    char * pszValue;
} STRING_MAP;

#define ARRAY_COUNT(array)  (sizeof(array)/sizeof(array[0]))

static STRING_MAP partnerNameMap[] = {
    {COMCAST_PARTNET_KEY, "comcast"},
    {COX_PARTNET_KEY    , "cox"},
};

static STRING_MAP friendlyNameMap[] = {
    {COMCAST_PARTNET_KEY, "XFINITY"},
    {COX_PARTNET_KEY    , "Contour"},
};

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

static char * getStrValueFromMap(char * pszKey, int nPairs, STRING_MAP map[])
{
    int i = 0;
    for(i = 0; i < nPairs; i++)
    {
        int nKeyLen = strlen(map[i].pszKey);
        if(0==strncasecmp(map[i].pszKey, pszKey, nKeyLen)) return map[i].pszValue;
    }

    // By default return value in entry 0;
    return map[0].pszValue;
}

static char * getPartnerID()
{
    return partner_id->str;
}

static char * getPartnerName()
{
    return getStrValueFromMap(getPartnerID(), ARRAY_COUNT(partnerNameMap), partnerNameMap);
}

static char * getFriendlyName()
{
    return getStrValueFromMap(getPartnerID(), ARRAY_COUNT(friendlyNameMap), friendlyNameMap);
}

static char * getProductName()
{
    return getStrValueFromMap(getPartnerID(), ARRAY_COUNT(productNameMap), productNameMap);
}

static char * getServiceName()
{
    return getStrValueFromMap(getPartnerID(), ARRAY_COUNT(serviceNameMap), serviceNameMap);
}

static char * getServiceDescription()
{
    return getStrValueFromMap(getPartnerID(), ARRAY_COUNT(serviceDescriptionMap), serviceDescriptionMap);
}

static char * getGatewayName()
{
    return getStrValueFromMap(getPartnerID(), ARRAY_COUNT(gatewayNameMap), gatewayNameMap);
}

static void _sysEventHandler(const char *owner, IARM_EventId_t eventId, void *data, size_t len)
{
    errno_t rc       = -1;
    int     ind      = -1;
    /* Only handle state events */
    rc = strcmp_s(owner, strlen(owner), IARM_BUS_SYSMGR_NAME , &ind);
    ERR_CHK(rc);
    if ((eventId != IARM_BUS_SYSMGR_EVENT_SYSTEMSTATE) || (ind  != 0) || (rc != EOK))

    return;

    IARM_Bus_SYSMgr_EventData_t *sysEventData = (IARM_Bus_SYSMgr_EventData_t*)data;
    IARM_Bus_SYSMgr_SystemState_t stateId = sysEventData->data.systemStates.stateId;
    int state = sysEventData->data.systemStates.state;


    switch(stateId) {
    case IARM_BUS_SYSMGR_SYSSTATE_TUNEREADY:
        if (tune_ready != sysEventData->data.systemStates.state)
        {
            tune_ready = sysEventData->data.systemStates.state;
            if (devConf->rmfCrshSupp == TRUE)
            {
                if (tune_ready == TRUE)
                {
                    gupnp_root_device_set_available (dev,TRUE);
                    g_message(" Start publishing %d ",tune_ready);
                    if (devConf->useGliDiag == FALSE)
                    {
                        updatesystemids();
                        notify_value_change("SystemIds", systemids->str);
                    }
                    notify_value_change("PlaybackUrl", playbackurl->str);
                }
                else
                {
                    gupnp_root_device_set_available (dev,FALSE);
                    g_message(" Stop publishing %d ",tune_ready);
                }
            }
            else
            {
                if (devConf->useGliDiag == FALSE)
                {
                    updatesystemids();
                    notify_value_change("SystemIds", systemids->str);
                }
                notify_value_change("PlaybackUrl", playbackurl->str);
            }
            g_message("Tune Ready Update Received: %d", tune_ready);
        }
        break;
    case IARM_BUS_SYSMGR_SYSSTATE_STB_SERIAL_NO:
        g_string_assign(serial_num, sysEventData->data.systemStates.payload);
        g_message("Serial Number Update Received: %s", serial_num->str);
        break;
    case IARM_BUS_SYSMGR_SYSSTATE_CHANNELMAP:
        g_message("Received channel map update");
        if (sysEventData->data.systemStates.error)
        {
            channelmap_id=0;
            //g_string_assign(channelmap_id, NULL);
        }
        else if (sysEventData->data.systemStates.state == 2)
        {
            if ((strlen(sysEventData->data.systemStates.payload) > 0) &&
                    is_num(sysEventData->data.systemStates.payload) == TRUE)
            {
                channelmap_id=strtoul(sysEventData->data.systemStates.payload, NULL, 10);
                //g_string_assign(channelmap_id, sysEventData->data.systemStates.payload);
                //g_message("Received channel map id: %s", channelmap_id->str);
                g_message("Received channel map id: %lu", channelmap_id);
                updatesystemids();
                notify_value_change("SystemIds", systemids->str);
            }

        }
        break;
    case IARM_BUS_SYSMGR_SYSSTATE_DAC_ID:
        g_message("Received controller id update");
        if (sysEventData->data.systemStates.error)
        {
            dac_id=0;
            //g_string_assign(dac_id, NULL);
        }
        else if (sysEventData->data.systemStates.state == 2)
        {
            if ((strlen(sysEventData->data.systemStates.payload) > 0) &&
                    (is_num(sysEventData->data.systemStates.payload) == TRUE))
            {
                dac_id=strtoul(sysEventData->data.systemStates.payload, NULL, 10);
                //g_string_assign(dac_id, sysEventData->data.systemStates.payload);
                //g_message("Received controller id: %s", dac_id->str);
                g_message("Received controller id: %lu", dac_id);
                updatesystemids();
                notify_value_change("SystemIds", systemids->str);
            }
        }
        break;
    case IARM_BUS_SYSMGR_SYSSTATE_PLANT_ID:
        g_message("Received plant id update");
        if (sysEventData->data.systemStates.error)
        {
            plant_id=0;
            //g_string_assign(plant_id, NULL);
        }
        else if (sysEventData->data.systemStates.state == 2)
        {
            if ((strlen(sysEventData->data.systemStates.payload) > 0) &&
                    is_num(sysEventData->data.systemStates.payload) == TRUE)
            {
                plant_id=strtoul(sysEventData->data.systemStates.payload, NULL, 10);
                //g_string_assign(plant_id, sysEventData->data.systemStates.payload);
                //g_message("Received plant id: %s", plant_id->str);
                g_message("Received plant id: %lu", plant_id);
                updatesystemids();
                notify_value_change("SystemIds", systemids->str);
            }
        }
        break;
    case IARM_BUS_SYSMGR_SYSSTATE_VOD_AD:
        g_message("Received vod server id update");
        if (sysEventData->data.systemStates.error)
        {
            vodserver_id=0;
            //g_string_assign(vodserver_id, NULL);
        }
        else if (sysEventData->data.systemStates.state == 2)
        {
            if ((strlen(sysEventData->data.systemStates.payload) > 0) &&
                    is_num(sysEventData->data.systemStates.payload) == TRUE)
            {
                vodserver_id=strtoul(sysEventData->data.systemStates.payload, NULL, 10);
                //g_string_assign(vodserver_id, sysEventData->data.systemStates.payload);
                //g_message("Received vod server id: %s", vodserver_id->str);
                g_message("Received vod server id: %lu", vodserver_id);
                updatesystemids();
                notify_value_change("SystemIds", systemids->str);
            }
        }
        break;

    case IARM_BUS_SYSMGR_SYSSTATE_TIME_ZONE:
        g_message("Received timezone update");
        if (sysEventData->data.systemStates.error)
        {
//          g_string_assign(dsgtimezone, "null");
            g_message("Time zone error");
        }
        else if (sysEventData->data.systemStates.state == 2)
        {
            if ((strlen(sysEventData->data.systemStates.payload) > 1)) /*&&
                                      is_alphanum(sysEventData->data.systemStates.payload) == TRUE)*/
            {
                //If in DST then the TZ string will contain , and . so is alpha num checking will fail
                mapTimeZoneToJavaFormat ((char*)sysEventData->data.systemStates.payload);

                //g_string_assign(dsgtimezone, sysEventData->data.systemStates.payload);
                g_message("Received dsgtimezone: %s", dsgtimezone->str);
                g_message("Received rawOffset: %d", rawOffset);

            }
        }
        break;
    case   IARM_BUS_SYSMGR_SYSSTATE_DST_OFFSET :
        if (sysEventData->data.systemStates.error)
        {
            g_message("dst offset error ");
        }
        else if (sysEventData->data.systemStates.state == 2)
        {
            dstOffset= atoi(sysEventData->data.systemStates.payload);
            dstSavings=(dstOffset*60000);
            g_message("Received dstSavings: %d", dstSavings);
            if (g_strcmp0(g_strstrip(dsgtimezone->str),"null") != 0)
            {

                notify_timezone();
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
    IARM_Bus_CommonAPI_SysModeChange_Param_t *param = (IARM_Bus_CommonAPI_SysModeChange_Param_t *)arg;
    g_message("Sys Mode Change::New mode --> %d, Old mode --> %d\n",param->newMode,param->oldMode);
    sysModeParam=param->newMode;
    return IARM_RESULT_SUCCESS;
}

static void _routesysEventHandler(const char *owner, IARM_EventId_t eventId, void *data, size_t len)
{
    errno_t rc       = -1;
    int     ind      = -1;
    rc = strcmp_s(owner, strlen(owner), IARM_BUS_NM_SRV_MGR_NAME, &ind );
    ERR_CHK(rc);
    if((ind == 0) && (rc == EOK))
    {
        switch (eventId) {
        case IARM_BUS_NETWORK_MANAGER_EVENT_ROUTE_DATA:
        {
            routeEventData_t *param = (routeEventData_t *)data;
            if(param->routeIp)
            {
                if(g_strcmp0(g_strstrip(param->routeIp),dataGatewayIPaddress->str) != 0)
                {
                    g_string_assign(dataGatewayIPaddress,param->routeIp);
                    g_message("route IP for the device %s ",dataGatewayIPaddress->str);
                    notify_value_change("DataGatewayIPaddress", dataGatewayIPaddress->str);
                }
                else
                    g_message("same route is send %s  %s ",param->routeIp,dataGatewayIPaddress->str);
            }
            else
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
gboolean XUPnP_IARM_Init(void)
{
    g_message("<<<<< Iniializing IARM XUPnP >>>>>>>>");


    if(IARM_RESULT_SUCCESS != IARM_Bus_Init(_IARM_XDEVICE_NAME))
    {
        g_message("<<<<<<<%s - Failed in IARM Bus IARM_Bus_Init>>>>>>>>",__FUNCTION__);
        return FALSE;
    }
    else if (IARM_RESULT_SUCCESS != IARM_Bus_Connect())
    {
        g_message("<<<<<<<%s - Failed in  IARM_Bus_Connect>>>>>>>>",__FUNCTION__);
        return FALSE;
    }
    else
    {
        IARM_Bus_RegisterEventHandler(IARM_BUS_SYSMGR_NAME, IARM_BUS_SYSMGR_EVENT_SYSTEMSTATE, _sysEventHandler);
        IARM_Bus_RegisterEventHandler(IARM_BUS_NM_SRV_MGR_NAME,IARM_BUS_NETWORK_MANAGER_EVENT_ROUTE_DATA, _routesysEventHandler);
        g_message("<<<<<<<%s - Registered the SYSMGR BUS Events >>>>>>>>",__FUNCTION__);
        IARM_Bus_RegisterCall(IARM_BUS_COMMON_API_SysModeChange,_SysModeChange);
        g_message("<<<<<<<%s - Registering Callback for Warehouse Mode Check >>>>>>>>",__FUNCTION__);
        return TRUE;
    }
}

void getRouteData(void)
{
    IARM_Bus_RouteSrvMgr_RouteData_Param_t param;
    IARM_Bus_Call(IARM_BUS_NM_SRV_MGR_NAME, IARM_BUS_ROUTE_MGR_API_getCurrentRouteData, &param, sizeof(param));
    if (param.status)
    {
        g_string_assign(dataGatewayIPaddress,param.route.routeIp);
        g_message("getRouteData: route IP for the device %s ",dataGatewayIPaddress->str);
    }
    else
    {
        g_message("route data not available");
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
    IARM_Bus_Call(IARM_BUS_SYSMGR_NAME, IARM_BUS_SYSMGR_API_GetSystemStates, &param, sizeof(param));


    if (param.channel_map.state == 2)
    {
        if (strlen(param.channel_map.payload) > 0
                && is_num(param.channel_map.payload) == TRUE)
        {
            channelmap_id=strtoul(param.channel_map.payload, NULL, 10);
            g_message("Channel map id available. Value %lu", channelmap_id);
        }
    }
    if (param.dac_id.state == 2)
    {
        if (strlen(param.dac_id.payload) > 0
                && is_num(param.dac_id.payload) == TRUE)
        {
            dac_id=strtoul(param.dac_id.payload, NULL, 10);
            g_message("dac id available. Value %lu", dac_id);
        }
    }

    if (param.plant_id.state == 2)
    {
        if (strlen(param.plant_id.payload) > 0
                && is_num(param.plant_id.payload) == TRUE)
        {
            plant_id=strtoul(param.plant_id.payload, NULL, 10);
            g_message("plant id available. Value %lu", plant_id);
        }
    }

    if (param.vod_ad.state == 2)
    {
        if (strlen(param.vod_ad.payload) > 0
                && is_num(param.vod_ad.payload) == TRUE)
        {
            vodserver_id=strtoul(param.vod_ad.payload, NULL, 10);
            g_message("vod ad available. Value %lu", vodserver_id);
        }
    }

    if (param.time_zone_available.state == 2)
    {
        if (strlen(param.time_zone_available.payload) > 0
                /*&& is_alphanum(param.time_zone_available.payload) == TRUE*/)
        {
            g_message("Timezone is available. Value %s",param.time_zone_available.payload);
            //g_string_assign(dsgtimezone, param.time_zone_available.payload);
            mapTimeZoneToJavaFormat ((char*)param.time_zone_available.payload);
            g_message("dsgtimezone: %s", dsgtimezone->str);
            g_message("rawOffset: %d", rawOffset);
        }
    }

    if (param.dst_offset.state == 2)
    {
        if (strlen(param.dst_offset.payload) > 0)
        {
            dstOffset= atoi(param.dst_offset.payload);
        }
        dstSavings=(dstOffset*60000);
        g_message("dstSavings: %d", dstSavings);
        if (g_strcmp0(g_strstrip(dsgtimezone->str),"null") != 0)
        {
            notify_timezone();
        }

    }
    if (tune_ready != param.TuneReadyStatus.state)
    {
        tune_ready = param.TuneReadyStatus.state;
        notify_value_change("PlaybackUrl", playbackurl->str);
    }

    g_message("Tune Ready: %d\n", tune_ready);
    if (param.stb_serial_no.payload != NULL)
    {
        g_string_assign(serial_num, param.stb_serial_no.payload);
        g_message("Serial no: %s\n", serial_num->str);
    }
    else
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

#endif //#if defined(USE_XUPNP_IARM_BUS)

/**
 * @brief This function is used to log the messages of XUPnP applications. Each Log message
 * will be written to a file along with the timestamp formated in ISO8601 format.
 *
 * @param[in] log_domain Character pointer variable for domain name.
 * @param[in] log_level Variable of glib log level enum.
 * @param[in] message Character pointer for the log message string.
 * @param[in] user_data Void pointer variable.
 *
 * @ingroup XUPNP_XCALDEV_FUNC
 */
void xupnp_logger (const gchar *log_domain, GLogLevelFlags log_level,
                   const gchar *message, gpointer user_data)
{

    GTimeVal timeval;
    g_get_current_time(&timeval);
    if (logoutfile == NULL)
    {
        // Fall back to console output if unable to open file
        g_print ("%s: g_time_val_to_iso8601(&timeval): %s\n", message);
        return;
    }

    g_fprintf (logoutfile, "%s : %s\n", g_time_val_to_iso8601(&timeval), message);
    fflush(logoutfile);

}

/**
 * @brief Callback function which is invoked when getBaseURL action is invoked and this sets the
 * state variable for base url.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 *
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetBaseUrl */
G_MODULE_EXPORT void
get_url_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //static int counter=0;
    //counter++;
    //g_print ("Got a call back for url %d\n", counter);
    gupnp_service_action_set (action, "BaseUrl", G_TYPE_STRING, url->str, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getBaseTrmUrl action is invoked and this sets the state
 * variable for base TRM Url.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 *
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetBaseTrmUrl */
G_MODULE_EXPORT void
get_trm_url_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back for trm url, value is %s\n", trmurl->str);
    gupnp_service_action_set (action, "BaseTrmUrl", G_TYPE_STRING, trmurl->str, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getPlaybackUrl action is invoked and this sets
 * the state variable for Playback Url.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetPlayBackUrl */
G_MODULE_EXPORT void
get_playback_url_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_message ("Got a call back for playback url, value is %s\n", playbackurl->str);
    if (tune_ready == TRUE)
    {
        //g_message ("Got a call back for playback url, value is %s\n", playbackurl->str);
        gupnp_service_action_set (action, "PlaybackUrl", G_TYPE_STRING, playbackurl->str, NULL);
    }

    else
    {
        //g_message ("Got a call back for playback url, Sending NULL\n", playbackurl->str);
        gupnp_service_action_set (action, "PlaybackUrl", G_TYPE_STRING, "NULL", NULL);
    }
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getGatewayIP action is invoked and this sets
 * the state variable for Gateway IP.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetGatewayIP */
G_MODULE_EXPORT void
get_gwyip_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    gupnp_service_action_set (action, "GatewayIP", G_TYPE_STRING, gwyip->str, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getGatewayIPv6 action is invoked and this sets
 * the state variable for Gateway IPv6.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetGatewayIPv6 */
G_MODULE_EXPORT void
get_gwyipv6_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    gupnp_service_action_set (action, "GatewayIPv6", G_TYPE_STRING, gwyipv6->str, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getGatewayStbIP action is invoked and this sets
 * the state variable for Gateway STB IP.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 *
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetGatewayIP */
G_MODULE_EXPORT void
get_gwystbip_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    gupnp_service_action_set (action, "GatewayStbIP", G_TYPE_STRING, gwystbip->str, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getIpv6Prefix action is invoked and this sets
 * the state variable for IPv6 Prefix.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 *
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetIpv6Prefix */
G_MODULE_EXPORT void
get_ipv6prefix_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    gupnp_service_action_set (action, "Ipv6Prefix", G_TYPE_STRING, ipv6prefix->str, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getHostMacAddress action is invoked and this sets
 * the state variable for Host MAC Address.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetHostMacAddress */
G_MODULE_EXPORT void
get_hostmacaddress_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    gupnp_service_action_set (action, "HostMacAddress", G_TYPE_STRING, hostmacaddress->str, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getBcastMacAddress action is invoked and this sets
 * the state variable for Broadcast MAC Address.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetBcastMacAddress */
G_MODULE_EXPORT void
get_bcastmacaddress_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    gupnp_service_action_set (action, "BcastMacAddress", G_TYPE_STRING, bcastmacaddress->str, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getRecvDevType action is invoked and this sets
 * the state variable for Receive Device Type.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetRecvDevType */
G_MODULE_EXPORT void
get_recvdevtype_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    gupnp_service_action_set (action, "RecvDevType", G_TYPE_STRING, recvdevtype->str, NULL);
    gupnp_service_action_return (action);
}

/* GetDeviceType */
G_MODULE_EXPORT void
get_devicetype_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    gupnp_service_action_set (action, "DeviceType", G_TYPE_STRING, devicetype->str, NULL);
    gupnp_service_action_return (action);
}
/**
 * @brief Callback function which is invoked when getBuildVersion action is invoked and this sets
 * the state variable for Build Version.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetBuildVersion */
G_MODULE_EXPORT void
get_buildversion_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    gupnp_service_action_set (action, "BuildVersion", G_TYPE_STRING, buildversion->str, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getDnsConfig action is invoked and this sets
 * the state variable for DNS Config.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetDnsConfig */
G_MODULE_EXPORT void
get_dnsconfig_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    getdnsconfig();
    gupnp_service_action_set (action, "DnsConfig", G_TYPE_STRING, dnsconfig->str, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getSystemIds action is invoked and this sets
 * the state variable for System Id.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetSystemsIds */
G_MODULE_EXPORT void
get_systemids_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    updatesystemids();
    gupnp_service_action_set (action, "SystemIds", G_TYPE_STRING, systemids->str, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getdataGatewayIPaddress action is invoked and this sets
 * the state variable for DataGatewayIPaddress.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetDataGatewayIPaddress */
G_MODULE_EXPORT void
get_dataGatewayIPaddress_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    gupnp_service_action_set (action, "DataGatewayIPaddress", G_TYPE_STRING, dataGatewayIPaddress->str, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when TimeZone action is invoked and this sets
 * the state variable for Time Zone.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetTimeZone */
G_MODULE_EXPORT void
get_timezone_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    if (devConf->useGliDiag == FALSE)
        gettimezone();
    gupnp_service_action_set (action, "TimeZone", G_TYPE_STRING, dsgtimezone->str, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getRawOffSet action is invoked and this sets
 * the state variable for Raw Offset.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetRawOffSet */
G_MODULE_EXPORT void
get_rawoffset_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    gupnp_service_action_set (action,"RawOffSet", G_TYPE_INT, rawOffset, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getDSTSavings action is invoked and this sets
 * the state variable for DST Savings.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetDSTSavings */
G_MODULE_EXPORT void
get_dstsavings_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    gupnp_service_action_set (action,"DSTSavings", G_TYPE_INT, dstSavings, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getUsesDaylightTime action is invoked and this sets
 * the state variable for Uses Daylight Time.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetUsesDaylightTime */
G_MODULE_EXPORT void
get_usesdaylighttime_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    gupnp_service_action_set (action,"UsesDaylightTime", G_TYPE_BOOLEAN, usesDaylightTime, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getDeviceName action is invoked and this sets
 * the state variable for Uses Service Name.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetDeviceName */
G_MODULE_EXPORT void
get_devicename_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    getdevicename();
    gupnp_service_action_set (action,"DeviceName", G_TYPE_STRING, devicename->str, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getDSTOffset action is invoked and this sets
 * the state variable for DST Offset.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetDSTOffset */
G_MODULE_EXPORT void
get_dstoffset_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    gupnp_service_action_set (action,"DSTOffset", G_TYPE_INT, dstOffset, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getHosts action is invoked and this sets
 * the state variable for Hosts.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetEtcHosts */
G_MODULE_EXPORT void
get_hosts_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    getetchosts();
    gupnp_service_action_set (action, "Hosts", G_TYPE_STRING, etchosts->str, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getIsGateway action is invoked and this sets
 * the state variable for Gatway is active or not.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetIsGateway */
G_MODULE_EXPORT void
get_isgateway_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    gupnp_service_action_set (action, "IsGateway", G_TYPE_BOOLEAN, isgateway, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when getRequiresTRM action is invoked and this sets
 * the state variable for Requiring TRM.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* IsTrmRequired */
G_MODULE_EXPORT void
get_requirestrm_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    gupnp_service_action_set (action, "RequiresTRM", G_TYPE_BOOLEAN, requirestrm, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when GetCompatibleUIs action is invoked and this sets
 * the state variable for InputDeviceProfile, UIFilter and UIListing.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetRuiBaseUrl */
G_MODULE_EXPORT void
get_rui_url_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    if (getruiurl()!=TRUE)  //initializes ruirul->str
        //must init every callback because it generates a unique
        //device number for each return value.
        g_print("Error in initializing RUI url value\n");

    //g_print ("Got a call back for Ruiurl, value is %s\n", ruiurl->str);
    gupnp_service_action_get (action,"InputDeviceProfile", G_TYPE_STRING, inDevProfile->str, NULL);
    gupnp_service_action_get (action,"UIFilter", G_TYPE_STRING, uiFilter->str,NULL);
    gupnp_service_action_set (action, "UIListing", G_TYPE_STRING, ruiurl->str, NULL);
    gupnp_service_action_return (action);
}


/*
 * State Variable query handlers
 */

/**
 * @brief Callback function which is invoked when getUrl action is invoked.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query)variable.
 * @param[in] value  New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* BaseUrl */
G_MODULE_EXPORT void
query_url_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, url->str);
}

/**
 * @brief Callback function which is invoked when TrmUrl action is invoked and this sets
 * the state variable with a new TRM Url value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* BaseTrmUrl */
G_MODULE_EXPORT void
query_trm_url_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, trmurl->str);
}

/**
 * @brief Callback function which is invoked when PlaybackUrl action is invoked and this sets
 * the state variable with a new playback url.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* PlaybackUrl */
G_MODULE_EXPORT void
query_playback_url_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    if (tune_ready == TRUE)
    {
        //g_message ("Got a query for playback url, sending %s\n", playbackurl->str);
        g_value_init (value, G_TYPE_STRING);
        g_value_set_string (value, playbackurl->str);
    }
    else
    {
        //g_message ("Got a query for playback url, sending NULL");
        g_value_init (value, G_TYPE_STRING);
        g_value_set_string (value, "NULL");

    }
}

/**
 * @brief Callback function which is invoked when DataGatewayIPaddress action is invoked and this sets
 * the state variable with a new DataGatewayIPaddress.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* DataGatewayIPaddress */
G_MODULE_EXPORT void
query_dataGatewayIPaddress_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, dataGatewayIPaddress->str);
}



/**
 * @brief Callback function which is invoked when DeviceName action is invoked and this sets
 * the state variable with a new device name.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* DeviceName */
G_MODULE_EXPORT void
query_devicename_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, devicename->str);
}

/**
 * @brief Callback function which is invoked when GatewayIP action is invoked and this sets
 * the state variable with a new Gateway IP.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GatewayIP */
G_MODULE_EXPORT void
query_gwyip_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, gwyip->str);
}

/**
 * @brief Callback function which is invoked when Ipv6Prefix action is invoked and this sets
 * the state variable with a new value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GatewayIPv6 */
G_MODULE_EXPORT void
query_gwyipv6_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, gwyipv6->str);
}

/**
 * @brief Callback function which is invoked when GatewayStbIP action is invoked and this sets
 * the state variable with a new value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GatewayStbIP */
G_MODULE_EXPORT void
query_gwystbip_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, gwystbip->str);
}

/**
 * @brief Callback function which is invoked when Ipv6Prefix action is invoked and this sets
 * the state variable with a new value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* Ipv6Prefix */
G_MODULE_EXPORT void
query_ipv6prefix_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, ipv6prefix->str);
}

/**
 * @brief Callback function which is invoked when HostMacAddress action is invoked and this sets
 * the state variable with a new value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* HostMacAddress */
G_MODULE_EXPORT void
query_hostmacaddress_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, hostmacaddress->str);
}

/**
 * @brief Callback function which is invoked when BcastMacAddress action is invoked and this sets
 * the state variable with a new value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* BcastMacAddress */
G_MODULE_EXPORT void
query_bcastmacaddress_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, bcastmacaddress->str);
}

/**
 * @brief Callback function which is invoked when RecvDevType action is invoked and this sets
 * the state variable with a new value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* RecvDevType */
G_MODULE_EXPORT void
query_recvdevtype_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, recvdevtype->str);
}

/* DeviceType */
G_MODULE_EXPORT void
query_devicetype_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, devicetype->str);
}

/**
 * @brief Callback function which is invoked when BuildVersion action is invoked and this sets
 * the state variable with a new value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* BuildVersion */
G_MODULE_EXPORT void
query_buildversion_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, buildversion->str);
}

/**
 * @brief Callback function which is invoked when DnsConfig action is invoked and this sets
 * the state variable with a new value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* DnsConfig */
G_MODULE_EXPORT void
query_dnsconfig_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, dnsconfig->str);
}

/**
 * @brief Callback function which is invoked when SystemIds action is invoked and this sets
 * the state variable with a new value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* SystemIds */
G_MODULE_EXPORT void
query_systemids_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{

    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, systemids->str);
}

/**
 * @brief Callback function which is invoked when TimeZone action is invoked and this sets
 * the state variable with a new value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* TimeZone */
G_MODULE_EXPORT void
query_timezone_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    if (devConf->useGliDiag == FALSE)
        gettimezone();
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, dsgtimezone->str);
}

/**
 * @brief Callback function which is invoked when Hosts action is invoked and this sets
 * the state variable with a new value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* EtcHosts */
G_MODULE_EXPORT void
query_hosts_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{

    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, etchosts->str);
}

/**
 * @brief Callback function which is invoked when IsGateway action is invoked and this sets
 * the state variable with a new value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* IsGateway */
G_MODULE_EXPORT void
query_isgateway_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{

    g_value_init (value, G_TYPE_BOOLEAN);
    g_value_set_boolean (value, isgateway);
}

/**
 * @brief Callback function which is invoked when RequiresTRM action is invoked and this sets
 * the state variable with a new value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* RequiresTRM */
G_MODULE_EXPORT void
query_requirestrm_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{

    g_value_init (value, G_TYPE_BOOLEAN);
    g_value_set_boolean (value, requirestrm);
}

/**
 * @brief Callback function which is invoked when RuiUrl action is invoked and this sets
 * the state variable with a new value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* RuiUrl */
G_MODULE_EXPORT void
query_rui_url_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, ruiurl->str);
}

/**
 * @brief Callback function which is invoked when RawOffSet action is invoked and this sets
 * the state variable with a new value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* RawOffSet */
G_MODULE_EXPORT void
query_rawoffset_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_INT);
    g_value_set_int (value, rawOffset);
}

/**
 * @brief Callback function which is invoked when DSTOffset action is invoked and this sets
 * the state variable with a new value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* DSTOffset */
G_MODULE_EXPORT void
query_dstoffset_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_INT);
    g_value_set_int (value, dstOffset);
}

/**
 * @brief Callback function which is invoked when DSTSavings action is invoked and this sets
 * the state variable with a new value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* DSTSavings */
G_MODULE_EXPORT void
query_dstsavings_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_INT);
    g_value_set_int (value, dstSavings);
}

/**
 * @brief Callback function which is invoked when UsesDaylightTime action is invoked and this sets
 * the state variable with a new value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* UsesDaylightTime */
G_MODULE_EXPORT void
query_usesdaylighttime_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_BOOLEAN);
    g_value_set_boolean (value, usesDaylightTime);
}

void* checkMainLoopRunning()
{
    guint checkMainLoopCounter=0;
    while(true)
    {
        if (! g_main_loop_is_running(main_loop))
        {
          if(checkMainLoopCounter < 7)
            g_message("TELEMETRY_XUPNP_DEVICE_MAIN_LOOP_NOT_RUNNING");
          checkMainLoopCounter++;
        }
        usleep(SLEEP_INTERVAL);
    }
}

int
main (int argc, char **argv)
{

    GThread *thread;

    GError *error = NULL;
    url = g_string_new("null");
    trmurl = g_string_new("null");
    trmurlCVP2 = g_string_new("null");
    playbackurl = g_string_new("null");
    playbackurlCVP2 = g_string_new("null");
    gwyip = g_string_new("null");
    gwyipv6 = g_string_new("null");
    gwystbip = g_string_new("null");
    ipv6prefix = g_string_new("null");
    gwyipCVP2 = g_string_new("null");
    dnsconfig = g_string_new("null");
    systemids = g_string_new("null");
    dsgtimezone = g_string_new("null");
    etchosts = g_string_new("null");
    serial_num = g_string_new("null");
    channelmap_id = dac_id = plant_id = vodserver_id = 0;
    isgateway=TRUE;
    requirestrm=TRUE;
    service_ready=FALSE;
    tune_ready=FALSE;
    ruiurl = g_string_new("null");
    inDevProfile = g_string_new("null");
    uiFilter = g_string_new("null");
    recv_id = g_string_new("null");
    partner_id = g_string_new("null");
    hostmacaddress = g_string_new("null");
    bcastmacaddress = g_string_new("null");
    devicename = g_string_new("null");
    buildversion = g_string_new("null");
    recvdevtype = g_string_new("null");
    devicetype = g_string_new("null");
#if !defined (NO_MOCA_FEATURE_SUPPORT)
    mocaIface = g_string_new("null");
#endif
    wifiIface = g_string_new("null");
    dataGatewayIPaddress = g_string_new("null");


    char ipAddressBuffer[INET6_ADDRSTRLEN];
    char stbipAddressBuffer[INET6_ADDRSTRLEN];

    g_thread_init (NULL);
    g_type_init ();

    dstOffset=1; //dstoffset can be only 0 or 60 so intializing with 1

#ifdef ENABLE_BREAKPAD
    installExceptionHandler();
#endif
    if (argc < 2)
    {
        fprintf(stderr, "Error in arguments\nUsage: %s config file name (eg: %s /etc/xdevice.conf)\n", argv[0], argv[0]);
#ifndef CLIENT_XCAL_SERVER
        exit(1);
#else
        devConf = g_new(ConfSettings,1);
#endif
    }
    else
    {

        const char* configfilename = argv[1];

        if (readconffile(configfilename)==FALSE)
        {
            g_print("Unable to find xdevice config, giving up\n");
#ifndef CLIENT_XCAL_SERVER
            exit(1);
#endif
        }
    }
#ifdef CLIENT_XCAL_SERVER
    if(! (devConf->bcastPort))
        devConf->bcastPort=BCAST_PORT;
    if(! (devConf->devPropertyFile))
        devConf->devPropertyFile=g_strdup(DEVICE_PROPERTY_FILE);
    if(! (devConf->deviceNameFile))
        devConf->deviceNameFile=g_strdup(DEVICE_NAME_FILE);
    if(! (devConf->logFile))
        devConf->logFile=g_strdup(LOG_FILE);
    if(! (devConf->devXmlPath))
        devConf->devXmlPath=g_strdup(DEVICE_XML_PATH);
    if(! (devConf->devXmlFile))
        devConf->devXmlFile=g_strdup(DEVICE_XML_FILE);
    devConf->allowGwy=FALSE;
    devConf->useIARM=TRUE;
    devConf->useGliDiag=TRUE;
#endif

    char* logfilename = argv[2];
    if(logfilename)
    {
      logoutfile = g_fopen (logfilename, "a");
    }
    else
    {
      g_message("xupnp not handling the logging");
    }
    if(logoutfile)
    {
      g_log_set_handler(G_LOG_DOMAIN, G_LOG_LEVEL_INFO | G_LOG_LEVEL_MESSAGE | \
                      G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_ERROR, xupnp_logger, NULL);
    }
    g_message("Starting xdevice service on interface %s", devConf->bcastIf);
    g_print("Starting xdevice service on interface %s\n", devConf->bcastIf);

    //const char* ifname = devConf->bcastIf;
    char* xmlfilename = g_strconcat(devConf->devXmlPath, "/", devConf->devXmlFile, NULL);
    const guint host_port = devConf->bcastPort;
    if (devConf->devPropertyFile != NULL)
    {
        if (readDevFile(devConf->devPropertyFile)==TRUE)
        {
#if !defined (NO_MOCA_FEATURE_SUPPORT)
            g_message("Receiver Type : %s Build Version :  %s Device Type: %s moca %s wifi %s \n", recvdevtype->str,buildversion->str,devicetype->str,mocaIface->str,wifiIface->str);
#else
            g_message("Receiver Type : %s Build Version :  %s Device Type: %s wifi %s \n", recvdevtype->str,buildversion->str,devicetype->str,wifiIface->str);
#endif
        }
        else
        {
            g_message(" ERROR in getting Receiver Type : %s Build Version :  %s \n", recvdevtype->str,buildversion->str);
#if !defined (NO_MOCA_FEATURE_SUPPORT)
            g_message("Receiver Type : %s Build Version :  %s Device Type: %s moca %s wifi %s \n", recvdevtype->str,buildversion->str,devicetype->str,mocaIface->str,wifiIface->str);
#else
            g_message("Receiver Type : %s Build Version :  %s Device Type: %s wifi %s \n", recvdevtype->str,buildversion->str,devicetype->str,wifiIface->str);
#endif
        }
    }

//	int result = getipaddress(devConf->bcastIf, ipAddressBuffer);
#ifndef CLIENT_XCAL_SERVER
    if( access(devConf->ipv6FileLocation, F_OK ) != -1 )
        ipv6Enabled=TRUE;
    int result = getipaddress(devConf->bcastIf,ipAddressBuffer,TRUE);
    if (!result)
    {
        fprintf(stderr,"In Ipv6 Could not locate the link  local ipv6 address of the broadcast interface %s\n", devConf->bcastIf);
        g_critical("In Ipv6 Could not locate the link local ipv6 address of the broadcast interface %s\n", devConf->bcastIf);
        exit(1);
    }
    g_string_assign(gwyipv6, ipAddressBuffer);
    result = getipaddress(devConf->bcastIf,ipAddressBuffer,FALSE);

    if (!result)
    {
        fprintf(stderr,"Could not locate the link local v4 ipaddress of the broadcast interface %s\n", devConf->bcastIf);
        g_critical("Could not locate the link local v4 ipaddress of the broadcast interface %s\n", devConf->bcastIf);
        exit(1);
    }
    else
        g_message("ipaddress of the interface %s\n", ipAddressBuffer);
#else
#if !defined (NO_MOCA_FEATURE_SUPPORT)
    int result = getipaddress(mocaIface->str,ipAddressBuffer,FALSE);
    if (!result)
    {
        g_message("Could not locate the ipaddress of the broadcast interface %s",mocaIface->str);
        result = getipaddress(wifiIface->str,ipAddressBuffer,FALSE);
        if (!result)
        {
            g_message("Could not locate the ipaddress of the wifi broadcast interface %s",wifiIface->str);
            g_critical("Could not locate the link local v4 ipaddress of the broadcast interface %s\n", devConf->bcastIf);
            exit(1);
        }
        else
        {
            devConf->bcastIf=g_strdup(wifiIface->str);
        }
    }
    else
    {
        devConf->bcastIf=g_strdup(mocaIface->str);
    }
    g_message("Starting xdevice service on interface %s", devConf->bcastIf);
#endif
#endif



    //readconffile();
    g_message("Broadcast Network interface: %s\n", devConf->bcastIf);
    g_message("Dev XML File Name: %s\n", devConf->devXmlFile);
    g_message("Use IARM value is: %u\n", devConf->useIARM);

    g_string_assign(gwyip, ipAddressBuffer);

    //Init IARM Events
#if defined(USE_XUPNP_IARM_BUS)
    gboolean iarminit = XUPnP_IARM_Init();
    if (iarminit==true)
    {
        //g_print("IARM init success");
        g_message("XUPNP IARM init success");
#ifndef CLIENT_XCAL_SERVER
        getSystemValues();
#endif
    }
    else
    {
        //g_print("IARM init failure");
        g_critical("XUPNP IARM init failed");
    }
#endif //#if defined(USE_XUPNP_IARM_BUS)

#ifndef CLIENT_XCAL_SERVER
    if(devConf->hostMacIf != NULL)
    {
        const gchar* hostmac=(gchar*)getmacaddress(devConf->hostMacIf);
        if(hostmac)
        {
            g_message("MAC address in  interface: %s  %s \n", devConf->hostMacIf,hostmac);
	}
	else
	{
            g_message("failed to retrieve macaddress on interface %s ", devConf->hostMacIf);
        }
        g_string_assign(hostmacaddress,hostmac);
        g_message("Host mac address is %s",hostmacaddress->str);
    }
#endif
    if (devConf->bcastIf != NULL )
    {
        const gchar* bcastmac=(gchar*)getmacaddress(devConf->bcastIf);
        if(bcastmac)
        {
            g_message("Broadcast MAC address in  interface: %s  %s \n", devConf->bcastIf,bcastmac);
        }
        else
        {
            g_message("failed to retrieve macaddress on interface %s ", devConf->bcastIf);
        }
        g_string_assign(bcastmacaddress,bcastmac);
        g_message("bcast mac address is %s",bcastmacaddress->str);
    }
    if (devConf->deviceNameFile != NULL)
    {
        if (getdevicename() == TRUE)
        {
            g_message("Device Name : %s ", devicename->str);
        }
        else
        {
            g_message(" ERROR in getting Device Name ");
        }
    }
    //status = FALSE;
    //g_string_assign(recv_id, argv[2]);
    g_message("getting the receiver id from %s", GET_DEVICEID_SCRIPT);
    recv_id=getID(RECEIVER_ID);

    g_string_printf(url, "http://%s:8080/videoStreamInit?recorderId=%s", ipAddressBuffer, recv_id->str);
    g_print ("The url is now %s.\n", url->str);

#ifndef CLIENT_XCAL_SERVER
    if (devConf->enableTRM == FALSE)
    {
        requirestrm=FALSE;
        g_string_printf(trmurl, "NULL");
    }
    else
    {
        requirestrm=TRUE;
        g_string_printf(trmurl, "ws://%s:9988", ipAddressBuffer);
    }
#endif
    if(devConf->allowGwy == FALSE)
    {
        isgateway=FALSE;
    }


#ifndef CLIENT_XCAL_SERVER
    g_string_printf(playbackurl, "http://%s:8080/hnStreamStart?deviceId=%s&DTCP1HOST=%s&DTCP1PORT=5000", ipAddressBuffer, recv_id->str, ipAddressBuffer);

    if (getdnsconfig()==TRUE)
    {
        g_print("Contents of dnsconfig is %s\n", dnsconfig->str);

    }
    if (updatesystemids()==TRUE)
    {
        g_message("System ids are %s\n", systemids->str);
    }
    else
    {
        g_warning("Error in finding system ids\n");
    }


#if defined(USE_XUPNP_IARM_BUS)
    while ((strlen(g_strstrip(serial_num->str)) < 6) || (is_alphanum(serial_num->str) == FALSE))
    {
        g_message("XUPnP: Waiting for Serial Number\n");
        usleep(5000000);
    }
    g_message("Received Serial Number:%s", serial_num->str);
#else
    if (getserialnum(serial_num)==TRUE)
    {
        g_print("Serial Number is %s\n", serial_num->str);
    }
#endif
#else
    if (getserialnum(serial_num)==TRUE)
    {
        g_print("Serial Number is %s\n", serial_num->str);
    }

#endif

#ifndef CLIENT_XCAL_SERVER
    if (getetchosts()==TRUE)
    {
        g_print("EtcHosts Content is \n%s\n", etchosts->str);
    }
    else
    {
        g_print("Error in getting etc hosts\n");
    }
#else
    getRouteData();
#endif
    const char* struuid = g_strconcat("uuid:", g_strstrip(recv_id->str),NULL);
    result = updatexmldata(xmlfilename, struuid, serial_num->str, "XFINITY"); // BasicDevice.xml currently does not need multi-tenancy support per RDK-8190. (May come in as part of some other ticket, in which case replace "XFINITY" with getFriendlyName().)

    if (!result)
    {
        fprintf(stderr,"Failed to open the device xml file %s\n", xmlfilename);
        exit(1);
    }
    else
        fprintf(stderr,"Updated the device xml file %s\n", xmlfilename);

#ifndef GUPNP_1_2
    upnpContext = gupnp_context_new (NULL, devConf->bcastIf, devConf->bcastPort, &error);
#else
    upnpContext = gupnp_context_new (devConf->bcastIf, devConf->bcastPort, &error);
#endif
    if (error) {
        g_printerr ("Error creating the Broadcast context: %s\n",
                    error->message);
        /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
        g_clear_error(&error);
        return EXIT_FAILURE;
    }


    gupnp_context_set_subscription_timeout(upnpContext, 0);
#ifndef GUPNP_1_2
    dev = gupnp_root_device_new (upnpContext, devConf->devXmlFile, devConf->devXmlPath);
#else
    dev = gupnp_root_device_new (upnpContext, devConf->devXmlFile, devConf->devXmlPath, &error);
#endif

#ifndef CLIENT_XCAL_SERVER
    if (devConf->disableTuneReady == FALSE)
    {
        while (FALSE == tune_ready)
        {
            g_message("XUPnP: Waiting for Tune Ready\n");
            usleep(5000000);
        }
        //g_message("Received Tune Ready:%u", tune_ready);
    }
    else
    {
        g_message("Tune Ready check is disabled - Setting tune_ready to TRUE");
        tune_ready=TRUE;
    }
    if((devConf->allowGwy == TRUE) && (ipv6Enabled==TRUE) && (devConf->ipv6PrefixFile != NULL))
    {
        while(access(devConf->ipv6PrefixFile, F_OK ) == -1 )
        {

            g_message(" Waiting to get  IPv6 prefix file ");
            usleep(5000000);
        }
        while (getipv6prefix() == FALSE)
        {

            g_message(" V6 prefix is not yet updated in file %s ",devConf->ipv6PrefixFile);
            usleep(2000000);
        }
        g_message("IPv6 prefix : %s ", ipv6prefix->str);
    }
    else
    {
	 g_message("Box is in IPV4 or ipv6 prefix is empty or  Not a gateway  ipv6enabled = %d ipv6PrefixFile = %s allowGwy = %d ",ipv6Enabled,devConf->ipv6PrefixFile,devConf->allowGwy);
    }
    if(devConf->hostMacIf != NULL)
    {
        result = getipaddress(devConf->hostMacIf,stbipAddressBuffer,ipv6Enabled);

        if (!result)
        {
            g_message("Could not locate the ipaddress of the host mac interface %s\n", devConf->hostMacIf);
        }
        else
            g_message("ipaddress of the interface %s\n", stbipAddressBuffer);

        g_string_assign(gwystbip, stbipAddressBuffer);
    }
#endif
    gupnp_root_device_set_available (dev, TRUE);
    upnpService = gupnp_device_info_get_service
              (GUPNP_DEVICE_INFO (dev), "urn:schemas-upnp-org:service:DiscoverFriendlies:1");
    if (!upnpService) {
        g_printerr ("Cannot get DiscoverFriendlies service\n");

        return EXIT_FAILURE;
    }

#ifdef ENABLE_SD_NOTIFY
    sd_notifyf(0, "READY=1\n"
              "STATUS=xcal-device is Successfully Initialized\n"
              "MAINPID=%lu",
              (unsigned long) getpid());
#endif


    g_signal_connect (upnpService, "action-invoked::GetBaseUrl", G_CALLBACK (get_url_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetBaseTrmUrl", G_CALLBACK (get_trm_url_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetGatewayIP", G_CALLBACK (get_gwyip_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetGatewayIPv6", G_CALLBACK (get_gwyipv6_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetIpv6Prefix", G_CALLBACK (get_ipv6prefix_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetGatewayStbIP", G_CALLBACK (get_gwystbip_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetDnsConfig", G_CALLBACK (get_dnsconfig_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetSystemIds", G_CALLBACK (get_systemids_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetTimeZone", G_CALLBACK (get_timezone_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetHosts", G_CALLBACK (get_hosts_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetRequiresTRM", G_CALLBACK (get_requirestrm_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetHostMacAddress", G_CALLBACK (get_hostmacaddress_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetRawOffSet", G_CALLBACK (get_rawoffset_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetDSTOffset", G_CALLBACK (get_dstoffset_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetDSTSavings", G_CALLBACK (get_dstsavings_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetUsesDaylightTime", G_CALLBACK (get_usesdaylighttime_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetPlaybackUrl", G_CALLBACK (get_playback_url_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetDataGatewayIPaddress", G_CALLBACK (get_dataGatewayIPaddress_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetDeviceName", G_CALLBACK (get_devicename_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetIsGateway", G_CALLBACK (get_isgateway_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetBcastMacAddress", G_CALLBACK (get_bcastmacaddress_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetRecvDevType", G_CALLBACK (get_recvdevtype_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetDeviceType", G_CALLBACK (get_devicetype_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetBuildVersion", G_CALLBACK (get_buildversion_cb), NULL);

    g_signal_connect (upnpService, "query-variable::Url", G_CALLBACK (query_url_cb), NULL);
    g_signal_connect (upnpService, "query-variable::TrmUrl", G_CALLBACK (query_trm_url_cb), NULL);
    g_signal_connect (upnpService, "query-variable::GatewayIP", G_CALLBACK (query_gwyip_cb), NULL);
    g_signal_connect (upnpService, "query-variable::GatewayIPv6", G_CALLBACK (query_gwyipv6_cb), NULL);
    g_signal_connect (upnpService, "query-variable::Ipv6Prefix", G_CALLBACK (query_ipv6prefix_cb), NULL);
    g_signal_connect (upnpService, "query-variable::GatewayStbIP", G_CALLBACK (query_gwystbip_cb), NULL);
    g_signal_connect (upnpService, "query-variable::DnsConfig", G_CALLBACK (query_dnsconfig_cb), NULL);
    g_signal_connect (upnpService, "query-variable::SystemIds", G_CALLBACK (query_systemids_cb), NULL);
    g_signal_connect (upnpService, "query-variable::TimeZone", G_CALLBACK (query_timezone_cb), NULL);
    g_signal_connect (upnpService, "query-variable::Hosts", G_CALLBACK (query_hosts_cb), NULL);
    g_signal_connect (upnpService, "query-variable::RequiresTRM", G_CALLBACK (query_requirestrm_cb), NULL);
    g_signal_connect (upnpService, "query-variable::HostMacAddress", G_CALLBACK (query_hostmacaddress_cb), NULL);
    g_signal_connect (upnpService, "query-variable::RawOffSet", G_CALLBACK (query_rawoffset_cb), NULL);
    g_signal_connect (upnpService, "query-variable::DSTOffset", G_CALLBACK (query_dstoffset_cb), NULL);
    g_signal_connect (upnpService, "query-variable::DSTSavings", G_CALLBACK (query_dstsavings_cb), NULL);
    g_signal_connect (upnpService, "query-variable::UsesDaylightTime", G_CALLBACK (query_usesdaylighttime_cb), NULL);
    g_signal_connect (upnpService, "query-variable::PlaybackUrl", G_CALLBACK (query_playback_url_cb), NULL);
    g_signal_connect (upnpService, "query-variable::DataGatewayIPaddress", G_CALLBACK (query_dataGatewayIPaddress_cb), NULL);
    g_signal_connect (upnpService, "query-variable::DeviceName", G_CALLBACK (query_devicename_cb), NULL);
    g_signal_connect (upnpService, "query-variable::IsGateway", G_CALLBACK (query_isgateway_cb), NULL);
    g_signal_connect (upnpService, "query-variable::BcastMacAddress", G_CALLBACK (query_bcastmacaddress_cb), NULL);
    g_signal_connect (upnpService, "query-variable::RecvDevType", G_CALLBACK (query_recvdevtype_cb), NULL);
    g_signal_connect (upnpService, "query-variable::DeviceType", G_CALLBACK (query_devicetype_cb), NULL);
    g_signal_connect (upnpService, "query-variable::BuildVersion", G_CALLBACK (query_buildversion_cb), NULL);

    service_ready=TRUE;

#ifndef CLIENT_XCAL_SERVER
    /*Code to handle RUI publishing*/
    if (devConf->enableCVP2)
    {
        char* cvpxmlfilename = g_strconcat(g_strstrip(devConf->devXmlPath), "/", g_strstrip(devConf->cvpXmlFile), NULL);
        g_print("Starting CVP2 Service with %s\n", cvpxmlfilename);

        char * struuidcvp = NULL;
        GString* mac = get_eSTBMAC();
        if(mac)
        {
            struuidcvp = g_strconcat("uuid:AA5859B7-EFF4-42FD-BB92-", mac->str, NULL);
            g_string_free(mac,TRUE);
            mac = NULL;
        }

        g_print("RemoteUIServerDevice UDN value: %s\n",struuidcvp);
        partner_id=getID(PARTNER_ID);

        if(struuidcvp)
        {
            result = updatexmldata(cvpxmlfilename, struuidcvp, serial_num->str, getFriendlyName());
            g_free(struuidcvp);
        }

        if(cvpxmlfilename)
        {
            g_free( cvpxmlfilename);
        }

        if (!result)
        {
            g_printerr("Failed to open the RemoteUIServerDevice xml file\n");
            exit(1);
        }
        else
            g_print("Updated the RemoteUIServerDevice xml file\n");

#ifndef GUPNP_1_2
       cvpcontext = gupnp_context_new (NULL, devConf->cvpIf, devConf->cvpPort, &error);
#else
       cvpcontext = gupnp_context_new (devConf->cvpIf, devConf->cvpPort, &error);
#endif
        if (error) {
            g_printerr ("Error creating the CVP context: %s\n", error->message);
            /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
            g_clear_error(&error);
            return EXIT_FAILURE;
        }


        gupnp_context_set_subscription_timeout(cvpcontext, 0);
#ifndef GUPNP_1_2
        cvpdev = gupnp_root_device_new (cvpcontext, devConf->cvpXmlFile, devConf->devXmlPath);
#else
        cvpdev = gupnp_root_device_new (cvpcontext, devConf->cvpXmlFile, devConf->devXmlPath, &error);
#endif
        gupnp_root_device_set_available (cvpdev, TRUE);

        /* Get the CVP service from the root device */
        cvpservice = gupnp_device_info_get_service
                     (GUPNP_DEVICE_INFO (cvpdev), "urn:schemas-upnp-org:service:RemoteUIServer:1");
        if (!cvpservice) {
            g_printerr ("Cannot get RemoteUI service\n");

            return EXIT_FAILURE;
        }
        g_signal_connect (cvpservice, "action-invoked::GetCompatibleUIs", G_CALLBACK (get_rui_url_cb), NULL);
    }

#endif
    //control the announcement frequency and life time
    /*
    GSSDPResourceGroup *ssdpgrp = gupnp_root_device_get_ssdp_resource_group(dev);
    guint msgdelay = gssdp_resource_group_get_message_delay(ssdpgrp);
    guint msgage = gssdp_resource_group_get_max_age(ssdpgrp);
    g_print("Message delay is %u, Message max age is %u", msgdelay, msgage);
     * /

    /* Run the main loop */
    main_loop = g_main_loop_new (NULL, FALSE);
    thread = g_thread_create(checkMainLoopRunning, NULL,FALSE, NULL);
    g_main_loop_run (main_loop);

    /* Cleanup */
    g_main_loop_unref (main_loop);
    g_object_unref (upnpService);
    g_object_unref (dev);
    g_object_unref (upnpContext);

    return EXIT_SUCCESS;
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
int getipaddress(const char* ifname, char* ipAddressBuffer, gboolean ipv6Enabled)
{
    struct ifaddrs * ifAddrStruct=NULL;
    struct ifaddrs * ifa=NULL;
    void * tmpAddrPtr=NULL;
    errno_t rc       = -1;
    int     ind      = -1;
    getifaddrs(&ifAddrStruct);
    //char addressBuffer[INET_ADDRSTRLEN] = NULL;
    int found=0;
    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ipv6Enabled == TRUE)
        {   // check it is IP6
            // is a valid IP6 Address
            rc = strcmp_s(ifa->ifa_name, strlen(ifa->ifa_name), ifname, &ind);
            ERR_CHK(rc);
            if (((ind == 0) && (rc == EOK)) && (ifa ->ifa_addr->sa_family==AF_INET6))
            {
                tmpAddrPtr=&((struct sockaddr_in6  *)ifa->ifa_addr)->sin6_addr;

                inet_ntop(AF_INET6, tmpAddrPtr, ipAddressBuffer, INET6_ADDRSTRLEN);

                //if (strcmp(ifa->ifa_name,"eth0")==0trcmp0(g_strstrip(devConf->mocaMacIf),ifname) == 0)
                if ((g_strcmp0(g_strstrip(devConf->bcastIf),ifname) == 0) && (IN6_IS_ADDR_LINKLOCAL(tmpAddrPtr)) || ((!(IN6_IS_ADDR_LINKLOCAL(tmpAddrPtr))) && (g_strcmp0(g_strstrip(devConf->hostMacIf),ifname) == 0)))
                {
                    found = 1;
                    break;
                }
            }
        }

        else {

            if (ifa ->ifa_addr->sa_family==AF_INET) { // check it is IP4
                // is a valid IP4 Address
                tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;

                inet_ntop(AF_INET, tmpAddrPtr, ipAddressBuffer, INET_ADDRSTRLEN);

                //if (strcmp(ifa->ifa_name,"eth0")==0)
                rc = strcmp_s(ifa->ifa_name, strlen(ifa->ifa_name), ifname, &ind);
                ERR_CHK(rc);
                if((ind == 0) && (rc == EOK))
                {
                    found = 1;
                    break;
                }
            }
        }
    }

    if (ifAddrStruct!=NULL) freeifaddrs(ifAddrStruct);
    return found;

}

/**
 * @brief This function is used to get the mac address of the target device.
 *
 * @param[in] ifname Name of the network interface.
 *
 * @return Returns the mac address of the interface given.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
gchar* getmacaddress(const gchar* ifname)
{
    errno_t rc = -1;
    int fd;
    struct ifreq ifr;
    unsigned char *mac;
    GString *data=g_string_new(NULL);

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    rc = strcpy_s(ifr.ifr_name , IFNAMSIZ-1, ifname);
    ERR_CHK(rc);
    if(rc == EOK)
    {
        ioctl(fd, SIOCGIFHWADDR, &ifr);

        close(fd);

        mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

        //display mac address
        //g_print("Mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        g_string_printf(data,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    return data->str;
}

/**
 * @brief This function is used to get the DNS value from DNS mask configuration file.
 *
 * @return Returns TRUE if successfully gets the DNS configuration, else returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
gboolean getdnsconfig(void)
{
    GError                  *error=NULL;
    gboolean                result = FALSE;
    gchar* dnsconfigfile = NULL;
    GString* strdnsconfig = g_string_new(NULL);

    if (devConf->dnsFile == NULL)
    {
        g_warning("dnsconfig file name not found in config");
        return result;
    }
    result = g_file_get_contents (devConf->dnsFile, &dnsconfigfile, NULL, &error);
    if (result == FALSE)
    {
        g_warning("Problem in reading dnsconfig file %s", error->message);
    }
    else
    {
        gchar **tokens = g_strsplit_set(dnsconfigfile,"\n\0", -1);
        //etchosts->str = g_strjoinv(";", tokens);
        guint toklength = g_strv_length(tokens);
        guint loopvar=0;
        gboolean firsttok = TRUE;

        for (loopvar=0; loopvar<toklength; loopvar++)
        {
            if ((strlen(g_strstrip(tokens[loopvar])) > 0))
            {
                //    		g_message("Token is %s\n",g_strstrip(tokens[loopvar]));
                if (firsttok == FALSE)
                {
                    g_string_append_printf(strdnsconfig,"%s;",g_strstrip(tokens[loopvar]));
                }
                else
                {
                    g_string_printf(strdnsconfig,"%s;",g_strstrip(tokens[loopvar]));
                    firsttok = FALSE;
                }
            }
        }

        g_string_assign(dnsconfig, strdnsconfig->str);
        g_string_free(strdnsconfig, TRUE);
        g_message("DNS Config is %s",dnsconfig->str);
        g_strfreev(tokens);
    }

    if(error)
    {
        /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
        g_clear_error(&error);
    }

    return result;
}

/**
 * @brief This function is used to update the system Ids such as channelMapId, controllerId, plantId
 * and vodServerId.
 *
 * @return Returns TRUE if successfully updates the system ids, else returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
gboolean updatesystemids(void)
{
    if (devConf->useGliDiag == TRUE)
    {
        g_string_printf(systemids, "channelMapId:%lu;controllerId:%lu;plantId:%lu;vodServerId:%lu",
                        channelmap_id,dac_id,plant_id,vodserver_id);
        return TRUE;
    }
    else
    {
        gchar* diagfile;
        unsigned long diagid=0;
        gboolean  result = FALSE;
        GError *error=NULL;

        if (devConf->diagFile == NULL)
        {
            g_warning("diag file name not found in config");
            return result;
        }
        result = g_file_get_contents (devConf->diagFile, &diagfile, NULL, &error);
        if (result == FALSE) {
            g_string_assign(systemids, "channelMapId:0;controllerId:0;plantId:0;vodServerId:0");
        }
        else
        {
            diagid = getidfromdiagfile("channelMapId", diagfile);
            g_string_printf(systemids, "channelMapId:%lu;", diagid);
            diagid = getidfromdiagfile("controllerId", diagfile);
            g_string_append_printf(systemids, "controllerId:%lu;", diagid);
            diagid = getidfromdiagfile("plantId", diagfile);
            g_string_append_printf(systemids, "plantId:%lu;", diagid);
            diagid = getidfromdiagfile("vodServerId", diagfile);
            g_string_append_printf(systemids, "vodServerId:%lu", diagid);
        }


        if(error)
        {
            /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
            g_clear_error(&error);
        }

        return result;
    }
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
unsigned long getidfromdiagfile(const gchar *diagparam, const gchar* diagfilecontents)
{

    unsigned long diagid=0;
    gchar **tokens = g_strsplit_set(diagfilecontents,":,{}", -1);
    guint toklength = g_strv_length(tokens);
    guint loopvar=0;

    for (loopvar=0; loopvar<toklength; loopvar++)
    {
        if (g_strrstr(g_strstrip(tokens[loopvar]), diagparam))
        {
            if ((loopvar+1) < toklength )
                diagid=strtoul(tokens[loopvar+1], NULL, 10);
        }
    }
    g_strfreev(tokens);
    return diagid;

}

/**
 * @brief This function is used to get the time zone. It gets the time zone information
 * from the device configuration.
 *
 * @return Returns TRUE if successfully gets the time zone value else, returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
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
    if (result == FALSE) {
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

/**
 * @brief This function is used to get the serial number of the device from the vendor specific file.
 *
 * @param[out] serial_num Manufacturer serial number
 *
 * @return Returns TRUE if successfully gets the serial number else, returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
gboolean getserialnum(GString* serial_num)
{
#ifndef CLIENT_XCAL_SERVER
    GError                  *error=NULL;
    gboolean                result = FALSE;
    gchar* udhcpcvendorfile = NULL;

    result = g_file_get_contents ("//etc//udhcpc.vendor_specific", &udhcpcvendorfile, NULL, &error);
    if (result == FALSE) {
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
    errno_t rc = -1;
    IARM_Bus_MFRLib_GetSerializedData_Param_t param;
    IARM_Result_t iarmRet = IARM_RESULT_IPCCORE_FAIL;
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
        g_message(  "IARM CALL failed  for mfrtype \n");
    }
    return bRet;
#endif
}

/**
 * @brief This function is used to get the hosts IP information from hosts configuration file "/etc/hosts".
 *
 * @return Returns TRUE if successfully gets the hosts else returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
gboolean getetchosts(void)
{
    GError                  *error=NULL;
    gboolean                result = FALSE;
    gchar* etchostsfile = NULL;
    gchar* hostsFile;

    if( ipv6Enabled == TRUE )
        hostsFile=g_strdup("//etc//xi-xconf-hosts.list");
    else
        hostsFile=g_strdup("//etc//hosts");
    result = g_file_get_contents (hostsFile, &etchostsfile, NULL, &error);
    if (result == FALSE) {
        g_warning("Problem in reading %s file %s", hostsFile,error->message);
    }
    else
    {
        gchar **tokens = g_strsplit_set(etchostsfile,"\n\0", -1);
        //etchosts->str = g_strjoinv(";", tokens);
        guint toklength = g_strv_length(tokens);
        guint loopvar=0;
        if ((toklength > 0) && (strlen(g_strstrip(tokens[0])) > 0) &&
                (g_strrstr(g_strstrip(tokens[0]), "127.0.0.1") == NULL))
        {
            g_string_printf(etchosts, "%s",gwyip->str);
            g_string_append_printf(etchosts,"%s"," ");
            g_string_append_printf(etchosts,"%s;", g_strstrip(tokens[0]));
        }
        else
        {
            g_string_assign(etchosts,"");
        }

        for (loopvar=1; loopvar<toklength; loopvar++)
        {
            //g_print("Token is %s\n",g_strstrip(tokens[loopvar]));
            //Do not send localhost 127.0.0.1 mapping
            if (g_strrstr(g_strstrip(tokens[loopvar]), "127.0.0.1") == NULL)
            {
                if (strlen(g_strstrip(tokens[loopvar])) > 0)
                {
                    g_string_append_printf(etchosts, "%s",gwyip->str);
                    g_string_append_printf(etchosts,"%s"," ");
                    g_string_append_printf(etchosts,"%s;",g_strstrip(tokens[loopvar]));
                }
            }
        }
        g_strfreev(tokens);
    }
    //diagid=1000;
    //g_print("Etc Hosts contents are %s", etchosts->str);
    g_free(hostsFile);

    if(error)
    {
        /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
        g_clear_error(&error);
    }

    return result;
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

    double t = timeval.tv_sec + (timeval.tv_usec/1000000.0); //number of seconds and microsecs since epoch
    char udnvalue[25];
    snprintf(udnvalue,25,"%s%f","CVP-",t);

    //get current ip address for CVP2
    char ipAddressBufferCVP2[INET6_ADDRSTRLEN];
    initIpAddressBufferCVP2(ipAddressBufferCVP2);

    //init uri parameters with current ip address
    g_string_printf(trmurlCVP2, "ws://%s:9988", ipAddressBufferCVP2);
    g_string_printf(playbackurlCVP2, "http://%s:8080/hnStreamStart?deviceId=%s&DTCP1HOST=%s&DTCP1PORT=5000", ipAddressBufferCVP2, recv_id->str, ipAddressBufferCVP2);


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
    char * pId = "channelMapId:";
    char *pChannelMapId = strstr(systemids->str,pId);
    if (pChannelMapId != NULL)
    {
        pChannelMapId += strlen(pId);
        size_t len = strcspn(pChannelMapId, ";");
        channelMapId = g_string_new_len(pChannelMapId, len);
    }
    if (channelMapId == NULL)
        channelMapId = g_string_new("0");

    GString *controllerId = NULL;
    pId = "controllerId:";
    char *pControllerId = strstr(systemids->str,pId);
    if (pControllerId != NULL)
    {
        pControllerId += strlen(pId);
        size_t len = strcspn(pControllerId, ";");
        controllerId = g_string_new_len(pControllerId, len);
    }
    if (controllerId == NULL)
        controllerId = g_string_new("0");

    GString *plantId = NULL;
    pId = "plantId:";
    char *pPlantId = strstr(systemids->str,pId);
    if (pPlantId != NULL)
    {
        pPlantId += strlen(pId);
        size_t len = strcspn(pPlantId, ";");
        plantId = g_string_new_len(pPlantId, len);
    }
    if (plantId == NULL)
        plantId = g_string_new("0");

    GString *vodServerId = NULL;
    pId = "vodServerId:";
    char *pVodServerId = strstr(systemids->str,pId);
    if (pVodServerId != NULL)
    {
        pVodServerId += strlen(pId);
        size_t len = strcspn(pVodServerId, ";");
        vodServerId = g_string_new_len(pVodServerId, len);
    }
    if (vodServerId == NULL)
        vodServerId = g_string_new("0");

    GString* eSTBMAC = get_eSTBMAC();
    if (eSTBMAC == NULL)
    {
        eSTBMAC = g_string_new("UNKNOWN");
    }


    gchar* gw_value= g_strconcat(
                         "{"
                         "\"deviceType\":\"DMS\","
                         "\"friendlyName\":\"" ,getGatewayName(),     "\","
                         "\"receiverID\":\""   ,recv_id->str,         "\","
                         "\"udn\":\""          ,udnvalue,             "\","
                         "\"gatewayIP\":\""    ,gwyipCVP2->str,       "\","
                         "\"baseURL\":\""      ,playbackurlCVP2->str, "\","
                         "\"trmURL\":\""       ,trmurlCVP2->str,      "\","
                         "\"channelMapId\":\"" ,channelMapId->str,    "\","
                         "\"controllerId\":\"" ,controllerId->str,    "\","
                         "\"plantId\":\""      ,plantId->str,         "\","
                         "\"vodServerId\":\""  ,vodServerId->str,     "\","
                         "\"eSTBMAC\":\""      ,eSTBMAC->str,         "\""
                         "}", NULL );

    g_string_free(eSTBMAC, TRUE);
    g_string_free(channelMapId,TRUE);
    g_string_free(controllerId,TRUE);
    g_string_free(plantId,TRUE);
    g_string_free(vodServerId,TRUE);

    //gchar *gw_value = "a&b\"c\'d<e>f;g/h?i:j@k&l=m+n$o,p{}q'r_s-t.u!v~x*y(z)"; //test string with reserved chars
    //g_print("gw_value string before escape = %s\n",gw_value);

    GString *gwescapededstr = g_string_sized_new(strlen(gw_value) * 3);//x3, big enough for all of the chars to be escaped

    uriescape(gw_value,gwescapededstr);

    g_free(gw_value);

    //g_print("gw_value string after URI escape = %s\n",gwescapededstr->str);

    gchar* uri = g_strconcat( urilink,"?partner=", getPartnerID(),"&gw=", gwescapededstr->str, NULL );

    g_string_free(gwescapededstr, TRUE);

    GString *xmlescapedstr = g_string_sized_new(strlen(uri) * 2);//x2 should be big enough

    xmlescape(uri, xmlescapedstr);

    g_free(uri);

    //g_print("uri string after XML escape = %s\n",xmlescapedstr->str);

    return xmlescapedstr;
}

/*----------------------------
* Init ruiurl var with the RUI GetCompatibleUIs return value
*/

/**
 * @brief This function is used to get the RUI(Remote user interface) Url. It uses xdevice.conf
 * file to get the RUI Url. If the xdevice.conf file is not present then create the the RUI url string.
 *
 * @return Returns TRUE if successfully gets the RUI url.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
gboolean getruiurl()
{

    if ( ruiurl->str != NULL )     //previous string needs to be freed
    {
        g_string_free( ruiurl, TRUE);//TRUE means free str allocation too
    }

    if (devConf->ruiPath != NULL) //use config file string if present
    {
        g_print("getruiurl using xdevice.conf RuiPath=value\n");
        ruiurl = g_string_new(g_strconcat(devConf->ruiPath, NULL));
    }
    else                          //otherwise, create with actual values
    {

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
        g_string_free(iconlist, TRUE);
    }
    //g_print("ruiurl string from getruiurl(): = %s\n",ruiurl->str);
    return TRUE;
}

static xmlNode * get_node_by_name(xmlNode * node, const char *node_name)
{
    xmlNode * cur_node = NULL;
    xmlNode * ret	= NULL;
    errno_t rc = -1;
    int ind = -1;

    for (cur_node = node ; cur_node ; cur_node = cur_node->next)
    {
        rc = strcmp_s(cur_node->name, strlen(cur_node->name), node_name, &ind);
        ERR_CHK(rc);
        if ((ind == 0) && (rc == EOK))
        {
            return cur_node;
        }
        ret = get_node_by_name(cur_node->children, node_name);
        if ( ret != NULL )
            break;
    }
    return ret;
}

/**
 * @brief This function is used to set new value to the given node from the xml file.
 *
 * @param[in] doc Xml document.
 * @param[in] node_name The name of the node to be updated.
 * @param[in] new_value New value to be set for the node.
 *
 * @return Returns Integer value '0' if successfully sets the new node value else returns '1'.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
int set_content(xmlDoc* doc, const char * node_name, const char * new_value)
{
    xmlNode * root_element = NULL;
    xmlNode * target_node = NULL;

    root_element = xmlDocGetRootElement(doc);
    target_node = get_node_by_name(root_element, node_name);

    if (target_node==NULL)
    {
        g_printerr("Couldn't locate the Target node\n");
        return 1;
    }

    xmlNodeSetContent(target_node,new_value);

    return 0;
}

/**
 * @brief This function is used to get the value of the node from the xml file.
 *
 * @param[in] doc Xml document.
 * @param[in] node_name Name of the node for which value has to be retrieved.
 *
 * @return Returns the Node value string else returns NULL.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
char * get_content(xmlDoc* doc, const char * node_name)
{
    xmlNode * root_element = xmlDocGetRootElement(doc);
    xmlNode * xml_node = get_node_by_name(root_element, node_name);

    if (xml_node==NULL)
    {
        g_printerr("Couldn't locate the %s node\n", node_name);
        return NULL;
    }

    return xmlNodeGetContent(xml_node);
}

/**
 * @brief Supporting function for reading the XML file
 *
 * @param[in] file_name Name of the xml file
 *
 * @return Returns the resulting document tree.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
xmlDoc * open_document(const char * file_name)
{
    xmlDoc * ret;

    ret = xmlReadFile(file_name, NULL, 0);
    if (ret == NULL)
    {
        //g_printerr("Failed to parse %s\n", file_name);
        return NULL;
    }
    return ret;
}

/*
* isVidiPathEnabled()
* If /opt/vidiPathEnabled does not exist, indicates VidiPath is NOT enabled.
* If /opt/vidiPathEnabled exists, VidiPath is enabled.
*/
#define VIDIPATH_FLAG "/opt/vidiPathEnabled"

static int isVidiPathEnabled()
{
    if (access(VIDIPATH_FLAG,F_OK) == 0)
        return 1; //vidipath enabled
    return 0;     //vidipath not enabled
}

/**
 * @brief This function is used to retrieve the data from the device configuration file
 *
 * @param[in] configfile Device configuration file name.
 *
 * @return Returns TRUE if successfully reads the configuration else returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
gboolean readconffile(const char* configfile)
{

    GKeyFile *keyfile = NULL;
    GKeyFileFlags flags;
    GError *error = NULL;
    gsize length;

    /* Create a new GKeyFile object and a bitwise list of flags. */
    keyfile = g_key_file_new ();
    flags = G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS;

    /* Load the GKeyFile from keyfile.conf or return. */
    if (!g_key_file_load_from_file (keyfile, configfile, flags, &error))
    {
        if(error)
        {
            g_error ("%s\n", error->message);

            /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
            g_clear_error(&error);
        }
        if(keyfile)
        {
            g_key_file_free(keyfile);
        }
        return FALSE;
    }
    g_message("Starting with Settings %s\n", g_key_file_to_data(keyfile, NULL, NULL));

    devConf = g_new(ConfSettings,1);
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

    devConf->bcastIf = g_key_file_get_string             (keyfile, "Network","BCastIf", NULL);
    devConf->bcastPort = g_key_file_get_integer          (keyfile, "Network","BCastPort", NULL);
#ifndef CLIENT_XCAL_SERVER
    devConf->streamIf = g_key_file_get_string             (keyfile, "Network","StreamIf", NULL);
    devConf->trmIf = g_key_file_get_string             (keyfile, "Network","TrmIf", NULL);
    devConf->gwIf = g_key_file_get_string             (keyfile, "Network","GwIf", NULL);
    devConf->cvpIf = g_key_file_get_string             (keyfile, "Network","CvpIf", NULL);
    devConf->cvpPort = g_key_file_get_integer          (keyfile, "Network","CvpPort", NULL);
    devConf->hostMacIf = g_key_file_get_string             (keyfile, "Network","HostMacIf", NULL);
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
    devConf->oemFile = g_key_file_get_string             (keyfile, "DataFiles","OemFile", NULL);
    devConf->dnsFile = g_key_file_get_string          (keyfile, "DataFiles","DnsFile", NULL);
    devConf->dsgFile = g_key_file_get_string             (keyfile, "DataFiles","DsgFile", NULL);
    devConf->diagFile = g_key_file_get_string             (keyfile, "DataFiles","DiagFile", NULL);
    devConf->devXmlPath = g_key_file_get_string             (keyfile, "DataFiles","DevXmlPath", NULL);
    devConf->devXmlFile = g_key_file_get_string             (keyfile, "DataFiles","DevXmlFile", NULL);
    devConf->cvpXmlFile = g_key_file_get_string             (keyfile, "DataFiles","CvpXmlFile", NULL);
    devConf->logFile = g_key_file_get_string             (keyfile, "DataFiles","LogFile", NULL);
    devConf->ipv6FileLocation = g_key_file_get_string          (keyfile, "DataFiles","Ipv6FileLocation", NULL);
    devConf->ipv6PrefixFile = g_key_file_get_string          (keyfile, "DataFiles","Ipv6PrefixFile", NULL);
    devConf->enableCVP2 = isVidiPathEnabled();
#endif
    devConf->deviceNameFile = g_key_file_get_string          (keyfile, "DataFiles","DeviceNameFile", NULL);
    devConf->devPropertyFile = g_key_file_get_string          (keyfile, "DataFiles","DevPropertyFile", NULL);
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
    devConf->useIARM = g_key_file_get_boolean          (keyfile, "Flags","UseIARM", NULL);
    devConf->allowGwy = g_key_file_get_boolean             (keyfile, "Flags","AllowGwy", NULL);
#ifndef CLIENT_XCAL_SERVER
    devConf->enableCVP2 = isVidiPathEnabled();

    devConf->ruiPath = g_key_file_get_string (keyfile,"Rui", "RuiPath" , NULL);

    if (devConf->ruiPath == NULL ) //only use overrides if ruiPath is not present
    {
        devConf->uriOverride = g_key_file_get_string (keyfile, "Rui", "uriOverride", NULL);
    }
    else
    {
        devConf->uriOverride = NULL;
    }
    devConf->enableTRM = g_key_file_get_boolean             (keyfile, "Flags","EnableTRM", NULL);
    devConf->useGliDiag = g_key_file_get_boolean             (keyfile, "Flags","UseGliDiag", NULL);
    devConf->disableTuneReady = g_key_file_get_boolean             (keyfile, "Flags","DisableTuneReady", NULL);
    devConf->enableHostMacPblsh = g_key_file_get_boolean             (keyfile, "Flags","EnableHostMacPblsh", NULL);
    devConf->rmfCrshSupp = g_key_file_get_boolean             (keyfile, "Flags","rmfCrshSupp", NULL);
    devConf->wareHouseMode = g_key_file_get_boolean             (keyfile, "Flags","wareHouseMode", NULL);
#endif

    g_key_file_free(keyfile);
#ifndef CLIENT_XCAL_SERVER
    if ((devConf->bcastIf == NULL)|| (devConf->bcastPort == 0) || (devConf->devXmlPath == NULL) ||
            (devConf->devXmlFile == NULL))
    {
        g_warning("Invalid or no values found for mandatory parameters\n");
        return FALSE;
    }
#endif
    return TRUE;

}

/**
 * @brief This function is used to update the xml node values UDN, serialNumber and friendlyName.
 *
 * @param[in] xmlfilename Name of the XML file.
 * @param[in] struuid Unique device Id .
 * @param[in] serialno Serial number.
 * @param[in] friendlyName Friendly name.
 *
 * @return Returns TRUE if successfully updated the xml data else returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
gboolean updatexmldata(const char* xmlfilename, const char* struuid, const char* serialno, const char* friendlyName)
{
    LIBXML_TEST_VERSION

    xmlDoc * doc = open_document(xmlfilename);

    if (doc == NULL)
    {
        g_printerr ("Error reading the Device XML file\n");
        return FALSE;
    }

    if (set_content(doc, "UDN", struuid)!=0)
    {
        g_printerr ("Error setting the unique device id in conf xml\n");
        return FALSE;
    }
    if (set_content(doc, "serialNumber", serialno)!=0)
    {
        g_printerr ("Error setting the serial number in conf xml\n");
        return FALSE;
    }

    if(NULL != friendlyName)
    {
        if (set_content(doc, "friendlyName", friendlyName)!=0)
        {
            g_printerr ("Error setting the friendlyName number in conf xml\n");
            return FALSE;
        }
    }
    else
    {
        g_printerr ("friendlyName is NULL\n");
    }

    FILE *fp = fopen(xmlfilename, "w");

    if (fp==NULL)
    {
        g_printerr ("Error opening the conf xml file for writing\n");
        return FALSE;
    }
    else if (xmlDocFormatDump(fp, doc, 1) == -1)
    {
        g_printerr ("Could not write the conf to xml file\n");
        return FALSE;
    }

    fclose(fp);

    xmlFreeDoc(doc);
    xmlCleanupParser();
    return TRUE;
}

/**
 * @brief A generic function to notify all the clients whenever there is a change found in the
 * service variable values.
 *
 * @param[in] varname Node name to be notified.
 * @param[in] strvalue New value to be notified.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
void notify_value_change(const char* varname, const char* strvalue)
{
    if ((service_ready==FALSE) || (!upnpService))
    {
        g_warning("Received notificaton before start of Service");
    }
    else
    {
//      GValue value = {0};
        GValue value = G_VALUE_INIT;
        g_value_init(&value, G_TYPE_STRING);
        g_value_set_static_string(&value, strvalue);
        g_message("Sending value change notification Name %s - Value: %s", varname, strvalue);
        gupnp_service_notify_value(upnpService, varname, &value);
        //g_value_unset(&value);
    }
    return;
}

/**
 * @brief Generic function to notify the change in the node value which are of integers type
 * from the XML service file.
 *
 * @param[in] varname Node name to be notified.
 * @param[in] strvalue New value to be notified.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
void notify_value_change_int(const char* varname, int intvalue)
{
    if ((service_ready==FALSE) || (!upnpService))
    {
        g_warning("Received notificaton before start of Service");
    }
    else
    {
        GValue value = G_VALUE_INIT;
        g_value_init(&value, G_TYPE_INT);
        g_value_set_int(&value, intvalue);
        g_message("Sending value change notification Name %s - Value: %d", varname, intvalue);
        gupnp_service_notify_value(upnpService, varname, &value);
        //g_value_unset(&value);
    }
    return;
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
GString* getID( const gchar *id )
{
    gboolean isDevIdPresent=FALSE;
    gshort counter=0;   // to limit the logging if the user doesnt activate for long time

    GString* jsonData=g_string_new(NULL);
    GString* value=g_string_new(NULL);
    while(TRUE)
    {
//    if (IARM_BUS_SYS_MODE_WAREHOUSE == sysModeParam)
#if defined(USE_XUPNP_IARM_BUS)
        if(( devConf->wareHouseMode == TRUE ) || (IARM_BUS_SYS_MODE_WAREHOUSE == sysModeParam))
        {
            const gchar* bcastmac=(gchar*)getmacaddress(devConf->bcastIf);
            g_string_assign(value, bcastmac);
            g_message("In WareHouse Mode recvid  %s bcastmac %s \n ",recv_id->str,bcastmac);
            break;
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

            if ((response[0] == '\0') && (counter < MAX_DEBUG_MESSAGE))
            {
                counter ++;
                g_message("No Json string found in Auth url  %s \n" ,response);
            }
            else
            {
                g_string_assign(jsonData,response);
                gchar **tokens = g_strsplit_set(jsonData->str,"{}:,\"", -1);
                guint tokLength = g_strv_length(tokens);
                guint loopvar=0;
                for (loopvar=0; loopvar<tokLength; loopvar++)
                {
                    if (g_strrstr(g_strstrip(tokens[loopvar]), id))
                    {
                        //"deviceId": "T00xxxxxxx" so omit 3 tokens ":" fromDeviceId
                        if ((loopvar+3) < tokLength )
                        {
                            g_string_assign(value, g_strstrip(tokens[loopvar+3]));
                            if(value->str[0] != '\0')
                            {
                                isDevIdPresent=TRUE;
                                break;
                            }
                        }
                    }
                }
                if(!isDevIdPresent)
                {
                    if (g_strrstr(id,PARTNER_ID))
                    {
                        g_message("%s not found in Json string in Auth url %s \n ",id,jsonData->str);
                        return value;
                    }
                    if (counter < MAX_DEBUG_MESSAGE )
                    {
                        counter++;
                        g_message("%s not found in Json string in Auth url %s \n ",id,jsonData->str);

                    }
                }
                else
                {
                    g_message("Successfully fetched %s %s \n ",id,value->str);
                    //g_free(tokens);
                    break;
                }
                g_strfreev(tokens);
            }
        }
        else
        {
            g_message("The deviceId script %s can't be executed\n", GET_DEVICEID_SCRIPT);
        }

        sleep(5);
    }
    g_string_free(jsonData,TRUE);
    return value;
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
            if (g_strrstr(g_strstrip(tokens[loopvar]), "RECEIVER_DEVICETYPE"))
            {
                if ((loopvar+1) < toklength )
                {
                    counter++;
                    g_string_assign(recvdevtype, g_strstrip(tokens[loopvar+1]));
                }
                if (counter == 5)
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
                if (counter == 5)
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
                if (counter == 5)
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
                if (counter == 5)
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
                if (counter == 5)
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
    notify_value_change("TimeZone", dsgtimezone->str);
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
    if (result == FALSE) {
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

/**
 * @brief This function is used to get the device name from /devicename/devicename file.
 *
 * @return Returns TRUE if successfully gets the device name string else returns FALSE.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
gboolean getdevicename(void)
{
    GError                  *error=NULL;
    gboolean                result = FALSE;
    gchar* devicenamefile = NULL;
    guint loopvar=0;
    gboolean devicenamematch = FALSE;
    if (devConf->deviceNameFile == NULL)
    {
        g_warning("device name file name not found in config");
        return result;
    }
    result = g_file_get_contents (devConf->deviceNameFile, &devicenamefile, NULL, &error);
    if (result == FALSE) {
        g_warning("Problem in reading /devicename/devicename file %s", error->message);
    }
    else
    {
        gchar **tokens = g_strsplit_set(devicenamefile,"'=''\n''\0'", -1);
        guint toklength = g_strv_length(tokens);

        while(loopvar < toklength)
        {
            if (g_strrstr(g_strstrip(tokens[loopvar]), "deviceName"))
            {
                result=TRUE;
                g_string_printf(devicename,"%s",g_strstrip(tokens[loopvar+1]));
                g_message("device name =  %s",devicename->str);
                devicenamematch=TRUE;

                break;
            }
            loopvar++;
        }
        g_strfreev(tokens);
        if(devicenamematch == FALSE)
        {
            g_message("No Matching  devicename in file %s",devicenamefile);
        }
    }
    if(error)
    {
        /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
        g_clear_error(&error);
    }
    g_free(devicenamefile);
    return result;
}
