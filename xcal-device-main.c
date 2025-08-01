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
#include <libgupnp/gupnp.h>
//#include <libgssdp/gssdp.h>
#include <stdio.h>
#include <stdlib.h>
#include <gmodule.h>
#include <stdbool.h>
#include <memory.h>
#include <libxml/tree.h>
#include <libxml/parser.h>

#include <string.h>
#include "secure_wrapper.h"
#include "xdevice.h"
#ifdef INCLUDE_BREAKPAD
#include "breakpad_wrapper.h"
#else
#endif
#ifdef ENABLE_SD_NOTIFY
#include <systemd/sd-daemon.h>
#endif
#include "rdk_safeclib.h"

#define DEVICE_XML_PATH     		"/etc/xupnp/"
#define DEVICE_XML_FILE     		"BasicDevice.xml"
#define CLIENT_DEVICE_XML_FILE		"X1Renderer.xml"
#define GW_DEVICE_XML_FILE		"X1VideoGateway.xml"
#define BROADBAND_DEVICE_XML_FILE	"X1BroadbandGateway.xml"
#define LOG_FILE			"/opt/logs/xdevice.log"
#define DEVICE_PROTECTION_CONTEXT_PORT  50757

#define MAXSIZE 256
#define RUIURLSIZE 2048
#define URLSIZE 512
#ifndef BOOL
#define BOOL  unsigned char
#endif
#ifndef BROADBAND
int xPKI_check_rfc();
#endif
static  GMainLoop *main_loop;

char devBcastIf[MAXSIZE],serial_Num[MAXSIZE], cvpInterface[MAXSIZE], cvPXmlFile[MAXSIZE],playBackUrl[URLSIZE],devXMlPath[MAXSIZE],uUid[MAXSIZE],ruiUrl[RUIURLSIZE];
char devXMlFile [MAXSIZE],devBcastIf[MAXSIZE],serial_Num[MAXSIZE],cvpInterface[MAXSIZE],cvPXmlFile[MAXSIZE],ipv6preFix[MAXSIZE],trmUrl[MAXSIZE],urL[MAXSIZE];

char gwyIp[MAXSIZE],gwyIpv6[MAXSIZE],gwystbIp[MAXSIZE],hostMacaddress[MAXSIZE],bcastMacaddress[MAXSIZE],recvdevType[MAXSIZE],deviceType[MAXSIZE],modelclass[MAXSIZE],modelNumber[MAXSIZE],deviceid[MAXSIZE],hardwarerevision[MAXSIZE],softwarerevision[MAXSIZE],managementurl[MAXSIZE],Make[MAXSIZE],accountId[MAXSIZE],clientIp[MAXSIZE];
char buildVersion[MAXSIZE],dnsConfig[MAXSIZE],systemIds[MAXSIZE],dataGatewayIPAddress[MAXSIZE],dsgtimeZone[MAXSIZE],deviceName[MAXSIZE],etcHosts[RUIURLSIZE],receiverId[MAXSIZE],ipsubnet[MAXSIZE];
char devPXmlFile[MAXSIZE], devCertFile[MAXSIZE], devCertPath[MAXSIZE], devKeyFile[MAXSIZE], devKeyPath[MAXSIZE];
gint rawoffset, dstoffset, dstsavings, devBcastPort, cvpPort;
gboolean usedaylightsavings,allowgwy,requiresTrm;
char *caFile="/tmp/UPnP_CA";

static int rfc_enabled;
#ifdef SAFEC_DUMMY_API
//adding strcmp_s defination
errno_t strcmp_s(const char * d,int max ,const char * src,int *r)
{
  *r= strcmp(d,src);
  return EOK;
}
#endif

static xmlNode * get_node_by_name(xmlNode * node, const char *node_name)
{
    errno_t rc       = -1;
    int     ind      = -1;
    xmlNode * cur_node = NULL;
    xmlNode * ret       = NULL;

    for (cur_node = node ; cur_node ; cur_node = cur_node->next)
    {
        rc = strcmp_s(cur_node->name, strlen(cur_node->name), node_name, &ind);
        ERR_CHK(rc);
        if ((ind ==0) && (rc == EOK))
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

BOOL updatexmldata(const char* xmlfilename, const char* struuid, const char* serialno, const char* friendlyName)
{
    LIBXML_TEST_VERSION
    
    xmlDoc * doc = open_document(xmlfilename);

    if (doc == NULL)
    {
        g_printerr ("Error reading the Device XML file\n");
        return FALSE;
    }
    if(rfc_enabled)
    {
        if (set_content(doc, "UPC", "10000")!=0)
        {
            g_printerr ("Error setting the upc in conf xml\n");
            return FALSE;
        }
	g_message("Added UPC value to %s",xmlfilename);
    }
    else
    {
        if (set_content(doc, "UPC", "")!=0)
        {
            g_printerr ("Error setting the upc in conf xml\n");
            return FALSE;
        }
        g_message("Updated UPC value as empty string in %s",xmlfilename);
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
        /*Coverity Fix CID 125137,28460  RESOURCE_LEAK */
         fclose(fp);
        xmlFreeDoc(doc);
       
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
    if ((service_ready==FALSE) )
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
        gupnp_service_notify_value((GUPnPService *)upnpService, varname, &value);
        //g_value_unset(&value);
    }
    return;
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
    getBaseUrl(urL);
    gupnp_service_action_set (action, "BaseUrl", G_TYPE_STRING, urL, NULL);
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
    //g_print ("Got a call back for trm url, value is %s\n", trmurl->str); trmUrl
    getTrmUrl(trmUrl);
    gupnp_service_action_set (action, "BaseTrmUrl", G_TYPE_STRING, trmUrl, NULL);
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
    if (getTuneReady())
    {
        //g_message ("Got a call back for playback url, value is %s\n", playbackurl->str);
	getPlaybackUrl(playBackUrl);
	gupnp_service_action_set (action, "PlaybackUrl", G_TYPE_STRING, playBackUrl ,NULL);
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
    getGatewayIp(gwyIp);
    gupnp_service_action_set (action, "GatewayIP", G_TYPE_STRING, gwyIp, NULL);
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
    getGatewayIpv6(gwyIpv6);
    gupnp_service_action_set (action, "GatewayIPv6", G_TYPE_STRING, gwyIpv6, NULL);
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
    getGatewayStbIp(gwystbIp);
    gupnp_service_action_set (action, "GatewayStbIP", G_TYPE_STRING, gwystbIp, NULL);
    gupnp_service_action_return (action);
}
#ifndef BROADBAND
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
    //g_print ("Got a call back\n"); ipv6preFix
    getIpv6Prefix(ipv6preFix);
    gupnp_service_action_set (action, "Ipv6Prefix", G_TYPE_STRING, ipv6preFix, NULL);
    gupnp_service_action_return (action);
}
#endif
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
    getHostMacAddress(hostMacaddress);
    gupnp_service_action_set (action, "HostMacAddress", G_TYPE_STRING, hostMacaddress, NULL);
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
//    getBcastMacAddress(bcastMacaddress);
    gupnp_service_action_set (action, "BcastMacAddress", G_TYPE_STRING, bcastMacaddress, NULL);
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
    getRecvDevType(recvdevType);
    gupnp_service_action_set (action, "RecvDevType", G_TYPE_STRING, recvdevType, NULL);
    gupnp_service_action_return (action);
}
/* GetDeviceType */
G_MODULE_EXPORT void
get_devicetype_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    getDeviceType(deviceType);
    gupnp_service_action_set (action, "DeviceType", G_TYPE_STRING, deviceType, NULL);
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
    getBuildVersion(buildVersion);
    gupnp_service_action_set (action, "BuildVersion", G_TYPE_STRING, buildVersion, NULL);
    gupnp_service_action_return (action);
}
#ifndef BROADBAND
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
    getDnsConfig(dnsConfig);
    gupnp_service_action_set (action, "DnsConfig", G_TYPE_STRING, dnsConfig, NULL);
    gupnp_service_action_return (action);
}
#endif
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
    getSystemsIds(systemIds);
    gupnp_service_action_set (action, "SystemIds", G_TYPE_STRING, systemIds, NULL);
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
    if ( rfc_enabled )
    {
        getGatewayStbIp(dataGatewayIPAddress);
    }
    else
    {
        getRouteDataGateway(dataGatewayIPAddress);
    }
    gupnp_service_action_set (action, "DataGatewayIPaddress", G_TYPE_STRING, dataGatewayIPAddress, NULL);
    gupnp_service_action_return (action);
}

/**
 * @brief Callback function which is invoked when IPSubNet action is invoked and this sets
 * the state variable for IPSubNet.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetIPSubNet */
G_MODULE_EXPORT void
get_ipsubnet_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    getIpSubnet(ipsubnet);
    gupnp_service_action_set (action, "IPSubNet", G_TYPE_STRING, ipsubnet, NULL);
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
    if(getIsuseGliDiagEnabled()) {
	getTimeZone(dsgtimeZone);
    }
    gupnp_service_action_set (action, "TimeZone", G_TYPE_STRING, dsgtimeZone, NULL);
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
    getRawOffSet(&rawoffset);
    gupnp_service_action_set (action,"RawOffSet", G_TYPE_INT, rawoffset, NULL);
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
    getDstSavings(&dstsavings);
    gupnp_service_action_set (action,"DSTSavings", G_TYPE_INT, dstsavings, NULL);
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
    getUsesDayLightTime((unsigned char *)&usedaylightsavings);
    gupnp_service_action_set (action,"UsesDaylightTime", G_TYPE_BOOLEAN, usedaylightsavings, NULL); 
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
    getDeviceName(deviceName);
    gupnp_service_action_set (action,"DeviceName", G_TYPE_STRING, deviceName, NULL);
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
    getDstOffset(&dstoffset);
    gupnp_service_action_set (action,"DSTOffset", G_TYPE_INT, dstoffset, NULL);
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
    getHosts(etcHosts);
    gupnp_service_action_set (action, "Hosts", G_TYPE_STRING, etcHosts, NULL);
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

    gchar *clientMacAddr=NULL;
    gchar *clientIpAddr=NULL;
    gboolean deviceProtectionEnabled=TRUE;
    if(rfc_enabled)
    {
        if(gupnp_service_action_get_argument_count(action))
        {
            gupnp_service_action_get (action, "deviceProtection", G_TYPE_BOOLEAN,&deviceProtectionEnabled, NULL);
            if(!deviceProtectionEnabled)
            {
                gupnp_service_action_get (action, "macAddr", G_TYPE_STRING, &clientMacAddr, NULL);
                gupnp_service_action_get (action, "ipAddr", G_TYPE_STRING, &clientIpAddr, NULL);
                if((clientMacAddr) && (clientIpAddr))
                    g_warning("Device Protection Disabled Device : %s,%s",clientMacAddr,clientIpAddr);
                else
                    g_warning("Device Protection Disabled Device without details");
             }
        }
        else
            g_warning("Device Protection Not supported legacy Device");
    }
    getIsGateway((unsigned char *)&allowgwy);
    gupnp_service_action_set (action, "IsGateway", G_TYPE_BOOLEAN, allowgwy,  NULL);
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
    getRequiresTRM((unsigned char *)&requiresTrm);
    gupnp_service_action_set (action, "RequiresTRM", G_TYPE_BOOLEAN, requiresTrm, NULL);
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
        //must init every callback because it generates a unique
        //device number for each return value.
    if(!getRUIUrl(ruiUrl)){
        g_print("Error in initializing RUI url value\n");
    //g_print ("Got a call back for Ruiurl, value is %s\n", ruiurl->str);
    }
    gupnp_service_action_get (action,"InputDeviceProfile", G_TYPE_STRING, inDevProfile->str, NULL);
    gupnp_service_action_get (action,"UIFilter", G_TYPE_STRING, uiFilter->str,NULL);
    gupnp_service_action_set (action, "UIListing", G_TYPE_STRING, ruiUrl, NULL);
    gupnp_service_action_return (action);
}
/*Coverity Fix CID: 45236 to 45244 MISSED_RETURN */
G_MODULE_EXPORT void
get_modelclass_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    getDeviceType(modelclass);
    gupnp_service_action_set (action, "ModelClass", G_TYPE_STRING, modelclass, NULL);
    gupnp_service_action_return (action);
}
G_MODULE_EXPORT void
get_modelnumber_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    getModelNumber(modelNumber);
    gupnp_service_action_set (action, "ModelNumber", G_TYPE_STRING, modelNumber, NULL);
    gupnp_service_action_return (action);
}
G_MODULE_EXPORT void
get_deviceid_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    gupnp_service_action_set (action, "DeviceId", G_TYPE_STRING, deviceid, NULL);
    gupnp_service_action_return (action);
}
G_MODULE_EXPORT void
get_hardwarerevision_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    gupnp_service_action_set (action, "HardwareRevision", G_TYPE_STRING, hardwarerevision, NULL);
    gupnp_service_action_return (action);
}
G_MODULE_EXPORT void
get_softwarerevision_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    gupnp_service_action_set (action, "SoftwareRevision", G_TYPE_STRING, softwarerevision, NULL);
    gupnp_service_action_return (action);
}
G_MODULE_EXPORT void
get_managementurl_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    gupnp_service_action_set (action, "ManagementURL", G_TYPE_STRING, managementurl, NULL);
    gupnp_service_action_return (action);
}
G_MODULE_EXPORT void
get_make_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    getMake(Make);
    gupnp_service_action_set (action, "Make", G_TYPE_STRING, Make, NULL);
    gupnp_service_action_return (action);
}
G_MODULE_EXPORT void
get_recev_id_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    gupnp_service_action_set (action, "ReceiverId", G_TYPE_STRING, receiverId, NULL);
    gupnp_service_action_return (action);
}
G_MODULE_EXPORT void
get_account_id_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    gchar *clientAccountId=NULL;
    //SoupMessage *msg;
    gchar *clientMacAddr=NULL;
    gchar *clientIpAddr=NULL;
#ifdef BROADBAND
    int ret = 0;
#endif
    /* Get the client account Id value */ 
    gupnp_service_action_get (action, "SAccountId", G_TYPE_STRING, &clientAccountId, NULL);
    gupnp_service_action_set (action, "GAccountId", G_TYPE_STRING, accountId, NULL);
    gupnp_service_action_get (action, "macAddr", G_TYPE_STRING, &clientMacAddr, NULL);
    gupnp_service_action_get (action, "ipAddr", G_TYPE_STRING, &clientIpAddr, NULL);
    if ((clientAccountId) && (!strcmp(clientAccountId, accountId)))
    {
       g_warning("Client connection account ID same : %s,%s,%s,%s" , accountId,clientAccountId,clientMacAddr,clientIpAddr);
#ifdef BROADBAND
        // add whitelist
#if !defined (NO_MOCA_FEATURE_SUPPORT)
       g_warning("/usr/ccsp/moca/moca_whitelist_ctl.sh add %s",clientIpAddr);
       ret = v_secure_system("/usr/ccsp/moca/moca_whitelist_ctl.sh add %s", clientIpAddr);
       if(ret != 0) {
           g_warning("Failure in executing command via v_secure_system. ret:[%d] ;\n", ret);
       }
#endif
#endif
       gupnp_service_action_return (action);
    }
    else 
    {
       // AccountId is not matching.
       // Log the message, accountId receivede
       // Disconnect soup session TBD.
       g_warning("Client connection account ID mismatch found : %s,%s,%s,%s" , accountId,clientAccountId,clientMacAddr,clientIpAddr);
#ifdef BROADBAND
#if !defined (NO_MOCA_FEATURE_SUPPORT)
       g_warning("/usr/ccsp/moca/moca_whitelist_ctl.sh del %s", clientIpAddr);
       ret = v_secure_system("/usr/ccsp/moca/moca_whitelist_ctl.sh del %s", clientIpAddr);
       if(ret != 0) {
           g_warning("Failure in executing command via v_secure_system. ret:[%d] ;\n", ret);
       }
#endif
#endif
       //msg = gupnp_service_action_get_message(action);
       gupnp_service_action_return (action);
       //g_warning("service action returning error "); 
       //gupnp_service_action_return_error (action, 402, "Account Id not matching");
       //g_warning("service action aborting session "); 
       //gupnp_service_action_abort_session(service);
    }
    //g_warning("get_account_id_cb exit "); 
}

/**
 * @brief Callback function which is invoked when getClientIP action is invoked and this sets
 * the state variable for Client IP.
 *
 * @param[in] service Name of the service.
 * @param[out] action Action to be invoked.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* GetGatewayIP */
G_MODULE_EXPORT void
get_client_ip_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    //g_print ("Got a call back\n");
    gupnp_service_action_set (action, "ClientIP", G_TYPE_STRING, clientIp, NULL);
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
    g_value_set_string (value, urL);
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
    g_value_set_string (value, trmUrl);
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
    if(getTuneReady())
    {
        //g_message ("Got a query for playback url, sending %s\n", playbackurl->str);
        g_value_init (value, G_TYPE_STRING);
	g_value_set_string (value, playBackUrl);	
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
    g_value_set_string (value, dataGatewayIPAddress);
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
    g_value_set_string (value, deviceName);
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
    g_value_set_string (value, gwyIp);
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
    g_value_set_string (value, gwyIpv6);
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
    g_value_set_string (value, gwystbIp);
}
#ifndef BROADBAND
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
    g_value_set_string (value, ipv6preFix);
}
#endif
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
    g_value_set_string (value, hostMacaddress);
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
    g_value_set_string (value, bcastMacaddress);
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
    g_value_set_string (value, recvdevType);
}
/* DeviceType */
G_MODULE_EXPORT void
query_devicetype_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, deviceType);
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
    g_value_set_string (value, buildVersion);
}
#ifndef BROADBAND
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
    g_value_set_string (value, dnsConfig);
}
#endif
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
    g_value_set_string (value, systemIds);
}
/**
 * @brief Callback function which is invoked when IPSubNet  action is invoked and this sets
 * the state variable with a new value.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* IPSubNet */
G_MODULE_EXPORT void
query_ipsubnet_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    getIpSubnet(ipsubnet);
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, ipsubnet);
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
    if (getIsuseGliDiagEnabled() == FALSE){
	getTimeZone(dsgtimeZone);
    }
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, dsgtimeZone);
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
    g_value_set_string (value, etcHosts);
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
    g_value_set_boolean (value, allowgwy);
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
    g_value_set_boolean (value, requiresTrm);
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
    g_value_set_string (value, ruiUrl);
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
    g_value_set_int (value, rawoffset);
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
    g_value_set_int (value, dstoffset);
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
    g_value_set_int (value, dstsavings);
}

/**
 * @brief Callback function which is invoked when ClientIP action is invoked and this sets
 * the state variable with a new Gateway IP.
 *
 * @param[in] service Name of the service.
 * @param[in] variable State(Query) variable.
 * @param[in] value New value to be assigned.
 * @param[in] user_data Usually null will be passed.
 * @ingroup XUPNP_XCALDEV_FUNC
 */
/* ClientIP */
G_MODULE_EXPORT void
query_client_ip_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, clientIp);
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
    g_value_set_boolean (value, usedaylightsavings);
}

G_MODULE_EXPORT void
query_modelclass_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, modelclass);
}
G_MODULE_EXPORT void
query_modelnumber_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, modelNumber);
}
G_MODULE_EXPORT void
query_deviceid_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, deviceid);
}
G_MODULE_EXPORT void
query_hardwarerevision_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, hardwarerevision);
}
G_MODULE_EXPORT void
query_softwarerevision_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, softwarerevision);
}
G_MODULE_EXPORT void
query_managementurl_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, managementurl);
}
G_MODULE_EXPORT void
query_make_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, Make);
}
G_MODULE_EXPORT void
query_recev_id_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, receiverId);
}
G_MODULE_EXPORT void
query_account_id_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, accountId);
}

int registerIdentityConfigurationService(GUPnPServiceInfo *upnpIdService)
{
    g_signal_connect (upnpIdService, "action-invoked::GetRecvDevType", G_CALLBACK (get_recvdevtype_cb), NULL);
    g_signal_connect (upnpIdService, "action-invoked::GetDeviceType", G_CALLBACK (get_devicetype_cb), NULL);
    g_signal_connect (upnpIdService, "action-invoked::GetBuildVersion", G_CALLBACK (get_buildversion_cb), NULL);
    g_signal_connect (upnpIdService, "action-invoked::GetDeviceName", G_CALLBACK (get_devicename_cb), NULL);
    g_signal_connect (upnpIdService, "action-invoked::GetModelClass", G_CALLBACK (get_modelclass_cb), NULL);
    g_signal_connect (upnpIdService, "action-invoked::GetModelNumber", G_CALLBACK (get_modelnumber_cb), NULL);
    g_signal_connect (upnpIdService, "action-invoked::GetDeviceId", G_CALLBACK (get_deviceid_cb), NULL);
    g_signal_connect (upnpIdService, "action-invoked::GetHardwareRevision", G_CALLBACK (get_hardwarerevision_cb), NULL);
    g_signal_connect (upnpIdService, "action-invoked::GetSoftwareRevision", G_CALLBACK (get_softwarerevision_cb), NULL);
    g_signal_connect (upnpIdService, "action-invoked::GetManagementUrl", G_CALLBACK (get_managementurl_cb), NULL);
    g_signal_connect (upnpIdService, "action-invoked::GetMake", G_CALLBACK (get_make_cb), NULL);
    g_signal_connect (upnpIdService, "action-invoked::GetReceiverId", G_CALLBACK (get_recev_id_cb), NULL);
    g_signal_connect (upnpIdService, "action-invoked::GetAccountId", G_CALLBACK (get_account_id_cb), NULL);
    g_signal_connect (upnpIdService, "action-invoked::GetClientIP", G_CALLBACK (get_client_ip_cb), NULL);
    g_signal_connect (upnpIdService, "action-invoked::GetBcastMacAddress", G_CALLBACK (get_bcastmacaddress_cb), NULL);
    g_signal_connect (upnpIdService, "query-variable::RecvDevType", G_CALLBACK (query_recvdevtype_cb), NULL);
    g_signal_connect (upnpIdService, "query-variable::DeviceType", G_CALLBACK (query_devicetype_cb), NULL);
    g_signal_connect (upnpIdService, "query-variable::BuildVersion", G_CALLBACK (query_buildversion_cb), NULL);
    g_signal_connect (upnpIdService, "query-variable::DeviceName", G_CALLBACK (query_devicename_cb), NULL);
    g_signal_connect (upnpIdService, "query-variable::ModelClass", G_CALLBACK (query_modelclass_cb), NULL);
    g_signal_connect (upnpIdService, "query-variable::ModelNumber", G_CALLBACK (query_modelnumber_cb), NULL);
    g_signal_connect (upnpIdService, "query-variable::DeviceId", G_CALLBACK (query_deviceid_cb), NULL);
    g_signal_connect (upnpIdService, "query-variable::HardwareRevision", G_CALLBACK (query_hardwarerevision_cb), NULL);
    g_signal_connect (upnpIdService, "query-variable::SoftwareRevision", G_CALLBACK (query_softwarerevision_cb), NULL);
    g_signal_connect (upnpIdService, "query-variable::ManagementUrl", G_CALLBACK (query_managementurl_cb), NULL);
    g_signal_connect (upnpIdService, "query-variable::Make", G_CALLBACK (query_make_cb), NULL);
    g_signal_connect (upnpIdService, "query-variable::ReceiverId", G_CALLBACK (query_recev_id_cb), NULL);
    g_signal_connect (upnpIdService, "query-variable::AccountId", G_CALLBACK (query_account_id_cb), NULL);
    g_signal_connect (upnpIdService, "query-variable::BcastMacAddress", G_CALLBACK (query_bcastmacaddress_cb), NULL);
    g_signal_connect (upnpIdService, "query-variable::ClientIP", G_CALLBACK (query_client_ip_cb), NULL);
    return 0;
}
int registerMediaConfigurationService(GUPnPServiceInfo *upnpMediaConfService)
{
    g_signal_connect (upnpMediaConfService, "action-invoked::GetBaseUrl", G_CALLBACK (get_url_cb), NULL);
    g_signal_connect (upnpMediaConfService, "action-invoked::GetPlaybackUrl", G_CALLBACK (get_playback_url_cb), NULL);
//    g_signal_connect (upnpMediaConfService, "action-invoked::GetFogTsbUrl", G_CALLBACK (get_fogtsb_url_cb), NULL);
//    g_signal_connect (upnpMediaConfService, "action-invoked::GetVideoBaseUrl", G_CALLBACK (get_videobase_url_cb), NULL);
    g_signal_connect (upnpMediaConfService, "query-variable::Url", G_CALLBACK (query_url_cb), NULL);
    g_signal_connect (upnpMediaConfService, "query-variable::PlaybackUrl", G_CALLBACK (query_playback_url_cb), NULL);
//    g_signal_connect (upnpMediaConfService, "query-variable::FogTsbUrl", G_CALLBACK (query_fogtsb_url_cb), NULL);
//    g_signal_connect (upnpMediaConfService, "query-variable::VideoBaseUrl", G_CALLBACK (query_videobase_url_cb), NULL);
    return 0;
}
int registerGatewayConfigurationService(GUPnPServiceInfo *upnpGatewayConf)
{
    g_signal_connect (upnpGatewayConf, "action-invoked::GetGatewayIP", G_CALLBACK (get_gwyip_cb), NULL);
    g_signal_connect (upnpGatewayConf, "action-invoked::GetGatewayIPv6", G_CALLBACK (get_gwyipv6_cb), NULL);
#ifndef BROADBAND
    g_signal_connect (upnpGatewayConf, "action-invoked::GetIpv6Prefix", G_CALLBACK (get_ipv6prefix_cb), NULL);
    g_signal_connect (upnpGatewayConf, "action-invoked::GetDnsConfig", G_CALLBACK (get_dnsconfig_cb), NULL);
#endif
    g_signal_connect (upnpGatewayConf, "action-invoked::GetGatewayStbIP", G_CALLBACK (get_gwystbip_cb), NULL);
    g_signal_connect (upnpGatewayConf, "action-invoked::GetHosts", G_CALLBACK (get_hosts_cb), NULL);
    g_signal_connect (upnpGatewayConf, "action-invoked::GetHostMacAddress", G_CALLBACK (get_hostmacaddress_cb), NULL);
    g_signal_connect (upnpGatewayConf, "action-invoked::GetDataGatewayIPaddress", G_CALLBACK (get_dataGatewayIPaddress_cb), NULL);
    g_signal_connect (upnpGatewayConf, "action-invoked::GetIsGateway", G_CALLBACK (get_isgateway_cb), NULL);
    g_signal_connect (upnpGatewayConf, "action-invoked::GetIPSubNet", G_CALLBACK (get_ipsubnet_cb), NULL);
    g_signal_connect (upnpGatewayConf, "query-variable::GatewayIP", G_CALLBACK (query_gwyip_cb), NULL);
    g_signal_connect (upnpGatewayConf, "query-variable::GatewayIPv6", G_CALLBACK (query_gwyipv6_cb), NULL);
#ifndef BROADBAND
    g_signal_connect (upnpGatewayConf, "query-variable::Ipv6Prefix", G_CALLBACK (query_ipv6prefix_cb), NULL);
    g_signal_connect (upnpGatewayConf, "query-variable::DnsConfig", G_CALLBACK (query_dnsconfig_cb), NULL);
#endif
    g_signal_connect (upnpGatewayConf, "query-variable::GatewayStbIP", G_CALLBACK (query_gwystbip_cb), NULL);
    g_signal_connect (upnpGatewayConf, "query-variable::Hosts", G_CALLBACK (query_hosts_cb), NULL);
    g_signal_connect (upnpGatewayConf, "query-variable::HostMacAddress", G_CALLBACK (query_hostmacaddress_cb), NULL);
    g_signal_connect (upnpGatewayConf, "query-variable::DataGatewayIPaddress", G_CALLBACK (query_dataGatewayIPaddress_cb), NULL);
    g_signal_connect (upnpGatewayConf, "query-variable::IsGateway", G_CALLBACK (query_isgateway_cb), NULL);
    g_signal_connect (upnpGatewayConf, "query-variable::IPSubNet", G_CALLBACK (query_ipsubnet_cb), NULL);
    return 0;
}
int registerQamConfigurationService(GUPnPServiceInfo *upnpQamConf)
{
    g_signal_connect (upnpQamConf, "action-invoked::GetBaseTrmUrl", G_CALLBACK (get_trm_url_cb), NULL);
    g_signal_connect (upnpQamConf, "action-invoked::GetSystemIds", G_CALLBACK (get_systemids_cb), NULL);
    g_signal_connect (upnpQamConf, "action-invoked::GetRequiresTRM", G_CALLBACK (get_requirestrm_cb), NULL);
    g_signal_connect (upnpQamConf, "query-variable::TrmUrl", G_CALLBACK (query_trm_url_cb), NULL);
    g_signal_connect (upnpQamConf, "query-variable::SystemIds", G_CALLBACK (query_systemids_cb), NULL);
    g_signal_connect (upnpQamConf, "query-variable::RequiresTRM", G_CALLBACK (query_requirestrm_cb), NULL);
    return 0;
}
int registerTimeConfigurationService(GUPnPServiceInfo *upnpTimeConf)
{
    g_signal_connect (upnpTimeConf, "action-invoked::GetTimeZone", G_CALLBACK (get_timezone_cb), NULL);
    g_signal_connect (upnpTimeConf, "action-invoked::GetRawOffSet", G_CALLBACK (get_rawoffset_cb), NULL);
    g_signal_connect (upnpTimeConf, "action-invoked::GetDSTOffset", G_CALLBACK (get_dstoffset_cb), NULL);
    g_signal_connect (upnpTimeConf, "action-invoked::GetDSTSavings", G_CALLBACK (get_dstsavings_cb), NULL);
    g_signal_connect (upnpTimeConf, "action-invoked::GetUsesDaylightTime", G_CALLBACK (get_usesdaylighttime_cb), NULL);
    g_signal_connect (upnpTimeConf, "query-variable::TimeZone", G_CALLBACK (query_timezone_cb), NULL);
    g_signal_connect (upnpTimeConf, "query-variable::RawOffSet", G_CALLBACK (query_rawoffset_cb), NULL);
    g_signal_connect (upnpTimeConf, "query-variable::DSTOffset", G_CALLBACK (query_dstoffset_cb), NULL);
    g_signal_connect (upnpTimeConf, "query-variable::DSTSavings", G_CALLBACK (query_dstsavings_cb), NULL);
    g_signal_connect (upnpTimeConf, "query-variable::UsesDaylightTime", G_CALLBACK (query_usesdaylighttime_cb), NULL);
    return 0;
}


int
main (int argc, char **argv)
{
    GError *error = NULL;
    g_thread_init (NULL);
    char devConfFile[] = "/etc/xdevice.conf";
    char *certFile=NULL, *keyFile=NULL;

    g_type_init ();
    g_message("Starting XCAL-DEVICE ");
    xupnpEventCallback_register(&notify_value_change);
    xdeviceInit(devConfFile,NULL);
    getGatewayIp(clientIp);
    rfc_enabled = check_rfc();
    if(!rfc_enabled)
    {
        g_message("Running Older Xcal Device");
    }
    if(!(getDevXmlPath(devXMlPath)&& getDevXmlFile(devXMlFile,0) && getUUID(uUid) && getBcastPort(&devBcastPort) && getSerialNum(serial_Num) && getBcastIf(devBcastIf)))
    {
        g_message("Failed to update the required gupnp xcal-device variables");
    }

    g_message("xmlfilename=%s struuid=%s serial_Num=%s",devXMlFile,uUid,serial_Num);
    g_message("devBcastIf=%sdevBcastPort=%d",devBcastIf,devBcastPort);
#ifdef INCLUDE_BREAKPAD
    breakpad_ExceptionHandler();
#endif
    char* xmlfilename = devXMlFile;
    const char* struuid = uUid;
    int result = updatexmldata(xmlfilename, struuid, serial_Num, "XFINITY"); // BasicDevice.xml currently does not need multi-tenancy support per RDK-8190. (May come in as part of some other ticket, in which case replace "XFINITY" with getFriendlyName().)
    if (!result)
    {
        fprintf(stderr,"Failed to open the device xml file %s\n", xmlfilename);
        exit(1);
    }
    else
    {
        g_message("Updated the device xml file:%s uuid: %s", xmlfilename,struuid);
    }
    if(!getBcastMacAddress(bcastMacaddress))
    {
        g_message("Unable to get bcastMacaddress");
    }

#ifndef GUPNP_1_2
    upnpContext = gupnp_context_new (NULL, devBcastIf, devBcastPort, &error);
#else
    upnpContext = gupnp_context_new (devBcastIf, devBcastPort, &error);
#endif
    if (error) {
        g_message("Error creating the Broadcast context: %s",
                error->message);
        /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
        g_clear_error(&error);
        return EXIT_FAILURE;
    }
    gupnp_context_set_subscription_timeout(upnpContext, 0);
#ifndef GUPNP_1_2
    baseDev = gupnp_root_device_new (upnpContext, devXMlFile, devXMlPath);
#else
    baseDev = gupnp_root_device_new (upnpContext, devXMlFile, devXMlPath, &error);
#endif
#ifndef CLIENT_XCAL_SERVER
    if(!getDisableTuneReadyStatus())
    {
        if(!getTuneReady())
        {
            g_message("Xupnp: Tune ready status is false");
        }
    }
#endif
    gupnp_root_device_set_available (baseDev, TRUE);
    /* Get the discover friendlies service from the root device */
    upnpService = gupnp_device_info_get_service
        (GUPNP_DEVICE_INFO (baseDev), "urn:schemas-upnp-org:service:DiscoverFriendlies:1");
    if (!upnpService) 
    {
        g_printerr ("Cannot get DiscoverFriendlies service\n");
        return EXIT_FAILURE;
    }
    if(rfc_enabled)
    {
        char devXMlFile_new[MAXSIZE];

        if(!getDevXmlFile(devXMlFile_new, 1))
        {
            g_message("Unable to get new device xml file");
        }
        char *xmlfilename_new = devXMlFile_new;

        char uuid_new[48];
        if(getAccountId(accountId))
        {
            g_message("Account Id of the device is %s", accountId);
        }
        else
        {
            g_message("Failed to get the Account Id");
        }
        if(strlen(bcastMacaddress) != 0)
        {
            /* Coverity Fix CID:46884 DC.STRING_BUFFER */ 
            if (snprintf(uuid_new,sizeof(uuid_new),"uuid:%s",bcastMacaddress) > (int)sizeof(uuid_new)) {
                g_message("truncation while copying bcastMacaddress to uuid_new \n");
            }
        }
#ifndef BROADBAND
        if(xPKI_check_rfc() == 1)
        {
            certFile= g_strdup("/tmp/xpki_cert");
            keyFile= g_strdup("/tmp/xpki_key");
            g_message("Using xPKI certs for handshaking");
        }
        else
        {
 #endif
        if ((getDevCertFile(devCertFile)) && (getDevCertPath(devCertPath)) && (getDevKeyFile(devKeyFile)) && (getDevKeyPath(devKeyPath)))
        {
            if (g_path_is_absolute (devCertFile)) 
            {
                certFile = g_strdup (devCertFile);
            }
            else 
            {
                certFile  = g_build_filename (devCertPath, devCertFile, NULL);
            }
            g_message("certFile loaded");

            if (g_path_is_absolute (devKeyFile))
            {
                keyFile = g_strdup (devKeyFile);
            }
            else
            {
                keyFile  = g_build_filename (devKeyPath, devKeyFile, NULL);
            }
            g_message("keyFile loaded ");
        }
#ifndef BROADBAND
        }
#endif
            if ( (certFile != NULL) && (keyFile != NULL) && (g_file_test(certFile, G_FILE_TEST_EXISTS)) && (g_file_test(keyFile, G_FILE_TEST_EXISTS))
                    && (g_file_test(caFile, G_FILE_TEST_EXISTS))) 
            {
                result = updatexmldata(xmlfilename_new, uuid_new, serial_Num, "XFINITY");
                if (!result)
                {
                    g_message("Failed to open the device xml file %s\n", xmlfilename_new);
                    exit(1);
                }
                else
                {
                    g_message("RFC enabled Updated the device xml file:%s uuid: %s", xmlfilename_new,uuid_new);
                }


#ifndef GUPNP_1_2
                upnpContextDeviceProtect = gupnp_context_new_s (NULL,  devBcastIf, DEVICE_PROTECTION_CONTEXT_PORT, certFile, keyFile, &error);
#else
                upnpContextDeviceProtect = gupnp_context_new_s ( devBcastIf, DEVICE_PROTECTION_CONTEXT_PORT, certFile, keyFile, &error);
#endif
                if (error)
                {
                    g_message("Error creating the Device Protection Broadcast context: %s",
                            error->message);
                    /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
                    g_clear_error(&error);
                }
                else
                {
                    gupnp_context_set_subscription_timeout(upnpContextDeviceProtect, 0);
                    // Set TLS config params here.
                    gupnp_context_set_tls_params(upnpContextDeviceProtect,caFile,keyFile, NULL);
#ifndef GUPNP_1_2
                    dev = gupnp_root_device_new (upnpContextDeviceProtect, devXMlFile_new, devXMlPath);
#else
                    dev = gupnp_root_device_new (upnpContextDeviceProtect, devXMlFile_new, devXMlPath, &error);
#endif
                    gupnp_root_device_set_available (dev, TRUE);

                    upnpIdService = gupnp_device_info_get_service
                        (GUPNP_DEVICE_INFO (dev), "urn:schemas-upnp-org:service:X1Identity:1");
                    if (!upnpIdService)
                    {
                        g_message("Cannot get X1Identity service\n");
                    }
                    else
                    {
                        g_message("XUPNP Identity service successfully created");
                    }
                    if (strstr(devXMlFile_new,BROADBAND_DEVICE_XML_FILE) || strstr(devXMlFile_new,GW_DEVICE_XML_FILE))
                    {
                        g_message("Broadband OR Gateway Device Configuration File");
                        upnpTimeConf = gupnp_device_info_get_service
                            (GUPNP_DEVICE_INFO (dev), "urn:schemas-upnp-org:service:X1Time:1");
                        if (!upnpTimeConf)
                        {
                            g_message("Cannot get XfinityTimeConfiguration service\n");
                        }
                        else
                        {
                            g_message("XUPNP XfinityTimeConfiguration service successfully created");
                        }
                        upnpGatewayConf = gupnp_device_info_get_service
                            (GUPNP_DEVICE_INFO (dev), "urn:schemas-upnp-org:service:X1GatewayConfiguration:1");
                        if (!upnpGatewayConf)
                        {
                            g_message("Cannot get XfinityGatewayConfiguration service\n");
                        }
                        else
                        {
                            g_message("XUPNP XfinityGatewayConfiguration service successfully created");
                        }
                    }
                    else
                    {
                        g_message("Client Device configuration file");
                        upnpMediaConfService = gupnp_device_info_get_service
                            (GUPNP_DEVICE_INFO (dev), "urn:schemas-upnp-org:service:X1MediaConfiguration:1");
                        if (!upnpMediaConfService)
                        {
                            g_message("Cannot get XfinityMediaConfiguration service\n");
                        }
                        else
                        {
                            g_message("XUPNP Media Configuration service successfully created");
                        }
                    }
                    if (strstr(devXMlFile_new,GW_DEVICE_XML_FILE))
                    {
                        g_message("Gateway Device Configuration file");
                        upnpMediaConfService = gupnp_device_info_get_service
                            (GUPNP_DEVICE_INFO (dev), "urn:schemas-upnp-org:service:X1MediaConfiguration:1");
                        if (!upnpMediaConfService)
                        {
                            g_message("Cannot get XfinityMediaConfiguration service\n");
                        }
                        else
                        {
                            g_message("XUPNP Media Configuration service successfully created");
                        }
                        upnpQamConf = gupnp_device_info_get_service
                            (GUPNP_DEVICE_INFO (dev), "urn:schemas-upnp-org:service:X1QamConfiguration:1");
                        if (!upnpQamConf)
                        {
                            g_message("Cannot get XfinityQamConfiguration service\n");
                        }
                        else
                        {
                            g_message("XUPNP XfinityQamConfiguration service successfully created");
                        }
                    }

                    if (!getReceiverId(receiverId))
                    {
                        g_message("Unable to get receiver id");
                    }
                }
           }
           else
           {
               g_message("DeviceProtection Error: Cert file, Key file not available, continuing with older xcal");
               rfc_enabled=0;
               result = updatexmldata(xmlfilename, struuid, serial_Num, "XFINITY"); // BasicDevice.xml currently does not need multi-tenancy support per RDK-8190. (May come in as part of some other ticket, in which case replace "XFINITY" with getFriendlyName().)
               if (!result)
               {
                   fprintf(stderr,"Failed to open the device xml file %s\n", xmlfilename);
                   exit(1);
               }
               else
               {
                   g_message("Updated the device xml file:%s uuid: %s", xmlfilename,struuid);
               }
           }
           g_free(keyFile);
           g_free(certFile);
        
    } //rfc_enabled

#ifdef ENABLE_SD_NOTIFY
    sd_notifyf(0, "READY=1\n"
            "STATUS=xcal-device is Successfully Initialized\n"
            "MAINPID=%lu",
            (unsigned long) getpid());
#endif
    /* Autoconnect the action and state variable handlers.  This connects
       query_target_cb and query_status_cb to the Target and Status state
       variables query callbacks, and set_target_cb, get_target_cb and
       get_status_cb to SetTarget, GetTarget and GetStatus actions
       respectively. */
    /*gupnp_service_signals_autoconnect (GUPNP_SERVICE (service), NULL, &error);
      if (error) {
      g_printerr ("Failed to autoconnect signals: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
      }*/
    g_signal_connect (upnpService, "action-invoked::GetBaseUrl", G_CALLBACK (get_url_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetBaseTrmUrl", G_CALLBACK (get_trm_url_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetGatewayIP", G_CALLBACK (get_gwyip_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetGatewayIPv6", G_CALLBACK (get_gwyipv6_cb), NULL);
#ifndef BROADBAND
    g_signal_connect (upnpService, "action-invoked::GetIpv6Prefix", G_CALLBACK (get_ipv6prefix_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetDnsConfig", G_CALLBACK (get_dnsconfig_cb), NULL);
#endif
    g_signal_connect (upnpService, "action-invoked::GetGatewayStbIP", G_CALLBACK (get_gwystbip_cb), NULL);
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
    g_signal_connect (upnpService, "action-invoked::GetClientIP", G_CALLBACK (get_client_ip_cb), NULL);
    g_signal_connect (upnpService, "query-variable::Url", G_CALLBACK (query_url_cb), NULL);
    g_signal_connect (upnpService, "query-variable::TrmUrl", G_CALLBACK (query_trm_url_cb), NULL);
    g_signal_connect (upnpService, "query-variable::GatewayIP", G_CALLBACK (query_gwyip_cb), NULL);
    g_signal_connect (upnpService, "query-variable::GatewayIPv6", G_CALLBACK (query_gwyipv6_cb), NULL);
#ifndef BROADBAND
    g_signal_connect (upnpService, "query-variable::Ipv6Prefix", G_CALLBACK (query_ipv6prefix_cb), NULL);
    g_signal_connect (upnpService, "query-variable::DnsConfig", G_CALLBACK (query_dnsconfig_cb), NULL);
#endif
    g_signal_connect (upnpService, "query-variable::GatewayStbIP", G_CALLBACK (query_gwystbip_cb), NULL);
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
    g_signal_connect (upnpService, "query-variable::ClientIP", G_CALLBACK (query_client_ip_cb), NULL);

    if(rfc_enabled)
    {
#ifdef BROADBAND
        //Broadband services
        registerGatewayConfigurationService(upnpGatewayConf);
        registerTimeConfigurationService(upnpTimeConf);
#else
#ifndef CLIENT_XCAL_SERVER
        //Video Gateway services
        registerQamConfigurationService(upnpQamConf);
        registerGatewayConfigurationService(upnpGatewayConf);
        registerTimeConfigurationService(upnpTimeConf);
        registerMediaConfigurationService(upnpMediaConfService);
#else
        //Client services
        registerMediaConfigurationService(upnpMediaConfService);
#endif
#endif
        registerIdentityConfigurationService(upnpIdService);
        g_message("Successfully registered all services");
    }

    service_ready=TRUE;
#ifndef CLIENT_XCAL_SERVER
    /*Code to handle RUI publishing*/
    if (checkCVP2Enabled())
    {
        if(!(getCVPIf(cvpInterface) && getCVPXmlFile(cvPXmlFile) && getCVPPort(&cvpPort)))
        {
            g_message("Failed to update the CVP variables for xcal-device");
        }
        char* cvpxmlfilename = g_strconcat(g_strstrip(devXMlPath), "/", g_strstrip(cvPXmlFile),NULL);
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
        if(struuidcvp)
        {
            result = updatexmldata(cvpxmlfilename, struuidcvp, serial_Num, "XFINITY");
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
        cvpcontext = gupnp_context_new (NULL, cvpInterface, cvpPort, &error);
#else
        cvpcontext = gupnp_context_new (cvpInterface, cvpPort, &error);
#endif
        if (error) {
            g_printerr ("Error creating the CVP context: %s\n", error->message);
            /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
            g_clear_error(&error);
            return EXIT_FAILURE;
        }
        gupnp_context_set_subscription_timeout(cvpcontext, 0);
#ifndef GUPNP_1_2
        cvpdev = gupnp_root_device_new (cvpcontext, cvPXmlFile, devXMlPath);
#else
        cvpdev = gupnp_root_device_new (cvpcontext, cvPXmlFile, devXMlPath, &error);
#endif
        /* Get the CVP service from the root device */
        gupnp_root_device_set_available (cvpdev, TRUE);
        cvpservice = gupnp_device_info_get_service
            (GUPNP_DEVICE_INFO (cvpdev), "urn:schemas-upnp-org:service:RemoteUIServer:1");
        if (!cvpservice) {
            g_printerr ("Cannot get RemoteUI service\n");
            return EXIT_FAILURE;
        }
        g_signal_connect (cvpservice, "action-invoked::GetCompatibleUIs", G_CALLBACK (get_rui_url_cb), NULL);
        fprintf(stderr,"exiting if dev-cvp\n");
    }
#endif
    //control the announcement frequency and life time
    /*
       GSSDPResourceGroup *ssdpgrp = gupnp_root_device_get_ssdp_resource_group(dev);
       guint msgdelay = gssdp_resource_group_get_message_delay(ssdpgrp);
       guint msgage = gssdp_resource_group_get_max_age(ssdpgrp);
       g_print("Message delay is %u, Message max age is %u", msgdelay, msgage);
     */
    /* Run the main loop */
    main_loop = g_main_loop_new (NULL, FALSE);
    g_main_loop_run (main_loop);
    /* Cleanup */
    g_main_loop_unref (main_loop);
    g_object_unref (upnpService);
    g_object_unref (baseDev);
    g_object_unref (upnpContext);
    if(rfc_enabled)
    {
        g_object_unref (upnpIdService);
        if(upnpMediaConfService)
        {
            g_object_unref (upnpMediaConfService);
        }
        if(upnpTimeConf)
        {
            g_object_unref (upnpTimeConf);
        }
        if(upnpGatewayConf)
        {
            g_object_unref (upnpGatewayConf);
        }
        if(upnpQamConf)
        {
            g_object_unref (upnpQamConf);
        }
        g_object_unref (dev);
        g_object_unref (upnpContextDeviceProtect);
    }
    return EXIT_SUCCESS;
}

