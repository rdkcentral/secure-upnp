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
#include <sys/types.h>
#include <string.h>
#include "rdk_safeclib.h"
#ifdef BROADBAND
#include <syscfg/syscfg.h>
#endif
#include <glib/gprintf.h>
#include <glib/gstdio.h>
#ifndef BROADBAND
#ifdef ENABLE_RFC
#include "rfcapi.h"
#endif
#else
#include <platform_hal.h>
#endif
#if defined(CLIENT_XCAL_SERVER) && !defined(BROADBAND)
#include "mfrMgr.h"
#endif
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
gboolean bSerialNum=FALSE;
#define BOOL unsigned char
#define ACCOUNTID_SIZE 30
gboolean getserialnum(GString* ownSerialNo)
{
#ifndef CLIENT_XCAL_SERVER
    GError                  *error=NULL;
    gboolean                result = FALSE;
    gchar* udhcpcvendorfile = NULL;
 
    result = g_file_get_contents ("//etc//udhcpc.vendor_specific", &udhcpcvendorfile, NULL, &error);
    if (result == FALSE) {
        g_message("Problem in reading /etc/udhcpcvendorfile file %s", error->message);
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
                    g_string_assign(ownSerialNo, g_strstrip(tokens[loopvar+2]));
                    bSerialNum=TRUE;
                    g_message("serialNumber fetched from udhcpcvendorfile:%s", ownSerialNo->str);
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
    if (udhcpcvendorfile) g_free(udhcpcvendorfile);
    return result;
#elif BROADBAND
    gboolean result = FALSE;
    char serialNumber[50] = {0};
    if ( platform_hal_GetSerialNumber(serialNumber) == 0)
    {
        g_message("serialNumber returned from hal:%s", serialNumber);
        g_string_assign(ownSerialNo, serialNumber);
        result = TRUE;
        bSerialNum=TRUE;
    }
    else
    {
        g_message("ERROR: Unable to get SerialNumber");
    }
    return result;
#else
    bool bRet;
    IARM_Bus_MFRLib_GetSerializedData_Param_t param;
    IARM_Result_t iarmRet = IARM_RESULT_IPCCORE_FAIL;
    memset(&param, 0, sizeof(param));
    param.type = mfrSERIALIZED_TYPE_SERIALNUMBER;
    iarmRet = IARM_Bus_Call(IARM_BUS_MFRLIB_NAME, IARM_BUS_MFRLIB_API_GetSerializedData, &param, sizeof(param));
    if(iarmRet == IARM_RESULT_SUCCESS)
    {
        if(param.buffer && param.bufLen)
        {
            g_message( " serialized data %s  \n",param.buffer );
            g_string_assign(ownSerialNo,param.buffer);
            bRet = true;
            bSerialNum=TRUE;
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
                if (strcmp_s(ifa->ifa_name,strlen(ifa->ifa_name),ifname,&ind)==EOK){
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
BOOL check_null(char *str)
{
    if (str) {
        return TRUE;
    }
    return FALSE;
}
BOOL check_empty(char *str)
{
    if (str[0]) {
        return TRUE;
    }
    return FALSE;
}
#ifdef BROADBAND
BOOL getAccountId(char *outValue)
{
    char temp[ACCOUNTID_SIZE] = {0};
    int rc;
    syscfg_init();
    rc = syscfg_get(NULL, "AccountID", temp, sizeof(temp));
    if(!rc)
    {
        if ((outValue != NULL))
        {
            strncpy(outValue, temp, ACCOUNTID_SIZE-1);
            return TRUE;
        }
    }
    else
    {
        g_message("getAccountId: Unable to get the Account Id");
    }
    return FALSE;
}
#else
BOOL getAccountId(char *outValue)
{
    gboolean result = FALSE;
#ifdef ENABLE_RFC
    RFC_ParamData_t param = {0};
    WDMP_STATUS status = getRFCParameter("XUPNP","Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AccountInfo.AccountID",&param);
    if (status == WDMP_SUCCESS)
    {
	if (((param.value == NULL)))
	{
	    g_message("getAccountId : NULL string !");
	    return result;
	}
	else
	{
	    if (strncpy(outValue,param.value, ACCOUNTID_SIZE-1))
	    {
	        result = TRUE;
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
#endif
