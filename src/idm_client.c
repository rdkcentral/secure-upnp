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
 * @file idm_client.c
 * @brief This source file contains functions  that will run as task for maintaining the device list.
 */
#ifndef _GNU_SOURCE
 #define _GNU_SOURCE
#endif
#include <libgupnp/gupnp-control-point.h>
#include <string.h>
#include <unistd.h>
#include <libgssdp/gssdp.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include "xdiscovery.h"
#include "secure_wrapper.h"
#include <sysevent/sysevent.h>
#include <glib/gprintf.h>
#include <string.h>
#include <glib/gstdio.h>
#include "rdk_safeclib.h"
#ifndef BROADBAND
#ifdef ENABLE_RFC
#include "rfcapi.h"
#endif
#else
#include <platform_hal.h>
#include <syscfg/syscfg.h>
#endif
#if defined(CLIENT_XCAL_SERVER) && !defined(BROADBAND)
#include "mfrMgr.h"
#endif
#include <libsoup/soup.h>
#include <idm_client.h>
#ifdef ENABLE_HW_CERT_USAGE
#include "rdkconfig.h"
#endif
#if defined(ENABLE_FEATURE_TELEMETRY2_0)
#include <telemetry_busmessage_sender.h>
#endif
#include "ccsp_trace.h"
#define CLIENT_CONTEXT_PORT 50767
#define IDM_CLIENT_DEVICE "urn:schemas-upnp-org:device:IDM:1"
#define IDM_SERVICE "urn:schemas-upnp-org:service:X1IDM:1"
#define IDM_DP_CLIENT_DEVICE "urn:schemas-upnp-org:device:IDM_DP:1"
#define IDM_DP_SERVICE "urn:schemas-upnp-org:service:X1IDM_DP:1"
#define IDM_CERT_FILE "/tmp/idm_xpki_cert"
#define IDM_KEY_FILE "/tmp/idm_xpki_key"
#define IDM_CA_FILE "/tmp/idm_UPnP_CA"

#ifdef ENABLE_HW_CERT_USAGE
char se_cert_p12[128];
char se_cert_conf_file[128];
#endif

static int fd = -1;
static gboolean idm_upnp_init_status = FALSE;
static GUPnPContext *upnpContextDeviceProtect;
static GMainLoop *main_loop;
typedef GTlsInteraction XupnpTlsInteraction;
typedef GTlsInteractionClass XupnpTlsInteractionClass;
static guint idm_stop_discovery_triggered = 0;
static GMutex stop_discovery_mutex;
static void xupnp_tls_interaction_init (XupnpTlsInteraction *interaction);
static void xupnp_tls_interaction_class_init (XupnpTlsInteractionClass *xupnpClass);
int s_sysevent_connect (token_t *out_se_token);
int SE_msg_receive(int fd, char *replymsg, unsigned int *replymsg_size, token_t *who);
GType xupnp_tls_interaction_get_type (void);

G_DEFINE_TYPE (XupnpTlsInteraction, xupnp_tls_interaction, G_TYPE_TLS_INTERACTION);

static gint
g_list_compare_sno(GwyDeviceData* gwData1, GwyDeviceData* gwData2, gpointer user_data )
{
  gint result = g_strcmp0(g_strstrip(gwData1->serial_num->str),g_strstrip(gwData2->serial_num->str));
  return result;
}

static gint
g_list_find_sno(GwyDeviceData* gwData, gconstpointer* sno )
{
    if (g_strcmp0(g_strstrip(gwData->serial_num->str),g_strstrip((gchar *)sno)) == 0)
        return 0;
    else
        return 1;
}
int s_sysevent_connect (token_t *out_se_token)
{
    static token_t sysevent_token = 0;
    if (0 > fd )
    {
        unsigned short sysevent_port = SE_SERVER_WELL_KNOWN_PORT;
        char          *sysevent_ip = "127.0.0.1";
        char          *sysevent_name = "idm_client";
        fd = sysevent_open(sysevent_ip, sysevent_port, SE_VERSION, sysevent_name, &sysevent_token);
        CcspTraceInfo(("%s: open new sysevent fd %d", __FUNCTION__,fd));
    }
    else
    {
        CcspTraceInfo(("Inside %s:%d",__FUNCTION__,__LINE__));
    }
    *out_se_token = sysevent_token;
    return fd;
}
int EventListen(void)
{
    fd_set  rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    int     retval,ret=-2;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    retval=select(fd+1, &rfds, NULL, NULL, NULL);

    if(retval)
    {
        se_buffer            msg_buffer;
        se_notification_msg *msg_body = (se_notification_msg *)msg_buffer;
        unsigned int         msg_size;
        token_t              from;
        int                  msg_type;

        msg_size  = sizeof(msg_buffer);
        msg_type = SE_msg_receive(fd, msg_buffer, &msg_size, &from);
        // if not a notification message then ignore it
        if (SE_MSG_NOTIFICATION == msg_type)
        {
            // extract the name and value from the return message data
            int   name_bytes;
            int   value_bytes;
            char *name_str;
            char *value_str;
            char *data_ptr;

            data_ptr   = (char *)&(msg_body->data);
            name_str   = (char *)SE_msg_get_string(data_ptr, &name_bytes);
            data_ptr  += name_bytes;
            value_str =  (char *)SE_msg_get_string(data_ptr, &value_bytes);
            if(!strcmp(name_str, "wan-status"))
            {
                if (!strncmp(value_str, "started", 7))
                {
                    CcspTraceInfo(("wan-status started"));
                    ret = 0;
                }
                else if (!strncmp(value_str, "stopped", 7))
                {
                    CcspTraceInfo(("wan-status stopped"));
                    ret = -1;
                }
            }
        }
        else
        {
            CcspTraceInfo(("Received msg that is not a SE_MSG_NOTIFICATION (%d)\n", msg_type));
        }
    }
    else
    {
        CcspTraceInfo(("%s: Received no event retval=%d\n", __FUNCTION__, retval));
    }
    return ret;
}
void* EventHandler(void* args)
{
    char wan_status[8]={'\0'};
    token_t  token;
    async_id_t wan_status_id;
    int ret,rc;
start:
    fd = s_sysevent_connect(&token);
    sysevent_set_options(fd, token, "wan-status", TUPLE_FLAG_EVENT);
    rc = sysevent_setnotification(fd, token, "wan-status", &wan_status_id);
    if(rc)
    {
        CcspTraceInfo(("goto start"));
        goto start;
    }
    if ( 0 == sysevent_get(fd, token, "wan-status", wan_status,sizeof(wan_status)) && '\0' != wan_status)
    {
        if (0 == strncmp(wan_status,"stopped",strlen("stopped")))
        {
            CcspTraceInfo(("present wan-status stopped"));
            gupnp_set_cert_flags(0x0010);
        }
        else
        {
            CcspTraceInfo(("present wan-status started"));
            sysevent_rmnotification(fd, token, wan_status_id);
            sysevent_close(fd, token);
            pthread_exit(NULL);
        }
        while(1)
        {
            ret = EventListen();
            if(ret == 0)
            {
                CcspTraceInfo(("EventListen returned zero"));
                gupnp_set_cert_flags(0x001C);
                v_secure_system("/etc/Xupnp/idm_certs.sh");
                break;
            }
            else if(ret == -1)
            {
                CcspTraceInfo(("EventListen returned minus 1"));
                gupnp_set_cert_flags(0x0010);
            }
            else
            {
                CcspTraceInfo(("EventListen returned neither 1 or -1"));
            }
        }
        sysevent_rmnotification(fd, token, wan_status_id);
        sysevent_close(fd, token);
        pthread_exit(NULL);
    }
    return NULL;
}

static void
xupnp_tls_interaction_init (XupnpTlsInteraction *interaction)
{

}
static GTlsInteractionResult
xupnp_tls_interaction_request_certificate (GTlsInteraction              *interaction,
                                         GTlsConnection               *connection,
                                         GTlsCertificateRequestFlags   flags,
                                         GCancellable                 *cancellable,
                                         GError                      **error)
{
    GTlsCertificate *cert = NULL;
    GError *xupnp_error = NULL;
    //ENABLE_HW_CERT_USAGE will be defined through disto feature flag check from OEM
#ifdef ENABLE_HW_CERT_USAGE
    uint8_t *pass_phrase = NULL;
    size_t pass_size = 0;
    size_t len = 0;

    if( (access(se_cert_p12, F_OK) == -1) && (access(certFile, F_OK) != -1) )
    {
        v_secure_system("ln -sf %s %s",certFile, se_cert_p12);
    }

    if(access(se_cert_p12, F_OK) != -1)
    {
        CcspTraceInfo(("Getting passcode\n"));

        if(rdkconfig_get(&pass_phrase, &pass_size, se_cert_conf_file) == RDKCONFIG_FAIL)
        {
            CcspTraceError(("rdkconfig_get failed for SE cert passcode"));
        }
        else
        {
            len = strcspn(pass_phrase, "\n");
            pass_phrase[len] = '\0';
            CcspTraceInfo(("SE cert passcode decoded"));
        }

        CcspTraceInfo(("using SE certificate with passcode"));

        cert = g_tls_certificate_new_from_file_with_password(se_cert_p12, pass_phrase, &xupnp_error);
        if(cert)
        {
            CcspTraceInfo(("SE certificate loaded successfully"));
        }
        else
        {
            CcspTraceError(("g_tls_certificate_new_from_file_with_password failed: %s",
                        xupnp_error ? xupnp_error->message : "unknown error"));
            if(xupnp_error)
            {
                CcspTraceInfo((" %s\n",xupnp_error->message));
            }
            g_error_free (xupnp_error);
            if(pass_phrase != NULL)
            {
                CcspTraceInfo((" Freeing pass phrase "));
                rdkconfig_free(&pass_phrase, pass_size);
            }
            return  G_TLS_INTERACTION_FAILED;
        }
        if(pass_phrase != NULL)
        {
            CcspTraceInfo((" Freeing pass phrase "));
            rdkconfig_free(&pass_phrase, pass_size);
        }
    }
    else // cannot access HW cert. Fallback to normal cert
    {
        if ((certFile[0] == '\0') || (keyFile[0] == '\0')) {

            CcspTraceError(("certFile or keyFile path is empty (HW cert fallback path)"));
            return  G_TLS_INTERACTION_FAILED;
        }

        if((access(certFile,F_OK ) != 0) || (access(keyFile,F_OK ) != 0)) {

          CcspTraceError(("certFile or keyFile not found"));
          return  G_TLS_INTERACTION_FAILED;
       }

       cert = g_tls_certificate_new_from_files (certFile,
                                                keyFile,
                                                &xupnp_error);
       if(cert == NULL) {
       
          CcspTraceError(("g_tls_certificate_new_from_files failed"));

          if(xupnp_error != NULL) {
          
                CcspTraceError(("Failure reason for certificate creation: %s\n", xupnp_error->message));
                g_clear_error(&xupnp_error);
            }
            return  G_TLS_INTERACTION_FAILED;
        }

    }
#else
    // Normal certificate
    if ((certFile[0] == '\0') || (keyFile[0] == '\0')) {

        CcspTraceError(("certFile or keyFile path is empty"));
        return  G_TLS_INTERACTION_FAILED;
    }

    if((access(certFile,F_OK ) != 0) || (access(keyFile,F_OK ) != 0)) {

        CcspTraceError(("certFile or keyFile not found"));
        return  G_TLS_INTERACTION_FAILED;
    }

    cert = g_tls_certificate_new_from_files (certFile,
            keyFile,
            &xupnp_error);
    if(cert == NULL) {

        CcspTraceError(("g_tls_certificate_new_from_files failed"));

        if(xupnp_error != NULL) {
            CcspTraceError(("Failure reason for certificate creation: %s\n", xupnp_error->message));
            g_clear_error(&xupnp_error);
          }
          return  G_TLS_INTERACTION_FAILED;
       }

#endif
    if(xupnp_error)
    {
        g_assert_no_error (xupnp_error);
        g_error_free (xupnp_error);
    }

    if(cert)
    {
        g_tls_connection_set_certificate (connection, cert);
        g_object_unref (cert);
        return G_TLS_INTERACTION_HANDLED;
    }
    return  G_TLS_INTERACTION_FAILED;
}

static void
xupnp_tls_interaction_class_init (XupnpTlsInteractionClass *xupnpClass)
{
       GTlsInteractionClass *interaction_class = G_TLS_INTERACTION_CLASS (xupnpClass);

       interaction_class->request_certificate = xupnp_tls_interaction_request_certificate;
}

gboolean init_gwydata(GwyDeviceData* gwydata)
{
    gwydata->serial_num = g_string_new(NULL);
    gwydata->bcastmacaddress = g_string_new(NULL);
    gwydata->clientip = g_string_new(NULL);
    gwydata->receiverid = g_string_new(NULL);
    gwydata->gwyipv6 = g_string_new(NULL);
    gwydata->sproxy=NULL;
    gwydata->sproxy_i=NULL;
    return TRUE;
}

guint deviceAddNo=0;
gboolean processStringRequest(const GUPnPServiceProxy *sproxy ,const char * requestFn,
                const char * responseFn, gchar ** result, gboolean isInCriticalPath)
{
GError *error = NULL;
#ifdef GUPNP_1_2
    GUPnPServiceProxyAction *action;
    action = gupnp_service_proxy_action_new (requestFn, NULL);
    gupnp_service_proxy_call_action ((GUPnPServiceProxy *)sproxy, action, NULL, &error);
    if( NULL == error )
    {
        gupnp_service_proxy_action_get_result (action,
                                               &error, responseFn, G_TYPE_STRING, result, NULL);
        g_clear_pointer (&action, gupnp_service_proxy_action_unref);
    }
#else
    gupnp_service_proxy_send_action ((GUPnPServiceProxy *)sproxy, requestFn, &error,NULL, responseFn, G_TYPE_STRING, result ,NULL);
#endif
    if ( NULL != error ) //Didn't went well
    {
        CcspTraceError(("gupnp_service_proxy_send_action failed fn=%s error=%s", requestFn, error->message));
        if ( isInCriticalPath ) // Update telemetry
        {
                CcspTraceError(("TELEMETRY_XUPNP_PARTIAL_DISCOVERY:%d,%s", error->code, requestFn));
        }
        g_clear_error(&error);
        return FALSE;
    }
    return TRUE;
}

void* verify_devices()
{
    guint sleepCounter=0;
    guint cp_bgw_inactive_count = 0;
    guint cp_bgw_null_count = 0;
    CcspTraceInfo(("verify_devices thread started"));
    //workaround to remove device in second attempt -Start
    usleep(sleep_seconds);
    while(1)
    {
        if(deviceAddNo)
        {
            if((sleepCounter > 6) && (sleepCounter < 12)) //wait for device addition to complete in 60 seconds and print only for another 60 seconds if there is a hang
            {
                CcspTraceInfo(("Device Addition %u going in main loop",deviceAddNo));
            }
            sleepCounter++;
            usleep(sleep_seconds);
            continue;
        }
        sleepCounter=0;

#ifdef IDM_DEBUG
        if(cp != NULL)
        {
            cp_bgw_null_count = 0;
            if (gssdp_resource_browser_rescan(GSSDP_RESOURCE_BROWSER(cp))==FALSE)
            {
                CcspTraceInfo(("gssdp rescan failed (cp)"));
                cp_bgw_inactive_count++;
                if(cp_bgw_inactive_count > 5)
                {
                    //xupnp thread  is stuck for 5 minutes
                    CcspTraceInfo(("xupnp is stuck for more than 5 minutes. Triggering IDM restart..."));
                    cp_bgw_inactive_count = 0;
                    v_secure_system("touch /tmp/idm_upnp_not_operational");
                }
                usleep(sleep_seconds);
            }
            else
            {
                if(cp_bgw_inactive_count)
                {
                    cp_bgw_inactive_count = 0;
                }
            }
        }
        else
        {
            cp_bgw_null_count++;
            if(cp_bgw_null_count > 5)
            {
                //xupnp got stuck for 5 minutes
                CcspTraceInfo(("xupnp is stuck for more than 5 minutes. Triggering IDM restart..."));
                cp_bgw_null_count = 0;
                v_secure_system("touch /tmp/idm_upnp_not_operational");
                // this is for information to confirm upnp locked with date and time
                v_secure_system("touch /tmp/upnp_locked;date > /tmp/upnp_locked");
            }
        }
#else
        if(cp_bgw != NULL)
        {
            cp_bgw_null_count = 0;
            if (gssdp_resource_browser_rescan(GSSDP_RESOURCE_BROWSER(cp_bgw))==FALSE)
            {
                CcspTraceInfo(("gssdp rescan failed (cp_bgw)"));
                cp_bgw_inactive_count++;
                if(cp_bgw_inactive_count > 5)
                {
                    //xupnp got stuck for 5 minutes
                    CcspTraceInfo(("xupnp is stuck for more than 5 minutes. Triggering IDM restart..."));
                    cp_bgw_inactive_count = 0;
                    v_secure_system("touch /tmp/idm_upnp_not_operational");
                    // this is for information to confirm upnp locked with date and time
                    v_secure_system("touch /tmp/upnp_locked;date > /tmp/upnp_locked");
                }
                usleep(sleep_seconds);
            }
            else
            {
                if(cp_bgw_inactive_count)
                {
                    cp_bgw_inactive_count = 0;
                }
            }
        }
        else
        {
            cp_bgw_null_count++;
            if(cp_bgw_null_count > 5)
            {
                //xupnp got stuck for 5 minutes
                CcspTraceInfo(("xupnp is stuck for more than 5 minutes. Triggering IDM restart..."));
                cp_bgw_null_count = 0;
                v_secure_system("touch /tmp/idm_upnp_not_operational");
                // this is for information to confirm upnp locked with date and time
                v_secure_system("touch /tmp/upnp_locked;date > /tmp/upnp_locked");
            }
        }
#endif
        usleep(sleep_seconds);
    }
}

// Thread to stop main discovery process. It will check the "stop discovery flag" for each 10 seconds */
// stop discovery flag will be set by IDM using API stop_discovery()
void* stop_discovery_process()
{
    int stop_discovery_status = 0;

    while(1)
    {
        g_mutex_lock(&stop_discovery_mutex);
        stop_discovery_status = idm_stop_discovery_triggered;
        if(idm_stop_discovery_triggered)
        {
            // reset discovery status global variable. This will be set by external module
            idm_stop_discovery_triggered = 0;
        }
        g_mutex_unlock(&stop_discovery_mutex);
            
        if(stop_discovery_status)
        {
            CcspTraceInfo(("stop discovery triggered"));
            if(main_loop)
            {
                if(g_main_loop_is_running(main_loop))
                {
                    CcspTraceInfo(("quitting main loop"));
                    g_main_loop_quit(main_loop);
                }
                else
                {
                    CcspTraceInfo(("main loop not running"));
                }
            } 
            else
            {
                CcspTraceInfo(("main loop is NULL"));
            }
            CcspTraceInfo(("stop discovery complete"));
        }
        sleep(5);
    }
}

gboolean delete_gwyitem(const char* serial_num)
{
    //look if the item exists
    GList* lstXdev = g_list_find_custom (xdevlist, serial_num, (GCompareFunc)g_list_find_sno);
    //if item exists delete the item
    if (lstXdev)
    {
        GwyDeviceData *gwydata = lstXdev->data;
        g_mutex_lock(mutex);
        xdevlist = g_list_remove_link(xdevlist, lstXdev);
        if(gwydata)
        {
            device_info_t di;
            strcpy(di.Ipv4,gwydata->clientip->str);
            strcpy(di.mac,gwydata->bcastmacaddress->str);
            strcpy(di.Ipv6,gwydata->gwyipv6->str);
            CcspTraceInfo(("callback=%p",callback));
            callback(&di,0,0);
            g_string_free(gwydata->serial_num, TRUE);
            g_string_free(gwydata->bcastmacaddress, TRUE);
            g_string_free(gwydata->gwyipv6,TRUE);
            g_string_free(gwydata->clientip,TRUE);
            g_string_free(gwydata->receiverid,TRUE);
            if(gwydata->sproxy)
            {
                g_clear_object(&(gwydata->sproxy));
            }
            if(gwydata->sproxy_i)
            {
                g_clear_object(&(gwydata->sproxy_i));
            }
        }
        g_free(gwydata);
        g_mutex_unlock(mutex);
        CcspTraceInfo(("device removed from list sno=%s", serial_num));
        g_list_free (lstXdev);
        return TRUE;
    }
    else
    {
        CcspTraceInfo(("device not found in list for removal sno=%s", serial_num));
    }
    return FALSE;
}

static void
device_proxy_unavailable_cb_bgw (GUPnPControlPoint *cp, GUPnPDeviceProxy *dproxy)
{
    const gchar* sno = gupnp_device_info_get_serial_number (GUPNP_DEVICE_INFO (dproxy));
    CcspTraceInfo(("device went down sno=%s", sno ? sno : "NULL"));
    if((g_strcmp0(g_strstrip(ownSerialNo->str),sno) == 0))
    {
        CcspTraceInfo(("Self Device [%s][%s] not removing",sno,ownSerialNo->str));
        g_free((gpointer)sno);
        return;
    }
    if (delete_gwyitem(sno) == FALSE)
    {
        CcspTraceError(("failed to delete device from list sno=%s", sno ? sno : "NULL"));
        return;
    }
    else
    {
        CcspTraceInfo(("device deleted from list sno=%s", sno));
    }
    g_free((gpointer)sno);
}
#ifndef IDM_DEBUG
static void
device_proxy_available_cb_bgw (GUPnPControlPoint *cp, GUPnPDeviceProxy *dproxy)
{
    CcspTraceInfo(("broadband device available cb triggered no=%u", deviceAddNo));
    deviceAddNo++;
    if ((NULL==cp) || (NULL==dproxy))
    {
        deviceAddNo--;
        CcspTraceError(("null pointer received for broadband device no %u", deviceAddNo));
        return;
    }
    gchar* sno = gupnp_device_info_get_serial_number (GUPNP_DEVICE_INFO (dproxy));
    GList* xdevlistitem = g_list_find_custom(xdevlist,sno,(GCompareFunc)g_list_find_sno);
    if(xdevlistitem!=NULL)
    {
        deviceAddNo--;
        CcspTraceInfo(("device already in list skipping sno=%s", sno ? sno : "NULL"));
        g_free((gpointer)sno);
        return;
    }
    GwyDeviceData *gwydata = g_new(GwyDeviceData,1);
    init_gwydata(gwydata);
    gwydata->sproxy_i = gupnp_device_info_get_service(GUPNP_DEVICE_INFO (dproxy), IDM_DP_SERVICE);
    if (sno != NULL)
    {
        CcspTraceInfo(("broadband device discovered sno=%s", sno));
        g_string_assign(gwydata->serial_num, sno);
        const char* udn = gupnp_device_info_get_udn(GUPNP_DEVICE_INFO (dproxy));
        if (udn != NULL)
        {
            if (g_strrstr(udn,"uuid:"))
            {
                gchar* receiverid = g_strndup(udn+5, strlen(udn)-5);
                if(receiverid)
                {
                    CcspTraceInfo(("Gateway device receiver id is %s",receiverid));
                    device_info_t di;
                    memset(&di,0,sizeof(di));
                    g_string_assign(gwydata->receiverid, receiverid);
                    g_free(receiverid);
                    gchar *temp=NULL;
                    if ( processStringRequest((GUPnPServiceProxy *)gwydata->sproxy_i, "GetClientIP", "ClientIP" , &temp, FALSE))
                    {
                        g_string_assign(gwydata->clientip, temp);
                        strncpy(di.Ipv4,gwydata->clientip->str,IPv4_ADDR_SIZE);
                        CcspTraceInfo(("clientIP=%s",di.Ipv4));
                        g_free(temp);
                    }
                    if ( processStringRequest((GUPnPServiceProxy *)gwydata->sproxy_i, "GetBcastMacAddress", "BcastMacAddress" , &temp, FALSE))
                    {
                        g_string_assign(gwydata->bcastmacaddress, temp);
                        strncpy(di.mac,gwydata->bcastmacaddress->str,MAC_ADDR_SIZE);
                        CcspTraceInfo(("BcastMacAddress=%s",di.mac));
                        g_free(temp);
                    }
                    if ( processStringRequest((GUPnPServiceProxy *)gwydata->sproxy_i, "GetGatewayIPv6", "GatewayIPv6" , &temp, FALSE))
                    {
                        g_string_assign(gwydata->gwyipv6,temp);
                        strncpy(di.Ipv6,gwydata->gwyipv6->str,IPv6_ADDR_SIZE);
                        CcspTraceInfo(("GatewayIPv6=%s",di.Ipv6));
                        g_free(temp);
                    }
                    g_mutex_lock(mutex);
                    xdevlist = g_list_insert_sorted_with_data(xdevlist, gwydata,(GCompareDataFunc)g_list_compare_sno, NULL);
                    g_mutex_unlock(mutex);
                    CcspTraceInfo(("device associated sno=%s", sno));
#if defined(ENABLE_FEATURE_TELEMETRY2_0)
                    t2_event_s("IDM_DEVICE_ASSOCIATED_split", sno);
#endif
                    callback(&di,1,1);
                }
                else
                {
                    CcspTraceError(("gateway device receiver id is NULL sno=%s", sno));
                }
            }
        }
        else
        {
            CcspTraceError(("gateway UDN is NULL sno=%s", sno));
        }
    }
    g_free(sno);
    deviceAddNo--;
    CcspTraceInfo(("Exiting from device_proxy_available_cb_broadband deviceAddNo = %u",deviceAddNo));
}
#else
static void device_proxy_available_cb (GUPnPControlPoint *cp, GUPnPDeviceProxy *dproxy)
{
    CcspTraceInfo(("new device available cb triggered no=%u", deviceAddNo));
    deviceAddNo++;
    if ((NULL==cp) || (NULL==dproxy))
    {
        deviceAddNo--;
        CcspTraceError(("null pointer received for gateway device no %u", deviceAddNo));
        return;
    }
    gchar* sno = gupnp_device_info_get_serial_number (GUPNP_DEVICE_INFO (dproxy));
    GList* xdevlistitem = g_list_find_custom(xdevlist,sno,(GCompareFunc)g_list_find_sno);
    if(xdevlistitem!=NULL)
    {
        deviceAddNo--;
        CcspTraceInfo(("device already in list skipping sno=%s", sno ? sno : "NULL"));
        g_free(sno);
        return;
    }
    GwyDeviceData *gwydata = g_new(GwyDeviceData,1);
    if(gwydata)
    {
        init_gwydata(gwydata);
    }
    else
    {
        CcspTraceError(("could not allocate memory for GwyData, exiting"));
        exit(1);
    }
    gwydata->sproxy = gupnp_device_info_get_service(GUPNP_DEVICE_INFO (dproxy), IDM_SERVICE);
    if(!gwydata->sproxy)
    {
        deviceAddNo--;
        CcspTraceError(("unable to get services sproxy null sno=%s", sno ? sno : "NULL"));
        return;
    }
    if (sno != NULL)
    {
        CcspTraceInfo(("device discovered sno=%s", sno));
        g_string_assign(gwydata->serial_num, sno);
        const char* udn = gupnp_device_info_get_udn(GUPNP_DEVICE_INFO (dproxy));
        if (udn != NULL)
        {
            if (g_strrstr(udn,"uuid:"))
            {
                gchar* receiverid = g_strndup(udn+5, strlen(udn)-5);
                if(receiverid)
                {
                    CcspTraceInfo(("Device receiver id is %s",receiverid));
                    g_string_assign(gwydata->receiverid, receiverid);
                    g_free(receiverid);
                    gchar *temp=NULL;
                    device_info_t di;
                    memset(&di,0,sizeof(di));
                    if ( processStringRequest((GUPnPServiceProxy *)gwydata->sproxy, "GetClientIP", "ClientIP" , &temp, FALSE))
                    {
                        g_string_assign(gwydata->clientip, temp);
                        strncpy(di.Ipv4,gwydata->clientip->str,IPv4_ADDR_SIZE);
                        CcspTraceInfo(("clientIP=%s",di.Ipv4));
                        g_free(temp);
                    }
                    if ( processStringRequest((GUPnPServiceProxy *)gwydata->sproxy, "GetBcastMacAddress", "BcastMacAddress" , &temp, FALSE))
                    {
                        g_string_assign(gwydata->bcastmacaddress, temp);
                        strncpy(di.mac,gwydata->bcastmacaddress->str,MAC_ADDR_SIZE);
                        CcspTraceInfo(("BcastMacAddress=%s",di.mac));
                        g_free(temp);
                    }
                    if ( processStringRequest((GUPnPServiceProxy *)gwydata->sproxy, "GetGatewayIPv6", "GatewayIPv6" , &temp, FALSE))
                    {
                        g_string_assign(gwydata->gwyipv6,temp);
                        strncpy(di.Ipv6,gwydata->gwyipv6->str,IPv6_ADDR_SIZE);
                        CcspTraceInfo(("GatewayIPv6=%s",di.Ipv6));
                        g_free(temp);
                    }
                    g_mutex_lock(mutex);
                    xdevlist = g_list_insert_sorted_with_data(xdevlist, gwydata,(GCompareDataFunc)g_list_compare_sno, NULL);
                    g_mutex_unlock(mutex);
                    CcspTraceInfo(("device associated sno=%s", sno));
#if defined(ENABLE_FEATURE_TELEMETRY2_0)
                    t2_event_s("IDM_DEVICE_ASSOCIATED_split", sno);
#endif
                    callback(&di,1,0);
                }
                else
                {
                    CcspTraceError(("device receiver id is NULL sno=%s", sno));
                }
            }
        }
        else
        {
            CcspTraceError(("device UDN is NULL sno=%s", sno));
        }
    }
    g_free(sno);
    deviceAddNo--;
    CcspTraceInfo(("Exiting from device_proxy_available_cb deviceAddNo = %u",deviceAddNo));
}
#endif

void remove_entries_in_list()
{
    CcspTraceInfo(("%s:%d Entered.",__FUNCTION__,__LINE__));
    if (g_list_length(xdevlist) > 0)
    {
        GList *element = NULL;
        element = g_list_first(xdevlist);
        while(element)
        {
            GwyDeviceData *gwydata = element->data;
            g_mutex_lock(mutex);
            xdevlist = g_list_remove_link(xdevlist,element);
            CcspTraceInfo(("%s:%d Deleting %s from the list",__FUNCTION__,__LINE__,gwydata->bcastmacaddress->str));
            g_string_free(gwydata->serial_num, TRUE);
            g_string_free(gwydata->bcastmacaddress, TRUE);
            g_string_free(gwydata->gwyipv6,TRUE);
            g_string_free(gwydata->clientip,TRUE);
            g_string_free(gwydata->receiverid,TRUE);
            if(gwydata->sproxy)
            {
                g_clear_object(&(gwydata->sproxy));
            }
            if(gwydata->sproxy_i)
            {
                g_clear_object(&(gwydata->sproxy_i));
            }
            g_free(gwydata);
            g_mutex_unlock(mutex);
            element = g_list_next(element);
        }
    }
}

/* This API is called by IDM to update flag to inform the stop_discovery_process() to quit main loop 
 To update flag, we need lock because the same flag is used by stop_discovery_process() thread */
int stop_discovery()
{
    CcspTraceInfo(("%s:%d Called.",__FUNCTION__,__LINE__));
    g_mutex_lock(&stop_discovery_mutex);
    idm_stop_discovery_triggered = 1;
    g_mutex_unlock(&stop_discovery_mutex);
    CcspTraceInfo(("%s:%d completed",__FUNCTION__,__LINE__));
    return 0;
}
void start_discovery(discovery_config_t* dc_obj,int (*func_callback)(device_info_t*,uint,uint))
{
    int rvalue=0;
    if(!(dc_obj->interface)||(dc_obj->port)==0||(dc_obj->discovery_interval)==0||(dc_obj->loss_detection_window)==0)
    {
        CcspTraceError(("mandatory values missing interface=%s port=%d interval=%d window=%d",
                    dc_obj->interface, dc_obj->port, dc_obj->discovery_interval, dc_obj->loss_detection_window));
        return;
    }
    CcspTraceInfo(("discovery started interface=%s port=%d", dc_obj->interface, dc_obj->port));
    g_thread_init (NULL);
    g_type_init();
    GError* error = 0;
    ownSerialNo=g_string_new(NULL);
    getserialnum(ownSerialNo);
    callback=func_callback;
    CcspTraceInfo(("TELEMETRY_IDM_DISCOVERY_STARTED:%s", ownSerialNo->str));
#if defined(ENABLE_FEATURE_TELEMETRY2_0)
    t2_event_s("IDM_DISCOVERY_STARTED_split", ownSerialNo->str);
#endif
#ifndef IDM_DEBUG
#ifndef ENABLE_HW_CERT_USAGE
    memset(caFile, 0 , sizeof(caFile));
    memset(certFile, 0 , sizeof(certFile));
    memset(keyFile, 0 , sizeof(keyFile));
    strncpy(caFile, dc_obj->sslCA, sizeof(caFile) -1);
    strncpy(certFile, dc_obj->sslCert, sizeof(certFile) -1);
    strncpy(keyFile, dc_obj->sslKey, sizeof(keyFile) -1);
#else
    memset(certFile, 0 , sizeof(certFile));
    strncpy(certFile, dc_obj->sslSeCert, sizeof(certFile) -1);
    strncpy(se_cert_conf_file, dc_obj->sslPassCodeFile, sizeof(se_cert_conf_file) -1);
    memset(caFile, 0 , sizeof(caFile));
    strncpy(caFile, dc_obj->sslSeCAFile, sizeof(caFile) -1);
    if(access(certFile, F_OK ) == 0)
    {
        // form .p12 file name from .pk12
        char tmp[128] = { 0 }, *token = NULL;
        strncpy(tmp, certFile, sizeof(tmp) - 1);
        token = strtok(tmp, ".");
        if(token != NULL)
        {
            strncpy(se_cert_p12, token, sizeof(se_cert_p12) - 1);
            strncat(se_cert_p12, ".p12", sizeof(se_cert_p12) - 1);
        }
        memset(tmp, 0, sizeof(tmp));
        if(access(se_cert_p12, F_OK ) == -1)
        {
            v_secure_system("ln -sf %s %s", certFile, se_cert_p12);
            if(access(se_cert_p12, F_OK ) == -1)
            {
                CcspTraceError(("cannot create p12 cert file"));
            }
            else
            {
                CcspTraceInfo(("p12 cert file created"));
            }
        }
    }
    else
    {
        memset(caFile, 0 , sizeof(caFile));
        memset(certFile, 0 , sizeof(certFile));
        memset(keyFile, 0 , sizeof(keyFile));
        strncpy(caFile, dc_obj->sslCA, sizeof(caFile) -1);
        strncpy(certFile, dc_obj->sslCert, sizeof(certFile) -1);
        strncpy(keyFile, dc_obj->sslKey, sizeof(keyFile) -1);
        CcspTraceError(("SE HW certificate not accessible, falling back to software cert"));

    }
#endif
#endif
    rvalue=idm_server_start(dc_obj->interface, dc_obj->base_mac);
    if(rvalue==1)
    {
        CcspTraceError(("idm_server_start failed rvalue=%d", rvalue));
        return;
    }
    mutex = g_mutex_new ();
#ifndef IDM_DEBUG
    GTlsInteraction *xupnp_tlsinteraction= NULL;
#ifndef ENABLE_HW_CERT_USAGE
    if((access(certFile,F_OK ) == 0) && (access(keyFile,F_OK ) == 0) && (access(caFile,F_OK ) == 0))
    {
#else
    if (((access(se_cert_p12, F_OK) == 0) || ((access(certFile,F_OK ) == 0) && (access(keyFile,F_OK ) == 0)))
            && (access(caFile, F_OK ) == 0)) 
    {
#endif
#ifndef GUPNP_1_2
#ifndef ENABLE_HW_CERT_USAGE
        upnpContextDeviceProtect = gupnp_context_new_s ( NULL,  dc_obj->interface, dc_obj->port,certFile,keyFile, &error);
#else
        if(access(se_cert_p12, F_OK) == 0)
        {
            CcspTraceInfo(("TLS context: using SE HW certificate"));
            upnpContextDeviceProtect = gupnp_context_new_s ( NULL,  dc_obj->interface, dc_obj->port,NULL,NULL, &error);
        }
        else
        {
            CcspTraceInfo(("TLS context: using extracted cert files"));
            upnpContextDeviceProtect = gupnp_context_new_s ( NULL,  dc_obj->interface, dc_obj->port,certFile,keyFile, &error);
        }
#endif
#else
#ifndef ENABLE_HW_CERT_USAGE
        upnpContextDeviceProtect = gupnp_context_new_s (dc_obj->interface, dc_obj->port,certFile,keyFile, &error);
#else
        if(access(se_cert_p12, F_OK) == 0)
        {
            CcspTraceInfo(("TLS context: using SE HW certificate"));
            upnpContextDeviceProtect = gupnp_context_new_s (dc_obj->interface, dc_obj->port,NULL,NULL, &error);
        }
        else
        {
            CcspTraceInfo(("TLS context: using extracted cert files"));
            upnpContextDeviceProtect = gupnp_context_new_s (dc_obj->interface, dc_obj->port,certFile,keyFile, &error);
        }
#endif
#endif
        if (error) {
            CcspTraceError(("%s:%d Error creating the Device Protection Broadcast context: %s\n", __FUNCTION__,__LINE__,error->message));
            /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
            g_clear_error(&error);
        }
        else
        {
            CcspTraceInfo(("UPnP running in secure mode"));
            gupnp_context_set_subscription_timeout(upnpContextDeviceProtect, 0);
            xupnp_tlsinteraction = g_object_new (xupnp_tls_interaction_get_type (), NULL);
            CcspTraceInfo(("TLS interaction object created"));
            // Set TLS config params here.
            CcspTraceInfo(("TLS CA file configured"));
            gupnp_context_set_tls_params(upnpContextDeviceProtect,caFile,NULL, xupnp_tlsinteraction);
            if(idm_upnp_init_status == FALSE) //Start event_handle_thread only for first time.
            {
                pthread_t event_handle_thread;
                int err = pthread_create(&event_handle_thread, NULL,&EventHandler,NULL);
                if(0 != err)
                {
                    CcspTraceError(("pthread_create EventHandler failed err=%d", err));
                }
            }
            cp_bgw = gupnp_control_point_new(upnpContextDeviceProtect, IDM_DP_CLIENT_DEVICE);
            g_signal_connect (cp_bgw,"device-proxy-available", G_CALLBACK (device_proxy_available_cb_bgw), NULL);
            g_signal_connect (cp_bgw,"device-proxy-unavailable", G_CALLBACK (device_proxy_unavailable_cb_bgw), NULL);
            gssdp_resource_browser_set_active (GSSDP_RESOURCE_BROWSER (cp_bgw), TRUE);
            CcspTraceInfo(("X1BroadbandGateway control point active"));
        }
    }
    else
    {
        CcspTraceError(("mandatory cert/key files not present, running without TLS"));
    }
#ifdef GUPNP_0_19
    main_loop = g_main_loop_new (NULL, FALSE);
#else
    main_loop = g_main_loop_new (upnpContextDeviceProtect, FALSE);
#endif
#else
    CcspTraceInfo(("UPnP running in non-secure mode"));
#ifndef GUPNP_1_2
#ifdef GUPNP_0_14
    main_context = g_main_context_new();
    context = gupnp_context_new (main_context, dc_obj->interface, CLIENT_CONTEXT_PORT, &error);
#else
    context = gupnp_context_new (NULL, dc_obj->interface, CLIENT_CONTEXT_PORT, &error);
#endif
#else
    context = gupnp_context_new (dc_obj->interface, CLIENT_CONTEXT_PORT, &error);
#endif
    if (error) {
        CcspTraceError(("GUPnP context creation failed on %s:%d error=%s", dc_obj->interface, CLIENT_CONTEXT_PORT, error->message));
        g_error_free (error);
        return;
    }
    gupnp_context_set_subscription_timeout(context, 0);
    cp = gupnp_control_point_new(context, IDM_CLIENT_DEVICE);
    g_signal_connect (cp,"device-proxy-available", G_CALLBACK (device_proxy_available_cb), NULL);
    g_signal_connect (cp,"device-proxy-unavailable", G_CALLBACK (device_proxy_unavailable_cb_bgw), NULL);
    gssdp_resource_browser_set_active (GSSDP_RESOURCE_BROWSER (cp), TRUE);
#ifdef GUPNP_0_19
    main_loop = g_main_loop_new (NULL, FALSE);
#else
    main_loop = g_main_loop_new (main_context, FALSE);
#endif
#endif
    sleep_seconds=((dc_obj->loss_detection_window+8)*1000000);
    CcspTraceInfo(("%s %d calling discovery_interval_configuration function %u loss_detection_window=%u",__FUNCTION__,__LINE__,dc_obj->discovery_interval,dc_obj->loss_detection_window));
    dc_obj->discovery_interval=dc_obj->discovery_interval*1000;
    discovery_interval_configuration(dc_obj->discovery_interval,dc_obj->loss_detection_window);
    CcspTraceInfo(("done timeout source assigning\n"));
    if(idm_upnp_init_status == FALSE) //Start verify_devices thread only for first time.
    {
        g_thread_create(verify_devices, NULL,FALSE, NULL);
        g_thread_create(stop_discovery_process, NULL,FALSE, NULL);
        CcspTraceInfo(("UPnP threads started"));
    }
    CcspTraceInfo(("IDM UPnP init complete"));
    idm_upnp_init_status = TRUE;
    g_main_loop_run (main_loop);
    CcspTraceInfo(("main loop exited"));
    /* emit unavailable signal for the resource connected devices */
#ifndef IDM_DEBUG
    gssdp_resource_browser_set_active (GSSDP_RESOURCE_BROWSER (cp_bgw), FALSE);
#else
    gssdp_resource_browser_set_active (GSSDP_RESOURCE_BROWSER (cp), FALSE);
#endif
    CcspTraceInfo(("freeing server memory"));
    free_server_memory();
    CcspTraceInfo(("removing device list entries"));
    remove_entries_in_list();
    g_main_loop_unref (main_loop);
    main_loop = NULL;
#ifdef IDM_DEBUG
    g_clear_object(&cp);
    g_clear_object(&context);
#else
    g_clear_object(&cp_bgw);
    g_clear_object(&upnpContextDeviceProtect);
    g_clear_object(&xupnp_tlsinteraction);
#endif
    g_mutex_free(mutex);
    /* upnp needs four seconds before restarting for avoiding port bind issues */
    sleep(4);
    CcspTraceInfo(("%s:%d Completed.",__FUNCTION__,__LINE__));
}
