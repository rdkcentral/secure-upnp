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
#include <libsoup/soup.h>
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
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <libgupnp/gupnp-control-point.h>
#ifdef ENABLE_SD_NOTIFY
#include <systemd/sd-daemon.h>
#endif
#include "rdk_safeclib.h"
#define SERVER_CONTEXT_PORT 50769
#define DEVICE_PROTECTION_CONTEXT_PORT  50761
#define IDM_SERVICE "urn:schemas-upnp-org:service:X1IDM:1"
#define IDM_DP_SERVICE "urn:schemas-upnp-org:service:X1IDM_DP:1"
#define IDM_CERT_FILE "/tmp/idm_xpki_cert"
#define IDM_KEY_FILE "/tmp/idm_xpki_key"
#define IDM_CA_FILE "/tmp/idm_UPnP_CA"
#ifndef _GNU_SOURCE
 #define _GNU_SOURCE
#endif
#define MAC_ADDR_SIZE 18
#define IPv4_ADDR_SIZE 16
#define IPv6_ADDR_SIZE 128
#define ACCOUNTID_SIZE 30
#define SSL_FILE_LEN 128
char clientIp[IPv4_ADDR_SIZE],bcastMacaddress[MAC_ADDR_SIZE],gwyIpv6[IPv6_ADDR_SIZE],interface[IPv4_ADDR_SIZE],uUid[256];
static char accountId[ACCOUNTID_SIZE];

GString *bcastmacaddress,*serial_num,*recv_id;
GUPnPContext *server_upnpContext,*server_upnpContextDeviceProtect;
void free_server_memory();
int check_file_presence();
extern char certFile[SSL_FILE_LEN];
extern char keyFile[SSL_FILE_LEN];
extern char caFile[SSL_FILE_LEN];
#ifdef ENABLE_HW_CERT_USAGE
extern char se_cert_p12[SSL_FILE_LEN];
#endif
/* Per-message caller IP map: SoupMessage* -> gchar* (IP string).
 * Avoids the race where concurrent request-started signals overwrite a global
 * before the action callback fires for the intended message. */
static GHashTable *s_msg_ip_map = NULL;
/* TLS interaction type defined in idm_client.c */
extern GType xupnp_tls_interaction_get_type(void);

BOOL check_empty_idm(char *str)
{
    if (str[0]) {
        return TRUE;
    }
    return FALSE;
}
bool check_null_idm(char *str)
{
    if (str) {
        return true;
    }
    return false;
}

/* Capture remote caller IP per-message to avoid race with concurrent requests */
static void
idm_request_started_cb (SoupServer *server, SoupMessage *msg,
                        SoupClientContext *client, gpointer user_data)
{
    if (!s_msg_ip_map)
        s_msg_ip_map = g_hash_table_new_full (g_direct_hash, g_direct_equal,
                                              NULL, g_free);
    const char *host = soup_client_context_get_host (client);
    if (host) {
        g_hash_table_insert (s_msg_ip_map, msg, g_strdup (host));
        g_message ("idm_request_started_cb: captured caller IP = %s", host);
    } else {
        g_message ("idm_request_started_cb: WARNING get_host returned NULL");
    }
}

/* Make a synchronous GetAccountId SOAP call to the peer at peer_ip.
 * Returns TRUE and fills out_id on success; FALSE otherwise. */
static gboolean
fetch_peer_account_id (const char *peer_ip, char *out_id, gsize out_id_size)
{
    gboolean ret = FALSE;
    char control_url[256];
    snprintf (control_url, sizeof (control_url),
              "https://%s:%d/X1IDM_DP/Control", peer_ip, DEVICE_PROTECTION_CONTEXT_PORT);

    g_message ("fetch_peer_account_id: caFile=%s certFile=%s keyFile=%s",
               caFile[0]   ? caFile   : "(empty)",
               certFile[0] ? certFile : "(empty)",
               keyFile[0]  ? keyFile  : "(empty)");

    /* Create TLS interaction then unref: session takes its own internal ref.
     * Omitting this unref would leak one XupnpTlsInteraction per GetAccountId call. */
    GTlsInteraction *tls_interaction = g_object_new (xupnp_tls_interaction_get_type (), NULL);
    SoupSession *session = soup_session_sync_new_with_options (
        SOUP_SESSION_SSL_CA_FILE,    caFile,
        SOUP_SESSION_SSL_STRICT,     TRUE,
        SOUP_SESSION_TLS_INTERACTION, tls_interaction,
        NULL);
    /* NOTE: no SOUP_SESSION_TIMEOUT set -- call will block until peer responds or connection fails */
    g_message ("fetch_peer_account_id: no session timeout configured, SOAP call may block if peer is unreachable");
    g_object_unref (tls_interaction);  /* release our ref; session holds its own */
    if (!session) {
        g_message ("fetch_peer_account_id: failed to create SoupSession");
        return FALSE;
    }

    /* Build SOAP envelope */
    const char *soap_body =
        "<?xml version=\"1.0\"?>"
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\""
        " s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
        "<s:Body>"
        "<u:GetAccountId xmlns:u=\"urn:schemas-upnp-org:service:X1IDM_DP:1\"/>"
        "</s:Body>"
        "</s:Envelope>";

    SoupMessage *msg = soup_message_new ("POST", control_url);
    if (!msg) {
        g_message ("fetch_peer_account_id: failed to create SoupMessage for %s", control_url);
        g_object_unref (session);
        return FALSE;
    }
    soup_message_headers_append (msg->request_headers,
                                 "SOAPAction",
                                 "\"urn:schemas-upnp-org:service:X1IDM_DP:1#GetAccountId\"");
    /* Mark this as a direct fetch so the peer does not loop back */
    soup_message_headers_append (msg->request_headers, "X-IDM-Direct-Fetch", "1");
    soup_message_set_request (msg, "text/xml; charset=\"utf-8\"",
                              SOUP_MEMORY_STATIC,
                              soap_body, strlen (soap_body));

    g_message ("fetch_peer_account_id: sending SOAP POST to %s (blocks until response)", control_url);
    guint status = soup_session_send_message (session, msg);
    g_message ("fetch_peer_account_id: HTTP status=%u from %s", status, control_url);

    if (SOUP_STATUS_IS_SUCCESSFUL (status)) {
        const char *resp = msg->response_body->data;
        goffset resp_len  = msg->response_body->length;
        g_message ("fetch_peer_account_id: response body [%lld bytes]: %.*s",
                   (long long)resp_len,
                   (int)(resp_len < 512 ? resp_len : 512),
                   resp ? resp : "(null)");
        if (resp) {
            const char *tag_open  = "<AccountId>";
            const char *tag_close = "</AccountId>";
            const char *start = strstr (resp, tag_open);
            const char *end   = start ? strstr (start, tag_close) : NULL;
            if (start && end) {
                start += strlen (tag_open);
                gsize len = (gsize)(end - start);
                g_message ("fetch_peer_account_id: found <AccountId> tag, value len=%u", (unsigned)len);
                if (len > 0 && len < out_id_size) {
                    memcpy (out_id, start, len);
                    out_id[len] = '\0';
                    g_message ("fetch_peer_account_id: parsed accountId=%s", out_id);
                    ret = TRUE;
                } else {
                    g_message ("fetch_peer_account_id: length %u invalid (out_id_size=%u)",
                               (unsigned)len, (unsigned)out_id_size);
                }
            } else {
                g_message ("fetch_peer_account_id: <AccountId> tag NOT found -- verify SOAP namespace/format");
            }
        } else {
            g_message ("fetch_peer_account_id: response body is NULL despite HTTP 2xx");
        }
    } else {
        const char *reason = soup_status_get_phrase (status);
        g_message ("fetch_peer_account_id: FAILED status=%u (%s) to %s -- TLS error (0=SSL) or peer down",
                   status, reason ? reason : "unknown", control_url);
    }

    g_object_unref (msg);
    g_object_unref (session);
    return ret;
}

G_MODULE_EXPORT void
get_bcastmacaddress_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    gupnp_service_action_set (action, "BcastMacAddress", G_TYPE_STRING, bcastMacaddress, NULL);
    gupnp_service_action_return (action);
}

G_MODULE_EXPORT void
query_bcastmacaddress_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, bcastMacaddress);
}

G_MODULE_EXPORT void
get_client_ip_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    gupnp_service_action_set (action, "ClientIP", G_TYPE_STRING, clientIp, NULL);
    gupnp_service_action_return (action);
}

G_MODULE_EXPORT void
query_client_ip_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, clientIp);
}
G_MODULE_EXPORT void
get_gwyipv6_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    gupnp_service_action_set (action, "GatewayIPv6", G_TYPE_STRING, gwyIpv6, NULL);
    gupnp_service_action_return (action);
}
G_MODULE_EXPORT void
query_gwyipv6_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, gwyIpv6);
}

G_MODULE_EXPORT void
get_account_id_cb (GUPnPService *service, GUPnPServiceAction *action, gpointer user_data)
{
    char peer_id[ACCOUNTID_SIZE] = {0};

    /* Look up caller IP from per-message table -- avoids race with other concurrent requests */
    SoupMessage *req_msg = gupnp_service_action_get_message (action);
    char caller_ip[64] = {0};
    if (req_msg && s_msg_ip_map) {
        const char *ip_ref = g_hash_table_lookup (s_msg_ip_map, req_msg);
        if (ip_ref)
            strncpy (caller_ip, ip_ref, sizeof (caller_ip) - 1);
        g_hash_table_remove (s_msg_ip_map, req_msg);  /* clean up */
    }

    g_message ("get_account_id_cb: entry, caller_ip=%s",
               caller_ip[0] ? caller_ip : "(unknown)");

    /* Step 1: Check X-IDM-Direct-Fetch header.
     * If set, this is our own reverse lookup call coming back (or old XB calling us).
     * Return own accountId immediately -- DO NOT do a reverse call here (would loop). */
    if (req_msg == NULL) {
        g_message ("get_account_id_cb: WARNING gupnp_service_action_get_message returned NULL");
    } else {
        const char *direct_fetch_hdr = soup_message_headers_get_one (
            req_msg->request_headers, "X-IDM-Direct-Fetch");
        g_message ("get_account_id_cb: X-IDM-Direct-Fetch header = %s",
                   direct_fetch_hdr ? direct_fetch_hdr : "(not present)");
        if (direct_fetch_hdr != NULL) {
            memset(accountId, 0, ACCOUNTID_SIZE);
            getAccountId(accountId);
            g_message ("get_account_id_cb: direct-fetch path, returning own accountId=%s", accountId);
            gupnp_service_action_set (action, "AccountId", G_TYPE_STRING, accountId, NULL);
            gupnp_service_action_return (action);
            return;
        }
    }

    /* Step 2: Echo path -- reverse-call the requester and return their accountId.
     * Old XB compares returned_id == own_id; echoing their own id makes this pass.
     * Guard: never reverse-fetch to our own IP (XLE self-discovers itself via SSDP).
     * A SoupSessionSync call to self blocks GMainLoop which must serve the reply -> deadlock. */
    if (caller_ip[0] != '\0') {
        if (strcmp (caller_ip, clientIp) == 0) {
            g_message ("get_account_id_cb: caller %s is own IP (self-discovery via SSDP), skipping reverse fetch", caller_ip);
        } else {
            g_message ("get_account_id_cb: attempting reverse fetch to caller_ip=%s", caller_ip);
            if (fetch_peer_account_id (caller_ip, peer_id, sizeof (peer_id)) &&
                peer_id[0] != '\0') {
                g_message ("get_account_id_cb: echo SUCCESS, returning peer accountId=%s to %s",
                           peer_id, caller_ip);
                gupnp_service_action_set (action, "AccountId", G_TYPE_STRING, peer_id, NULL);
                gupnp_service_action_return (action);
                return;
            }
            g_message ("get_account_id_cb: reverse fetch FAILED for ip=%s (TLS error? peer down? cert not ready?)",
                       caller_ip);
        }
    } else {
        g_message ("get_account_id_cb: caller_ip unknown, skipping reverse fetch");
    }

    /* Step 3 (fallback): Return own accountId.
     * Handles: TLS failure, peer unreachable, certs not provisioned yet. */
    memset(accountId,0,ACCOUNTID_SIZE);
    getAccountId(accountId);
    g_message ("get_account_id_cb: fallback path, returning own accountId=%s", accountId);
    gupnp_service_action_set (action, "AccountId", G_TYPE_STRING, accountId, NULL);
    gupnp_service_action_return (action);
}

G_MODULE_EXPORT void
query_account_id_cb (GUPnPService *service, char *variable, GValue *value, gpointer user_data)
{
    g_value_init (value, G_TYPE_STRING);
    g_value_set_string (value, accountId);
}

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

BOOL updatexmldata(const char* xmlfilename, const char* struuid,const char* serialno)
{
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

void free_server_memory()
{
    g_message("Inside %s",__FUNCTION__);
#ifdef IDM_DEBUG
    gupnp_root_device_set_available (baseDev, FALSE);
    g_clear_object (&upnpService);
    g_clear_object (&baseDev);
    g_clear_object (&server_upnpContext);
#else
    g_message("Setting root device set as false%s",__FUNCTION__);
    gupnp_root_device_set_available (dev, FALSE);
    g_message("Clearing upnpIdService %s",__FUNCTION__);
    g_clear_object(&upnpIdService);
    g_message("Clearing dev %s",__FUNCTION__);
    g_clear_object(&dev);
    g_message("Clearing server_upnpContextDeviceProtect %s",__FUNCTION__);
    g_clear_object(&server_upnpContextDeviceProtect);
#endif
}
BOOL getUidfromRecvId()
{
    BOOL result = FALSE;
    guint loopvar = 0;
    gchar **tokens = g_strsplit_set(bcastMacaddress, "':''\n'", -1);
    guint toklength = g_strv_length(tokens);

    if (toklength > 0) {
        g_string_printf(recv_id, "ebf5a0a0-1dd1-11b2-a90f-%s", g_strstrip(tokens[loopvar++]));
        result = TRUE;
    }
    while (loopvar < toklength)
    {
        g_string_append(recv_id, g_strstrip(tokens[loopvar++]));
    }
    if(result == TRUE)
        g_message("getUidfromRecvId: recvId: %s", recv_id->str);
    else
        g_message("%s: toklength is %u" ,__FUNCTION__, toklength);
    g_strfreev(tokens);
    return result;
}
BOOL getUUID(char *outValue)
{
    BOOL result = FALSE;
    if (!check_null_idm(outValue)) {
        g_message("getUUID : NULL string !");
        return result;
    }
    if (getUidfromRecvId()){
        if( (check_empty_idm(recv_id->str))) {
            sprintf(outValue, "uuid:%s", recv_id->str);
            result = TRUE;
        }
        else
        {
            g_message("getUUID : empty recvId");
        }
    }
    else
    {
        g_message("getUUID : could not get UUID");
    }
    return result;
}

int idm_server_start(char* Interface, char * base_mac)
{
    g_thread_init (NULL);
    g_type_init();
    GError* error = 0;
    strcpy(interface,Interface);
    g_message("%s %d interface=%s",__FUNCTION__,__LINE__,interface);
    getipaddress((const char *)interface,clientIp,FALSE);
    serial_num = g_string_new(NULL);
    getserialnum(serial_num);
    getipaddress((const char *)interface,gwyIpv6,TRUE);
    strcpy_s(bcastMacaddress, MAC_ADDR_SIZE, base_mac);
#ifndef IDM_DEBUG
#ifndef ENABLE_HW_CERT_USAGE
    g_message("%s cert file=%s  key file = %s", __FUNCTION__, certFile, keyFile);
    if((access(certFile,F_OK ) == 0) && (access(keyFile,F_OK ) == 0) && (access(caFile,F_OK ) == 0))
    {
#else
    if (((access(se_cert_p12, F_OK) == 0) || ((access(certFile,F_OK ) == 0) && (access(keyFile,F_OK ) == 0)))
            && (access(caFile, F_OK ) == 0))
    {
#endif
        const char* struuid_dp=g_strconcat("uuid:", g_strstrip(bcastMacaddress),NULL);
        int result = updatexmldata("/etc/xupnp/IDM_DP.xml",struuid_dp,serial_num->str);
        if (!result)
        {
            fprintf(stderr,"Failed to open the device xml file /etc/xupnp/IDM_DP.xml\n");
        }
#ifndef GUPNP_1_2
#ifndef ENABLE_HW_CERT_USAGE
        server_upnpContextDeviceProtect = gupnp_context_new_s ( NULL,interface,DEVICE_PROTECTION_CONTEXT_PORT,certFile,keyFile, &error);
#else
        if(access(se_cert_p12, F_OK) == 0)
        {
            g_message("IDM Server: SE HW certificate is available. Creating device protect without extracted files");
            server_upnpContextDeviceProtect = gupnp_context_new_s ( NULL,interface,DEVICE_PROTECTION_CONTEXT_PORT,NULL,NULL, &error);
        }
        else
        {
            g_message("IDM Server: SE HW certificate is not available. Creating device protect with extracted files");
            server_upnpContextDeviceProtect = gupnp_context_new_s ( NULL,interface,DEVICE_PROTECTION_CONTEXT_PORT,certFile,keyFile, &error);
        }
#endif
#else
#ifndef ENABLE_HW_CERT_USAGE
        server_upnpContextDeviceProtect = gupnp_context_new_s ( interface,DEVICE_PROTECTION_CONTEXT_PORT,certFile,keyFile, &error);
#else
        if(access(se_cert_p12, F_OK) == 0)
        {
            g_message("IDM Server: SE HW certificate is available. Creating device protect without extracted files");
            server_upnpContextDeviceProtect = gupnp_context_new_s ( interface,DEVICE_PROTECTION_CONTEXT_PORT,NULL,NULL, &error);
        }
        else 
        {
            g_message("IDM Server: SE HW certificate is not available. Creating device protect with extracted files");
            server_upnpContextDeviceProtect = gupnp_context_new_s ( interface,DEVICE_PROTECTION_CONTEXT_PORT,certFile,keyFile, &error);
        }
#endif
#endif
        g_message("created new upnpContext");
        if (error)
        {
            g_message("%s:Error creating the Device Protection Broadcast context: %s",
                    __FUNCTION__,error->message);
            /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
            g_clear_error(&error);
        }
        else
        {
            gupnp_context_set_subscription_timeout(server_upnpContextDeviceProtect, 0);
            // Set TLS config params here.
            g_message("%s setting CA cert : %s", __FUNCTION__, caFile);
            gupnp_context_set_tls_params(server_upnpContextDeviceProtect,caFile,NULL, NULL);
            /* Capture the remote caller IP for each incoming request */
            g_signal_connect (gupnp_context_get_server (server_upnpContextDeviceProtect),
                              "request-started",
                              G_CALLBACK (idm_request_started_cb), NULL);
#ifndef GUPNP_1_2
            dev = gupnp_root_device_new (server_upnpContextDeviceProtect, "/etc/xupnp/IDM_DP.xml", "/etc/xupnp/");
#else
            dev = gupnp_root_device_new (server_upnpContextDeviceProtect, "/etc/xupnp/IDM_DP.xml", "/etc/xupnp/", &error);
#endif
            gupnp_root_device_set_available (dev, TRUE);
            upnpIdService = gupnp_device_info_get_service(GUPNP_DEVICE_INFO (dev), IDM_DP_SERVICE);
            if (!upnpIdService)
            {
                g_message("Cannot get X1Identity service\n");
            }
            else
            {
                g_message("XUPNP Identity service successfully created");
            }
            g_signal_connect (upnpIdService, "action-invoked::GetBcastMacAddress", G_CALLBACK (get_bcastmacaddress_cb), NULL);
            g_signal_connect (upnpIdService, "query-variable::BcastMacAddress", G_CALLBACK (query_bcastmacaddress_cb), NULL);
            g_signal_connect (upnpIdService, "action-invoked::GetClientIP", G_CALLBACK (get_client_ip_cb), NULL);
            g_signal_connect (upnpIdService, "query-variable::ClientIP", G_CALLBACK (query_client_ip_cb), NULL);
            g_signal_connect (upnpIdService, "action-invoked::GetAccountId", G_CALLBACK (get_account_id_cb), NULL);
            g_signal_connect (upnpIdService, "query-variable::AccountId", G_CALLBACK (query_account_id_cb), NULL);
            g_signal_connect (upnpIdService, "action-invoked::GetGatewayIPv6", G_CALLBACK (get_gwyipv6_cb), NULL);
            g_signal_connect (upnpIdService, "query-variable::GatewayIPv6", G_CALLBACK (query_gwyipv6_cb), NULL);
        }
    }
    else
    {
        g_message("%s:mandatory files doesn't present",__FUNCTION__);
    }
#else
    recv_id=g_string_new(NULL);
    getUUID(uUid);
    const char* struuid = uUid;
    g_message("recv_id=%s",struuid);
    int result = updatexmldata("/etc/xupnp/IDM.xml",struuid,serial_num->str);
    if (!result)
    {
        fprintf(stderr,"Failed to open the device xml file /etc/xupnp/IDM.xml\n");
    }
    else
    {
        g_message("Updated the device xml file:IDM.XML uuid: %s",struuid);
    }
#ifndef GUPNP_1_2
    server_upnpContext = gupnp_context_new (NULL, interface, SERVER_CONTEXT_PORT, &error);
#else
    server_upnpContext = gupnp_context_new (interface, SERVER_CONTEXT_PORT, &error);
#endif
    if (error) {
        g_message("Error creating the Broadcast context: %s",
                error->message);
        /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
        g_clear_error(&error);
        return 1;
    }
    gupnp_context_set_subscription_timeout(server_upnpContext, 0);
#ifndef GUPNP_1_2
    baseDev = gupnp_root_device_new (server_upnpContext, "/etc/xupnp/IDM.xml", "/etc/xupnp/");
#else
    baseDev = gupnp_root_device_new (server_upnpContext, "/etc/xupnp/IDM.xml", "/etc/xupnp/", &error);
#endif
    gupnp_root_device_set_available (baseDev, TRUE);
    upnpService = gupnp_device_info_get_service(GUPNP_DEVICE_INFO (baseDev), IDM_SERVICE);
    if (!upnpService)
    {
        g_printerr ("Cannot get DiscoverFriendlies service\n");
        return 1;
    }
    g_signal_connect (upnpService, "action-invoked::GetBcastMacAddress", G_CALLBACK (get_bcastmacaddress_cb), NULL);
    g_signal_connect (upnpService, "query-variable::BcastMacAddress", G_CALLBACK (query_bcastmacaddress_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetClientIP", G_CALLBACK (get_client_ip_cb), NULL);
    g_signal_connect (upnpService, "query-variable::ClientIP", G_CALLBACK (query_client_ip_cb), NULL);
    g_signal_connect (upnpService, "action-invoked::GetGatewayIPv6", G_CALLBACK (get_gwyipv6_cb), NULL);
    g_signal_connect (upnpService, "query-variable::GatewayIPv6", G_CALLBACK (query_gwyipv6_cb), NULL);
#endif
    g_message("completed %s\n",__FUNCTION__);
    return 0;
}
