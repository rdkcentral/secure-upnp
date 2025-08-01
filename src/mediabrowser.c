/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2021 RDK Management
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
 * @file mediabrowser.c
 * @brief This source file contains functions  that will help us to discover mediaservers in network.
 */
#include "mediabrowser_private.h"
#include "mediabrowser.h"

GList *msList = NULL; // mediaserver list

/**
 * Custom glist search function based on UDN
 * */
static gint
g_list_find_udn(mediaServerCfg *gwData, gconstpointer *udn)
{
    int result = -1;
    if (strcmp_s((gchar *)udn, strlen((gchar *)udn), gwData->udn, &result) == EOK &&
        !result)
    {
        return 0;
    }
    return 1;
}

static gboolean
browse_remote_directory(GUPnPServiceInfo *browserService, gchar *root, int startIndex, int maxCount, guint *totalResults, gchar **result)
{
    gchar *browseFlag = BROWSE_MODE_CHILD_NODE;
    gchar *filter = "*";
    gchar *sortCriteria = "";
    GError *error = NULL;
    guint numberReturned, totalMatches, updateId;
    gboolean status = TRUE;

#ifdef GUPNP_1_2
    GUPnPServiceProxyAction *action = gupnp_service_proxy_action_new("Browse",
                                                                     "ObjectID", G_TYPE_STRING, root, "BrowseFlag", G_TYPE_STRING, browseFlag,
                                                                     "Filter", G_TYPE_STRING, filter, "StartingIndex", G_TYPE_INT, startIndex,
                                                                     "RequestedCount", G_TYPE_INT, maxCount, "SortCriteria", G_TYPE_STRING, sortCriteria,
                                                                     NULL);
    gupnp_service_proxy_call_action(browserService, action, NULL, &error);
    if (error == NULL)
    {
        gupnp_service_proxy_action_get_result(action,
                                              &error, "Result", G_TYPE_STRING, result,
                                              "NumberReturned ", G_TYPE_INT, &numberReturned,
                                              "TotalMatches", G_TYPE_INT, &totalMatches,
                                              "UpdateID ", G_TYPE_INT, &updateId,
                                              NULL);
        g_clear_pointer(&action, gupnp_service_proxy_action_unref);
    }
#else
    gupnp_service_proxy_send_action(browserService, "Browse", &error,
                                    "ObjectID", G_TYPE_STRING, root, "BrowseFlag", G_TYPE_STRING, browseFlag,
                                    "Filter", G_TYPE_STRING, filter, "StartingIndex", G_TYPE_INT, startIndex,
                                    "RequestedCount", G_TYPE_INT, maxCount, "SortCriteria", G_TYPE_STRING, sortCriteria,
                                    NULL,
                                    "Result", G_TYPE_STRING, result,
                                    "NumberReturned ", G_TYPE_INT, &numberReturned,
                                    "TotalMatches", G_TYPE_INT, &totalMatches,
                                    "UpdateID ", G_TYPE_INT, &updateId,
                                    NULL);
#endif
    if (NULL != error) // Didn't went well
    {
        g_message("[%s]  UPNP Browse call failed : %s\n", __FUNCTION__, error->message);
        g_clear_error(&error);
        status = FALSE;
    }
    return status;
}

bool browse_remote_dir_with_udn(const char *server_udn, const char *path_id, int start_index,
                                int max_entries, int *totalCount, char **results)
{
    GList *msListItem = NULL;
    g_mutex_lock(locker);
    msListItem = g_list_find_custom(msList, server_udn, (GCompareFunc)g_list_find_udn);
    g_mutex_unlock(locker);

    if (NULL == msListItem)
    {
        g_message("[%s] Failed to identify the device in cache %s ", __FUNCTION__, server_udn);
        return false;
    }
    mediaServerCfg *msConfig = (mediaServerCfg *)msListItem->data;

    return browse_remote_directory(msConfig->browserService, path_id, start_index, max_entries, totalCount, results);
}

static void
device_proxy_available_mr_cb(GUPnPControlPoint *cp, GUPnPDeviceProxy *dproxy)
{
    g_message("%s] Found a new UPNP media server", __FUNCTION__);
    if ((NULL == cp) || (NULL == dproxy))
    {
        g_message("[%s] Got empty control point or device  proxy. Leaving", __FUNCTION__);
        return;
    }
    gchar *data = gupnp_device_info_get_udn(GUPNP_DEVICE_INFO(dproxy));
    g_message("[%s] Got UDN as %s ", __FUNCTION__, data);
    GList *msListItem = NULL;

    g_mutex_lock(locker);
    msListItem = g_list_find_custom(msList, data, (GCompareFunc)g_list_find_udn);
    g_mutex_unlock(locker);
    if (NULL != msListItem)
    {
        g_message("[%s] Existing device, ignoring.", __FUNCTION__);
        return;
    }
    mediaServerCfg *mserver = g_new(mediaServerCfg, 1);
    mserver->friendlyname = NULL;
    mserver->udn = strdup(data);
    g_free(data);

    data = gupnp_device_info_get_friendly_name(GUPNP_DEVICE_INFO(dproxy));
    g_message("[%s] Got Friendly name  as %s ", __FUNCTION__, data);
    mserver->friendlyname = strdup(data);
    g_free(data);
    /*
        GList *service_list = gupnp_device_info_list_services(GUPNP_DEVICE_INFO(dproxy));
        int srv_list_size = g_list_length(service_list);
        g_message("[%s] There are total %d services ", __FUNCTION__, srv_list_size);
    */
    mserver->browserService = gupnp_device_info_get_service(GUPNP_DEVICE_INFO(dproxy), XUPNP_SERVICE_CONTENT_DIR);

    g_mutex_lock(locker);
    msList = g_list_append(msList, mserver);
    g_mutex_unlock(locker);
}

static void
device_proxy_unavailable_mr_cb(GUPnPControlPoint *cp, GUPnPDeviceProxy *dproxy)
{

    g_message("Mediaserver disconnected event received.");
    if ((NULL == cp) || (NULL == dproxy))
    {
        g_message("[%s] Got empty control point or device  proxy. Leaving", __FUNCTION__);
        return;
    }
    gchar *data = gupnp_device_info_get_udn(GUPNP_DEVICE_INFO(dproxy));
    g_message("[%s] Got UDN as %s ", __FUNCTION__, data);

    GList *msListItem = NULL;
    g_mutex_lock(locker);
    g_list_find_custom(msList, data, (GCompareFunc)g_list_find_udn);

    if (NULL != msListItem)
    {

        msList = g_list_remove_link(msList, msListItem);
        g_mutex_unlock(locker);
        {
            mediaServerCfg *msItem = msListItem->data;
            free(msItem->friendlyname);
            free(msItem->udn);
            g_clear_object(&(msItem->browserService));
            g_free(msItem);
        }
        g_list_free(msListItem);
    }
    else
    {
        g_message("[%s] Not found in cache. ", __FUNCTION__);
    }
   
}
/**
 * This method registered mediaserver control point and notification call backs.
 * */
void registerBrowserConfig(GUPnPContext *context)
{
    g_message("[%s] Registering media renderer device ", __FUNCTION__);
    cp_media_rndr = gupnp_control_point_new(context, XUPNP_DEVICE_MEDIASERVER_CONTROL_URN);
    g_signal_connect(cp_media_rndr, "device-proxy-available", G_CALLBACK(device_proxy_available_mr_cb), NULL);
    g_signal_connect(cp_media_rndr, "device-proxy-unavailable", G_CALLBACK(device_proxy_unavailable_mr_cb), NULL);
    gssdp_resource_browser_set_active(GSSDP_RESOURCE_BROWSER(cp_media_rndr), TRUE);
}
/**
 * Initialises the variables used in mediabrowser
 * */
void init_media_browser()
{
    locker = g_mutex_new();
    init_ipc_iface();
}
/**
 * De-initialises the variables used in mediabrowser
 * */
void close_media_browser()
{
    g_mutex_free(locker);
    close_rpc_iface();
}
