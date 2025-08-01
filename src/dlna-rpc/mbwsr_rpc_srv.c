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

#include "mediabrowser_private.h"
#include "mediabrowser.h"

#include <rbus.h>


#define BUFFER_SIZE  20
char keyBuffer[BUFFER_SIZE] = {0};

rbusHandle_t handle;
int rbus_response = RBUS_ERROR_SUCCESS;

static rbusError_t remoteMethodHandler(rbusHandle_t handle, char const *methodName,
                                       rbusObject_t inParams, rbusObject_t outParams,
                                       rbusMethodAsyncHandle_t asyncHandle);
rbusDataElement_t dataElements[3] = {
            {METHOD_DISCOVER_MEDIA_DEVICES_SIZE, RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, remoteMethodHandler}},
            {METHOD_GET_MEDIA_DEVICE_AT, RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, remoteMethodHandler}},
            {METHOD_BROWSE_CONTENT_ON_MEDIA_SERVER, RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, remoteMethodHandler}}
        };

void init_ipc_iface()
{

    rbus_response = rbus_open(&handle, RBUS_XUPNP_SERVICE_PROVIDER);
    if(RBUS_ERROR_SUCCESS == rbus_response )
    {
        rbus_response = rbus_regDataElements(handle, 3, dataElements);
        if(RBUS_ERROR_SUCCESS != rbus_response)
            g_critical("[%s] Failed to register to RPC methods, reason %d ", __FUNCTION__ , rbus_response);
    }
    else
        g_critical("[%s] Failed to open  RPC Channel, reason %d ", __FUNCTION__ , rbus_response);
}

static void getServerDetails(rbusObject_t inParams, rbusObject_t outParams)
{
        rbusValue_t value;
        rbusProperty_t prop = NULL;
        if (NULL != msList)
        {
            g_mutex_lock(locker);

            //Total count
            int count = g_list_length(msList);
            int index = -1;

            prop = rbusObject_GetProperties(inParams);

            if( NULL != prop && rbusProperty_Count(prop) > 0 ) //expecting only one
            {
                value = rbusProperty_GetValue(prop);
                index = rbusValue_GetInt32(value);

                GList * entry = g_list_nth(msList, index);
                if(NULL!= entry)
                {
                    mediaServerCfg *mserver = (mediaServerCfg *)entry->data;

                    rbusValue_Init(&value);
                    sprintf_s(keyBuffer, BUFFER_SIZE, "server.name");
                    rbusValue_SetString(value, mserver->friendlyname);
                    rbusObject_SetValue(outParams, keyBuffer, value);
                    rbusValue_Release(value);

                    rbusValue_Init(&value);
                    sprintf_s(keyBuffer, BUFFER_SIZE, "server.udn");
                    rbusValue_SetString(value, mserver->udn);
                    rbusObject_SetValue(outParams, keyBuffer, value);
                    rbusValue_Release(value);
                }
            }
            g_mutex_unlock(locker);
        }
        else{
            g_message("[%s] No media servers discovered ", __FUNCTION__);
        }
}

static void getServerContents(rbusObject_t inParams, rbusObject_t outParams)
{
    rbusProperty_t prop;
    char * udn = NULL, *path = NULL;
    int start_index = 0 , max_results = 0;
    rbusValue_t value;

    char * entries = NULL;
    int total_count = 0;

    prop = rbusObject_GetProperties(inParams);

    if(NULL == prop || rbusProperty_Count(prop) != 4 )
    {
        g_message("[%s] Insufficient arguments args size = %d", __FUNCTION__ , rbusProperty_Count(prop));
        return ;
    }
    value = rbusProperty_GetValue(prop);
    udn = rbusValue_ToString(value,NULL,0); //UDN

    prop = rbusProperty_GetNext(prop);
    value = rbusProperty_GetValue(prop);
    path = rbusValue_ToString(value,NULL,0); //path

    prop = rbusProperty_GetNext(prop);
    value = rbusProperty_GetValue(prop);
    start_index = rbusValue_GetInt32(value); //start index

    prop = rbusProperty_GetNext(prop);
    value = rbusProperty_GetValue(prop);
    max_results = rbusValue_GetInt32(value); //max results

    // Get mediaserver config based on UDN
    if(browse_remote_dir_with_udn(udn,path,start_index,max_results,&total_count, &entries))
    {
        rbusValue_Init(&value);
        sprintf_s(keyBuffer, BUFFER_SIZE, "results.xmldata");
        rbusValue_SetString(value, entries);
        rbusObject_SetValue(outParams,keyBuffer, value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        sprintf_s(keyBuffer, BUFFER_SIZE, "results.size");
        rbusValue_SetInt32(value, total_count);
        rbusObject_SetValue(outParams,keyBuffer, value);
        rbusValue_Release(value);
    }
}

// RBUS connector methods

static rbusError_t remoteMethodHandler(rbusHandle_t handle, char const *methodName,
                                       rbusObject_t inParams, rbusObject_t outParams,
                                       rbusMethodAsyncHandle_t asyncHandle)
{
    rbusValue_t value;
    int result = -1;

    g_message("[%s] Received a request for %s ", __FUNCTION__, methodName);

    if (strcmp_s(METHOD_DISCOVER_MEDIA_DEVICES_SIZE,
                 strlen(METHOD_DISCOVER_MEDIA_DEVICES_SIZE),
                 methodName, &result) == EOK &&
        !result)
    {
        if (NULL != msList)
        {
            g_mutex_lock(locker);

            //Total count
            int count = g_list_length(msList);
            g_message("[%s]  Media servers discovered = %d ", __FUNCTION__, count);
            rbusValue_Init(&value);
            rbusValue_SetInt32(value, count);
            rbusObject_SetValue(outParams, "payload.size", value);
            rbusValue_Release(value);
            g_mutex_unlock(locker);
        }
        else{
            g_message("[%s] No media servers discovered ", __FUNCTION__);
            rbusValue_Init(&value);
            rbusValue_SetInt32(value, 0);
            rbusObject_SetValue(outParams, "payload.size", value);
            rbusValue_Release(value);
        }
        return RBUS_ERROR_SUCCESS;
    }

    else if (strcmp_s(METHOD_GET_MEDIA_DEVICE_AT,
                 strlen(METHOD_GET_MEDIA_DEVICE_AT),
                 methodName, &result) == EOK &&
        !result)
    {
        getServerDetails(inParams, outParams);
        return RBUS_ERROR_SUCCESS;
    }
    else if (strcmp_s(METHOD_BROWSE_CONTENT_ON_MEDIA_SERVER,
                      strlen(METHOD_BROWSE_CONTENT_ON_MEDIA_SERVER),
                      methodName, &result) == EOK &&
            !result)
    {
        getServerContents(inParams,outParams);
        return RBUS_ERROR_SUCCESS;
    }
    else
    {
        return RBUS_ERROR_INVALID_METHOD;
    }
}
void close_rpc_iface()
{
    rbus_unregDataElements(handle, 3, dataElements);
    rbus_close(handle);
}
