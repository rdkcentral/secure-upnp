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

#include "mediabrowser.h"
#include <rbus.h>
#include <safec_lib.h>
#include <stdlib.h>
#define RBUS_XUPNP_SERVICE_CONSUMER "rbus.xupnp.dlna.client"

#define BUFFER_SIZE  20
char keyBuffer[BUFFER_SIZE] = {0};

rbusHandle_t handle;
int rbus_response = RBUS_ERROR_SUCCESS;

bool InitializeRPC()
{
    rbus_response = rbus_open(&handle, RBUS_XUPNP_SERVICE_CONSUMER);
    return (RBUS_ERROR_SUCCESS == rbus_response)?true:false;
}

static bool getMediaServer(rbusProperty_t outProps,  char ** friendly_name, char **udn)
{

    bool status = false;

    int  result = rbusProperty_Count(outProps);
    if (result % 2 != 0)
    {
        fprintf(stderr, "[%s] Expected name/udn pair, but found odd property entries.  = %d \n", __FUNCTION__, result);
        return status;
    }

    rbusValue_t value = rbusProperty_GetValue(outProps);
    if (value)
        *friendly_name = rbusValue_ToString(value, NULL, 0); // This is a copy
    outProps = rbusProperty_GetNext(outProps);
    value = rbusProperty_GetValue(outProps);
    if (value)
    {
        *udn = rbusValue_ToString(value, NULL, 0); // This is a copy
        status = true;
    }
    return status;
}
bool getDiscoveredMediaServers(int *size)
{
    rbusObject_t inParams;
    rbusObject_t outParams;
    rbusValue_t value;
    bool status = false;

    rbusObject_Init(&inParams, NULL);
    rbus_response = rbusMethod_Invoke(handle, METHOD_DISCOVER_MEDIA_DEVICES_SIZE, inParams, &outParams);
    rbusObject_Release(inParams);
    if (RBUS_ERROR_SUCCESS == rbus_response)
    {
        rbusProperty_t outProps = rbusObject_GetProperties(outParams);
        int payload = 0;
        int count = 0;
        fprintf(stderr, "[%s] Successfully invoked METHOD_DISCOVER_MEDIA_DEVICES_SIZE  \n", __FUNCTION__ );
        // First property is the payload size
        if (outProps)
        {
            value = rbusProperty_GetValue(outProps);
            if (value && rbusValue_GetType(value) == RBUS_INT32)
            {
                payload = rbusValue_GetInt32(value);
            }
            else
            {
                fprintf(stderr, "[%s] Expected payload but got type %d \n", __FUNCTION__, rbusValue_GetType(value));
                return false;
            }
            fprintf(stderr, "[%s]  payload size %d \n", __FUNCTION__, payload);
            *size = payload;
            status = true;
        }
        else
        {
            fprintf(stderr, "[%s] Failed to retrieve properties \n", __FUNCTION__ );
        }
        rbusObject_Release(outParams);
    }
    return status;
}
bool getDiscoveredMediaServerAt(int index, char **friendlyName, char ** udn, int *err)
{
    rbusObject_t inParams;
    rbusObject_t outParams;
    rbusValue_t value;
    bool status = false;

    *err = 0;

    rbusObject_Init(&inParams, NULL);
    rbusValue_Init(&value);
    rbusValue_SetInt32(value, index);
    rbusObject_SetValue(inParams, "pos", value);
    rbusValue_Release(value);

    rbus_response = rbusMethod_Invoke(handle, METHOD_GET_MEDIA_DEVICE_AT, inParams, &outParams);
    rbusObject_Release(inParams);

    if (RBUS_ERROR_SUCCESS == rbus_response)
    {
        rbusProperty_t outProps = rbusObject_GetProperties(outParams);
        int payload = 0;
        int count = 0;

        if (outProps)
        {
            status = getMediaServer(outProps, friendlyName,udn);
            if (!status)
            {
                fprintf(stderr, "[%s]  Failed to retrieve media details %d \n", __FUNCTION__, count);
                *err = 1;
            }
        }
        else
        {
            *err = 1;
        }
        status = true; // Indicate RPC communication worked
        rbusObject_Release(outParams);
    }
    else
    {
        fprintf(stderr, "[%s] Critical : Failed to invoke rpc communication %d \n", __FUNCTION__, rbus_response);
    }
    return status;
}
bool browseContentOnServer(const char * server_udn, const char * path_id, int start_index, 
        int max_entries, int * total_count, char ** content_list, int *err)
{
    rbusObject_t inParams;
    rbusObject_t outParams;
    rbusValue_t value;
    bool status = false;

    *err = 0;

    fprintf(stderr, "[%s] Received request for browsing udn = [%s], path=[%s] \n", __FUNCTION__, server_udn, path_id);
    rbusObject_Init(&inParams, NULL);

    rbusValue_Init(&value);
    rbusValue_SetString(value, server_udn);
    rbusObject_SetValue(inParams, "udn", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, path_id);
    rbusObject_SetValue(inParams, "path", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetInt32(value, start_index);
    rbusObject_SetValue(inParams, "start_index", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetInt32(value, max_entries);
    rbusObject_SetValue(inParams, "max_results", value);
    rbusValue_Release(value);
    rbus_response = rbusMethod_Invoke(handle, METHOD_BROWSE_CONTENT_ON_MEDIA_SERVER, inParams, &outParams);
    rbusObject_Release(inParams);

    *content_list = NULL;
    *total_count = -1;

    if (RBUS_ERROR_SUCCESS == rbus_response)
    {
        //fprintf(stderr, "[%s] Received response from Xupnp \n", __FUNCTION__);
        rbusProperty_t outProps = rbusObject_GetProperties(outParams);
        if(outProps)
        {
            value = rbusProperty_GetValue(outProps);

            if (value)
                *content_list = rbusValue_ToString(value, NULL, 0); // This is a copy

            outProps = rbusProperty_GetNext(outProps);
        }
        else
            *err = 1;

        if(outProps)
        {
            value = rbusProperty_GetValue(outProps);
            if (value)
                *total_count = rbusValue_GetInt32(value); // This is a copy
        }
        else
            *err = 1;
        status = true; //RPC communication is successfull.
        rbusObject_Release(outParams);
    }
    else
    {
        fprintf(stderr, "[%s] Received error from Xupnp : %d \n", __FUNCTION__, rbus_response);
        status =  false;
    }
    fprintf(stderr, "[%s] returning %d \n" , __FUNCTION__, status);
    return status;
}
void cleanup()
{

}
