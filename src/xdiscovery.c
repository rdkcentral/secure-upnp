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
 * @file xdiscovery.c
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
#include "xdiscovery_private.h"
#include "secure_wrapper.h"
#include <glib/gprintf.h>
#include <string.h>
#include <glib/gstdio.h>
#ifdef INCLUDE_BREAKPAD
#include "breakpad_wrapper.h"
#endif
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
int gatewayDetected=0;
gboolean partialDiscovery=FALSE;
#include "rdk_safeclib.h"

#ifdef LOGMILESTONE
#include "rdk_logger_milestone.h"
#endif

#ifdef BROADBAND
#include <syscfg/syscfg.h>
#endif
#include <libsoup/soup.h>

#ifdef GUPNP_GENERIC_MEDIA_RENDERER
#include "mediabrowser_private.h"
#endif //GUPNP_GENERIC_MEDIA_RENDERER
#ifdef ENABLE_HW_CERT_USAGE
#include "rdkconfig.h"
#endif
#define OUTPLAYURL_SIZE 180 //current max size of playbackurl with ocap locator is 145 adding few more just to accomdate future increase in receiver id or ipv6.

#define DEVICE_PROTECTION_CONTEXT_PORT  50760

#define ACCOUNTID_SIZE 30

#define MILESTONE_LOG_FILENAME "/opt/logs/rdk_milestones.log"

//Symbols defined in makefile (via defs.mk)
//#define USE_XUPNP_IARM
//#define GUPNP_0_19
//#define GUPNP_0_14
const char* localHostIP="127.0.0.1";
static int rfc_enabled ;
#if !defined(BROADBAND)
#define RESTART_XDISCOVERY_FILE      "/tmp/restartedXdiscovery"
#endif

#ifdef BROADBAND
#define WEBGUI_VIDEO_ANAL_FILE       "/tmp/videoanalytic_started"
#ifdef ENABLE_HW_CERT_USAGE
char se_cert_p12[128] ;
char *se_cert_pk12 = NULL;
char *se_cert_conf_file = NULL;
#endif
#endif

static GMainLoop *main_loop;
gboolean checkDevAddInProgress=FALSE;
#define WAIT_TIME_SEC 5
#define PNAME "/tmp/xpki_cert"
#define PID 21699
#define SHM_EXISTS 17
guint deviceAddNo=0;
int getSoupStatusFromUrl(char* url);

#ifdef SAFEC_DUMMY_API
//adding strcmp_s defination
errno_t strcmp_s(const char * d,int max ,const char * src,int *r)
{
  *r= strcmp(d,src);
  return EOK;
}
#endif
char *cert_File=NULL;
char *key_File=NULL;
#ifdef ENABLE_HW_CERT_USAGE
char *ca_File = NULL;
#else
char *ca_File="/tmp/UPnP_CA";
#endif
char accountId[ACCOUNTID_SIZE]={'\0',};

#ifdef BROADBAND
// shared memory id for sharing white list
// with mrd
static int shmId;
DEF_FIFO(dp_wlist_fifo,MAX_OVERFLOW, unsigned int);
dp_wlist_t *dp_wlist=NULL;
dp_wlist_ss_t dpnode_insert(long ipaddr, char *macaddr);
#endif

typedef GTlsInteraction XupnpTlsInteraction;
typedef GTlsInteractionClass XupnpTlsInteractionClass;
static void xupnp_tls_interaction_init (XupnpTlsInteraction *interaction);
static void xupnp_tls_interaction_class_init (XupnpTlsInteractionClass *xupnpClass);
static gboolean getAccountId(char *outValue);
static gboolean update_gwylist(GwyDeviceData* gwydata);
#ifdef USE_XUPNP_TZ_UPDATE
void broadcastTimeZoneChange(GwyDeviceData *gwdata);
#endif
GType xupnp_tls_interaction_get_type (void);
G_DEFINE_TYPE (XupnpTlsInteraction, xupnp_tls_interaction, G_TYPE_TLS_INTERACTION);

#ifdef BROADBAND
void dp_signal_handlr(int sig)
{
     //detach and remove
     //white list from memory.
     if (dp_wlist && (shmId > 0)) 
     {
        shmdt((void *) dp_wlist);
        shmctl(shmId, IPC_RMID, NULL);
     }
     exit(0);
}

/* 
   This function takes an ipv4 address as input
   and returns a 10 bit hash table index.
*/
unsigned short dp_hashindex (long ipaddr)
{
    unsigned short ret;
    // Fold the ip address to get a 9 bit hansh index
    ret =(ipaddr & 0x3FF) + ((ipaddr >> 10)&0x3FF) + ((ipaddr >> 20)&0x3FF) 
                                                   + ((ipaddr >> 30) & 0x3FF);
    ret = ((ret & 0x3FF) + ((ret >> 10) && 0x3FF)) &0x3FF;
    if (ret) 
       ret = ret-1;
    return(ret);
}

/* 
  Initialize the dp whitelist and associated data structures.
*/
int dp_wlistInit()
{
   int ret=0, fstat;
   key_t key;
   int i;

   // signal handlers for cleaning up
   // on termination of service.
   signal(SIGHUP,dp_signal_handlr);
   signal(SIGINT,dp_signal_handlr);
   signal(SIGQUIT,dp_signal_handlr);
   signal(SIGABRT,dp_signal_handlr);
   signal(SIGTSTP,dp_signal_handlr);
   signal(SIGKILL,dp_signal_handlr);

   // create a unique key
   if ((key =  ftok(PNAME, PID)) != (key_t) -1) { 
      //Allocate white list in shared memory shared   
      //with 'mrd' service.
      //White list contain 1024 hash indexed entries 
      //and 1024 overflow table. Hash is calculated
      //by folding the IPv4 address to a 10 bit hash
      //index value.
      //Overflow table indexes are stored in a FIFO
      //every entry in the whitelist contain a field 
      //(ofb_index) point to a collision index in the 
      //overflow table.
      //On further collision,every collistion entry 
      //subsequently contain index of (ofb_index)  
      //another collision entry in the overflow table.
      shmId = shmget(key, MAX_BUF_SIZE*sizeof(dp_wlist_t),  
           S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH|IPC_CREAT);

      if (shmId < 0)
      {
         g_message("dp_wlistInit:dp list creation, shared memory failure %d %s\n",
                                                     errno, strerror(errno));
         if (errno != SHM_EXISTS) {
             dp_wlist = (void *) -1;
             return -1;
          }
         shmId = shmget(key, MAX_BUF_SIZE*sizeof(dp_wlist_t), S_IRUSR|S_IRGRP|S_IROTH);
         if (shmId < 0) {
             g_message("dp_wlistInit:shmget  failure %d %s\n", errno, strerror(errno));
             dp_wlist = (void *) -1;
             return -1;
         }
      }
      //get a pointer to white list created in shared memory. 
      dp_wlist = (dp_wlist_t *) shmat(shmId, 0, 0);
      if (dp_wlist == (void *) -1)
      {
          g_message("dp_wlistInit: shared memory attach failed errno %d %s\n",
                                                   errno, strerror(errno));
          ret = -1;
      }
      else 
      {
         // push the overflow indexs into a fifo
         for (i=MAX_ENTRIES; i<MAX_BUF_SIZE; i++) 
         {
            ENQUEUE_FIFO(dp_wlist_fifo, i, fstat); 
            if (fstat== FIFO_FULL) 
            {
               break;         
            }
         }

         //initialize the  white list
         for (i=0; i<MAX_BUF_SIZE; i++) 
         {
            //initialize next index entry of whilte list
            //to -1, which indicate no collision for the.
            //current index.
            dp_wlist[i].ofb_index=(short ) -1; 
         }
       }
  }
  else {
     dp_wlist = (void *) -1;
     ret = -1;
  }
  return (ret);
}

/* 
   This function lookup the dp white list for a ip address
   and mac address.

   input - ipaddr - ipv4 address
         - MAC    - mac address 

   output - stat
            - DP_COLLISION - entry in the collision table
            - DP_INVALID_MAC - ip address existing in whitelist
                               mac address not matching.
   return 
         - index - if the lookup found entry in whitelist.
         - -1    - entry not existing in white list 
*/
         
short dpnode_lookup(long ipaddr, char MAC[], dp_wlist_ss_t *stat, 
                                          unsigned short *lastnode)
{
    short index;

    if (dp_wlist == (void *) -1) return (DP_WLIST_ERROR);
    index = dp_hashindex(ipaddr); 
    //check if the ip address is already existing in the white list
    if (dp_wlist[index].ofb_index == (short) -1) return -1; 
    else 
    {
       if (dp_wlist[index].ipaddr == ipaddr) 
       {
           if (!strncmp(MAC, dp_wlist[index].macaddr, MAC_ADDRESS_SIZE)) 
           { 
              *stat = DP_SUCCESS;
           }
           else 
           {
               *stat = DP_INVALID_MAC;
           }
           return (index);; 
       }
       else 
       {
            *lastnode = index;
            //search overflow table
            while (dp_wlist[index].ofb_index > 0) 
            {
                *lastnode = index;
                index = dp_wlist[index].ofb_index;
                if (dp_wlist[index].ipaddr == ipaddr) 
                {
                    if (!strncmp(MAC, dp_wlist[index].macaddr, 
                                            MAC_ADDRESS_SIZE))  
                    {
                       *stat = DP_COLLISION;
                       return (index); 
                    }
                    else 
                    {
                       *stat = DP_INVALID_MAC;
                       return (index);
                    }
                }
            }
            *stat = DP_COLLISION;
       }
    }
    return -1;
}

/* 
   This function lookup the dp white list for a ip address
   and mac address, if the entry is not existing add the .
   entry into the white list. If entry is existing
   but mac is not matching, update the mac address

   input - ipaddr - ipv4 address
         - MAC    - mac address 

   return 
            - DP_COLLISION - entry in the collision table
            - DP_SUCCESS   - successfully added entry 
*/
dp_wlist_ss_t dpnode_insert(long ipaddr, char *macaddr)
{
    dp_wlist_ss_t stat; 
    dp_wlist_ss_t ret=DP_SUCCESS;
    fstat_t fret;
    short index, pindex;
  
    if (dp_wlist == (void *) -1) return (DP_WLIST_ERROR);;
    if ((index = dpnode_lookup(ipaddr, macaddr, &stat,&pindex)) == (short) -1)
    {
       // check if there is collision
       if (stat == DP_COLLISION) 
       {
          // collision add to the collision table and link the last index
          // to the new node. 
          DEQUEUE_FIFO(dp_wlist_fifo, index, fret);    
          if (fret == FIFO_OK) 
          { 
             g_message("dpnode_insert:collsion ip:%lu mac:%s hash index %d\n",ipaddr, macaddr, index);
             dp_wlist[pindex].ofb_index = index;  
             dp_wlist[index].ipaddr = ipaddr;
             strncpy(dp_wlist[index].macaddr, macaddr, MAC_ADDRESS_SIZE);
             dp_wlist[index].ofb_index = 0;
          }
       }
       else 
       {
             // add new entry 
             index = dp_hashindex (ipaddr);
             g_message("dpnode_insert:new ip:%lu mac:%s hash index %d\n",ipaddr, macaddr, index);
             dp_wlist[index].ipaddr = ipaddr;
             strncpy(dp_wlist[index].macaddr, macaddr,MAC_ADDRESS_SIZE);
             dp_wlist[index].ofb_index = 0;
       }
        
    }
    else 
    {
       if (stat == DP_INVALID_MAC) 
       {
             g_message("dpnode_insert:mac update ip:%lu mac:%s hash index %d\n",ipaddr, macaddr, index);
             // update mac address
             strncpy(dp_wlist[index].macaddr, macaddr,MAC_ADDRESS_SIZE);
       }
       else {
          ret = DP_WLIST_ERROR;
       }
    }
    return (ret);
}

/* 
   This function delete an entry from dp whitelist.

   input - ipaddr  - ipv4 address
         - macaddr - mac address 

   return 
        void.
*/
void dpnode_delete(long ipaddr, char *macaddr)
{
   dp_wlist_ss_t stat; 
   int ret = 0;
   unsigned short index, pindex, tindex;

   if (((index = dpnode_lookup(ipaddr, macaddr, &stat, &pindex)) >= 0) && (index != DP_WLIST_ERROR))
   {

      if (index < MAX_ENTRIES )
      {
         // The entry is in the main table
         // If there are no subsequent nodes, delete the entry
         if (dp_wlist[index].ofb_index ==0) 
         {
            // No collision just delete the node
            g_message("No Collision ip:%lu mac:%s \n",ipaddr, macaddr);
            dp_wlist[index].ofb_index =-1; 
            dp_wlist[index].ipaddr = 0;
         }
         else 
         {
            // there are subsequent nodes in overflow table, delete the entry
            // copy the subsequent node from overflow table and then 
            // push the subsequent overflow table entry into fifo
            g_message("Collision ip:%lu mac:%s \n",ipaddr, macaddr);
            tindex = dp_wlist[index].ofb_index;
            dp_wlist[index].ofb_index = dp_wlist[tindex].ofb_index;
            dp_wlist[index].ipaddr  = dp_wlist[tindex].ipaddr;
            strncpy(dp_wlist[index].macaddr, dp_wlist[tindex].macaddr,MAC_ADDRESS_SIZE);
            dp_wlist[tindex].ofb_index=-1;
            dp_wlist[tindex].ipaddr=0;
            ENQUEUE_FIFO(dp_wlist_fifo, tindex, ret);
         }
      }
      else 
      {
         // Entry is in the overflow table.
         dp_wlist[pindex].ofb_index = dp_wlist[index].ofb_index;
         dp_wlist[index].ofb_index=-1;
         dp_wlist[index].ipaddr=0;
         ENQUEUE_FIFO(dp_wlist_fifo, index, ret);
      }
   }
   (void)(ret); // unused variable.
}
#endif
#if !defined (NO_MOCA_FEATURE_SUPPORT)
static void addRouteToMocaBridge(char *subnetip)
{
    int ret = 0;
    ret = v_secure_system("/etc/Xupnp/addRouteToMocaBridge.sh %s &",subnetip );
    if(ret != 0) {
        g_message("Failure in executing command via v_secure_system. ret val : %d \n", ret);
    } 
}
#endif

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
#ifdef BROADBAND
//ENABLE_HW_CERT_USAGE will be defined through disto feature flag check from OEM
#ifdef ENABLE_HW_CERT_USAGE
    uint8_t *pass_phrase = NULL;
    size_t pass_size = 0;
    size_t len = 0;

    g_message("%s Checking SE certificate\n", __FUNCTION__);
    if(access(se_cert_p12, F_OK) != -1)
    {
        g_message("Getting passcode\n");

        if(rdkconfig_get(&pass_phrase, &pass_size, se_cert_conf_file) == RDKCONFIG_FAIL)
        {
            g_message("Error in getting passcode\n");
        }
        else
        {
            len = strcspn(pass_phrase, "\n");
            pass_phrase[len] = '\0';
            g_message("Passcode decoded successfully\n");
        }

        g_message(" Using SE certificate \n");

        cert = g_tls_certificate_new_from_file_with_password(se_cert_p12, pass_phrase, &xupnp_error);
        if(cert)
        {
            g_message(" Successfully generated g_tls cert from SE certificate\n");
        }
        else
        {
            g_message(" Failed to generate g_tls cert from SE certificate\n");
            if(xupnp_error)
            {
                g_message(" %s\n",xupnp_error->message);
            }

            g_error_free (xupnp_error);

            if(pass_phrase != NULL)
            {
                g_message(" Freeing pass phrase ");
                rdkconfig_free(&pass_phrase, pass_size);
            }

            return  G_TLS_INTERACTION_FAILED;
        }
        if(pass_phrase != NULL)
        {
            g_message(" Freeing pass phrase ");
            rdkconfig_free(&pass_phrase, pass_size);
        }
    }
    else // cannot access HW cert. Fallback to normal cert
    {
        g_message(" Error: SE HW certificate is not accessible. Using extracted cert and key files\n");
        g_message(" Error: cert file: %s,  key file:%s\n",cert_File, key_File);
        if ((cert_File == NULL)  || (key_File == NULL) ) 
        {
            g_message(" Certificate or Key file NULL");
            return  G_TLS_INTERACTION_FAILED;
        }
        cert = g_tls_certificate_new_from_files (cert_File,
                key_File,
                &xupnp_error);
    }
#endif // HW cert
#else 
//video
    if ((cert_File == NULL)  || (key_File == NULL) ) 
    {
        g_message(" Certificate or Key file NULL");
        return  G_TLS_INTERACTION_FAILED;
    }
    cert = g_tls_certificate_new_from_files (cert_File,
            key_File,
            &xupnp_error);

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

#ifdef BROADBAND
gboolean getAccountId(char *outValue)
{
    char temp[ACCOUNTID_SIZE] = {0};
    int rc;
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
gboolean getAccountId(char *outValue)
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

gboolean selfDeviceDiscovered=FALSE;
gboolean bSerialNum=FALSE;

#if defined(USE_XUPNP_IARM) || defined(USE_XUPNP_IARM_BUS)

typedef struct _iarmDeviceData {
    unsigned long bufferLength;
    char* pBuffer;
} IarmDeviceData;

//static GMainLoop *main_loop;
#define WAIT_TIME_SEC 5
#ifdef USE_XUPNP_IARM
#include "uidev.h"
static void *gCtx = NULL;
static void _GetXUPNPDeviceInfo(void *callCtx, unsigned long methodID, void *arg, unsigned int serial);
#else
#include "libIBus.h"
#include "libIARMCore.h"
#include "sysMgr.h"
IARM_Result_t _GetXUPNPDeviceInfo(void *arg);
#endif


static IARM_Result_t GetXUPNPDeviceInfo(char *pDeviceInfo, unsigned long length)
{
    g_mutex_lock(devMutex);
    g_message("<<<<<<<IARM XUPnP Call Reached API Processor - length: %ld Output Data length: %d>>>>>>>>", length, outputcontents->len);

    //IarmDeviceData *param = (IarmDeviceData *)arg;
    if (outputcontents->len <= length)
    {
        //Copy the output to buffer and return success
        g_message("Output string is\n %s\nAddress of received memory is %p", outputcontents->str, pDeviceInfo);
        //Append space for null character
        strncpy (pDeviceInfo, outputcontents->str, outputcontents->len+1);
        g_mutex_unlock(devMutex);
        g_message("<<<<<<<IARM XUPnP Call Returned success from API Processor>>>>>>>>");
        return IARM_RESULT_SUCCESS;
    }
    else
    {
        //return IARM Error
        g_mutex_unlock(devMutex);
        g_message("<<<<<<<IARM XUPnP Call Returned failure from API Processor>>>>>>>>");
        return IARM_RESULT_INVALID_STATE;
    }

    //IARM_CallReturn(callCtx, "UIMgr", "GetXUPNPDeviceInfo", ret, serial);
    //g_mutex_unlock(mutex);
}

//notifyXUPnPDataUpdateEvent(UIDEV_EVENT_XUPNP_DATA_UPDATE)
static void notifyXUPnPDataUpdateEvent(int eventId)
{
#ifdef USE_XUPNP_IARM
    g_message("<<<<<<<IARM XUPnP Posted update request>>>>>>>>");
    UIDev_EventData_t eventData;
    eventData.id = eventId;

    //   struct _UIDEV_XUPNP_DATA {
    //         unsigned long deviceInfoLength;
    //      } xupnpData;
    //Add the length to accommodate NULL character
    g_mutex_lock(devMutex);
    eventData.data.xupnpData.deviceInfoLength = outputcontents->len+1;
    g_mutex_unlock(devMutex);
    UIDev_PublishEvent(eventId, &eventData);
#else

    IARM_Bus_SYSMgr_EventData_t eventData;
    g_mutex_lock(devMutex);
    eventData.data.xupnpData.deviceInfoLength = outputcontents->len+1;
    g_mutex_unlock(devMutex);
    g_message("<<<<<<<IARM XUPnP Posted update request with Length %ld>>>>>>>>",eventData.data.xupnpData.deviceInfoLength);
    IARM_Bus_BroadcastEvent(IARM_BUS_SYSMGR_NAME, (IARM_EventId_t)IARM_BUS_SYSMGR_EVENT_XUPNP_DATA_UPDATE,(void *)&eventData, sizeof(eventData));

#endif
}

#ifdef USE_XUPNP_IARM

/**
 * @brief If there is any other process wants to get XUPnP data, the event will be handled here.
 *
 * @param[in] eventId Event Identifier identifying the Data request event.
 * @param[in] eventData Optional Event data.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
void _evtHandler(int eventId, void *eventData)
#else

/**
 * @brief This is a call back function for handling SYS Manager events. It notifies the XUPnP
 * about The Data update event triggered by IARM.
 *
 * @param[in] owner Owner of the event, contains name of the Manager.
 * @param[in] eventId Event Identifier identifying the Data request event.
 * @param[in] data Event data.
 * @param[in] len Size of the event data.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
void _evtHandler(const char *owner, IARM_EventId_t eventId, void *data, size_t len)
#endif
{
    g_message("<<<<<<<IARM XUPnP Received update request>>>>>>>>");
#ifdef USE_XUPNP_IARM
    UIDev_EventData_t *evt = eventData;
    if (eventId == UIDEV_EVENT_XUPNP_DATA_REQUEST)
    {
        notifyXUPnPDataUpdateEvent(UIDEV_EVENT_XUPNP_DATA_UPDATE);
    }
#else
    errno_t rc       = -1;
    int     ind      = -1;

    rc = strcmp_s(owner, strlen(owner), IARM_BUS_SYSMGR_NAME, &ind );
    ERR_CHK(rc);
    if((ind == 0) && (rc == EOK))
    {
        switch (eventId) {
        case IARM_BUS_SYSMGR_EVENT_XUPNP_DATA_REQUEST:
        {
            notifyXUPnPDataUpdateEvent(IARM_BUS_SYSMGR_EVENT_XUPNP_DATA_UPDATE);
        }
        break;
        default:
            break;
        }
    }
#endif
}

/**
 * @brief This function will do the initialization procedure for using the IARM Bus within XUPnP.
 * This will register the event handlers to receive events from IARM Managers and will connect
 * with the IARM Bus.
 *
 * @return TRUE if initialization is successful.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
gboolean XUPnP_IARM_Init(void)
{
    g_message("<<<<< Iniializing IARM XUPnP >>>>>>>>");

#ifdef USE_XUPNP_IARM
    if (gCtx == NULL) {
        UIDev_Init(_IARM_XUPNP_NAME);
        g_message("<<<<<<<IARM XUPnP Init Done>>>>>>>>");
        if (UIDev_GetContext(&gCtx) == IARM_RESULT_SUCCESS) {
            g_message("<<<<<<<IARM XUPnP Got the context>>>>>>>");
            IARM_RegisterCall(gCtx, "UIMgr", "GetXUPNPDeviceInfo", _GetXUPNPDeviceInfo, NULL/*callCtx*/);
            UIDev_RegisterEventHandler(UIDEV_EVENT_XUPNP_DATA_REQUEST, _evtHandler);
            g_message("<<<<<<<IARM XUPnP Registered the events>>>>>>>>");
            return TRUE;
        }
        else {
            return FALSE;
        }
    }
#else
    if(IARM_RESULT_SUCCESS != IARM_Bus_Init(_IARM_XUPNP_NAME))
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
        IARM_Bus_RegisterEventHandler(IARM_BUS_SYSMGR_NAME,IARM_BUS_SYSMGR_EVENT_XUPNP_DATA_REQUEST,_evtHandler);
        IARM_Bus_RegisterCall(IARM_BUS_XUPNP_API_GetXUPNPDeviceInfo,_GetXUPNPDeviceInfo);
        g_message("<<<<<<<%s - Registered the BUS Events >>>>>>>>",__FUNCTION__);
        return TRUE;
    }
#endif

}

#ifdef USE_XUPNP_IARM
static void _GetXUPNPDeviceInfo(void *callCtx, unsigned long methodID, void *arg, unsigned int serial)
#else
IARM_Result_t _GetXUPNPDeviceInfo(void *arg)
#endif
{
    g_message("<<<<<<<IARM XUPnP API Call received>>>>>>>>");
    g_mutex_lock(mutex);

#ifdef USE_XUPNP_IARM
    IarmDeviceData *param = (IarmDeviceData *)arg;
    g_message("Address of received memory is %p - Call 0", param->pBuffer);
    IARM_Result_t ret = GetXUPNPDeviceInfo(param->pBuffer, param->bufferLength);
    IARM_CallReturn(gCtx, "UIMgr", "GetXUPNPDeviceInfo", ret, serial);
#else
    // Extract the XUPNP Info data
    IARM_Bus_SYSMGR_GetXUPNPDeviceInfo_Param_t *param = (IARM_Bus_SYSMGR_GetXUPNPDeviceInfo_Param_t *)arg;
#ifdef USE_DBUS
    GetXUPNPDeviceInfo((char *)param + sizeof(IARM_Bus_SYSMGR_GetXUPNPDeviceInfo_Param_t), param->bufLength);
#else
    IARM_Result_t retCode = IARM_RESULT_SUCCESS;
    // Create a Mem space for the buff
    retCode = IARM_Malloc(IARM_MEMTYPE_PROCESSSHARE,param->bufLength, &(param->pBuffer));
    g_message("Address of received memory is %p - Call 0", param->pBuffer);
    if(IARM_RESULT_SUCCESS == retCode)
    {
        GetXUPNPDeviceInfo(param->pBuffer, param->bufLength);
    }
#endif
#endif

    g_mutex_unlock(mutex);

    return IARM_RESULT_SUCCESS;

}
#endif //#if defined(USE_XUPNP_IARM) || defined(USE_XUPNP_IARM_BUS)

#ifndef BROADBAND
int xPKI_check_rfc()
{
    errno_t rc       = -1;
    int     ind      = -1;
#ifdef ENABLE_RFC
    RFC_ParamData_t param = {0};

    WDMP_STATUS status = getRFCParameter("XUPNP","Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.UPnPxPKI.Enable",&param);

    if (status == WDMP_SUCCESS)
    {
        rc = strcmp_s(param.value,sizeof(param.value),"true",&ind);
        if ((ind == 0) && (rc == EOK))
        {
            g_message("New Device xPKI rfc_enabled and xdiscovery is running with new certs");
            return 1;
        }
        else
        {
            g_message("Running device protection with old certs");
        }
    }
    else
    {
        g_message("getRFCParameter Failed : %s", getRFCErrorString(status));
    }
#else
    g_message("Not built with RFC support.");
#endif
    return 0;
}
#endif

int check_rfc()
{
#ifndef BROADBAND
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
            g_message("Running older xdiscovery");
        }
    }
    else
    {
        g_message("getRFCParameter Failed : %s", getRFCErrorString(status));
    }
#else
    g_message("Not built with RFC support.");
#endif
#else
    syscfg_init();
    char temp[24] = {0};
    errno_t rc       = -1;
    int     ind      = -1;
    if (!syscfg_get(NULL, "Refactor", temp, sizeof(temp)) )
    {
        rc = strcmp_s("true", strlen("true"), temp, &ind);
        ERR_CHK(rc);
        if((ind == 0) && (rc == EOK))
        {
            return 1;
        }
    }
#endif
    return 0;
}

/**
 * @brief This function is used to log the messages of XUPnP applications. Each Log message
 * will be written to a file along with the timestamp formated in ISO8601 format.
 *
 * @param[in] log_domain Defines the log domain. For applications, this is typically left as
 * the default NULL domain. Libraries should define this so that any messages that they log
 * can be differentiated from messages from other libraries/applications.
 * @param[in] log_level Log level used to categorize messages of type warning, error, info, debug etc.
 * @param[in] message The Message to be logged represented in string format.
 * @param[in] user_data Contains the Log file name.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
void xupnp_logger (const gchar *log_domain, GLogLevelFlags log_level,
                   const gchar *message, gpointer user_data)
{

    GTimeVal timeval;
    gchar *date_str;
    g_get_current_time(&timeval);
    if (logoutfile == NULL)
    {
        // Fall back to console output if unable to open file
        g_print ("g_time_val_to_iso8601(&timeval): %s\n", message);
        return;
    }

    date_str = g_time_val_to_iso8601 (&timeval);
    g_fprintf (logoutfile, "%s : %s\n", date_str, message);
    if(date_str)
    {
        g_free (date_str);
    }
    fflush(logoutfile);
}


static gint
g_list_find_sno(GwyDeviceData* gwData, gconstpointer* sno )
{

    if(gwData == NULL || gwData->serial_num == NULL || sno == NULL)
    {
        g_message ("g_list_find_sno: gwData or sno is NULL");
        return 1;
    }

    if(gwData->serial_num->len == 0)
    {
        g_message ("g_list_find_sno: serial_num str or sno is not a valid string");
        return 1;
    }

    // do g_strstrip and g_strcmp0 only for valid strings
    if (g_strcmp0(g_strstrip(gwData->serial_num->str),g_strstrip((gchar *)sno)) == 0)
        return 0;
    else
        return 1;
}

static gint
g_list_find_udn(GwyDeviceData* gwData, gconstpointer* udn )
{

    if(gwData == NULL || gwData->receiverid == NULL || udn == NULL)
    {
        g_message ("g_list_find_udn: gwData or udn is NULL");
        return 1;
    }

    if(gwData->receiverid->len == 0)
    {
        g_message ("g_list_find_udn: serial_num str or udn is not a valid string");
        return 1;
    }

    // do g_strstrip and g_strcmp0 only for valid strings
    if (g_strcmp0(g_strstrip(gwData->receiverid->str),g_strstrip((gchar *)udn)) == 0)
        return 0;
    else
        return 1;
}

static gint
g_list_compare_sno(GwyDeviceData* gwData1, GwyDeviceData* gwData2, gpointer user_data )
{
    gint result = g_strcmp0(g_strstrip(gwData1->serial_num->str),g_strstrip(gwData2->serial_num->str));
    return result;
}

/**
 * @brief This will Scan through the device list to check whether a particular device entry exists.
 *
 * It will Match the device serial number in the list to find the desired device entry.
 *
 * @param[in] sno Serial number of the device represented in string format.
 *
 * @return Returns TRUE if serial number is present in the device list else returns FALSE.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
//Find a device with given serial number is in our list of gateways
gboolean checkDeviceExists(const char* sno,char* outPlayUrl)
{
    gboolean retval = FALSE;
    errno_t rc       = -1;
    if (g_list_length(xdevlist) > 0)
    {
        GList *element = NULL;
        element = g_list_first(xdevlist);
        while(element)
        {
            gint result = g_strcmp0(g_strstrip((gchar *)(((GwyDeviceData *)element->data)->serial_num->str)),g_strstrip((gchar *)sno));
            //Matched the serial number
            if (result==0)
            {
                retval = TRUE;
                if((((GwyDeviceData *)element->data)->isgateway) == TRUE)
                {
                    rc = strcpy_s(outPlayUrl, OUTPLAYURL_SIZE,  g_strstrip(((GwyDeviceData *)element->data)->playbackurl->str));
                    ERR_CHK(rc);
                    if ( rc != EOK)
                    {
                        retval = FALSE;
                    }
                    else
                    {
                        if (outPlayUrl)
                        {
                            strcat(outPlayUrl,"&live=ocap://0xffff");
                        }
                    }
                }
                break;
            }
            //Past the search string value in sorted list
            else if (result>0)
            {
                retval = FALSE;
                break;
            }
            //There are still elements to search
            element = g_list_next(element);
        }
//        if (element) g_object_unref(element);
    }
    return retval;
}


static void
device_proxy_unavailable_cb (GUPnPControlPoint *cp, GUPnPDeviceProxy *dproxy)
{
    char gwyPlayUrl[OUTPLAYURL_SIZE]={'\0'};
    const gchar* sno = gupnp_device_info_get_serial_number (GUPNP_DEVICE_INFO (dproxy));

    g_message ("In unavailable_cb  Device %s went down",sno);

    if((g_strcmp0(g_strstrip(ownSerialNo->str),sno) == 0))
    {
        g_message ("Self Device [%s][%s] not removing",sno,ownSerialNo->str);
        g_free((gpointer)sno);
        return;
    }
    GUPnPServiceInfo *sproxy = gupnp_device_info_get_service(GUPNP_DEVICE_INFO (dproxy), XDISC_SERVICE);

    if (gupnp_service_proxy_get_subscribed((GUPnPServiceProxy *)sproxy) == TRUE)
    {
        g_message("Removing notifications on %s", sno);
        gupnp_service_proxy_set_subscribed((GUPnPServiceProxy *)sproxy, FALSE);
        gupnp_service_proxy_remove_notify((GUPnPServiceProxy *)sproxy, "PlaybackUrl", on_last_change, NULL);
        gupnp_service_proxy_remove_notify((GUPnPServiceProxy *)sproxy, "SystemIds", on_last_change, NULL);
    }

    if (checkDeviceExists(sno,gwyPlayUrl))
    {
        if(gwyPlayUrl[0] != '\0')
        {
            if (getSoupStatusFromUrl(gwyPlayUrl))
            {
                g_message("Network Multicast issue for device %s",sno);
                g_free((gpointer)sno);
                g_object_unref(sproxy);
                return;
            }
            else
            {
                g_message("Can't reach device %s",sno);
            }
        }
        else
        {
            g_message("GW playback url is NULL");
        }

        if (delete_gwyitem(sno) == FALSE)
        {
            g_message("%s found, but unable to delete it from list", sno);
        }
        else
        {
            g_message("Deleted %s from list", sno);
            sendDiscoveryResult(disConf->outputJsonFile);
        }
    }
    g_free((gpointer)sno);
    g_object_unref(sproxy);
}

static void
device_proxy_unavailable_cb_client (GUPnPControlPoint *cp, GUPnPDeviceProxy *dproxy)
{
    const gchar* sno = gupnp_device_info_get_serial_number (GUPNP_DEVICE_INFO (dproxy));

    g_message ("In unavailable_client Device %s went down",sno);
    if((g_strcmp0(g_strstrip(ownSerialNo->str),sno) == 0))
    {
        g_message ("Self Device [%s][%s] not removing",sno,ownSerialNo->str);
        g_free((gpointer)sno);
        return;
    }
    GUPnPServiceInfo *sproxy = gupnp_device_info_get_service(GUPNP_DEVICE_INFO (dproxy), XDISC_SERVICE_MEDIA);
    if (gupnp_service_proxy_get_subscribed((GUPnPServiceProxy *)sproxy) == TRUE)
    {
	g_message("Removing notifications on %s", sno);
	gupnp_service_proxy_set_subscribed((GUPnPServiceProxy *)sproxy, FALSE);
    }
    if (delete_gwyitem(sno) == FALSE)
    {
        g_message("%s found, but unable to delete it from list", sno);
    }
    else
    {
        g_message("Deleted %s from list", sno);
        sendDiscoveryResult(disConf->outputJsonFile);
    }
    g_free((gpointer)sno);
    g_object_unref(sproxy);
}

static void
device_proxy_unavailable_cb_gw (GUPnPControlPoint *cp, GUPnPDeviceProxy *dproxy)
{
    const gchar* sno = gupnp_device_info_get_serial_number (GUPNP_DEVICE_INFO (dproxy));
    char gwyPlayUrl[OUTPLAYURL_SIZE]={0};
    g_message ("In unavailable_gw Device %s went down",sno);
    if((g_strcmp0(g_strstrip(ownSerialNo->str),sno) == 0))
    {
        g_message ("Self Device [%s][%s] not removing",sno,ownSerialNo->str);
        g_free((gpointer)sno);
        return;
    }
    GUPnPServiceInfo *sproxy = gupnp_device_info_get_service(GUPNP_DEVICE_INFO (dproxy), XDISC_SERVICE_MEDIA);
    if (gupnp_service_proxy_get_subscribed((GUPnPServiceProxy *)sproxy) == TRUE)
    {
	g_message("Removing notifications on %s", sno);
	gupnp_service_proxy_set_subscribed((GUPnPServiceProxy *)sproxy, FALSE);
	gupnp_service_proxy_remove_notify((GUPnPServiceProxy *)sproxy, "PlaybackUrl", on_last_change, NULL);
    }
    if (checkDeviceExists(sno, gwyPlayUrl))
    {
        if(gwyPlayUrl[0] != '\0')
        {
            if (getSoupStatusFromUrl(gwyPlayUrl))
            {
                g_message("Network Multicast issue for device %s",sno);
                g_free((gpointer)sno);
                g_object_unref(sproxy);
                return;
            }
            else
            {
                g_message("Can't reach device %s",sno);
            }
        }
        else
        {
            g_message("GW playback url is NULL");
        }
        if (delete_gwyitem(sno) == FALSE)
        {
            g_message("%s found, but unable to delete it from list", sno);
        }
        else
        {
            g_message("Deleted %s from list", sno);
            sendDiscoveryResult(disConf->outputJsonFile);
        }
    }
    g_free((gpointer)sno);
    g_object_unref(sproxy);
}

static void
device_proxy_available_cb (GUPnPControlPoint *cp, GUPnPDeviceProxy *dproxy)
{
    errno_t rc       = -1;
    int     ind      = -1;
    GList* xdevlistitem = NULL;
    //g_print("Found a new device\n");
//    if(!checkDevAddInProgress)
//    {
//    ret=g_mutex_trylock(devMutex);
//    if (TRUE == ret)
//    {
    g_message("Found a new device. deviceAddNo = %u ",deviceAddNo);
    deviceAddNo++;
    if ((NULL==cp) || (NULL==dproxy))
    {
//	        g_mutex_unlock(devMutex);
        deviceAddNo--;
        g_message("WARNING - Received a null pointer for gateway device device no %u",deviceAddNo);
        return;
    }
    if(rfc_enabled)
    {
        gchar* upc = gupnp_device_info_get_upc (GUPNP_DEVICE_INFO (dproxy));
        if(upc)
        {
            rc =strcmp_s("10000", strlen("10000"), upc, &ind);
            ERR_CHK(rc);
            if((!ind) && (rc == EOK))
            {
                g_message("Exiting the device addition as UPC value matched");
                g_free(upc);
                deviceAddNo--;
                return;
            }
	}
    }
    gchar* sno = gupnp_device_info_get_serial_number (GUPNP_DEVICE_INFO (dproxy));
    if(sno)
    {
        xdevlistitem = g_list_find_custom(xdevlist,sno,(GCompareFunc)g_list_find_sno);
    }
    if(xdevlistitem!=NULL)
    {
        GwyDeviceData *gwdata = xdevlistitem->data;
        gchar *temp=NULL;
        if ( processStringRequest((GUPnPServiceProxy *)gupnp_device_info_get_service(GUPNP_DEVICE_INFO (dproxy), XDISC_SERVICE), "GetIpv6Prefix", "Ipv6Prefix" , &temp, FALSE ))
        {
            if(g_strcmp0(g_strstrip(temp),gwdata->ipv6prefix->str) != 0)
            {
                g_string_assign(gwdata->ipv6prefix, temp);
                sendDiscoveryResult(disConf->outputJsonFile);
            }
            g_free(temp);
        }
        deviceAddNo--;
        g_message("Existing as SNO is present in list so no update of devices %s device no %u",sno,deviceAddNo);
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
        g_critical("Could not allocate memory for Gwydata. Exiting...");
        exit(1);
    }

    gwydata->sproxy = gupnp_device_info_get_service(GUPNP_DEVICE_INFO (dproxy), XDISC_SERVICE);
    if(!gwydata->sproxy)
    {
       deviceAddNo--;
       g_message("Unable to get the services, sproxy null. returning");
       return;
    }
    if (sno != NULL)
    {
        //g_print("Device serial number is %s\n",sno);
        g_message("Device serial number is %s",sno);
        g_string_assign(gwydata->serial_num, sno);
        const char* udn = gupnp_device_info_get_udn(GUPNP_DEVICE_INFO (dproxy));
        if (udn != NULL)
        {
            if (g_strrstr(udn,"uuid:"))
            {
                gchar* receiverid = g_strndup(udn+5, strlen(udn)-5);
                if(receiverid)
                {
                    g_message("Device receiver id is %s",receiverid);
                    g_string_assign(gwydata->receiverid, receiverid);
                    g_free(receiverid);

                    if(!process_gw_services((GUPnPServiceProxy *)gwydata->sproxy, gwydata))
                    {
		        free_gwydata(gwydata);
                        g_free(gwydata);
                        g_free(sno);
                        deviceAddNo--;
                        partialDiscovery=TRUE;
    		        g_message("Exting from device_proxy_available_cb since mandatory paramters are not there  device no %u",deviceAddNo);
		        return;
		    }
                }
                else
                    g_message("Device receiver id is NULL");
            }
        }
        else
            g_message("Device UDN is NULL");
    }

    if(g_strrstr(g_strstrip(gwydata->devicetype->str),"XB") != NULL )
    {
        g_message("Discovered a XB device");
    }
    else if(g_strrstr(g_strstrip(gwydata->devicetype->str),"XI") == NULL )
    {
       g_message("Discovered a XG device");
       if (gupnp_service_proxy_add_notify ((GUPnPServiceProxy *)gwydata->sproxy, "PlaybackUrl", G_TYPE_STRING, on_last_change, NULL) == FALSE)
           g_message("Failed to add url notifications for %s", sno);
       if (gupnp_service_proxy_add_notify ((GUPnPServiceProxy *)gwydata->sproxy, "SystemIds", G_TYPE_STRING, on_last_change, NULL) == FALSE)
           g_message("Failed to add systemid notifications for %s", sno);
       if (gupnp_service_proxy_add_notify ((GUPnPServiceProxy *)gwydata->sproxy, "DnsConfig", G_TYPE_STRING, on_last_change, NULL) == FALSE)
           g_message("Failed to add DNS notifications for %s", sno);
       if (gupnp_service_proxy_add_notify ((GUPnPServiceProxy *)gwydata->sproxy, "TimeZone", G_TYPE_STRING, on_last_change, NULL) == FALSE)
           g_message("Failed to add TimeZone notifications for %s", sno);
    }
    else
    {
       if (gupnp_service_proxy_add_notify ((GUPnPServiceProxy *)gwydata->sproxy, "DataGatewayIPaddress", G_TYPE_STRING, on_last_change, NULL) == FALSE)
           g_message("Failed to add DataGatewayIPaddress notifications for %s", sno);
    }
    gupnp_service_proxy_set_subscribed((GUPnPServiceProxy *)gwydata->sproxy, TRUE);

    if (gupnp_service_proxy_get_subscribed((GUPnPServiceProxy *)gwydata->sproxy) == FALSE)
    {
        g_message("Failed to register for notifications on %s", sno);
        g_clear_object(&(gwydata->sproxy));
    }
    g_free(sno);
    deviceAddNo--;
    g_message("Exting from device_proxy_available_cb deviceAddNo = %u",deviceAddNo);

//    }
//    else
//    {
//        g_message("Already Existing device addition going on ");
//    }
//	    g_mutex_unlock(devMutex);
//    }
//    else
//    {
//          g_message("Not able to get the device mutex lock");
//    }
}

static void
device_proxy_available_cb_client (GUPnPControlPoint *cp, GUPnPDeviceProxy *dproxy)
{
    GList* xdevlistitem = NULL;
    g_message("Found a new Client device. deviceAddNo = %u ",deviceAddNo);
    deviceAddNo++;
    if ((NULL==cp) || (NULL==dproxy))
    {
        deviceAddNo--;
        g_message("WARNING - Received a null pointer for client device device no %u",deviceAddNo);
        return;
    }
    gchar* sno = gupnp_device_info_get_serial_number (GUPNP_DEVICE_INFO (dproxy));
    if(sno)
    {
        xdevlistitem = g_list_find_custom(xdevlist,sno,(GCompareFunc)g_list_find_sno);
    }
    if(xdevlistitem!=NULL)
    {
        deviceAddNo--;
        g_message("Existing as client SNO is present in list so no update of devices %s device no %u",sno,deviceAddNo);
        g_free(sno);
        return;
    }

    GwyDeviceData *gwydata = g_new(GwyDeviceData,1);
    init_gwydata(gwydata);
    gwydata->sproxy_i = gupnp_device_info_get_service(GUPNP_DEVICE_INFO (dproxy), XDISC_SERVICE_IDENTITY);
    gwydata->sproxy_m = gupnp_device_info_get_service(GUPNP_DEVICE_INFO (dproxy), XDISC_SERVICE_MEDIA);
    if (sno != NULL)
    {
        g_message("XI device serial number is %s",sno);
        g_string_assign(gwydata->serial_num, sno);
        const char* udn = gupnp_device_info_get_udn(GUPNP_DEVICE_INFO (dproxy));
        if (udn != NULL)
        {
            if (g_strrstr(udn,"uuid:"))
            {
                gchar* receiverid = g_strndup(udn+5, strlen(udn)-5);
                if(receiverid)
                {
                    g_message("Client device receiver id is %s",receiverid);
                    g_string_assign(gwydata->receiverid, receiverid);
                    g_free(receiverid);
                    if(!process_gw_services_identity((GUPnPServiceProxy *)gwydata->sproxy_i, gwydata))
                    {
                        free_gwydata(gwydata);
                        g_free(gwydata);
                        g_free(sno);
                        deviceAddNo--;
                        g_message("Exting from device_proxy_available_cb_client since mandatory paramters are not there  device no %u",deviceAddNo);
                        return;
                    }
                    else
                    {
			g_message("Received XI Identity service");
                    }
		    if(!process_gw_services_media_config((GUPnPServiceProxy *)gwydata->sproxy_m, gwydata))
		    {
			free_gwydata(gwydata);
			g_free(gwydata);
			g_free(sno);
			deviceAddNo--;
			g_message("Exting from device_proxy_available_cb_client since mandatory paramters are not there  device no %u",deviceAddNo);
			return;
		    }
                    else
		    {
			g_message("Received XI Media Config service");
                        gwydata->isDevRefactored = TRUE;
			if (update_gwylist(gwydata)==FALSE )
			{
			    g_message("Failed to update gw data into the list");
			    g_critical("Unable to update the Client device-%s in the list",(char*)gwydata->serial_num);
			    return;
			}
		    }
                }
                else
		{
                    g_message("Client device receiver id is NULL");
		}
            }
        }
        else
	{
            g_message("Client UDN is NULL");
	}
    }
    g_message("Discovered a Xi device");
    g_free(sno);
    deviceAddNo--;
    g_message("Exting from Device_proxy_available_cb client deviceAddNo = %u",deviceAddNo);

}

static void
device_proxy_available_cb_gw (GUPnPControlPoint *cp, GUPnPDeviceProxy *dproxy)
{
    GList* xdevlistitem = NULL;
    g_message("In device_proxy_available_cb_gw found a Gateway device. deviceAddNo = %u ",deviceAddNo);
    deviceAddNo++;
    if ((NULL==cp) || (NULL==dproxy))
    {
        deviceAddNo--;
        g_message("WARNING - Received a null pointer for gateway device device no %u",deviceAddNo);
        return;
    }
    gchar* sno = gupnp_device_info_get_serial_number (GUPNP_DEVICE_INFO (dproxy));
    if(sno)
    {
        xdevlistitem = g_list_find_custom(xdevlist,sno,(GCompareFunc)g_list_find_sno);
    }
    if(xdevlistitem!=NULL)
    {
        GwyDeviceData *gwdata = xdevlistitem->data;
        gchar *temp=NULL;
        if ( processStringRequest((GUPnPServiceProxy *)gupnp_device_info_get_service(GUPNP_DEVICE_INFO (dproxy), XDISC_SERVICE_GW_CFG), "GetIpv6Prefix", "Ipv6Prefix" , &temp, FALSE ))
        {
            if(g_strcmp0(g_strstrip(temp),gwdata->ipv6prefix->str) != 0)
            {
                g_string_assign(gwdata->ipv6prefix, temp);
                sendDiscoveryResult(disConf->outputJsonFile);
            }
            g_free(temp);
        }
        deviceAddNo--;
        g_message("Existing available_cb_gw as SNO is present in list so no update of devices %s device no %u",sno,deviceAddNo);
        g_free(sno);
        return;
    }
    GwyDeviceData *gwydata = g_new(GwyDeviceData,1);
    init_gwydata(gwydata);
    gwydata->sproxy_i = gupnp_device_info_get_service(GUPNP_DEVICE_INFO (dproxy), XDISC_SERVICE_IDENTITY);
    gwydata->sproxy_m = gupnp_device_info_get_service(GUPNP_DEVICE_INFO (dproxy), XDISC_SERVICE_MEDIA);
    gwydata->sproxy_t = gupnp_device_info_get_service(GUPNP_DEVICE_INFO (dproxy), XDISC_SERVICE_TIME);
    gwydata->sproxy_g = gupnp_device_info_get_service(GUPNP_DEVICE_INFO (dproxy), XDISC_SERVICE_GW_CFG);
    gwydata->sproxy_q = gupnp_device_info_get_service(GUPNP_DEVICE_INFO (dproxy), XDISC_SERVICE_QAM_CFG);
    if (sno != NULL)
    {
	g_message("In available_cb_gw Gateway device serial number: %s",sno);
	g_string_assign(gwydata->serial_num, sno);
	const char* udn = gupnp_device_info_get_udn(GUPNP_DEVICE_INFO (dproxy));
	if (udn != NULL)
	{
	    if (g_strrstr(udn,"uuid:"))
	    {
		gchar* receiverid = g_strndup(udn+5, strlen(udn)-5);
		if(receiverid)
		{
		    g_message("Gateway device receiver id is %s",receiverid);
		    g_string_assign(gwydata->receiverid, receiverid);
		    g_free(receiverid);
		    if(!process_gw_services_identity((GUPnPServiceProxy *)gwydata->sproxy_i, gwydata))
		    {
			free_gwydata(gwydata);
			g_free(gwydata);
			g_free(sno);
			deviceAddNo--;
			partialDiscovery=TRUE;
			g_message("Exting from available_cb_gw since mandatory paramters are not there  device no %u",deviceAddNo);
			return;
		    }
		    else
		    {
			g_message("Received XI Identity service");
		    }
		    if(!process_gw_services_media_config((GUPnPServiceProxy *)gwydata->sproxy_m, gwydata))
		    {
			free_gwydata(gwydata);
			g_free(gwydata);
			g_free(sno);
			deviceAddNo--;
			partialDiscovery=TRUE;
			g_message("Exting from available_cb_gw since mandatory paramters are not there  device no %u",deviceAddNo);
			return;
		    }
		    else
		    {
			g_message("Received XI Media Config service");
		    }
		    if(!process_gw_services_time_config((GUPnPServiceProxy *)gwydata->sproxy_t, gwydata))
		    {
			free_gwydata(gwydata);
			g_free(gwydata);
			g_free(sno);
			deviceAddNo--;
			partialDiscovery=TRUE;
			g_message("Exting from available_cb_gw since mandatory paramters are not there  device no %u",deviceAddNo);
			return;
		    }
		    else
		    {
			g_message("Received XI Time Config service");
		    }
		    if(!process_gw_services_gateway_config((GUPnPServiceProxy *)gwydata->sproxy_g, gwydata))
		    {
			free_gwydata(gwydata);
			g_free(gwydata);
			g_free(sno);
			deviceAddNo--;
			partialDiscovery=TRUE;
			g_message("Exting from available_cb_gw since mandatory paramters are not there  device no %u",deviceAddNo);
			return;
		    }
		    else
		    {
			g_message("Received XI Gateway Config service");
		    }
		    if(!process_gw_services_qam_config((GUPnPServiceProxy *)gwydata->sproxy_q, gwydata))
		    {
			free_gwydata(gwydata);
			g_free(gwydata);
			g_free(sno);
			deviceAddNo--;
			partialDiscovery=TRUE;
			g_message("Exting from available_cb_gw since mandatory paramters are not there  device no %u",deviceAddNo);
			return;
		    }
		    else
                    {
			g_message("Received XI QAM Config service");
                        gwydata->isDevRefactored = TRUE;
			if (update_gwylist(gwydata)==FALSE )
			{
			    g_message("Failed to update gw data into the list\n");
			    g_critical("Unable to update the gateway-%s in the device list",(char*)gwydata->serial_num);
			    return;
			}
		    }
		}
		else
		{
		    g_message("In available_cb_gw gateway device receiver id is NULL");
		}
	    }
	}
	else
	{
	    g_message("Gateway UDN is NULL");
	}
    }
    if(!strcasestr(g_strstrip(gwydata->devicetype->str),"XI") )
    {
       if (gupnp_service_proxy_add_notify ((GUPnPServiceProxy *)gwydata->sproxy_m, "PlaybackUrl", G_TYPE_STRING, on_last_change, NULL) == FALSE)
	   g_message("Failed to add url notifications for %s", sno);
       if (gupnp_service_proxy_add_notify ((GUPnPServiceProxy *)gwydata->sproxy_q, "SystemIds", G_TYPE_STRING, on_last_change, NULL) == FALSE)
	   g_message("Failed to add systemid notifications for %s", sno);
       if (gupnp_service_proxy_add_notify ((GUPnPServiceProxy *)gwydata->sproxy_g, "DnsConfig", G_TYPE_STRING, on_last_change, NULL) == FALSE)
	   g_message("Failed to add DNS notifications for %s", sno);
       if (gupnp_service_proxy_add_notify ((GUPnPServiceProxy *)gwydata->sproxy_t, "TimeZone", G_TYPE_STRING, on_last_change, NULL) == FALSE)
	   g_message("Failed to add TimeZone notifications for %s", sno);
       if (gupnp_service_proxy_add_notify ((GUPnPServiceProxy *)gwydata->sproxy_q, "VideoBaseUrl", G_TYPE_STRING, on_last_change, NULL) == FALSE)
	   g_message("Failed to add VideoBaseUrl notifications for %s", sno);
    }
    gupnp_service_proxy_set_subscribed((GUPnPServiceProxy *)gwydata->sproxy_m, TRUE);
    gupnp_service_proxy_set_subscribed((GUPnPServiceProxy *)gwydata->sproxy_t, TRUE);
    gupnp_service_proxy_set_subscribed((GUPnPServiceProxy *)gwydata->sproxy_g, TRUE);
    gupnp_service_proxy_set_subscribed((GUPnPServiceProxy *)gwydata->sproxy_q, TRUE);

    if (gupnp_service_proxy_add_notify ((GUPnPServiceProxy *)gwydata->sproxy_m, "FogTsbUrl", G_TYPE_STRING, on_last_change, NULL) == FALSE)
	   g_message("Failed to add FogTsbUrl notifications for %s", sno);

    if ((gupnp_service_proxy_get_subscribed((GUPnPServiceProxy *)gwydata->sproxy_m) == FALSE) && (gupnp_service_proxy_get_subscribed((GUPnPServiceProxy *)gwydata->sproxy_t) == FALSE) && (gupnp_service_proxy_get_subscribed((GUPnPServiceProxy *)gwydata->sproxy_g) == FALSE) && (gupnp_service_proxy_get_subscribed((GUPnPServiceProxy *)gwydata->sproxy_q) == FALSE))
    {
	g_message("Failed to register for notifications on %s", sno);
	g_object_unref(gwydata->sproxy_m);
	g_object_unref(gwydata->sproxy_t);
	g_object_unref(gwydata->sproxy_g);
	g_object_unref(gwydata->sproxy_q);
    }
    g_free(sno);
    deviceAddNo--;
    g_message("Discovered a XG device");
    g_message("Exting from device_proxy_available_cb_gateway deviceAddNo = %u",deviceAddNo);
}

static void
device_proxy_unavailable_cb_bgw (GUPnPControlPoint *cp, GUPnPDeviceProxy *dproxy)
{
    const gchar* sno = gupnp_device_info_get_serial_number (GUPNP_DEVICE_INFO (dproxy));
    g_message ("In unavailable_bgw Device %s went down",sno);
    if((g_strcmp0(g_strstrip(ownSerialNo->str),sno) == 0))
    {
        g_message ("Self Device [%s][%s] not removing",sno,ownSerialNo->str);
        g_free((gpointer)sno);
        return;
    }
    if (delete_gwyitem(sno) == FALSE)
    {
	g_message("%s found, but unable to delete it from list", sno);
	return;
    }
    else
    {
	g_message("Deleted %s from list", sno);
	sendDiscoveryResult(disConf->outputJsonFile);
    }
    g_free((gpointer)sno);
}

static void
device_proxy_available_cb_bgw (GUPnPControlPoint *cp, GUPnPDeviceProxy *dproxy)
{
    GList* xdevlistitem = NULL;
    g_message("In available_bgw found a Broadband device. deviceAddNo = %u ",deviceAddNo);
    deviceAddNo++;
    if ((NULL==cp) || (NULL==dproxy))
    {
	deviceAddNo--;
	g_message("WARNING - Received a null pointer for broadband device device no %u",deviceAddNo);
	return;
    }
    gchar* sno = gupnp_device_info_get_serial_number (GUPNP_DEVICE_INFO (dproxy));
    if(sno)
    {
        xdevlistitem = g_list_find_custom(xdevlist,sno,(GCompareFunc)g_list_find_sno);
    }
    if(xdevlistitem!=NULL)
    {
	deviceAddNo--;
	g_message("Existing available_cb_bgw as SNO is present in list so no update of devices %s device no %u",sno,deviceAddNo);
	g_free((gpointer)sno);
	return;
    }
    GwyDeviceData *gwydata = g_new(GwyDeviceData,1);
    init_gwydata(gwydata);
    gwydata->sproxy_i = gupnp_device_info_get_service(GUPNP_DEVICE_INFO (dproxy), XDISC_SERVICE_IDENTITY);
    gwydata->sproxy_t = gupnp_device_info_get_service(GUPNP_DEVICE_INFO (dproxy), XDISC_SERVICE_TIME);
    gwydata->sproxy_g = gupnp_device_info_get_service(GUPNP_DEVICE_INFO (dproxy), XDISC_SERVICE_GW_CFG);
    if (sno != NULL)
    {
        g_message("In available_cb_bgw Broadband device serial number: %s",sno);
        g_string_assign(gwydata->serial_num, sno);
        const char* udn = gupnp_device_info_get_udn(GUPNP_DEVICE_INFO (dproxy));
        if (udn != NULL)
        {
            if (g_strrstr(udn,"uuid:"))
            {
                gchar* receiverid = g_strndup(udn+5, strlen(udn)-5);
                if(receiverid)
                {
                    g_message("Gateway device receiver id is %s",receiverid);
                    g_string_assign(gwydata->receiverid, receiverid);
                    g_free(receiverid);
                    if(!process_gw_services_identity((GUPnPServiceProxy *)gwydata->sproxy_i, gwydata))
                    {
                        free_gwydata(gwydata);
                        g_free(gwydata);
                        g_free(sno);
                        deviceAddNo--;
                        g_message("Exting from available_cb_bgw since Identity paramters are not there  device no %u",deviceAddNo);
                        return;
                    }
                    else
                    {
                        g_message("Received XI Identity service");
                    }
                    if(!process_gw_services_time_config((GUPnPServiceProxy *)gwydata->sproxy_t, gwydata))
                    {
                        free_gwydata(gwydata);
                        g_free(gwydata);
                        g_free(sno);
                        deviceAddNo--;
                        g_message("Exting from available_cb_bgw since Time paramters are not there  device no %u",deviceAddNo);
                        return;
                    }
                    else
                    {
                        g_message("Received XI Time Config service");
                    }
                    if(!process_gw_services_gateway_config((GUPnPServiceProxy *)gwydata->sproxy_g, gwydata))
                    {
                        free_gwydata(gwydata);
                        g_free(gwydata);
                        g_free(sno);
                        deviceAddNo--;
                        g_message("Exting from available_cb_bgw since mandatory paramters are not there  device no %u",deviceAddNo);
                        return;
                    }
                    else
                    {
                        g_message("Received XI Gateway Config service");
                        gwydata->isDevRefactored = TRUE;
                        if (update_gwylist(gwydata)==FALSE )
                        {
                            g_message("Failed to update gw data into the list\n");
                            g_critical("Unable to update the gateway-%s in the device list",(char*)gwydata->serial_num);
                            return;
                        }
                    }
                }
                else
                {
                    g_message("In available_cb_bgw gateway device receiver id is NULL");
                }
            }
        }
        else
        {
            g_message("Gateway UDN is NULL");
        }
    }

    gupnp_service_proxy_set_subscribed((GUPnPServiceProxy *)gwydata->sproxy_i, TRUE);
    gupnp_service_proxy_set_subscribed((GUPnPServiceProxy *)gwydata->sproxy_t, TRUE);
    gupnp_service_proxy_set_subscribed((GUPnPServiceProxy *)gwydata->sproxy_g, TRUE);

    if ((gupnp_service_proxy_get_subscribed((GUPnPServiceProxy *)gwydata->sproxy_i) == FALSE) && (gupnp_service_proxy_get_subscribed((GUPnPServiceProxy *)gwydata->sproxy_t) == FALSE) && (gupnp_service_proxy_get_subscribed((GUPnPServiceProxy *)gwydata->sproxy_g) == FALSE))
    {
	    g_message("Failed to register for notifications on %s", sno);
	    g_object_unref(gwydata->sproxy_i);
	    g_object_unref(gwydata->sproxy_t);
	    g_object_unref(gwydata->sproxy_g);
    }
    g_free(sno);
    deviceAddNo--;
    g_message("Discovered a XB device");
    g_message("Exting from device_proxy_available_cb_broadband deviceAddNo = %u",deviceAddNo);
}

int main(int argc, char *argv[])
{
    //preamble
    g_thread_init (NULL);
    g_type_init();

    gboolean ipv6Enabled=FALSE;
    gboolean bInterfaceReady=FALSE;

    GError* error = 0;
    GTlsInteraction *xupnp_tlsinteraction= NULL;
    mutex = g_mutex_new ();
    devMutex = g_mutex_new ();
    cond = g_cond_new ();
    logoutfile = NULL;
    
#ifdef INCLUDE_BREAKPAD
    breakpad_ExceptionHandler();
#endif


    outputcontents = g_string_new(NULL);
    ipMode = g_string_new("ipv4");

    ownSerialNo=g_string_new(NULL);
    if (argc < 2)
    {
	fprintf(stderr, "Error in arguments\nUsage: %s config file name (eg: /etc/xdiscovery.conf) %s log file location \n", argv[0], argv[1]);
	exit(1);
    }

	//    outputfilename = g_string_assign(outputfilename, argv[2]);
	//    const char* ifname = argv[1];

    char* logfilename = argv[2];
    if(logfilename)
    {
	logoutfile = g_fopen (logfilename, "a");
    }
    /*else if (disConf->logFile)
    {
	logoutfile = g_fopen (disConf->logFile, "a");
    }*/
    else

    {
	g_message("xupnp not handling the logging");
    }
    if(logoutfile)
    {
	g_log_set_handler(G_LOG_DOMAIN, G_LOG_LEVEL_INFO | G_LOG_LEVEL_MESSAGE | \
			  G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_ERROR, xupnp_logger, NULL);
    }

    char* configfilename = argv[1];

    rfc_enabled = check_rfc();
    if(!rfc_enabled)
    {
	g_message("Running Older Xdiscovery");
    }

    if (readconffile(configfilename)==FALSE)
    {
	g_message("Unable to find xdevice config, Loading default settings ");
	//	      disConf->discIf = g_string_assign(disConf->discIf, "eth1");
	//	      disConf->gwIf = g_string_assign(disConf->gwIf, "eth1");
	//	      disConf->gwSetupFile = g_string_assign(disConf->gwSetupFile, "/lib/rdk/gwSetup.sh");
	//	      disConf->logFile = g_string_assign(disConf->logFile, "/opt/logs/xdiscovery.log");
	//	      disConf->outputJsonFile = g_string_assign(disConf->outputJsonFile, "/opt/output.json");
	//    	      disConf->GwPriority = 500
	//              disConf->enableGwSetup = false
	exit(1);
    }

    /* int result = getipaddress(disConf->discIf,ipaddress,ipv6Enabled);

    if (!result)
    {
	fprintf(stderr,"Could not locate the ipaddress of the discovery interface %s\n", disConf->discIf);
	g_critical("Could not locate the ipaddress of the discovery interface %s\n", disConf->discIf);
	exit(1);
    }
	else
		g_message("ipaddress of the interface %s\n", ipaddress);
    */
    gchar **tokens = g_strsplit_set(disConf->discIf,",", -1);
    guint toklength = g_strv_length(tokens);
    guint loopvar=0;
    for (loopvar=0; loopvar<toklength; loopvar++)
    {
	if ((strlen(g_strstrip(tokens[loopvar])) > 0))
	{
	    int result = getipaddress(g_strstrip(tokens[loopvar]),ipaddress,ipv6Enabled);
	    if (result)
	    {
		g_message(" \n ***Got Ip address for interface  = %s ipaddr = %s *****",g_strstrip(tokens[loopvar]),ipaddress);
		g_stpcpy(disConf->discIf,g_strstrip(tokens[loopvar]));
		g_stpcpy(disConf->gwIf,g_strstrip(tokens[loopvar]));
		bInterfaceReady=TRUE;
		break;
	    }
	    else
	    {
		guint retries=3;
		int ipaddr = 0;
		for (retries=3; retries>0; retries--) {
		    sleep(1); //sleep for every retries
		    ipaddr = getipaddress(g_strstrip(tokens[loopvar]),ipaddress,ipv6Enabled);
		    if (ipaddr) {
			g_message("\n **Got Ip address for interface = %s with retries = %d ipaddr = %s **",g_strstrip(tokens[loopvar]),retries,ipaddress);
			g_stpcpy(disConf->discIf,g_strstrip(tokens[loopvar]));
			g_stpcpy(disConf->gwIf,g_strstrip(tokens[loopvar]));
			bInterfaceReady=TRUE;
			break; //Exiting Inner for loop
		    }
		}
		if (!ipaddr) {
		    g_message("Could not locate the ipaddress of the broadcast interface %s continue with next ", g_strstrip(tokens[loopvar]));
		    bInterfaceReady=FALSE;
		}
		else
		    break; //Exiting outer for loop
	    }
	}
    }
    g_strfreev(tokens);
    if ( FALSE == bInterfaceReady)
    {

	fprintf(stderr,"Could not locate the ipaddress of the discovery interface %s\n", disConf->discIf);
	g_critical("Could not locate the ipaddress of the discovery interface %s\n", disConf->discIf);
	exit(1);
    }

    g_message("Starting xdiscovery service on interface %s", disConf->discIf);
    g_print("Starting xdiscovery service on interface %s\n", disConf->discIf);


    bcastmac = (gchar *)getmacaddress(disConf->discIf);
#ifndef GUPNP_1_2
    #ifdef GUPNP_0_14
         main_context = g_main_context_new();
         context = gupnp_context_new (main_context, disConf->discIf, host_port, &error);
    #else
         context = gupnp_context_new (NULL, disConf->discIf, host_port, &error);
    #endif
#else
        context = gupnp_context_new (disConf->discIf, host_port, &error);
#endif

    if (error) {
	g_message ("Error creating the GUPnP context: %s", error->message);
	g_critical("Error creating the XUPnP context on %s:%d Error:%s", disConf->discIf, host_port, error->message);
	g_error_free (error);
	return EXIT_FAILURE;
    }

#if defined(USE_XUPNP_IARM) || defined(USE_XUPNP_IARM_BUS)
    gboolean iarminit = XUPnP_IARM_Init();
    if (iarminit==true)
    {
	//g_print("IARM init success");
	g_message("XUPNP IARM init success");
    }
    else
    {
	//g_print("IARM init failure");
	g_critical("XUPNP IARM init failed");
    }
#endif

#ifdef GUPNP_GENERIC_MEDIA_RENDERER
    init_media_browser();
#endif //GUPNP_GENERIC_MEDIA_RENDERER

    //context = gupnp_context_new (main_context, host_ip, host_port, NULL);
    gupnp_context_set_subscription_timeout(context, 0);
    if(rfc_enabled)
    {
        //Get account Id of the control point.
        if (!getAccountId(accountId)) {
            g_message("Failed to retrieve AccountId of the control point");
        }
#ifndef BROADBAND
        if(xPKI_check_rfc() == 1)
        {
            cert_File= g_strdup ("/tmp/xpki_cert");
            key_File= g_strdup ("/tmp/xpki_key");
            g_message("Using xPKI certs for handshaking");
        }
#endif
#ifndef ENABLE_HW_CERT_USAGE
        if ( ( cert_File == NULL ) && (key_File == NULL )){
            if (g_path_is_absolute (disConf->disCertFile)) {
                cert_File= g_strdup (disConf->disCertFile);
            }
            else {
                 cert_File = g_build_filename (disConf->disCertPath, disConf->disCertFile, NULL);
            }
            if (g_path_is_absolute (disConf->disKeyFile)) {
                key_File= g_strdup (disConf->disKeyFile);
            }
            else {
                key_File = g_build_filename (disConf->disKeyPath, disConf->disKeyFile, NULL);
            }
        }
#else        
    if (g_path_is_absolute (disConf->disSeCertFile)) {

        g_message("Getting SE certificate from configuration");
        se_cert_pk12 = g_strdup (disConf->disSeCertFile);
    }

    if (g_path_is_absolute (disConf->disPassCodeFile)) {
        se_cert_conf_file = g_strdup (disConf->disPassCodeFile);
    }

    if (g_path_is_absolute (disConf->disSeCAFile)) {
        ca_File = g_strdup (disConf->disSeCAFile);
    }
    if(g_file_test(se_cert_pk12, G_FILE_TEST_EXISTS))
    {
        // form .p12 certificate
        char tmp[128] = { 0 }, *token = NULL;
        strncpy(tmp, se_cert_pk12, sizeof(tmp) - 1);
        token = strtok(tmp, ".");
        if(token != NULL)
        {
            strncpy(se_cert_p12, token , sizeof(se_cert_p12) - 1);
            strncat(se_cert_p12, ".p12", sizeof(se_cert_p12) -1);
        }
        g_message("Forming p12 certificate...");
        v_secure_system("ln -sf %s %s",se_cert_pk12, se_cert_p12);
    }
    else
    {
	g_message("SE HW certificate is not accessible. Using cert file %s", cert_File);
        // use extracted cert ,key, and CA files
        if ( ( cert_File == NULL ) && (key_File == NULL )){
            if (g_path_is_absolute (disConf->disCertFile)) {
                cert_File= g_strdup (disConf->disCertFile);
            }
            else {
                cert_File = g_build_filename (disConf->disCertPath, disConf->disCertFile, NULL);
            }
            if (g_path_is_absolute (disConf->disKeyFile)) {
                key_File= g_strdup (disConf->disKeyFile);
            }
            else {
                key_File = g_build_filename (disConf->disKeyPath, disConf->disKeyFile, NULL);
            }
        }
        if(ca_File) {
            g_free(ca_File);
            ca_File  = NULL;
        }
        ca_File = "/tmp/UPnP_CA";
    }
#endif

#ifndef ENABLE_HW_CERT_USAGE
        if (((cert_File != NULL) && (key_File !=NULL)) && ((g_file_test(cert_File, G_FILE_TEST_EXISTS)) && (g_file_test(key_File, G_FILE_TEST_EXISTS)) 
                    && (g_file_test(ca_File, G_FILE_TEST_EXISTS)))) 
        {
#else
    if (((g_file_test(se_cert_p12, G_FILE_TEST_EXISTS)) || (((cert_File != NULL) && (key_File !=NULL) 
                    && (g_file_test(cert_File, G_FILE_TEST_EXISTS)) && (g_file_test(key_File, G_FILE_TEST_EXISTS))))) 
                    && (g_file_test(ca_File, G_FILE_TEST_EXISTS)) )
    {
#endif 

#ifndef GUPNP_1_2
#ifndef ENABLE_HW_CERT_USAGE
            upnpContextDeviceProtect = gupnp_context_new_s ( NULL,  disConf->discIf, DEVICE_PROTECTION_CONTEXT_PORT, cert_File, key_File, &error);
#else
            if(access(se_cert_p12, F_OK) == 0)
            {
                 g_message("SE HW certificate is available. Creating device protect without extracted files");
                upnpContextDeviceProtect = gupnp_context_new_s ( NULL,  disConf->discIf, DEVICE_PROTECTION_CONTEXT_PORT, NULL, NULL, &error);
            }
            else
            {
                g_message("SE HW certificate is not available. Creating device protect with extracted files");
                upnpContextDeviceProtect = gupnp_context_new_s ( NULL,  disConf->discIf, DEVICE_PROTECTION_CONTEXT_PORT, cert_File, key_File, &error);
            }
#endif
#else
#ifndef ENABLE_HW_CERT_USAGE
            upnpContextDeviceProtect = gupnp_context_new_s ( disConf->discIf, DEVICE_PROTECTION_CONTEXT_PORT, cert_File, key_File, &error);
#else
            if(access(se_cert_p12, F_OK) == 0)
            {
                 g_message("SE HW certificate is available. Creating device protect without extracted files");
                upnpContextDeviceProtect = gupnp_context_new_s ( disConf->discIf, DEVICE_PROTECTION_CONTEXT_PORT, NULL, NULL, &error);
            }
            else
            {
                g_message("SE HW certificate is not available. Creating device protect with extracted files");
                upnpContextDeviceProtect = gupnp_context_new_s ( disConf->discIf, DEVICE_PROTECTION_CONTEXT_PORT, cert_File, key_File, &error);
            }
#endif
#endif
            if (error) {
                g_printerr ("Error creating the Device Protection Broadcast context: %s\n",
                        error->message);
                /* g_clear_error() frees the GError *error memory and reset pointer if set in above operation */
                g_clear_error(&error);
                rfc_enabled = 0;
            }
            else {

#ifdef BROADBAND
                int ret = 0;
                //initialize the device protection white list
                g_message("calling dp whitelistInit ");
                ret = dp_wlistInit();
                if (!ret) {
                    g_message("initialization of dp whitelist successful ");
                }
#endif

                gupnp_context_set_subscription_timeout(upnpContextDeviceProtect, 0);
                xupnp_tlsinteraction = g_object_new (xupnp_tls_interaction_get_type (), NULL);
                g_message("tls interaction object created");
                // Set TLS config params here.
                g_message("Setting CA file %s", ca_File);
                gupnp_context_set_tls_params(upnpContextDeviceProtect,ca_File,NULL, xupnp_tlsinteraction);

                cp_client = gupnp_control_point_new(upnpContextDeviceProtect, "urn:schemas-upnp-org:device:X1Renderer:1");
                g_signal_connect (cp_client,"device-proxy-available", G_CALLBACK (device_proxy_available_cb_client), NULL);
                g_signal_connect (cp_client,"device-proxy-unavailable", G_CALLBACK (device_proxy_unavailable_cb_client), NULL);
                gssdp_resource_browser_set_active (GSSDP_RESOURCE_BROWSER (cp_client), TRUE);
                g_message("X1Renderer controlpoint created");

                cp_gw = gupnp_control_point_new(upnpContextDeviceProtect, "urn:schemas-upnp-org:device:X1VideoGateway:1");
                g_signal_connect (cp_gw,"device-proxy-available", G_CALLBACK (device_proxy_available_cb_gw), NULL);
                g_signal_connect (cp_gw,"device-proxy-unavailable", G_CALLBACK (device_proxy_unavailable_cb_gw), NULL);
                gssdp_resource_browser_set_active (GSSDP_RESOURCE_BROWSER (cp_gw), TRUE);
                g_message("X1VideoGateway controlpoint created");

                cp_bgw = gupnp_control_point_new(upnpContextDeviceProtect, "urn:schemas-upnp-org:device:X1BroadbandGateway:1");
                g_signal_connect (cp_bgw,"device-proxy-available", G_CALLBACK (device_proxy_available_cb_bgw), NULL);
                g_signal_connect (cp_bgw,"device-proxy-unavailable", G_CALLBACK (device_proxy_unavailable_cb_bgw), NULL);
                gssdp_resource_browser_set_active (GSSDP_RESOURCE_BROWSER (cp_bgw), TRUE);
                g_message("X1BroadbandGateway controlpoint created");
            }
        }
        else {
            g_message("DeviceProtection Error: check Cert File or Key  File or  CA file not existing");
            rfc_enabled = 0;
        }
    }

    cp = gupnp_control_point_new(context, "urn:schemas-upnp-org:device:BasicDevice:1");
    g_signal_connect (cp,"device-proxy-available", G_CALLBACK (device_proxy_available_cb), NULL);
    g_signal_connect (cp,"device-proxy-unavailable", G_CALLBACK (device_proxy_unavailable_cb), NULL);
    gssdp_resource_browser_set_active (GSSDP_RESOURCE_BROWSER (cp), TRUE);

#ifdef GUPNP_GENERIC_MEDIA_RENDERER
    registerBrowserConfig(context);
#endif //GUPNP_GENERIC_MEDIA_RENDERER

#ifdef LOGMILESTONE
    logMilestone("UPNP_START_DISCOVERY");
#else
    g_message("UPNP_START_DISCOVERY");
#endif

#ifdef GUPNP_0_19
    main_loop = g_main_loop_new (NULL, FALSE);
#else
    main_loop = g_main_loop_new (main_context, FALSE);
#endif
    if(!bSerialNum)
        getserialnum(ownSerialNo);

    g_thread_create(verify_devices, NULL,FALSE, NULL);
    g_message("Started discovery on interface %s", disConf->discIf);
    g_main_loop_run (main_loop);
    g_main_loop_unref (main_loop);
    g_object_unref (cp);
    if(rfc_enabled)
    {
	g_object_unref (cp_client);
	g_object_unref (cp_gw);
	g_object_unref (cp_bgw);
	g_object_unref (upnpContextDeviceProtect);
	g_object_unref (xupnp_tlsinteraction);

    }
#ifdef GUPNP_GENERIC_MEDIA_RENDERER
    close_media_browser();
#endif //GUPNP_GENERIC_MEDIA_RENDERER

    if (cert_File != NULL) {
       g_free(cert_File);
    }
    if (key_File != NULL) {
       g_free(key_File);
    }
#ifdef ENABLE_HW_CERT_USAGE
    if(se_cert_pk12) {
        g_free(se_cert_pk12);
    }
    if(se_cert_conf_file) {
        g_free(se_cert_conf_file);
    }
    if(ca_File) {
        g_free(ca_File);
    }
#endif
    g_object_unref (context);
    if(logoutfile)
    {
	fclose (logoutfile);
    }
    return 0;
}
/**
 * @brief This function is used to retrieve a boolean parameter from discovered data.
 * Use this function only when there are no parameters passed to the action call
 *
 * @param[in] sproxy The Service proxy object
 * @param[in] requestFn The required parameter to be retrieved
 * @param[in] responseFn The function to retrieve requried function
 * @param[out] result the result to be stored.
 * @param[in] isInCriticalPath if true, a log message will be printed for telemetry
 * @return Returns TRUE if the gateway service requests processed successfully else returns FALSE.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */

gboolean processBooleanRequest(const GUPnPServiceProxy *sproxy ,const char * requestFn, 
		const char * responseFn,gboolean * result, gboolean isInCriticalPath)
{
    GError *error = NULL;
    
#ifdef GUPNP_1_2
    GUPnPServiceProxyAction *action;
    action = gupnp_service_proxy_action_new (requestFn, NULL);
    gupnp_service_proxy_call_action ((GUPnPServiceProxy *)sproxy, action, NULL, &error);

    if( NULL == error )
    {
        gupnp_service_proxy_action_get_result (action,
                                               &error, responseFn, G_TYPE_BOOLEAN, result, NULL);
        g_clear_pointer (&action, gupnp_service_proxy_action_unref);

    }
#else
    gupnp_service_proxy_send_action ((GUPnPServiceProxy *)sproxy, requestFn, &error, NULL, responseFn, G_TYPE_BOOLEAN, result ,NULL);
#endif
    if ( NULL != error ) //Didn't went well
    {
        g_message ("%s  process gw services  Error: %s\n", requestFn, error->message);
	if ( isInCriticalPath ) // Update telemetry
	{
        	g_message("TELEMETRY_XUPNP_PARTIAL_DISCOVERY:%d,%s",error->code, requestFn);
	}
        g_clear_error(&error);
        return FALSE;
    }
    return TRUE;
}

/**
 * @brief This function is used to retrieve a string parameter from discovered data.
 * Use this function only when there are no parameters passed to the action call
 *
 * @param[in] sproxy The Service proxy object
 * @param[in] requestFn The required parameter to be retrieved
 * @param[in] responseFn The function to retrieve requried function
 * @param[out] result the result to be stored.
 * @param[in] isInCriticalPath if true, a log message will be printed for telemetry
 * @return Returns TRUE if the gateway service requests processed successfully else returns FALSE.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
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
        g_message ("%s  process gw services  Error: %s\n", requestFn, error->message);
	if ( isInCriticalPath ) // Update telemetry
	{
        	g_message("TELEMETRY_XUPNP_PARTIAL_DISCOVERY:%d,%s",error->code, requestFn);
	}
        g_clear_error(&error);
        return FALSE;
    }
    return TRUE;
}

/**
 * @brief This function is used to retrieve a int parameter from discovered data.
 * Use this function only when there are no parameters passed to the action call
 *
 * @param[in] sproxy The Service proxy object
 * @param[in] requestFn The required parameter to be retrieved
 * @param[in] responseFn The function to retrieve requried function
 * @param[out] result the result to be stored.
 * @param[in] isInCriticalPath if true, a log message will be printed for telemetry
 * @return Returns TRUE if the gateway service requests processed successfully else returns FALSE.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
gboolean processIntRequest(const GUPnPServiceProxy *sproxy ,const char * requestFn, 
		const char * responseFn,guint * result, gboolean isInCriticalPath)
{
    GError *error = NULL;
    
#ifdef GUPNP_1_2
    GUPnPServiceProxyAction *action;
    action = gupnp_service_proxy_action_new (requestFn, NULL);
    gupnp_service_proxy_call_action ((GUPnPServiceProxy *)sproxy, action, NULL, &error);

    if( NULL == error )
    {
        gupnp_service_proxy_action_get_result (action,
                                               &error, responseFn, G_TYPE_INT, result, NULL);
        g_clear_pointer (&action, gupnp_service_proxy_action_unref);

    }
#else
    gupnp_service_proxy_send_action ((GUPnPServiceProxy *)sproxy, requestFn , &error,NULL, responseFn, G_TYPE_INT, result ,NULL);
#endif
    if ( NULL != error ) //Didn't went well
    {
        g_message ("%s  process gw services  Error: %s\n", requestFn, error->message);
	if ( isInCriticalPath ) // Update telemetry
	{
        	g_message("TELEMETRY_XUPNP_PARTIAL_DISCOVERY:%d,%s",error->code, requestFn);
	}
        g_clear_error(&error);
        return FALSE;
    }
    return TRUE;
}

/**
 * @brief This function is used to get attributes of different Gateway services using GUPnP Service Proxy.
 *
 * GUPnP Service Proxy sends commands to a remote UPnP service and handles incoming event notifications.
 * It will request the proxy to get services and attributes such as:
 * - Base TRM URL.
 * - Playback URL.
 * - Gateway IP.
 * - DNS Configuration.
 * - Device Type.
 * - Time Zone.
 * - DST (Daylight Saving Time).
 * - MAC Address.
 * - System ID and so on.
 *
 * @param[in] sproxy Address of the GUPnP Service Proxy instance.
 * @param[in] gwData Address of the Structure holding gateway service attributes.
 *
 * @return Returns TRUE if the gateway service requests processed successfully else returns FALSE.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
gboolean process_gw_services(GUPnPServiceProxy *sproxy, GwyDeviceData* gwData)
{
    /* Does not look elegant, but call all the actions one after one - Seems like
     UPnP service proxy does not provide a way to call all the actions in a list
    */
    GError *error = NULL;
    gchar *temp=NULL;
    guint temp_i=0;
    gboolean temp_b=FALSE;
    
  /* Coverity Fix CID: 21875 REVERSE_INULL */
    if(gwData == NULL)
      return FALSE;

    g_message("Entering into process_gw_services ");

#ifdef GUPNP_1_2    
    GUPnPServiceProxyAction * action = gupnp_service_proxy_action_new ("GetIsGateway", "deviceProtection", G_TYPE_BOOLEAN, FALSE, "macAddr", G_TYPE_STRING, bcastmac, "ipAddr",G_TYPE_STRING, ipaddress,NULL);
    gupnp_service_proxy_call_action (sproxy, action, NULL, &error);
    if (error == NULL)
    {
        gupnp_service_proxy_action_get_result (action,
                                               &error, "IsGateway", G_TYPE_BOOLEAN, &temp_b, NULL);
        g_clear_pointer (&action, gupnp_service_proxy_action_unref);       
    }
#else
    gupnp_service_proxy_send_action (sproxy, "GetIsGateway", &error,"deviceProtection", G_TYPE_BOOLEAN, FALSE, "macAddr", G_TYPE_STRING, bcastmac, "ipAddr",G_TYPE_STRING, ipaddress,NULL,"IsGateway", G_TYPE_BOOLEAN, &temp_b ,NULL);
#endif
    if (error!=NULL)
    {
       g_message ("GetIsGateway process gw services  Error: %s", error->message);
       g_message("TELEMETRY_XUPNP_PARTIAL_DISCOVERY:%d,IsGateway",error->code);
       g_clear_error(&error);
       return FALSE;  
    }    
    else
    {
       gwData->isgateway = (gboolean)temp_b;
    }
    if ( processStringRequest(sproxy, "GetRecvDevType", "RecvDevType" , &temp, FALSE))
    {
	g_string_assign(gwData->recvdevtype,temp);
	g_free(temp);
    }

    if ( processStringRequest(sproxy, "GetBuildVersion", "BuildVersion" , &temp, FALSE))
    {
	g_string_assign(gwData->buildversion,temp);
	g_free(temp);
    }

    if ( processStringRequest(sproxy, "GetDeviceName", "DeviceName" , &temp, FALSE))
    {
	g_string_assign(gwData->devicename,temp);
	g_free(temp);
    }

    if ( processStringRequest(sproxy, "GetDeviceType", "DeviceType" , &temp, FALSE))
    {
	g_string_assign(gwData->devicetype,temp);
	g_free(temp);
    }

    if (! processStringRequest(sproxy, "GetBcastMacAddress", "BcastMacAddress" , &temp, TRUE))
    {
	return FALSE;
    }
    else
    {    
        g_string_assign(gwData->bcastmacaddress,temp);
        g_free(temp);
    }

    if(!strcasestr(g_strstrip(gwData->devicetype->str),"XI") )
    {
	if (! processStringRequest(sproxy, "GetBaseUrl", "BaseUrl" , &temp, TRUE))
	{
	    return FALSE;
	}
	else
	{
	    g_string_assign(gwData->baseurl,temp);
	    g_free(temp);
	}

        if (! processStringRequest(sproxy, "GetBaseTrmUrl", "BaseTrmUrl" , &temp, TRUE))
        {
	    return FALSE;
        }
	else
	{
	    g_string_assign(gwData->basetrmurl,temp);
	    g_free(temp);
	}
     //Do not return error as the boxes which are not running single step tuning code base could still exist in the network
        if ( processStringRequest(sproxy, "GetGatewayIP", "GatewayIP" , &temp, FALSE))
        {
	    g_string_assign(gwData->gwyip,temp);
	    g_free(temp);
	}
 
        if ( processStringRequest(sproxy, "GetClientIP", "ClientIP" , &temp, FALSE))
        {
            g_string_assign(gwData->clientip,temp);
            g_free(temp);
        }

        if ( processStringRequest(sproxy, "GetGatewayIPv6", "GatewayIPv6" , &temp, FALSE))
        {
	    g_string_assign(gwData->gwyipv6,temp);
	    g_free(temp);
	}

        if ( processStringRequest(sproxy, "GetGatewayStbIP", "GatewayStbIP" , &temp, FALSE))
        {
	    g_string_assign(gwData->gatewaystbip,temp);
	    g_free(temp);
	}
        if ( processStringRequest(sproxy, "GetIpv6Prefix", "Ipv6Prefix" , &temp, FALSE))
        {
	    g_string_assign(gwData->ipv6prefix,temp);
	    g_free(temp);
#ifdef LOGMILESTONE
	    if (gwData && gwData->ipv6prefix && gwData->ipv6prefix->str && (g_strcmp0(gwData->ipv6prefix->str, "") != 0))
	    {
		logMilestone("UPNP_RECV_IPV6_PREFIX");
	    }
#else
	    g_message("UPNP_RECV_IPV6_PREFIX");
#endif
	}

        if ( processStringRequest(sproxy, "GetDnsConfig", "DnsConfig" , &temp, FALSE))
        {
	    g_string_assign(gwData->dnsconfig,temp);
	    g_free(temp);
	}
	if ( processStringRequest(sproxy,"GetPlaybackUrl","PlaybackUrl", &temp, TRUE))
        {
	    g_string_assign(gwData->playbackurl,temp);
	    g_free(temp);
        }
        else
        {
	    return FALSE;
        }
	g_message("GetPlaybackUrl = %s",gwData->playbackurl->str);

        if ( processStringRequest(sproxy, "GetSystemIds", "SystemIds" , &temp, FALSE))
        {
	    g_string_assign(gwData->systemids,temp);
	    g_free(temp);
	}

        if ( processStringRequest(sproxy, "GetTimeZone", "TimeZone" , &temp, FALSE))
        {
	    g_string_assign(gwData->dsgtimezone,temp);
	    g_free(temp);
	}

        if ( processStringRequest(sproxy, "GetHosts", "Hosts" , &temp, FALSE))
        {
	    g_string_assign(gwData->etchosts,temp);
	    g_free(temp);
	}

        if ( !processBooleanRequest(sproxy, "GetRequiresTRM", "RequiresTRM" , &temp_b, TRUE))
        {
            return FALSE;
        }
        else
        {
	    gwData->requirestrm = (gboolean)temp_b;
	}

        if ( processStringRequest(sproxy, "GetHostMacAddress", "HostMacAddress" , &temp, FALSE))
        {
	    g_string_assign(gwData->hostmacaddress,temp);
	    g_free(temp);
	}

        if ( processIntRequest( sproxy, "GetRawOffSet", "RawOffSet" , &temp_i, FALSE))
        {
	    gwData->rawoffset = (gint)temp_i;
	}

        if ( processIntRequest( sproxy, "GetDSTSavings", "DSTSavings" , &temp_i, FALSE))
        {
	    gwData->dstsavings = (gint)temp_i;
	}

        if ( processBooleanRequest( sproxy, "GetUsesDaylightTime", "UsesDaylightTime" , &temp_b, FALSE))
        {
	    gwData->usesdaylighttime = (gboolean)temp_b;
	}

        if ( processIntRequest( sproxy, "GetDSTOffset", "DSTOffset" , &temp_i, FALSE))
        {
	    gwData->dstoffset = (gint)temp_i;
	}
    } // If discovered device is XG1 or RNG device 
    else
    {
        g_message("Discovered a Xi device ");

        if ( processStringRequest(sproxy, "GetDataGatewayIPaddress", "DataGatewayIPaddress" , &temp, FALSE))
        {
	    g_string_assign(gwData->dataGatewayIPaddress,temp);
	    g_free(temp);
	}
	g_message("GetDataGatewayIPaddress = %s",gwData->dataGatewayIPaddress->str);
    }
#ifndef CLIENT_XCAL_SERVER

    //if ((gwData->isgateway == TRUE) && (gwData->isOwnGateway == FALSE))
    if (gwData->isOwnGateway == FALSE)
    {
#if !defined (NO_MOCA_FEATURE_SUPPORT)
        if (replace_local_device_ip(gwData) == TRUE)
        {
            g_message("Replaced MocaIP for %s with localhost", gwData->serial_num->str);
        }
#endif
    }
#endif
    gwData->devFoundFlag = TRUE;
    gwData->isDevRefactored = FALSE;
    if (update_gwylist(gwData)==FALSE )
    {
        g_message("Failed to update gw data into the list");
        /*Coverity Fix CID: 28232 PRINTF_ARGS_MISMATCH */
        g_critical("Unable to update the gateway-%s in the device list",gwData->serial_num->str);
        return FALSE;
    }
    g_message("Exiting from process_gw_services ");
    return TRUE;
}

gboolean process_gw_services_identity(GUPnPServiceProxy *sproxy, GwyDeviceData* gwData)
{
    /* Does not look elegant, but call all the actions one after one - Seems like
     UPnP service proxy does not provide a way to call all the actions in a list
    */
    GError *error = NULL;
    gchar *temp=NULL;

    g_message("Entering into process_gw_services_identity ");
/*
  DELIA-47613 : Need to use direct calls whenever there is an input parameter(s) to the service proxy call
*/
#ifdef GUPNP_1_2
    GUPnPServiceProxyAction * action = gupnp_service_proxy_action_new ("GetAccountId", "SAccountId", G_TYPE_STRING, accountId, "macAddr", G_TYPE_STRING, bcastmac, "ipAddr",G_TYPE_STRING, ipaddress, NULL);
    gupnp_service_proxy_call_action (sproxy, action, NULL, &error);
    if (error == NULL)
    {
        gupnp_service_proxy_action_get_result (action,
                                               &error, "GAccountId", G_TYPE_STRING, &temp, NULL);
        g_clear_pointer (&action, gupnp_service_proxy_action_unref);
    }
#else
     gupnp_service_proxy_send_action (sproxy, "GetAccountId", &error,"SAccountId", G_TYPE_STRING, accountId, "macAddr", G_TYPE_STRING, bcastmac, "ipAddr",G_TYPE_STRING, ipaddress, NULL, "GAccountId", G_TYPE_STRING, &temp, NULL);
#endif
    if (error!=NULL)
    {
       g_message ("GetAccountId process gw Identity services Error: %s", error->message);
       g_clear_error(&error);
    }
    else
    {
      g_message ("Received account id: %s", temp);
      g_string_assign(gwData->accountid, temp);
      g_free(temp);
    }

    if ( processStringRequest(sproxy, "GetRecvDevType", "RecvDevType" , &temp, FALSE))
    {
        g_string_assign(gwData->recvdevtype, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetBuildVersion", "BuildVersion" , &temp, FALSE))
    {
        g_string_assign(gwData->buildversion, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetDeviceName", "DeviceName" , &temp, FALSE))
    {
        g_string_assign(gwData->devicename, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetDeviceType", "DeviceType" , &temp, FALSE))
    {
        g_string_assign(gwData->devicetype, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetModelClass", "ModelClass" , &temp, FALSE))
    {
        g_string_assign(gwData->modelclass, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetModelNumber", "ModelNumber" , &temp, FALSE))
    {
        g_string_assign(gwData->modelnumber, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetDeviceId", "DeviceId" , &temp, FALSE))
    {
        g_string_assign(gwData->deviceid, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetHardwareRevision", "HardwareRevision" , &temp, FALSE))
    {
        g_string_assign(gwData->hardwarerevision, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetSoftwareRevision", "SoftwareRevision" , &temp, FALSE))
    {
        g_string_assign(gwData->softwarerevision, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetManagementUrl", "ManagementURL" , &temp, FALSE))
    {
        g_string_assign(gwData->managementurl, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetMake", "Make" , &temp, FALSE))
    {
        g_string_assign(gwData->make, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetReceiverId", "ReceiverId" , &temp, FALSE))
    {
        g_string_assign(gwData->receiverid, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetClientIP", "ClientIP" , &temp, FALSE))
    {
        g_string_assign(gwData->clientip, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetBcastMacAddress", "BcastMacAddress" , &temp, FALSE))
    {
        g_string_assign(gwData->bcastmacaddress, temp);
        g_free(temp);
    }

    g_message("Exiting from process_gw_services_identity ");
    return TRUE;
}


gboolean process_gw_services_media_config(GUPnPServiceProxy *sproxy, GwyDeviceData* gwData)
{
    /* Does not look elegant, but call all the actions one after one - Seems like
     UPnP service proxy does not provide a way to call all the actions in a list
    */
    gchar *temp=NULL;

    g_message("Entering into process_gw services_media_config ");
    if ( processStringRequest(sproxy, "GetPlaybackUrl", "PlaybackUrl" , &temp, FALSE))
    {
        g_string_assign(gwData->playbackurl, temp);
        g_free(temp);
    }
/*    GError *error = NULL;
      gupnp_service_proxy_send_action (sproxy, "GetFogTsbUrl",&error,NULL,"FogTsbUrl",G_TYPE_STRING, gwData->fogtsburl ,NULL);
    if (error!=NULL)
    {
        g_message (" GetFogTsbUrl process gw services Error: %s\n", error->message);
        g_clear_error(&error);
    }*/
    g_message("Exiting from process_gw_services_media_config ");
    return TRUE;
}

gboolean process_gw_services_gateway_config(GUPnPServiceProxy *sproxy, GwyDeviceData* gwData)
{
    /* Does not look elegant, but call all the actions one after one - Seems like
     UPnP service proxy does not provide a way to call all the actions in a list
    */
    GError *error = NULL;
    gchar *temp=NULL;
    gboolean temp_b=FALSE;

    g_message("Entering into process_gw_services_gateway_config ");
    if ( processStringRequest(sproxy, "GetDataGatewayIPaddress", "DataGatewayIPaddress" , &temp, FALSE))
    {
        g_string_assign(gwData->dataGatewayIPaddress, temp);
        g_free(temp);
    }
    
    if ( processStringRequest(sproxy, "GetGatewayStbIP", "GatewayStbIP" , &temp, FALSE))
    {
        g_string_assign(gwData->gatewaystbip, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetIpv6Prefix", "Ipv6Prefix" , &temp, FALSE ))
    {
        g_string_assign(gwData->ipv6prefix, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetDnsConfig", "DnsConfig" , &temp, FALSE))
    {
        g_string_assign(gwData->dnsconfig, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetDeviceName", "DeviceName" , &temp, FALSE))
    {
        g_string_assign(gwData->devicename, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetBcastMacAddress", "BcastMacAddress" , &temp, FALSE))
    {
	    g_string_assign(gwData->bcastmacaddress,temp);
	    g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetGatewayIPv6", "GatewayIPv6" , &temp, FALSE))
    {
        g_string_assign(gwData->gwyipv6, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetGatewayIP", "GatewayIP" , &temp, FALSE))
    {
        g_string_assign(gwData->gwyip, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetHostMacAddress", "HostMacAddress" , &temp, FALSE))
    {
        g_string_assign(gwData->hostmacaddress, temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetHosts", "Hosts" , &temp, FALSE))
    {
        g_string_assign(gwData->etchosts, temp);
        g_free(temp);
    }
#ifdef GUPNP_1_2    
    GUPnPServiceProxyAction * action = gupnp_service_proxy_action_new ("GetIsGateway", "deviceProtection", G_TYPE_BOOLEAN,TRUE, NULL);
    gupnp_service_proxy_call_action (sproxy, action, NULL, &error);
    if (error == NULL)
    {
        gupnp_service_proxy_action_get_result (action,
                                               &error, "IsGateway", G_TYPE_BOOLEAN, &temp_b, NULL);
        g_clear_pointer (&action, gupnp_service_proxy_action_unref);
    }

#else
    gupnp_service_proxy_send_action (sproxy, "GetIsGateway", &error, "deviceProtection", G_TYPE_BOOLEAN, TRUE, NULL,"IsGateway", G_TYPE_BOOLEAN, &temp_b ,NULL);
#endif    
    if (error!=NULL)
    {
        g_message ("GetIsGateway process gw services  Error: %s", error->message);
        g_message("TELEMETRY_XUPNP_PARTIAL_DISCOVERY:%d,IsGateway",error->code);
        g_clear_error(&error);
        return FALSE;
    }
    else
    {
        gwData->isgateway = (gboolean)temp_b;
    }

    if ( processStringRequest(sproxy, "GetIPSubNet", "IPSubNet" , &temp, FALSE))
    {
        g_string_assign(gwData->ipSubNet, temp);
        if(temp && strlen(temp))
#if !defined (NO_MOCA_FEATURE_SUPPORT)
            addRouteToMocaBridge(temp);
#endif
        g_free(temp);
    }

    g_message("Exiting from process_gw_services_gateway_config ");
    return TRUE;
}


gboolean process_gw_services_time_config(GUPnPServiceProxy *sproxy, GwyDeviceData* gwData)
{
    /* Does not look elegant, but call all the actions one after one - Seems like
     UPnP service proxy does not provide a way to call all the actions in a list
    */
    gchar *temp=NULL;
    guint temp_i=0;
    gboolean temp_b=FALSE;

    g_message("Entering into process_gw_services_time_config ");
    if ( processStringRequest(sproxy, "GetTimeZone", "TimeZone" , &temp, FALSE))
    {
        g_string_assign(gwData->dsgtimezone, temp);
        g_free(temp);
    }
    if ( processIntRequest( sproxy, "GetRawOffSet", "RawOffSet" , &temp_i, FALSE))
    {
        gwData->rawoffset = (gint)temp_i;
    }
    if ( processIntRequest( sproxy, "GetDSTSavings", "DSTSavings" , &temp_i, FALSE))
    {
        gwData->dstsavings = (gint)temp_i;
    }
    if ( processBooleanRequest( sproxy, "GetUsesDaylightTime", "UsesDaylightTime" , &temp_b, FALSE ))
    {
        gwData->usesdaylighttime = (gboolean)temp_b;
    }
    if ( processIntRequest( sproxy, "GetDSTOffset", "DSTOffset" , &temp_i, FALSE))
    {
        gwData->dstoffset = (gint)temp_i;
    }
    g_message("Exiting from process_gw_services_time_config ");
    return TRUE;
}

gboolean process_gw_services_qam_config(GUPnPServiceProxy *sproxy, GwyDeviceData* gwData)
{
    /* Does not look elegant, but call all the actions one after one - Seems like
     UPnP service proxy does not provide a way to call all the actions in a list
    */
    gchar *temp=NULL;
    gboolean temp_b=FALSE;

    g_message("Entering into process_gw_services_qam_config ");

    //Do not return error as the boxes which are not running trm supported code base could still exist in the network
    if ( processStringRequest(sproxy, "GetBaseTrmUrl", "BaseTrmUrl" , &temp, FALSE))
    {
        g_string_assign(gwData->basetrmurl , temp);
        g_free(temp);
    }
    if ( processStringRequest(sproxy, "GetSystemIds", "SystemIds" , &temp, FALSE ))
    {
        g_string_assign(gwData->systemids , temp);
        g_free(temp);
    }
    if ( processBooleanRequest(sproxy, "GetRequiresTRM", "RequiresTRM" , &temp_b, TRUE))
    {
        gwData->requirestrm = (gboolean)temp_b;
    }
/*    GError *error = NULL;
      gupnp_service_proxy_send_action (sproxy, "GetVideoBaseUrl", &error,NULL,"VideoBaseUrl",G_TYPE_STRING, gwData->videobaseurl,NULL);
    if (error!=NULL)
    {
        g_message (" GetVideoBaseUrl process gw services Error: %s\n", error->message);
        g_clear_error(&error);
    }*/
#ifndef CLIENT_XCAL_SERVER
    if (gwData->isOwnGateway == FALSE)
    {
#if !defined (NO_MOCA_FEATURE_SUPPORT)
        if (replace_local_device_ip(gwData) == TRUE)
        {
            g_message("Replaced MocaIP for %s with localhost", gwData->serial_num->str);
        }
#endif
    }
#endif
    g_message("Exiting from process_gw_services_qam_config ");
    return TRUE;
}

/**
 * @brief Replace IP Address part of the Gateway URL attributes from home networking IP with the local host IP.
 * It Replaces the URL attribute of playbackurl, baseurl, basetrmurl.
 *
 * @param[in] gwyData Address of the structure holding Gateway attributes.
 *
 * @return Returns TRUE indicating the call has finished.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
gboolean replace_hn_with_local(GwyDeviceData* gwyData)
{
   /*Coverity Fix CID:29376 RESOURCE_LEAK */
    char * tempStr = NULL;
     
    //g_print("replace: %s with %s\n", gwyData->gwyip->str, localHostIP);
    tempStr = replace_string(gwyData->playbackurl->str, gwyData->gwyip->str, (char *)localHostIP);
    g_string_assign(gwyData->playbackurl, tempStr);
    free(tempStr);
    
   
    tempStr =  replace_string(gwyData->baseurl->str, gwyData->gwyip->str, (char *)localHostIP);  
    g_string_assign(gwyData->baseurl,tempStr);
    free(tempStr);
    
  
    tempStr = replace_string(gwyData->basetrmurl->str, gwyData->gwyip->str, (char *)localHostIP);
    g_string_assign(gwyData->basetrmurl,tempStr);
    free(tempStr);
    
  
    g_message("baseurl:%s, playbackurl:%s, basetrumurl:%s", gwyData->baseurl->str,
              gwyData->playbackurl->str, gwyData->gwyip->str);
    return TRUE;
}

/**
 * @brief Initializes gateway attributes such as serial number, IP details , MAC details, URL details  etc.
 *
 * @param[in] gwyData Address of the structure holding gateway attributes.
 *
 * @return Returns TRUE indicating the call has finished.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
//Initializes gateway data item
gboolean init_gwydata(GwyDeviceData* gwydata)
{
    gwydata->serial_num = g_string_new(NULL);
    gwydata->isgateway=FALSE;
    gwydata->requirestrm=TRUE;
    gwydata->gwyip = g_string_new(NULL);
    gwydata->gwyipv6 = g_string_new(NULL);
    gwydata->hostmacaddress = g_string_new(NULL);
    gwydata->recvdevtype = g_string_new(NULL);
    gwydata->devicetype = g_string_new(NULL);
    gwydata->buildversion = g_string_new(NULL);
    gwydata->dsgtimezone = g_string_new(NULL);
    gwydata->ipSubNet = g_string_new(NULL);
    gwydata->dataGatewayIPaddress = g_string_new(NULL);
    gwydata->dstoffset = 0;
    gwydata->dstsavings = 0;
    gwydata->rawoffset = 0;
    gwydata->usesdaylighttime = FALSE;
    gwydata->baseurl = g_string_new(NULL);
    gwydata->basetrmurl = g_string_new(NULL);
    gwydata->playbackurl = g_string_new(NULL);
    gwydata->dnsconfig = g_string_new(NULL);
    gwydata->etchosts = g_string_new(NULL);
    gwydata->systemids = g_string_new(NULL);
    gwydata->receiverid = g_string_new(NULL);
    gwydata->gatewaystbip = g_string_new(NULL);
    gwydata->ipv6prefix = g_string_new(NULL);
    gwydata->devicename = g_string_new(NULL);
    gwydata->bcastmacaddress = g_string_new(NULL);
    gwydata->modelclass = g_string_new(NULL);
    gwydata->modelnumber = g_string_new(NULL);
    gwydata->deviceid = g_string_new(NULL);
    gwydata->hardwarerevision = g_string_new(NULL);
    gwydata->softwarerevision = g_string_new(NULL);
    gwydata->managementurl = g_string_new(NULL);
    gwydata->make = g_string_new(NULL);
    gwydata->accountid = g_string_new(NULL);
    gwydata->clientip = g_string_new(NULL);
    gwydata->devFoundFlag=FALSE;
    gwydata->isOwnGateway=FALSE;
    gwydata->isRouteSet=FALSE;
    gwydata->isDevRefactored=FALSE;
    gwydata->sproxy=NULL;
    gwydata->sproxy_i=NULL;
    gwydata->sproxy_m=NULL;
    gwydata->sproxy_t=NULL;
    gwydata->sproxy_g=NULL;
    gwydata->sproxy_q=NULL;
    return TRUE;
}

/**
 * @brief Uninitialize gateway data attributes by resetting them to default value.
 *
 * @param[in] gwyData Address of the structure variable holding Gateway attributes.
 *
 * @return Returns a boolean value indicating success/failure of the call.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
gboolean free_gwydata(GwyDeviceData* gwydata)
{
    if(gwydata)
    {
        g_string_free(gwydata->serial_num, TRUE);
        g_string_free(gwydata->gwyip, TRUE);
        g_string_free(gwydata->gwyipv6, TRUE);
        g_string_free(gwydata->hostmacaddress, TRUE);
        g_string_free(gwydata->recvdevtype, TRUE);
        g_string_free(gwydata->devicetype, TRUE);
        g_string_free(gwydata->buildversion, TRUE);
        g_string_free(gwydata->dataGatewayIPaddress, TRUE);
        g_string_free(gwydata->dsgtimezone, TRUE);
        g_string_free(gwydata->ipSubNet, TRUE);
        g_string_free(gwydata->baseurl, TRUE);
        g_string_free(gwydata->basetrmurl, TRUE);
        g_string_free(gwydata->playbackurl, TRUE);
        g_string_free(gwydata->dnsconfig, TRUE);
        g_string_free(gwydata->etchosts, TRUE);
        g_string_free(gwydata->systemids, TRUE);
        g_string_free(gwydata->receiverid, TRUE);
        g_string_free(gwydata->gatewaystbip, TRUE);
        g_string_free(gwydata->ipv6prefix, TRUE);
        g_string_free(gwydata->devicename, TRUE);
        g_string_free(gwydata->bcastmacaddress, TRUE);
        g_string_free(gwydata->clientip, TRUE);
        if(gwydata->sproxy)
        {
            g_clear_object(&(gwydata->sproxy));
        }
        if(gwydata->sproxy_i)
        {
            g_string_free(gwydata->make, TRUE);
            g_string_free(gwydata->accountid, TRUE);
            g_string_free(gwydata->modelnumber, TRUE);
            g_clear_object(&(gwydata->sproxy_i));
        }
        if(gwydata->sproxy_m)
        {
            g_clear_object(&(gwydata->sproxy_m));
        }
        if(gwydata->sproxy_t)
        {
            g_clear_object(&(gwydata->sproxy_t));
        }
        if(gwydata->sproxy_g)
        {
            g_clear_object(&(gwydata->sproxy_g));
        }
        if(gwydata->sproxy_q)
        {
            g_clear_object(&(gwydata->sproxy_q));
        }
    }
    return TRUE; /*CID-10127*/
}

/**
 * @brief Check for any addition or deletion of gateway from the list. If any update occurs, this routine
 * will validate and add/delete the entry to/from the gateway list and the updated list will be published
 * to others.
 *
 * @param[in] gwyData Address of the structure holding Gateway attributes.
 *
 * @return Returns TRUE if successfully updated the gateway list else returns FALSE.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
gboolean update_gwylist(GwyDeviceData* gwydata)
{
    char* sno = gwydata->serial_num->str;
    gchar* gwipaddr = gwydata->gwyip->str;
    int ret=0;
#ifdef BROADBAND
    dp_wlist_ss_t wstatus;
    struct in_addr x_r;
#endif

    if (sno != NULL)
    {
        GList* xdevlistitem = g_list_find_custom (xdevlist, sno, (GCompareFunc)g_list_find_sno);
        //If item already exists delete it - may be efficient than looking for
        //all the data items and updating them
        if (xdevlistitem != NULL)
        {
            gint result = g_strcmp0(g_strstrip(((GwyDeviceData *)xdevlistitem->data)->gwyip->str),g_strstrip(gwipaddr));
#ifdef ENABLE_ROUTE
            if ((disConf->enableGwSetup == TRUE) && (gwydata->isRouteSet) && (result != 0))
            {
                g_message("***** stored device gwip = %s new device gwip = %s result = %d sno = %s *****",(((GwyDeviceData *)xdevlistitem->data)->gwyip->str),g_strstrip(gwipaddr),result,sno);
                
                ret = v_secure_system("route del default gw %s", gwydata->gwyip->str);
                if(ret != 0) {
                    g_message("Failure in executing v_secure_system. ret val: %d \n", ret);
                }
            
                g_message("Clearing the default gateway %s from route list", gwydata->gwyip->str);
            }
#else
            (void)(result); // this variable is unused if ENABLE_ROUTE is not defined.
#endif
            if (delete_gwyitem(sno) == FALSE)
            {
                //g_print("Item found, but not able to delete it from list\n");
                g_message("Found device: %s in the list, but unable to delete for update", sno);
                return FALSE;
            }
            else
            {
                //g_print("Deleted existing item\n");
                g_message("Found device: %s in the list, Deleted before update", sno);
            }
        }
        else
        {
            g_message("Item %s not found in the list", sno);
        }

        g_mutex_lock(mutex);
        xdevlist = g_list_insert_sorted_with_data(xdevlist, gwydata,(GCompareDataFunc)g_list_compare_sno, NULL);
        g_mutex_unlock(mutex);
        g_message("Inserted new/updated device %s in the list", sno);
#ifdef BROADBAND
        if ((rfc_enabled) && (gwydata->isDevRefactored)) {
           // for XG devices insert ip address and mac address to whitelist
            if(g_strrstr(g_strstrip(gwydata->devicetype->str),"XG") != NULL)
            {
                if (gwydata->gwyip->str) {
                    ret = inet_aton(gwydata->gwyip->str, &x_r);
                    if (ret) {
                        if ((wstatus = dpnode_insert(x_r.s_addr, gwydata->bcastmacaddress->str)) != DP_WLIST_ERROR) {
                            g_message("Inserted ip address:index  %s:%d mac address %s to whitelist", gwydata->gwyip->str, x_r.s_addr, gwydata->bcastmacaddress->str);
                        }
                        else
                        {
                            g_message("dpnode_insert failure");
                        }
                    }
                    else
                    {
                        g_message("ip address conversion failure");
                    }
                }
                else
                {
                    g_message("gateway ip address empty");
                } 
            }           
            else if ((g_strrstr(g_strstrip(gwydata->devicetype->str),"XID") != NULL ) || (g_strrstr(g_strstrip(gwydata->devicetype->str),"XI3") != NULL))
            {
                if (gwydata->clientip->str) {
                    ret = inet_aton(gwydata->clientip->str, &x_r);
                    if (ret) {
                        if ((wstatus = dpnode_insert(x_r.s_addr, gwydata->bcastmacaddress->str)) != DP_WLIST_ERROR) {
                            g_message("Inserted ip address:index  %s:%d mac address %s to whitelist", gwydata->clientip->str, x_r.s_addr, gwydata->bcastmacaddress->str);
                        }
                        else
                        {
                            g_message("dpnode_insert failure");
                        }
                    }
                    else
                    {
                        g_message("ip address conversion failure");
                    }
                }
                else
                {
                    g_message("client ip address empty");
                }
            }
        }
#else
	(void)(ret); //variable unused
#endif
        sendDiscoveryResult(disConf->outputJsonFile);
        if(xdevlistitem)
          xdevlistitem=NULL;
        return TRUE;
    }
    else
    {
        //g_print("Serial numer is NULL\n");
        g_critical("Got a device with empty serianl number");
        return FALSE;
    }
}

/**
 * @brief Deletes a gateway entry from the list of Gateway devices if it matches
 * with the serial number supplied as input.
 *
 * @param[in] serial_num Serial number of the gateway device represented in string format.
 *
 * @return Returns TRUE if successfully deleted an item from the Gateway device list else returns FALSE.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
gboolean delete_gwyitem(const char* serial_num)
{
    GList* lstXdev = NULL;
#ifdef BROADBAND
    struct in_addr x_r;
    int ret=0;
#endif
    //look if the item exists
    if(serial_num)
    {
        lstXdev = g_list_find_custom (xdevlist, serial_num, (GCompareFunc)g_list_find_sno);
    }
    //if item exists delete the item
    if (lstXdev)
    {
        GwyDeviceData *gwdata = lstXdev->data;
        g_mutex_lock(mutex);
        if(gwdata->isgateway == TRUE)
        {
#ifdef CLIENT_XCAL_SERVER
            if (gatewayDetected)
            {
                gatewayDetected--;
            }
            g_message("Removing Gateway Device %s from the device list %d", gwdata->serial_num->str,gatewayDetected);

#ifdef BROADBAND
            if ((rfc_enabled) && (g_strrstr(g_strstrip(gwdata->devicetype->str),"XG") != NULL ) && (gwdata->isDevRefactored)) {
                  // Delete the entry from white list
                  // since the device is not in the network.
                  ret = inet_aton(gwdata->gwyip->str, &x_r);
                  if (ret) {
                     dpnode_delete(x_r.s_addr, " "); 
                  }
            }
#endif
#else
            g_message("Removing Gateway Device %s from the device list", gwdata->serial_num->str);
#endif
        }
        else
        {
            g_message("Removing Client Device %s from the device list", gwdata->serial_num->str);
#ifdef BROADBAND
            if ((rfc_enabled) && ((g_strrstr(g_strstrip(gwdata->devicetype->str),"XID") != NULL ) || (g_strrstr(g_strstrip(gwdata->devicetype->str),"XI3") != NULL )) && (gwdata->isDevRefactored)) {
                  // Delete the entry from white list
                  // since the device is not in the network.
                  ret = inet_aton(gwdata->clientip->str, &x_r);
                  if (ret) {
                     dpnode_delete(x_r.s_addr, " "); 
                  }
            }
#endif
        }
/*        g_mutex_lock(mutex);
        free_gwydata(gwdata);
        g_free(gwdata);
        xdevlist = g_list_remove(xdevlist, gwdata);
        g_mutex_unlock(mutex);
        g_message("Deleted device %s from the list", serial_num);
        if(lstXdev)
          lstXdev=NULL;
        return TRUE;
        GwyDeviceData *gwdata = lstXdev->data;*/
        if(lstXdev)
        {
            xdevlist = g_list_remove_link(xdevlist, lstXdev);
        }
        free_gwydata(gwdata);
        g_free(gwdata);
        g_mutex_unlock(mutex);
        g_message("Deleted device %s from the list", serial_num);
        if(lstXdev)
          g_list_free (lstXdev);
        return TRUE;
    }
    else
    {
        g_message("Device %s to be removed not in the discovered device list", serial_num);
    }
    return FALSE;
}

/**
 * @brief This will store the updated device discovery results in local storage as JSON formatted data.
 *
 * Whenever there's add/delete of gateway list it will create a json file, and all service variables will
 * be added to output.json. It will notify to all the listeners that listen for change of xupnp data.
 *
 * @param[in] outfilename Name of the output file to store JSON data.
 *
 * @return Returns TRUE when successfully stored the device discovery result else returns FALSE.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */

gboolean sendDiscoveryResult(const char* outfilename)
{
    gboolean firstXG1GwData=TRUE;
    gboolean firstXG2GwData=TRUE;
    const gchar v4ModeValue[]="ipv4";
    const gchar v6ModeValue[]="ipv6";
    gboolean isMediaClientConnected=FALSE;

    if(!bSerialNum)
    {
        getserialnum(ownSerialNo);
    }

    GString *localOutputContents=g_string_new(NULL);
    GString *logDevicesList=g_string_new(NULL);
    g_string_printf(localOutputContents, "{\n\"xmediagateways\":\n\t[");

    GList *xdevlistDup=NULL;
    g_mutex_lock(mutex);
    if((xdevlist) && (g_list_length(xdevlist) > 0))
    {
        xdevlistDup = g_list_copy(xdevlist);
        g_mutex_unlock(mutex);
        GList *element;
        element = g_list_first(xdevlistDup);
        while(element)
        {
            g_string_append_printf(localOutputContents,"\n\t\t{\n\t\t\t");
            GwyDeviceData *gwdata = (GwyDeviceData *)element->data;
            if(g_strcmp0(gwdata->recvdevtype->str, "broadband")) {
                g_string_append_printf(logDevicesList, "%s,%s,", gwdata->bcastmacaddress->str, gwdata->devicetype->str);
            }
            {
                g_string_append_printf(localOutputContents,"\"sno\":\"%s\",\n", gwdata->serial_num->str);
                g_string_append_printf(localOutputContents,"\t\t\t\"isgateway\":\"%s\",\n", gwdata->isgateway?"yes":"no");
                g_string_append_printf(localOutputContents,"\t\t\t\"deviceName\":\"%s\",\n", gwdata->devicename->str);
                g_string_append_printf(localOutputContents,"\t\t\t\"recvDevType\":\"%s\",\n", gwdata->recvdevtype->str);
                g_string_append_printf(localOutputContents,"\t\t\t\"DevType\":\"%s\",\n", gwdata->devicetype->str);
                g_string_append_printf(localOutputContents,"\t\t\t\"bcastMacAddress\":\"%s\",\n", gwdata->bcastmacaddress->str);

                if(gwdata->sproxy_i != NULL)
                {
                    g_string_append_printf(localOutputContents,"\t\t\t\"accountId\":\"%s\",\n", gwdata->accountid->str);
                    g_string_append_printf(localOutputContents,"\t\t\t\"modelNumber\":\"%s\",\n", gwdata->modelnumber->str);
                    g_string_append_printf(localOutputContents,"\t\t\t\"modelClass\":\"%s\",\n", gwdata->modelclass->str);
                    g_string_append_printf(localOutputContents,"\t\t\t\"make\":\"%s\",\n", gwdata->make->str);
                    g_string_append_printf(localOutputContents,"\t\t\t\"softwareRevision\":\"%s\",\n", gwdata->buildversion->str);
                    if(g_strcmp0(gwdata->recvdevtype->str,"broadband"))
                    {
                        g_string_append_printf(localOutputContents,"\t\t\t\"hardwareRevision\":\"%s\",\n", gwdata->hardwarerevision->str);
                        g_string_append_printf(localOutputContents,"\t\t\t\"managementUrl\":\"%s\",\n", gwdata->managementurl->str);
                    }
                }
                else
                {
                    g_string_append_printf(localOutputContents,"\t\t\t\"buildVersion\":\"%s\",\n", gwdata->buildversion->str);
                }
                if(strcasestr(g_strstrip(gwdata->devicetype->str),"XI") == NULL )
                {
                    g_string_append_printf(localOutputContents,"\t\t\t\"gatewayip\":\"%s\",\n", gwdata->gwyip->str);
                    g_string_append_printf(localOutputContents,"\t\t\t\"gatewayipv6\":\"%s\",\n", gwdata->gwyipv6->str);
                    g_string_append_printf(localOutputContents,"\t\t\t\"hostMacAddress\":\"%s\",\n", gwdata->hostmacaddress->str);
                    if(g_strcmp0(gwdata->recvdevtype->str,"hybrid"))
                        g_string_append_printf(localOutputContents,"\t\t\t\"IPSubNet\":\"%s\",\n", gwdata->ipSubNet->str);
                    if(g_strcmp0(gwdata->recvdevtype->str,"broadband"))
                    {
                        g_string_append_printf(localOutputContents,"\t\t\t\"gatewayStbIP\":\"%s\",\n", gwdata->gatewaystbip->str);
                        g_string_append_printf(localOutputContents,"\t\t\t\"ipv6Prefix\":\"%s\",\n", gwdata->ipv6prefix->str);
                        g_string_append_printf(localOutputContents,"\t\t\t\"timezone\":\"%s\",\n", gwdata->dsgtimezone->str);
                        g_string_append_printf(localOutputContents,"\t\t\t\"rawoffset\":\"%d\",\n", gwdata->rawoffset);
                        g_string_append_printf(localOutputContents,"\t\t\t\"dstoffset\":\"%d\",\n", gwdata->dstoffset);
                        g_string_append_printf(localOutputContents,"\t\t\t\"dstsavings\":\"%d\",\n", gwdata->dstsavings);
                        g_string_append_printf(localOutputContents,"\t\t\t\"usesdaylighttime\":\"%s\",\n", gwdata->usesdaylighttime?"yes":"no");
                        g_string_append_printf(localOutputContents,"\t\t\t\"requiresTRM\":\"%s\",\n", gwdata->requirestrm?"true":"false");
                        g_string_append_printf(localOutputContents,"\t\t\t\"baseTrmUrl\":\"%s\",\n", gwdata->basetrmurl->str);
                        g_string_append_printf(localOutputContents,"\t\t\t\"systemids\":\"%s\",\n", gwdata->systemids->str);
                        g_string_append_printf(localOutputContents,"\t\t\t\"playbackUrl\":\"%s\",\n", gwdata->playbackurl->str);
                        g_string_append_printf(localOutputContents,"\t\t\t\"dnsconfig\":\"%s\",\n", gwdata->dnsconfig->str);
                        g_string_append_printf(localOutputContents,"\t\t\t\"hosts\":\"%s\",\n", gwdata->etchosts->str);
                    }
                    if(gwdata->sproxy_i != NULL)
                    {
                        g_string_append_printf(localOutputContents,"\t\t\t\"dataGatewayIPaddress\":\"%s\",\n", gwdata->dataGatewayIPaddress->str);
                        g_string_append_printf(localOutputContents,"\t\t\t\"clientip\":\"%s\",\n", gwdata->clientip->str);
                    }
                }
                else
                {
                    g_string_append_printf(localOutputContents,"\t\t\t\"clientip\":\"%s\",\n", gwdata->clientip->str);
                    g_string_append_printf(localOutputContents,"\t\t\t\"dataGatewayIPaddress\":\"%s\",\n", gwdata->dataGatewayIPaddress->str);
                }
                g_string_append_printf(localOutputContents,"\t\t\t\"receiverid\":\"%s\"\n\t\t}", gwdata->receiverid->str);
                #ifdef CLIENT_XCAL_SERVER
                if (gwdata->isgateway)
                {
                    gatewayDetected++;
                }
                #endif
            }
            if((!selfDeviceDiscovered) && (g_strcmp0(g_strstrip(ownSerialNo->str),gwdata->serial_num->str) == 0))
            {
                selfDeviceDiscovered=TRUE;
                g_message("Self Discovery Success %s",ownSerialNo->str);
            }
            if((disConf->enableGwSetup == TRUE) && ((firstXG1GwData == TRUE) || (firstXG2GwData == TRUE)) && (gwdata->isgateway == TRUE) && (checkvalidhostname(gwdata->dnsconfig->str) == TRUE ) && (checkvalidhostname(gwdata->etchosts->str) == TRUE) && (checkvalidip(gwdata->gwyip->str) == TRUE) && (checkvalidip(gwdata->gwyipv6->str) == TRUE))
            {

#ifdef ENABLE_ROUTE
                GString *GwRouteParam=g_string_new(NULL);
                g_string_printf(GwRouteParam,"%s" ,disConf->gwSetupFile);
                g_string_append_printf(GwRouteParam," \"%s\"" ,gwdata->gwyip->str);
                g_string_append_printf(GwRouteParam," \"%s\"" ,gwdata->dnsconfig->str);
                g_string_append_printf(GwRouteParam," \"%s\"" ,gwdata->etchosts->str);
                g_string_append_printf(GwRouteParam," \"%s\"" ,disConf->gwIf);
                g_string_append_printf(GwRouteParam," \"%d\"" ,disConf->GwPriority);
                g_string_append_printf(GwRouteParam," \"%s\"" ,gwdata->ipv6prefix->str);
                g_string_append_printf(GwRouteParam," \"%s\"" ,gwdata->gwyipv6->str);
                g_string_append_printf(GwRouteParam," \"%s\"" ,gwdata->devicetype->str);
//            	g_string_append_printf(GwRouteParam," %s " ,"&");
                g_message("Calling gateway script %s",GwRouteParam->str);
                system(GwRouteParam->str);
                g_string_free(GwRouteParam,TRUE);
                gwdata->isRouteSet = TRUE;
                if(firstXG1GwData == TRUE)
                {
                    firstXG1GwData=FALSE;
                }
                else if(firstXG2GwData == TRUE)
                {

                    firstXG2GwData=FALSE;
                }
#endif
                if (g_strrstr(g_strstrip(gwdata->ipv6prefix->str),"null") ||  ! *(gwdata->ipv6prefix->str))
                {

                    if( g_strcmp0(ipMode->str,v4ModeValue) != 0 )
                    {
                        g_message("v4 mode changed");
                        g_string_assign(ipMode,v4ModeValue);
                    }
                }
                else
                {
                    if( g_strcmp0(ipMode->str,v6ModeValue) != 0 )
                    {
                        g_message("v6 mode changed");
                        g_string_assign(ipMode,v6ModeValue);
                    }
                }


#ifdef USE_XUPNP_TZ_UPDATE
                if (g_strcmp0(g_strstrip(gwdata->dsgtimezone->str),"null") != 0)
                    broadcastTimeZoneChange(gwdata);
#endif

            }
            element = g_list_next(element);
            if (element) g_string_append_printf(localOutputContents, ",");
        }
	if(element)
          g_list_free(element);
    if(xdevlistDup)
        g_list_free(xdevlistDup);
    }
    else
    {
        g_message("Send Discovery Result : Device List Null or Empty");
        g_mutex_unlock(mutex);
    }
    if (logDevicesList->len) 
    {
        g_string_truncate(logDevicesList, logDevicesList->len-1);
    }
    g_message("DISCOVERED_MANAGED_DEVICE:%s\n", logDevicesList->str);

#if defined(ENABLE_FEATURE_TELEMETRY2_0)
    char telemetryBuff[4096] = {'\0'};
    strncpy(telemetryBuff, logDevicesList->str, logDevicesList->len);
    t2_event_s("Discovered_MngdDev_split", telemetryBuff);
#endif

    //g_print("\n\t]\n}\n");
    g_string_append_printf(localOutputContents,"\n\t]\n}\n");
    //g_print("\nOutput is\n%s", outputcontents->str);
    g_message("Output is\n%s", localOutputContents->str);
    g_mutex_lock(devMutex);
    g_string_assign(outputcontents,localOutputContents->str);
    g_mutex_unlock(devMutex);

    //IARM Update
#if defined(USE_XUPNP_IARM)
    notifyXUPnPDataUpdateEvent(UIDEV_EVENT_XUPNP_DATA_UPDATE);
#elif defined(USE_XUPNP_IARM_BUS)
    notifyXUPnPDataUpdateEvent(IARM_BUS_SYSMGR_EVENT_XUPNP_DATA_UPDATE);
#endif
    //End - IARM Update


    if (g_file_set_contents(outfilename, localOutputContents->str, -1, NULL)==FALSE)
    {
        g_string_free(localOutputContents,TRUE);
        g_print("xdiscovery:Problem in updating the output file contents\n");
        g_critical("Problem in updating the file contents");
        return FALSE;
    } else {
        /* Flag to set if media client is discovered */
        if (strstr(localOutputContents->str, "mediaclient") != NULL)
          isMediaClientConnected = TRUE;
        g_string_free(localOutputContents,TRUE);
    }

#ifdef BROADBAND
    // Restart webgui.sh to listen on video analytics port if not listesting and
    // mediaclient is connected after webgui process up
    int ret = 0;
    if ((access(WEBGUI_VIDEO_ANAL_FILE, F_OK) == -1) && (isMediaClientConnected == TRUE))
    {
        g_message("Open Video Analytic port if mediaclient is connected\n");
        ret = v_secure_system ("/etc/webgui.sh &");
        if(ret != 0) {
            g_message("Failure in executing command via v_secure_system. ret val : %d\n", ret);
        }
    }
#else
    // isMediaClientConnected is unused if BROADBAND is not defined.
    (void)(isMediaClientConnected);
#endif

    return TRUE;
}

/*Thread to continuously pole and verify that existing devices are alive and responding
 If not take them off from device list*/

//#ifdef GUPNP_0_19

/**
 * @brief Verify and update the gateway list according to the availability of the gateway devices
 * connected to the network. New devices will be added to the list and dead devices will be deleted
 * from the list.
 *
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
void* verify_devices()
{
/*
    guint lenPrevDevList = 0;
    guint lenCurDevList = 0;
    guint lenXdevList = 0;
//workaround to remove device in second attempt -Start
    guint removeDeviceNo=0;
    guint counter=0;
    guint preCounter=0;
    guint removeDeviceNo1=0;
    guint counter1=0;
    guint preCounter1=0;
*/
    guint checkMainLoopCounter=0;
    guint sleepCounter=0;
#ifdef CLIENT_XCAL_SERVER
    guint browserDisableEnableCounter=0;
#endif
#if !defined(BROADBAND)
    guint selfDiscoveryFailCount=0;
#endif
   //workaround to remove device in second attempt -Start
    usleep(XUPNP_RESCAN_INTERVAL);
    while(1)
    {
        //g_main_context_push_thread_default(main_context);
        if (! g_main_loop_is_running(main_loop))
        {
          if(checkMainLoopCounter < 7)
            g_message("TELEMETRY_XUPNP_DISCOVERY_MAIN_LOOP_NOT_RUNNING");
          checkMainLoopCounter++;
        }
        if(deviceAddNo)
        {
            if((sleepCounter > 6) && (sleepCounter < 12)) //wait for device addition to complete in 60 seconds and print only for another 60 seconds if there is a hang
            {
                g_message("Device Addition %u going in main loop",deviceAddNo);
            }
            sleepCounter++;
            usleep(XUPNP_RESCAN_INTERVAL);
            continue;
        }
        // If self discovery fails even after local xdevice is publishing then do an restart of xdiscovery for one time.
#if !defined(BROADBAND)
        if((!selfDeviceDiscovered) && (access(RESTART_XDISCOVERY_FILE, F_OK ) == -1))
        {
            if (selfDiscoveryFailCount >= 20)
            {
                FILE *fDiscoveryFile;
                fDiscoveryFile = fopen(RESTART_XDISCOVERY_FILE, "w");
                if(! fDiscoveryFile)
                {
                    g_message("Restart Xdiscovery File open failure");
                }
                else
                {
                    g_message("Self Discovery Failed %d ! exiting",selfDiscoveryFailCount);
                    fclose(fDiscoveryFile);
                    exit(1);
                }
            }
            else
                selfDiscoveryFailCount++;
        }
#endif
        sleepCounter=0;
#ifdef CLIENT_XCAL_SERVER
        // When there is a partial discovery make sure that we gssdp cache is flushed out using resource browser
        if((partialDiscovery) && (!gatewayDetected) && (browserDisableEnableCounter <=2))
        {
            g_message("Partial Device Discovery Disable Enable Resource Browser");
            gssdp_resource_browser_set_active(GSSDP_RESOURCE_BROWSER(cp),FALSE);
            partialDiscovery=FALSE;
            usleep(XUPNP_RESCAN_INTERVAL/5);
            gssdp_resource_browser_set_active(GSSDP_RESOURCE_BROWSER(cp),TRUE);
            usleep(XUPNP_RESCAN_INTERVAL);
            browserDisableEnableCounter++;
            continue;
        }
#endif
	if(rfc_enabled)
	{
	    if (gssdp_resource_browser_rescan(GSSDP_RESOURCE_BROWSER(cp_client))==FALSE)
	    {
		g_message("Forced rescan failed for renderer");
		usleep(XUPNP_RESCAN_INTERVAL);
	    }
	    if (gssdp_resource_browser_rescan(GSSDP_RESOURCE_BROWSER(cp_gw))==FALSE)
	    {
		g_message("Forced rescan failed for gateway");
		usleep(XUPNP_RESCAN_INTERVAL);
	    }
	    if (gssdp_resource_browser_rescan(GSSDP_RESOURCE_BROWSER(cp_bgw))==FALSE)
	    {
		g_message("Forced rescan failed for broadband");
		usleep(XUPNP_RESCAN_INTERVAL);
	    }
	}
        if (gssdp_resource_browser_rescan(GSSDP_RESOURCE_BROWSER(cp))==FALSE)
        {
            g_message("Forced rescan failed");
            //g_debug("Forced rescan failed, sleeping");
            usleep(XUPNP_RESCAN_INTERVAL);
            continue;
        }
        //else
        //    g_print("Forced rescan success\n");
        //g_debug("Forced rescan success");
        usleep(XUPNP_RESCAN_INTERVAL);
/*        const GList *constLstProxies = gupnp_control_point_list_device_proxies(cp);
        counter++;
        counter1++;
        if (NULL == constLstProxies)
        {
            if(disConf->enableGwSetup == TRUE)
            {
                g_message("Error in getting list of device proxies or No device proxies found");
            }
            if( removeDeviceNo == 0 )
            {
                removeDeviceNo++;
                preCounter=counter;
            }
            else if(( removeDeviceNo == 1) && (preCounter == (counter-1)))
            {
                removeDeviceNo=0;
                delOldItemsFromList(TRUE);
                counter=0;
                preCounter=0;
            }
            else
            {
                removeDeviceNo=0;
                counter=0;
                preCounter=0;

            }
            continue;
        }
        GList *xdevlistDup=NULL;

        lenCurDevList = g_list_length(constLstProxies);
        g_mutex_lock(mutex);
        if((xdevlist) && (g_list_length(xdevlist) > 0))
        {
            xdevlistDup = g_list_copy(xdevlist);
            lenXdevList = g_list_length(xdevlistDup);
        }
        g_mutex_unlock(mutex);


//        lenXdevList = g_list_length(xdevlist);
        //g_message("Current list length is %u\n",lenCurDevList);

        if (lenCurDevList > 0)
        {
            //Compare new list with existing list
            if (lenXdevList > 0)
            {
                gboolean existsFlag = FALSE;
                gboolean delCheckFlag = FALSE;
                GList *element = NULL;

                element = g_list_first(xdevlistDup);
                while(element)
                {
                    GwyDeviceData *gwdata = (GwyDeviceData *)element->data;

                    //Loop through all new found devices
                    GList* lstProxies = g_list_first(constLstProxies);
                    //g_message("Length of lstProxies is %u", g_list_length(lstProxies));
                    existsFlag = FALSE;
                    while(lstProxies)
                    {
                        if (NULL == lstProxies->data)
                        {
                            g_message("1-Error - Got Null pointer as deviceproxy");
                            continue;
                        }
                        const GUPnPDeviceProxy* dproxy;
                        dproxy = (GUPnPDeviceProxy *)lstProxies->data;
                        gchar* sno = gupnp_device_info_get_serial_number (GUPNP_DEVICE_INFO(dproxy));
                        gint result = g_strcmp0(g_strstrip(gwdata->serial_num->str),g_strstrip(sno));
                        g_free(sno);
                        lstProxies = g_list_next(lstProxies);
                        //Matched the serial number - No need to do anything - quit the loop
                        if (result==0)
                        {
                            existsFlag=TRUE;
                            break;
                        }

                        //There are still elements to search

                    }
                    //g_list_free(lstProxies);
                    //End - Loop through all new found devices

                    //Device not found in new device list. Mark it for deletion later.
                    if (existsFlag==FALSE)
                    {
                        delCheckFlag = TRUE;
                        gwdata->devFoundFlag = FALSE;
                    }

                    //There are still elements to search
                    element = g_list_next(element);
                }
                if (delCheckFlag == TRUE)
                {
                    //	g_message("delCheckFlag is enabled ");
                    if( removeDeviceNo1 == 0 )
                    {
                        removeDeviceNo1++;
                        preCounter1=counter1;
                    }
                    else if(( removeDeviceNo1 == 1) && (preCounter1 == (counter1-1)))
                    {
                        removeDeviceNo1=0;
                        delOldItemsFromList(FALSE);
                        counter1=0;
                        preCounter1=0;
                    }
                    else
                    {
                        removeDeviceNo1=0;
                        counter1=0;
                        preCounter1=0;
                    }
                }
            }
        }
        else
        {
            //g_message("Device List length - Current length: %u - Previous Length: %u",lenCurDevList, lenPrevDevList);
            g_message("Current dev length is empty ");
            delOldItemsFromList(TRUE);
        }
	if(xdevlistDup)
	{
	    g_list_free(xdevlistDup);
	}

                  //Find out newly discovered devices and add to cleaned up list
                lenXdevList = g_list_length(xdevlist);
                if (lenCurDevList > 0)
                {
                      //Loop through all new found devices
                      //g_message("Device List length change - Current length: %u - Previous Length: %u - xdevlist len %u",lenCurDevList, lenPrevDevList, lenXdevList);


                      gboolean existsFlag = FALSE;
                      GList* lstProxies = g_list_first(constLstProxies);
                      while(lstProxies)
                      {
                          if (NULL == lstProxies->data)
                          {
                            g_message("2-Error - Got Null pointer as deviceproxy");
                            continue;
                          }
                          const GUPnPDeviceProxy* dproxy;
        		  dproxy = (GUPnPDeviceProxy *)lstProxies->data;

                          //g_print("Serial Number %s\n", sno, lenCurDevList);
                          existsFlag = FALSE;
                          if (lenXdevList > 0)
                          {

                            gchar* sno = gupnp_device_info_get_serial_number (GUPNP_DEVICE_INFO (dproxy));
                              //g_message("Searching for serial number %s", sno);
                            existsFlag = checkDeviceExists(sno);
                          }
                          //End - Loop through all new found devices

                          //Device not found in device list. Mark it for addition.
                          if (existsFlag==FALSE)
                          {
                              device_proxy_available_cb(cp, (GUPnPDeviceProxy *)lstProxies->data);
                          }

                          //There are still elements to search
                          lstProxies = g_list_next(lstProxies);
                      }
                      //g_list_free(lstProxies);

                      //g_print("Current list is greater\n");
                  }

*/


        //After cleaning up, update the prev list length
//        lenPrevDevList=lenCurDevList;
        //g_print("\nWaiting Discovery...\n");
    }
}

/**
 * @brief Delete all the devices from the device list or delete devices marked
 * as "Not Found" from device list.
 *
 * @param[in] bDeleteAll Boolean variable indicating whether to delete all entries.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
void delOldItemsFromList(gboolean bDeleteAll)
{
    guint lenXDevList = 0;
    guint deletedDeviceNo=0;
    lenXDevList = g_list_length(xdevlist);
    int ret = 0;
    //g_message("Length of the list before deletion is %u", lenXDevList);
    if (lenXDevList > 0)
    {
        GwyDeviceData *gwdata = NULL;
        GList *element = g_list_first(xdevlist);

        while (element && (lenXDevList > 0))
        {
            gwdata = element->data;
            element = g_list_next(element);
            if (gwdata->isOwnGateway==FALSE)
            {
                if (gwdata->devFoundFlag==FALSE || bDeleteAll==TRUE)
                {
                    if(gwdata->isgateway == TRUE)
                        g_message("Removing Gateway Device %s from the device list", gwdata->serial_num->str);
                    else
                        g_message("Removing Client Device %s from the device list", gwdata->serial_num->str);
#ifdef ENABLE_ROUTE
                    if ((disConf->enableGwSetup == TRUE) && (gwdata->isRouteSet) && checkvalidip(gwdata->gwyip->str))
                    {
                        ret = v_secure_system("route del default gw %s", gwdata->gwyip->str);
                        if(ret != 0) {
                            g_message("Failure in executing command via v_secure_system. ret val : %d \n", ret);
                        }
                        g_message("Clearing the default gateway %s from route list", gwdata->gwyip->str);
                    }
#else
		    (void)(ret); //variable not used outside ENABLE_ROUTE flag.
#endif
                    g_mutex_lock(mutex);
                    deletedDeviceNo++;
                  /* Coverity Fix CID:125350 : Used After Free */
                    xdevlist = g_list_remove(xdevlist, gwdata);
                    free_gwydata(gwdata);
                    g_free(gwdata);
                    //g_print("Element Removed\n");

                    g_mutex_unlock(mutex);
                }
            }
            lenXDevList--;
        }
        g_list_free(element);
        if(deletedDeviceNo > 0)
        {
            g_message("removed %d devices,sending updated discovery result",deletedDeviceNo);
            sendDiscoveryResult(disConf->outputJsonFile);
        }
    }
}

static void on_last_change (GUPnPServiceProxy *sproxy, const char  *variable_name, GValue  *value, gpointer user_data)
{
    GwyDeviceData *gwdata = NULL;
    const char* updated_value;
    gboolean bUpdateDiscoveryResult=FALSE;
    GList* xdevlistitem = NULL;
    const char* udn = gupnp_service_info_get_udn(GUPNP_SERVICE_INFO(sproxy));
    g_message("Variable name is %s udn is %s", variable_name, udn);

    if (udn != NULL)
    {
        if (g_strrstr(udn,"uuid:"))
        {
            gchar* receiverid = g_strndup(udn+5, strlen(udn)-5);
            if(receiverid)
            {
                xdevlistitem = g_list_find_custom (xdevlist, receiverid, (GCompareFunc)g_list_find_udn);
            }
            if (xdevlistitem != NULL)
            {
                gwdata = xdevlistitem->data;
                g_message("Found device: %s - Receiver id %s in the list, Updating %s",
                          gwdata->serial_num->str,gwdata->receiverid->str, variable_name);
                if (g_strcmp0(g_strstrip((gchar *)variable_name),"PlaybackUrl") == 0)
                {
                    updated_value = g_value_get_string(value);
                    g_message("Updated value is %s ", updated_value);
                    if(g_strcmp0(g_strstrip((gchar *)updated_value),gwdata->playbackurl->str) != 0)
                    {
                        bUpdateDiscoveryResult=TRUE;
                        g_string_assign(gwdata->playbackurl, updated_value);

                        //Check if it is local device and replace MoCA IP with 127.0.0.1
                        //if ((gwdata->isgateway == TRUE))
                        //{
#if !defined (NO_MOCA_FEATURE_SUPPORT)
                        if (replace_local_device_ip(gwdata) == TRUE)
                        {
                            g_message("Replaced MocaIP for %s with localhost", gwdata->serial_num->str);
                        }
#endif
                        //}
                    }

                }

                if (g_strcmp0(g_strstrip((gchar *)variable_name),"SystemIds") == 0)
                {
                    updated_value = g_value_get_string(value);
                    g_message("Updated value is %s ", updated_value);
                    if(g_strcmp0(g_strstrip((gchar *)updated_value),gwdata->systemids->str) != 0)
                    {
                        bUpdateDiscoveryResult=TRUE;
                        g_string_assign(gwdata->systemids, updated_value);
                    }
                }
                if (g_strcmp0(g_strstrip((gchar *)variable_name),"DataGatewayIPaddress") == 0)
                {
                    updated_value = g_value_get_string(value);
                    g_message("Updated value of DataGatewayIPaddressis %s ", updated_value);
                    if(g_strcmp0(g_strstrip((gchar *)updated_value),gwdata->dataGatewayIPaddress->str) != 0)
                    {
                        bUpdateDiscoveryResult=TRUE;
                        g_string_assign(gwdata->dataGatewayIPaddress, updated_value);
                    }
                }
                if (g_strcmp0(g_strstrip((gchar *)variable_name),"DnsConfig") == 0)
                {
                    updated_value = g_value_get_string(value);
                    g_message("Updated value is %s ", updated_value);
                    if(g_strcmp0(g_strstrip((gchar *)updated_value),gwdata->dnsconfig->str) != 0)
                    {
                        bUpdateDiscoveryResult=TRUE;
                        g_string_assign(gwdata->dnsconfig, updated_value);
                    }
                }
                if (g_strcmp0(g_strstrip((gchar *)variable_name),"TimeZone") == 0)
                {
                    updated_value = g_value_get_string(value);
                    g_message("Updated value is %s ", updated_value);
                    if(g_strcmp0(g_strstrip((gchar *)updated_value),gwdata->dsgtimezone->str) != 0)
                    {
                        bUpdateDiscoveryResult=TRUE;
                        g_string_assign(gwdata->dsgtimezone, updated_value);
#ifdef USE_XUPNP_TZ_UPDATE
                    if (g_strcmp0(g_strstrip(gwdata->dsgtimezone->str),"null") != 0)
                        broadcastTimeZoneChange(gwdata);
#endif
                    }
                }
                if (g_strcmp0(g_strstrip((gchar*)variable_name),"IPSubNet") == 0)
                {
                    updated_value = g_value_get_string(value);
                    g_message("Updated value is %s ", updated_value);
                    if(g_strcmp0(g_strstrip((gchar*)updated_value),gwdata->ipSubNet->str) != 0)
                    {
                        bUpdateDiscoveryResult=TRUE;
                        g_string_assign(gwdata->ipSubNet, updated_value);
                        if(updated_value && strlen(updated_value))
#if !defined (NO_MOCA_FEATURE_SUPPORT)
                            addRouteToMocaBridge((char*)updated_value);
#endif
                    }
                }
                //update_gwylist(gwdata);
                g_free(receiverid);
                if(bUpdateDiscoveryResult)
                    sendDiscoveryResult(disConf->outputJsonFile);

            }
        }
    }
    return;
}
/**
 * @brief This will parse and load the configuration file in a key/value pair format as specified
 * in GLib encoding. The configuration file contain attributes which are categorized into following:
 * - Network   : Contains parameters such as interface name, IP etc.
 * - Datafiles : Contains Name of Script and Log files.
 *
 * @param[in] configfile Name of the configuration file.
 *
 * @return Returns TRUE if successfully loaded the configuration file in GKey file structure else returns FALSE.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
gboolean readconffile(const char* configfile)
{

    GKeyFile *keyfile = NULL;
    GKeyFileFlags flags;
    GError *error = NULL;
    
    if(configfile)
    {

        /* Create a new GKeyFile object and a bitwise list of flags. */
        keyfile = g_key_file_new ();
        flags = G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS;

        /* Load the GKeyFile from keyfile.conf or return. */
        if (!g_key_file_load_from_file (keyfile, configfile, flags, &error))
        {
            /*Coverity Fix CID:28701 NON_CONST_PRINTF_FORMAT */
            g_error("%s",error->message);
            g_clear_error(&error);
            g_key_file_free(keyfile);
            return FALSE;
        }
        //g_message("Starting with Settings %s\n", g_key_file_to_data(keyfile, NULL, NULL));

        disConf = g_new(ConfSettings,1);
        /*
        # Names of all network interfaces used for publishing
        [Network]
        discIf=eth1
        GwIf=eth1
        GwPriority=50
        */

        /* Read in data from the key file from the group "Network". */
        disConf->discIf = g_key_file_get_string(keyfile, "Network","discIf", NULL);
        disConf->gwIf = g_key_file_get_string(keyfile, "Network","GwIf", NULL);
        disConf->GwPriority = g_key_file_get_integer(keyfile, "Network","GwPriority", NULL);
        /*
        # Paths and names of all input data files
        [DataFiles]
        gwSetupFile=/lib/rdk/gwSetup.sh
        LogFile=/opt/logs/xdiscovery.log
	outputJsonFile=/opt/output.json
	certPath=/tmp/
	keyPath=/tmp/
	certFile=xpki_cert
	keyFile=xpki_key
        */
        /* Read in data from the key file from the group "DataFiles". */
        disConf->gwSetupFile = g_key_file_get_string(keyfile, "DataFiles","gwSetupFile", NULL);
        disConf->logFile = g_key_file_get_string(keyfile, "DataFiles","LogFile", NULL);
        disConf->outputJsonFile = g_key_file_get_string(keyfile, "DataFiles","outputJsonFile", NULL);

        if(rfc_enabled)
        {
           disConf->disCertFile= g_key_file_get_string(keyfile, "DataFiles","certFile", NULL);
           disConf->disCertPath= g_key_file_get_string(keyfile, "DataFiles","certPath", NULL);
           disConf->disKeyPath= g_key_file_get_string(keyfile, "DataFiles","keyPath", NULL);
           disConf->disKeyFile= g_key_file_get_string(keyfile, "DataFiles","keyFile", NULL);
        }
        disConf->disSeCertFile= g_key_file_get_string(keyfile, "DataFiles","seCertFile", NULL);
        disConf->disPassCodeFile= g_key_file_get_string(keyfile, "DataFiles","sePassFile", NULL);
        disConf->disSeCAFile= g_key_file_get_string(keyfile, "DataFiles","seCAFile", NULL);
        /*
        # Enable/Disable feature flags
        enableGwSetup=TRUE
         */
        disConf->enableGwSetup = g_key_file_get_boolean(keyfile, "Flags","enableGwSetup", NULL);

        g_key_file_free(keyfile);
        if (disConf->logFile == NULL)
            g_warning("configuration doesnt have log file so log file should be given explicitly or it will be written in console\n");

        if (disConf->discIf == NULL)
        {
            g_warning("Invalid or no values found for mandatory parameters\n");
            return FALSE;
        }

        return TRUE;
    }
    else
    {
        g_warning("No configuration file \n");
        return FALSE;
    }
}

/**
 * @brief Get the serial number of the device from Vendor specific UDHCPC config file.
 *
 * @param[out] ownSerialNo Address of the string to return the Serial number.
 *
 * @return Returns TRUE if successfully get the own serial number else returns FALSE.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */

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


/**
 * @brief Replace all occurrences of a sub-string in the given string to value the specified.
 *
 * @param[in] src_string Source String.
 * @param[in] sub_string Sub string which has to be searched and replaced.
 * @param[in] replace_string New sub string that will be replaced.
 *
 * @return Returns TRUE if successfully replaced the sub string with replace string else returns FALSE.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
char *replace_string(char *src_string, char *sub_string, char *replace_string) {

    char *return_str = NULL;
    char *insert_str = NULL;
    char *tmp_str    = NULL;
    errno_t rc       = -1;
    int distance, lenSubStr, lenRepStr, numOccurences;

    if ((!src_string) || (!sub_string) || (!replace_string))return src_string;

    lenSubStr = strlen(sub_string);
    lenRepStr = strlen(replace_string);

    insert_str = src_string;
    for (numOccurences = 0; (tmp_str = strstr(insert_str, sub_string)); ++numOccurences) {
        insert_str = tmp_str + lenSubStr;
    }

    int rstrsize = strlen(src_string) + (lenRepStr - lenSubStr) * numOccurences + 1;
    tmp_str = return_str = malloc(rstrsize);

    if (!return_str) return src_string;

    while (numOccurences--) {
        insert_str = strstr(src_string, sub_string);
        distance = insert_str - src_string;
        rc = strncpy_s(tmp_str, rstrsize, src_string, distance);
        ERR_CHK(rc);
        tmp_str += distance;
        rstrsize -= distance;
        rc = strcpy_s(tmp_str, rstrsize, replace_string);
        ERR_CHK(rc);
        tmp_str += lenRepStr;
        rstrsize -= lenRepStr;
        src_string += distance + lenSubStr;
    }
    rc =strcpy_s(tmp_str, rstrsize, src_string);
    ERR_CHK(rc);
    return return_str;
}

/**
 * @brief This function gets the IP address for the given interface. The IP Address will be
 * formatted to IPv6 or IPv4 address depending upon the configuration.
 *
 * @param[in] ifname Name of the network interface.
 * @param[out] ipAddressBuffer String which will store the result IP Address.
 * @param[in] ipv6Enabled Boolean value indicating whether IPv6 is enabled.
 *
 * @return Returns an Integer value.
 * @retval 1 If an IP address is found.
 * @retval 0 If No IP address found on specified interface.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
int getipaddress(const char* ifname, char* ipAddressBuffer, gboolean ipv6Enabled)
{
    struct ifaddrs * ifAddrStruct=NULL;
    struct ifaddrs * ifa=NULL;
    void * tmpAddrPtr=NULL;
    /* Coverity Fix CID:28732 CHECKED_RETURN */
    if( getifaddrs(&ifAddrStruct) < 0 )
    {
       g_message(" getifaddrs is failed\n");
        return -1;
    }
    //char addressBuffer[INET_ADDRSTRLEN] = NULL;
    int found=0;
    errno_t rc       = -1;
    int     ind      = -1;

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if ((ifa ->ifa_addr->sa_family==AF_INET6) && (ipv6Enabled == TRUE)) { // check it is IP6
            // is a valid IP6 Address
            tmpAddrPtr=&((struct sockaddr_in6  *)ifa->ifa_addr)->sin6_addr;

            inet_ntop(AF_INET6, tmpAddrPtr, ipAddressBuffer, INET6_ADDRSTRLEN);

            //if (strcmp(ifa->ifa_name,"eth0")==0)
            rc = strcmp_s(ifa->ifa_name, strlen(ifa->ifa_name) ,ifname, &ind);
            ERR_CHK(rc);
            if((ind == 0) && (rc == EOK))
            {
                found = 1;
                break;
            }
        }

        else {

            if (ifa ->ifa_addr->sa_family==AF_INET) { // check it is IP4
                // is a valid IP4 Address
                tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;

                inet_ntop(AF_INET, tmpAddrPtr, ipAddressBuffer, INET_ADDRSTRLEN);

                //if (strcmp(ifa->ifa_name,"eth0")==0)
                rc =strcmp_s(ifa->ifa_name,strlen(ifa->ifa_name), ifname, &ind);
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
 * @brief When the discovered device is the own device then MOcA IP is replaced.
 *
 * @param[in] gwyData Address of structure holding the Gateway device attributes.
 *
 * @return Returns TRUE if successfully replaced the IP else returns FALSE.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
gboolean replace_local_device_ip(GwyDeviceData* gwydata)
{
    //if(gwydata->isgateway == TRUE)
    //{
    if ((g_strcmp0 (g_strstrip(gwydata->gwyip->str), g_strstrip(ipaddress)) == 0))
    {
        g_message("isown gateway is true");
        gwydata->isOwnGateway=TRUE;
        gboolean result = replace_hn_with_local(gwydata);
        return result;
    }
    //}
    return FALSE;
}

/**
 * @brief This will check whether the input IP Address is a valid IPv4 or IPv6 address.
 *
 * @param[in] ipAddress IP Address in string format.
 *
 * @return Returns TRUE if IP address is valid else returns FALSE.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
gboolean checkvalidip( char* ipAddress)
{
    struct in_addr addr4;
    struct in6_addr addr6;
    int validip4 = inet_pton(AF_INET, ipAddress, &addr4);
    int validip6 = inet_pton(AF_INET6, ipAddress, &addr6);
    if (g_strrstr(g_strstrip(ipAddress),"null") || ! *ipAddress )
    {
        g_message ("ipaddress are empty %s",ipAddress);
        return TRUE;
    }

    if ((validip4 == 1 ) || (validip6 == 1 ))
    {
        return TRUE;
    }
    else
    {
        g_message("Not a valid ip address %s " , ipAddress);
        return FALSE;
    }
}

/**
 * @brief This function will check whether a Host name is valid by validating all the associated IP addresses.
 *
 * @param[in] hostname Host name represented as a string.
 *
 * @return Returns TRUE if host name is valid else returns FALSE.
 * @ingroup XUPNP_XDISCOVERY_FUNC
 */
gboolean checkvalidhostname( char* hostname)
{
    if (g_strrstr(g_strstrip(hostname),"null") || ! *hostname )
    {
        g_message ("hostname  values are empty %s",hostname);
        return TRUE;
    }
    gchar **tokens = g_strsplit_set(hostname," ;\n\0", -1);
    guint toklength = g_strv_length(tokens);
    guint loopvar=0;

    for (loopvar=0; loopvar<toklength; loopvar++)
    {
        if (checkvalidip(tokens[loopvar]))
        {
	    g_strfreev(tokens);
            return TRUE;
        }
    }
    g_message(" no valid ip so rejecting the dns values %s ",hostname);
    g_strfreev(tokens); /*CID-24000*/
    return FALSE;
}

#if defined(USE_XUPNP_IARM) || defined(USE_XUPNP_IARM_BUS)
void broadcastIPModeChange(void)
{
    errno_t rc       = -1;
    IARM_Bus_SYSMgr_EventData_t eventData;
    eventData.data.systemStates.stateId = IARM_BUS_SYSMGR_SYSSTATE_IP_MODE;
    eventData.data.systemStates.state = 1;
    eventData.data.systemStates.error = 0;
    rc = strcpy_s(eventData.data.systemStates.payload, sizeof(eventData.data.systemStates.payload), ipMode->str);
    ERR_CHK(rc);
    eventData.data.systemStates.payload[strlen(ipMode->str)]='\0';
    IARM_Bus_BroadcastEvent(IARM_BUS_SYSMGR_NAME, (IARM_EventId_t) IARM_BUS_SYSMGR_EVENT_SYSTEMSTATE, (void *)&eventData, sizeof(eventData));
    g_message("sent event for ipmode= %s",ipMode->str);
}
#endif

#ifdef USE_XUPNP_TZ_UPDATE
void broadcastTimeZoneChange(GwyDeviceData *gwdata)
{
    IARM_Bus_SYSMgr_EventData_t eventData;
    static int prevTzIndex = -1;
    int currTZIndex = -1;
    static bool IsDst = false;

    //g_message("broadcastTimeZoneChange: Input  Payload - %s",gwdata->dsgtimezone->str);
    /* get the Mapped Time Zone for Sys Mgr */
    int size = sizeof(m_timezoneinfo)/sizeof(struct _Timezone);
    int i = 0;
    for (i = 0; i < size; i++ )
    {
        if (g_strcmp0(m_timezoneinfo[i].upnpTZ, gwdata->dsgtimezone->str) == 0)
        {
            currTZIndex = i;
            break;
        }
    }

    /* No Valid Mapped Time Zone Found , return */
    if(currTZIndex == -1)
    {
        g_message("broadcastTimeZoneChange: Do Not Update Inavlid Time Zone - %s ",gwdata->dsgtimezone->str);
        return;
    }


    //g_message("broadcastTimeZoneChange Size = %d : currTZIndex =  %d",size,currTZIndex);
    /* Broadcast only on Change of Time Zone Information */
    if((prevTzIndex != currTZIndex) || (IsDst != gwdata->usesdaylighttime))
    {
        eventData.data.systemStates.stateId = IARM_BUS_SYSMGR_SYSSTATE_TIME_ZONE;
        eventData.data.systemStates.state = 2;
        eventData.data.systemStates.error = 0;

        /* Send the pay load based on DST */
        if(gwdata->usesdaylighttime)
        {
            snprintf(eventData.data.systemStates.payload,
                     sizeof(eventData.data.systemStates.payload),"%s", m_timezoneinfo[currTZIndex].tzInDst);
        }
        else
        {
            snprintf(eventData.data.systemStates.payload,
                     sizeof(eventData.data.systemStates.payload),"%s", m_timezoneinfo[currTZIndex].tz);
        }
        g_message("broadcastTimeZoneChange: sending SysMgr TZ Event with Payload - %s",eventData.data.systemStates.payload);

        IARM_Bus_BroadcastEvent(IARM_BUS_SYSMGR_NAME, (IARM_EventId_t) IARM_BUS_SYSMGR_EVENT_SYSTEMSTATE, (void *)&eventData, sizeof(eventData));
        prevTzIndex = currTZIndex;
        IsDst = gwdata->usesdaylighttime;
    }
}
#endif

int getSoupStatusFromUrl(char* url)
{
    int ret=0;
    SoupSession *session = soup_session_sync_new_with_options (SOUP_SESSION_TIMEOUT,1, NULL); //timeout 1 secs
    if(session)
    {
        SoupMessage *msg = soup_message_new ("HEAD", url);
        if(msg != NULL)
        {
            soup_session_send_message (session, msg);
            if (SOUP_STATUS_IS_SUCCESSFUL(msg->status_code))
            {
                g_message("soup status for %s success",url);
                ret=1;
            }
        }
        else
            g_message("soup message creation failed url %s ",url);
        soup_session_abort (session);
        g_object_unref (session);
    }
    else
        g_message("soup session creation failed");
    return ret;
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

    if(data == NULL || ifname == NULL)
        return NULL;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        g_message("socket failed\n");
        return data->str;
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , ifname , IFNAMSIZ - 1);
    /* Coverity Fix CID:18403 CHECKED_RETURN */
    if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0 )
    {
       g_message(" ioctl is failed\n");
       close(fd); 
       return data->str;
    }
    close(fd);   //CID:18597 , 158830- negative returns
    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    //display mac address
    //g_print("Mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    g_string_printf(data, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[0], mac[1], mac[2],
                    mac[3], mac[4], mac[5]);
    return data->str;
}
