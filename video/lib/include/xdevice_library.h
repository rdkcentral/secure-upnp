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
 * @file xdevice.h
 * @brief The header file provides xcal devices APIs.
 */

 /**
 * @defgroup XUPNP_XCALDEV XUPnP XCal-Device
 * The XUPnP XCal-Device moudule is responssible for getting the device discovery information.
 * - Read the xupnp configuration details from configuration file.
 * - Getting the input for different gateway to populate all the service veriables.
 * - It act like a server & whenever requested it will give the services details such as ipv6 ip address,
 * receiver Id, etc.
 * - Once the xcal-device receive the services details, it will create a UPnP object and start publishing the UPnP data.
 * @ingroup XUPNP
 *
 * @defgroup XUPNP_XCALDEV_FUNC XUPnP XCal-Device Functions
 * Describe the details about XCal-Device functional specifications.
 * @ingroup XUPNP_XCALDEV
 */

#ifndef __XDEVICE_LIBRARY_H__
#define __XDEVICE_LIBRARY_H__
typedef enum serviceListCb
{
    SERIAL_NUMBER,
    IPV6_PREFIX,
    TUNE_READY,
    DST_OFFSET,
    TIME_ZONE,
    CHANNEL_MAP,
    RAW_OFFSET,
}serviceListCb;

#ifndef BOOL
#define BOOL  unsigned char
#endif
#ifndef TRUE
#define TRUE     1
#endif
#ifndef FALSE
#define FALSE    0
#endif
#ifndef RETURN_OK
#define RETURN_OK   0
#endif
#ifndef RETURN_ERR
#define RETURN_ERR   -1
#endif

BOOL getBaseUrl(char *outValue);
BOOL getFogTsbUrl(char *outValue);
BOOL getPlaybackUrl(char *outValue);
BOOL getVideoBasedUrl(char *outValue);
BOOL getTrmUrl(char *outValue);
BOOL getIpv6Prefix(char *outValue);
BOOL getDeviceName(char *outValue);
BOOL getDeviceType(char *outValue);
BOOL getBcastMacAddress(char *outValue);
BOOL getGatewayStbIp(char *outValue);
BOOL getGatewayIpv6(char *outValue);
BOOL getGatewayIp(char *outValue);
BOOL getRecvDevType(char *outValue);
BOOL getBuildVersion(char *outValue);
BOOL getHostMacAddress(char *outValue);
BOOL getDnsConfig(char *outValue);
BOOL getSystemsIds(char *outValue);
BOOL getTimeZone(char *outValue);
BOOL getRawOffSet(int *outValue);
BOOL getDstOffset(int *outValue);
BOOL getDstSavings(int *outValue);
BOOL getUsesDayLightTime(BOOL *outValue);
BOOL getIsGateway(BOOL *outValue);
BOOL getHosts(char *outValue);
BOOL getRequiresTRM(BOOL *outValue);
BOOL getBcastPort(int *outValue);
BOOL getBcastIf(char *outValue);
BOOL getBcastIp(char *outValue);
BOOL getRUIUrl(char *outValue);
BOOL getSerialNum(char *outValue);
BOOL getPartnerId(char *outValue);
BOOL getUUID(char *outValue);
BOOL getReceiverId(char *outValue);
BOOL getCVPIp(char *outValue);
BOOL getCVPIf(char *outValue);
BOOL getCVPPort(int *outValue);
BOOL getCVPXmlFile(char *outValue);
BOOL getRouteDataGateway(char *outValue);
BOOL getLogFile(char *outValue);
BOOL getDevXmlPath(char *outValue);
BOOL getDevXmlFile(char *outValue, int refactor);
BOOL getModelNumber(char *outValue);
BOOL getMake(char *outValue);
BOOL getAccountId(char *outValue);
BOOL checkCVP2Enabled();
int check_rfc();
BOOL getIpSubnet(char *outValue);
BOOL getDevKeyPath(char *outValue);
BOOL getDevKeyFile(char *outValue);
BOOL getDevCertPath(char *outValue);
BOOL getDevCertPath(char *outValue);
void notify_timezone(void);
//typedef INT (*xdevice_service_callback)(enum serviceListCb , char *data);
//void xdevice_service_register(xdevice_service_callback callback_proc);
#else
#error "! __XDEVICE_LIBRARY_H__"
#endif
