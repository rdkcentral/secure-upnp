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
 * @file xdiscovery.h
 * @brief The header file provides xdiscovery APIs.
 */

/**
 * @defgroup XUPNP XUPnP
 * @par XUPnP Overview:
 * XUPnP is an implementation of the generic GUPnP framework for device discovery and using services from control points.
 * GUPnP is a library for implementing both UPnP clients and services using GObject and LibSoup.
 * It allows for fully asynchronous use without using threads and so cleanly integrates naturally
 * into daemons, and supports all of the UPnP features.
 * The GUPnP framework consists of the following libraries:
 * - GSSDP implements resource discovery and announcement over SSDP.
 * - GUPnP implements the UPnP specification:
 * @n
 * @li Resource announcement and discovery.
 * @li Description.
 * @li Control.
 * @li Event notification.
 * @li Presentation (GUPnP includes basic web server functionality through libsoup).
 *
 * @par Procedure involving in implementation of the GUPnP Client:
 *
 * - <b> Finding Services:</b>
 *  Initialize GUPnP and create a control point targeting the service type.
 *  Then we connect a signal handler so that we are notified when services we are interested in are found.
 * @n
 * - <b> Invoking Actions:</b>
 * GUPnP has a set of methods to invoke actions  where you pass a NULL-terminated varargs list
 * of (name, GType, value) tuples for the in-arguments, then a NULL-terminated varargs list of
 * (name, GType, return location) tuples for the out-arguments.
 * @n
 * - <b> Subscribing to state variable change notifications:</b>
 * It is possible to get change notifications for the service state variables that have attribute sendEvents="yes".
 *
 * @par XUPnP Applications:
 * @n
 * The XUPnP daemon xdiscovery runs in system on MoCA interface.
 * @n While starting the xdiscovery service, we create a UPnP control point with target device type as
 * urn:schemas-upnp-org:device:BasicDevice:1.
 * @n Once UPNP control point is added and active in the network, It search for the target device
 * types in the network.
 * @n The device-proxy-available Signal is emitted when any device which matches target types is found
 * in the network and the event is handled in a callback routine.
 * @n @n
 * The discovery messages contains a few information about the device , Usually the device descriptions
 * is in an XML file and it includes vendor specific information like Manufacturer, Model Name, Serial No.,
 * URL to vendor specific web sites etc. Also it lists the services as well if any.
 * @n @n
 * Each service description includes a list of commands to which the service responds with its parameters and arguments.
 * The UPnP control point subscribes for the notification if any of the service variable changes during run time.
 * @n @n
 * After the device is discovered in the network, the UPnP control point send an action by calling the GUPnP API
 * gupnp_service_proxy_send_action() to retrieve device info and its capabilities.
 * @n @n
 * After that it add or update the device in device list using its serial number.
 * @n @n
 * Gateway set up : Internally XUPnP uses a script /lib/rdk/gwSetup.sh to set up the gateway in client devices.
 * Here we sets up the routing table, DNS setting etc.
 * @n
 * @par An example of XUPnP Device Info in JSON format
 * @code
 *	{
 *		"sno":"PAD200067027",
 *		"isgateway":"yes",
 *		"gatewayip":"169.254.106.182",
 *		"gatewayipv6":"null",
 *		"hostMacAddress":"84:e0:58:57:73:55",
 *		"gatewayStbIP":"69.247.111.43",
 *		"ipv6Prefix":"null",
 *		"deviceName":"null",
 *		"bcastMacAddress":"84:e0:58:57:73:59",
 *		"recvDevType":"X1",
 *		"buildVersion":"66.77.33p44d5_EXP",
 *		"timezone":"US/Eastern",
 *		"rawoffset":"-18000000",
 *		"dstoffset":"60",
 *		"dstsavings":"3600000",
 *		"usesdaylighttime":"yes",
 *		"baseStreamingUrl":"http://127.0.0.1:8080/videoStreamInit?recorderId=P0118154760",
 *		"requiresTRM":"true",
 *		"baseTrmUrl":"ws://127.0.0.1:9988",
 *		"playbackUrl":"http://127.0.0.1:8080/hnStreamStart?deviceId=P0118154760&DTCP1HOST=127.0.0.1&DTCP1PORT=5000",
 *		"dnsconfig":"search hsd.tvx.comcast.net;nameserver 75.75.75.75;nameserver 75.75.76.76;nameserver 69.252.80.80;",
 *		"hosts":"69.247.111.43 pacexg1v3;",
 *		"systemids":"channelMapId:1901;controllerId:3415;plantId:0;vodServerId:70001",
 *		"receiverid":"P0118154760"
 *	}
 * @endcode
 *
 * @ingroup XUPNP
 *
 * @defgroup XUPNP_XDISCOVERY XUPnP XCal-Discovery
 * Describe the details about XUPnP XCal-Discovery specifications.
 * @ingroup XUPNP
 *
 * @defgroup XUPNP_XDISCOVERY_FUNC XUPnP XCal-Discovery Functions
 * Describe the details about XUPnP XCal-Discovery specifications.
 * @ingroup XUPNP_XDISCOVERY
 */

#ifndef XDISCOVERY_H
#define XDISCOVERY_H

#define  _IARM_XUPNP_NAME							"XUPnP" /*!< Method to Get the Xupnp Info */
#define  IARM_BUS_XUPNP_API_GetXUPNPDeviceInfo		"GetXUPNPDeviceInfo" /*!< Method to Get the Xupnp Info */

#endif // XDISCOVERY_H
