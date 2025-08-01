#!/bin/sh
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2016 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
#
x=""
while [ "started" != "$x" ]
do
   x=`sysevent get lan-status`
   echo "sysevent status = $x"
   start_upnp=`syscfg get start_upnp_service`
   if [[ "$start_upnp" != "true" && "z$x" != "z" ]]; then
       echo "Stopping Xcal as RFC disabled"
       systemctl stop xcal-device.service
   fi
   y=`sysevent get bridge_mode`
   if [ "z$y" == "z" ]; then
       echo "Delay in fetching Bridge mode details from syscfg. Retrying.."
       x=""
   fi
   if [[ "$y" != "0" && "z$x" != "z" ]] ; then
       echo "Shutting down the services as Bridge mode is Enabled"
       systemctl stop xupnp
       systemctl stop xcal-device
   fi

   sleep 2
done
status=""
while [ "X$status" == "X" ]
do
        status=`psmcli get dmsb.l2net.HomeNetworkIsolation`

	#Handle PSM fallback case
        if [ "$status" == "" ];
	then
	      status=0
 	fi

        if [ $status == "0" ];
        then
                echo "Moca Isolation disabled creating new interface brlan0:0"
		ifconfig brlan0:0 169.254.100.1 netmask 255.255.255.0 up
		MOCA_INTERFACE="brlan0:0"
                XCAL_DEF_INTERFACE="brlan0:0"
        sysevent set xcal_mocaisol_disabled_inf $XCAL_DEF_INTERFACE
        else
                echo "Moca Isolation Enabled, using brlan10 interface"
		MOCA_INTERFACE="brlan10"
                XCAL_DEF_INTERFACE="brlan10"
        fi
        echo "Success"
done

export XCAL_DEF_INTERFACE=$MOCA_INTERFACE

. /etc/device.properties
. /etc/include.properties
if [ -f /SetEnv.sh ]; then
    . /SetEnv.sh
fi
. $RDK_PATH/utils.sh
if [ -f $RDK_PATH/commonUtils.sh ]; then
   . $RDK_PATH/commonUtils.sh
fi
WAREHOUSE_ENV="$RAMDISK_PATH/warehouse_mode_active"
LOG_PATH="/rdklogs/logs"
export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib:/lib:$LD_LIBRARY_PATH
if [ "$FS_DBUS_SIGNAL_HANDLER" = "false" ]; then
    export FSARGS="no-sighandler"
    export DFBARGS="no-sighandler"
fi
wifi_interface=""
# initial cleanup
killall xdiscovery
if [ "$GATEWAY_DEVICE" = "yes" ];then
     killall xcal-device
fi
# inputs arguments
XDISC_LOG_FILE=""
if [ "$1" != "" ]; then
     XDISC_LOG_FILE="$1"
fi

mkdir -p /nvram/xupnp
stbIp=""
mocaIpWait()
{
  while [ -z $stbIp ]
  do
   stbIp=`ifconfig $XCAL_DEF_INTERFACE | grep inet | tr -s ' ' | cut -d ' ' -f3 | sed -e 's/addr://g'`
   sleep 2
   echo "MoCA ipaddress is not assigned, waiting to get the STB Ipaddress"
  done
  echo "Got MOCA Ip Address: $stbIp"
}

estbIpWait()
{
   loop=1
   while [ $loop -eq 1 ]
   do
       estbIp=`getIPAddress`
       if [ "X$estbIp" == "X" ]; then
           sleep 10
       else
           if [ "$IPV6_ENABLED" = "true" ]; then
                if [ "Y$estbIp" != "Y$DEFAULT_IP" ] && [ -f $WAREHOUSE_ENV ]; then
                   loop=0
                elif [ ! -f /tmp/estb_ipv4 ] && [ ! -f /tmp/estb_ipv6 ]; then
                   sleep 10
                elif [ "Y$estbIp" == "Y$DEFAULT_IP" ] && [ -f /tmp/estb_ipv4 ]; then
                   #echo "waiting for IP ..."
                   sleep 10
                else
                   loop=0
                fi
           else
                if [ "Y$estbIp" == "Y$DEFAULT_IP" ]; then
                    #echo "waiting for IP ..."
                    sleep 10
                else
                    loop=0
                fi
          fi
      fi
done
}
# configuration setup

xcalDeviceConfig="/etc/xupnp/xdevice.conf"
if [ "$BUILD_TYPE" != "prod" ] && [ -f /etc/xdevice.conf ]; then
     xcalDeviceConfig="/etc/xdevice.conf"
fi
xcalDiscoveryConfig="/etc/xdiscovery.conf"
if [ "$BUILD_TYPE" != "prod" ] && [ -f /etc/xdiscovery.conf ]; then
     xcalDiscoveryConfig="/etc/xdiscovery.conf"
fi

echo "Moca interface =  $XCAL_DEF_INTERFACE"
echo "Mediaclient Execution..!"
if [ -s /etc/xupnp/BasicDevice.xml ] || [ -f /etc/xupnp/BasicDevice.xml ]; then
    cp /etc/xupnp/BasicDevice.xml /nvram/xupnp/BasicDevice.xml
    chmod +x /etc/xupnp/BasicDevice.xml
fi
if [ -f /etc/xupnp/DiscoverFriendlies.xml ]; then
    cp /etc/xupnp/DiscoverFriendlies.xml  /nvram/xupnp/DiscoverFriendlies.xml
fi
if [ -f /etc/xupnp/RemoteUIServerDevice.xml ]; then
    cp /etc/xupnp/RemoteUIServerDevice.xml /nvram/xupnp/RemoteUIServerDevice.xml
    chmod +x /nvram/xupnp/RemoteUIServerDevice.xml
fi
if [ -f /etc/xupnp/RemoteUIServer.xml ]; then
    cp /etc/xupnp/RemoteUIServer.xml /nvram/xupnp/RemoteUIServer.xml
fi
if [ -f /etc/xupnp/X1BroadbandGateway.xml ]; then
    cp /etc/xupnp/X1BroadbandGateway.xml /nvram/xupnp/X1BroadbandGateway.xml
fi
if [ -f /etc/xupnp/X1GatewayConfiguration.xml ]; then
    cp /etc/xupnp/X1GatewayConfiguration.xml /nvram/xupnp/X1GatewayConfiguration.xml
fi
if [ -f /etc/xupnp/X1Time.xml ]; then
    cp /etc/xupnp/X1Time.xml /nvram/xupnp/X1Time.xml
fi
if [ -f /etc/xupnp/X1Identity.xml ]; then
    cp /etc/xupnp/X1Identity.xml /nvram/xupnp/X1Identity.xml
fi

mocaIpWait
INTERFACE_TEST=`ifconfig $XCAL_DEF_INTERFACE`
if [ "X$INTERFACE_TEST" == "X" ] ; then
        echo "XCAL-UPnP - Selected UPnP interface $XCAL_DEF_INTERFACE does not exist ... cannot start Services"
        exit 1
else
        INTERFACE_IP=`ifconfig $XCAL_DEF_INTERFACE | grep 'inet addr:' | cut -d: -f2 | awk '{print $1}'`
        if [ "X$INTERFACE_IP" == "X" ] ; then
                echo "XCAL-UPnP - Selected UPnP interface $XCAL_DEF_INTERFACE does not have a valid ip address ... cannot start Services"
                exit 1
        fi
fi
touch /tmp/start_xupnp
echo "Starting Xcal UPNP client xcal-discovery-list"

