#!/bin/sh

. /etc/include.properties

if [ -f $RDK_PATH/utils.sh ]; then
   . $RDK_PATH/utils.sh
fi

getESTBInterfaceName()
{
   if [ -f /tmp/wifi-on ]; then
      interface=`getWiFiInterface`
   else
      interface=$MOCA_INTERFACE
      if [ ! "$interface" ]; then
                interface=eth1
      fi
   fi
   echo ${interface}
}

#Opening Required PORTS
XDIAL_IFNAME=$(getESTBInterfaceName)
echo $XDIAL_IFNAME
ROUTE_ADDR=$1
echo $ROUTE_ADDR
ip="$(grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' <<< "$ROUTE_ADDR")"
count=$(route -n | grep -c $ip)
echo $count
if [ $count -ge 1 ]
then
    echo "route is already added for $ROUTE_ADDR"
else
    echo "adding route for $ROUTE_ADDR"
    ip route add $ROUTE_ADDR dev  $XDIAL_IFNAME
fi
