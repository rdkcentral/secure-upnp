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
ifeq ($(USE_UNIFIED), y)
USE_IARM=n
USE_IARM_BUS=y
endif

-include ../../soc/$(PLATFORM_SOC)/defs.mk


CC=$(CROSS_COMPILE)-gcc
CXX=$(CROSS_COMPILE)-g++

CORE_CFLAGS = -I.\
	-I../include \
	-I$(OPENSOURCE_HOME)/include \
	-I$(OPENSOURCE_HOME)/include/libxml2 \
	-I$(OPENSOURCE_HOME)/include/gssdp-1.0 \
	-I$(OPENSOURCE_HOME)/include/libsoup-2.4 \
	-I$(CROSS_TOOLCHAIN)/include \
	-I$(CROSS_TOOLCHAIN)/include/glib-2.0 \
	-I$(CROSS_TOOLCHAIN)/include/gio-unix-2.0 \
	-I$(CROSS_TOOLCHAIN)/lib/glib-2.0/include \
	-I$(CROSS_TOOLCHAIN)/usr/include \
	-I$(CROSS_TOOLCHAIN)/usr/local/include \
	-I$(CROSS_TOOLCHAIN)/include/libxml2 \
	-I$(OPENSOURCE_HOME)/include/gupnp-1.0/ \
	-I$(OPENSOURCE_HOME)/include/glib-2.0 \
	-I$(OPENSOURCE_HOME)/include/gio-unix-2.0 \
	-I$(OPENSOURCE_HOME)/lib/glib-2.0/include \
	-I$(SDK_APPLIBS_HOME)/usr/local/include/ \
	-I$(SDK_APPLIBS_HOME)/usr/local/include/glib-2.0 \
	-I$(SDK_APPLIBS_HOME)/usr/local/include/gio-unix-2.0 \
	-I$(SDK_APPLIBS_HOME)/usr/local/lib/glib-2.0/include


ifeq ($(USE_IARM), y)
CFLAGS = $(CORE_CFLAGS) $(IARM_CFLAGS) -DUSE_XUPNP_IARM
else ifeq ($(USE_IARM_BUS), y)
CFLAGS = $(CORE_CFLAGS) $(IARM_CFLAGS) -DUSE_XUPNP_IARM_BUS
else
CFLAGS = $(CORE_CFLAGS)
endif


CFLAGS += $(SOC_CFLAGS) -g3

CFLAGS += -D$(GUPNP_VERSION)

CORE_LDFLAGS=-L.\
                -L$(OPENSOURCE_HOME)/lib \
		-L$(OPENSOURCE_HOME)/libxml2 \
		-L$(CROSS_TOOLCHAIN)/usr/lib \
		-L$(CROSS_TOOLCHAIN)/usr/local/lib \
		-L$(CROSS_TOOLCHAIN)/lib \
		-L$(SDK_APPLIBS_HOME)/usr/local/lib
	
ifeq ($(USE_IARM), y)
LDFLAGS = $(CORE_LDFLAGS) $(IARM_LDFLAGS)
else ifeq ($(USE_IARM_BUS), y)
LDFLAGS = $(CORE_LDFLAGS) $(IARM_LDFLAGS)
else
LDFLAGS = $(CORE_LDFLAGS)
endif

LDFLAGS += $(SOC_LDFLAGS)

G_LIBS1=-lglib-2.0 -lgthread-2.0 -lgobject-2.0 -lgio-2.0

ifeq ($(USE_UNIFIED), y)
G_LIBS=$(G_LIBS1) -lffi -luuid -lstdc++
else
G_LIBS=$(G_LIBS1)
endif

ifeq ($(ENABLE_BREAKPAD),y)
CFLAGS += -I$(OPENSOURCE_HOME)/include/breakpad -DENABLE_BREAKPAD
CXXFLAGS += -I${top_srcdir}/src/main -I$(PKG_CONFIG_SYSROOT_DIR)${includedir} -I$(PKG_CONFIG_SYSROOT_DIR)${includedir}/wdmp-c
LDFLAGS += -L$(OPENSOURCE_HOME)/lib/ -lbreakpad_client -lbreakpadwrapper -lrfcapi
endif

ifeq ($(USE_IARM), y)
UPNP_LIBS= $(UPNP1_LIBS) $(G_LIBS) -lxml2 -lz -lgmodule-2.0 -lgpg-error -lgcrypt -lgnutls -lsoup-2.4 -lgssdp-1.0 -lgupnp-1.0 $(IARM_LIBS)
else ifeq ($(USE_IARM_BUS), y)
UPNP_LIBS= $(UPNP1_LIBS) $(G_LIBS) -lxml2 -lz -lgmodule-2.0 -lgpg-error -lgcrypt -lgnutls -lsoup-2.4 -lgssdp-1.0 -lgupnp-1.0 $(IARM_LIBS)
else
UPNP_LIBS= $(UPNP1_LIBS) $(G_LIBS) -lxml2 -lz -lgmodule-2.0 -lgpg-error -lgcrypt -lgnutls -lsoup-2.4 -lgssdp-1.0 -lgupnp-1.0
endif

.PHONY: discovery device install

all : clean  discovery device
disconly : clean discovery
	DISCONLY=true

ifeq ($(ENABLE_BREAKPAD),y)	
breakpad: breakpadWrapper.cpp
	$(CXX) -c -fpic $(CFLAGS) $(CXXFLAGS)   breakpadWrapper.cpp
	$(CC)  -static-libgcc -shared -fpic   -o libbreakpadWrapper.so breakpadWrapper.o  $(LDFLAGS)

discovery: breakpad xdiscovery.o 
	$(CC) -v $(CFLAGS) $(UPNP_LIBS) $(LDFLAGS)  -lbreakpadWrapper xdiscovery.o  -o xdiscovery
device: xcal-device.o
	$(CC) -v $(CFLAGS) $(LDFLAGS) $(UPNP_LIBS) -lbreakpadWrapper xcal-device.o -o xcal-device
else

discovery: xdiscovery.o 
	$(CC) -v $(CFLAGS) $(LDFLAGS) $(UPNP_LIBS) xdiscovery.o -o xdiscovery
device: xcal-device.o
	$(CC) -v $(CFLAGS) $(LDFLAGS) $(UPNP_LIBS) xcal-device.o -o xcal-device
endif
clean:
	rm -rf *.o xcal-device xdiscovery xcal-discovery-list *.so
	rm -rf ../bin

install:
	echo "Installing all UPnP objects -------"
	mkdir -p ../bin
	cp xcal-device ../bin/
	cp xdiscovery ../bin/

install1:
	echo "Installing discovery objects -------"
	mkdir -p ../bin
	cp xdiscovery  ../bin/
