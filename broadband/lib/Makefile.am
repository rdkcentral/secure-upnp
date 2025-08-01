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
SUBDIRS =  
AM_CFLAGS=$(DBUS_CFLAGS) $(GTHREAD_CFLAGS) $(LIBSOUP_CFLAGS) \
	-I$(top_srcdir)/include -I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rdk/iarmbus \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/directfb \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rdk/iarmmgrs-hal \
        -I$(top_srcdir)/include \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rdk/iarmmgrs/sysmgr \
	-I$(top_srcdir)/broadband/lib/include \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/ccsp

AM_CFLAGS+=  -g3
AM_LDFLAGS=$(IARMBUSLIB) $(IARMLIB) $(DBUS_LIBS) $(GTHREAD_LIBS) $(LIBSOUP_LIBS) -lccsp_common -lhal_platform -lhal_moca -lhal_msomgmt -lcm_mgnt -llmapi -lsyscfg -lsecure_wrapper
AM_LDFLAGS+=-lhal_ethsw

noinst_LTLIBRARIES = libxdevice.la
libxdevice_la_SOURCES = src/xcal-device-library.c

