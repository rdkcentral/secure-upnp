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

if VIDEO_SUPPORT
AM_CFLAGS=$(GUPNP_CFLAGS) -D$(GUPNP_VERSION)  $(GTHREAD_CFLAGS) $(LIBSOUP_CFLAGS)\
    $(GCRYPT_CFLAGS) $(GNUTLS_CFLAGS) $(LIBGSSDP_CFLAGS) $(LIBXML_CFLAGS) $(LIBFFI_CFLAGS) $(SQLITE_CFLAGS) \
	-I$(top_srcdir)/include 
AM_LDFLAGS=$(GUPNP_LIBS) $(GTHREAD_LIBS) $(GCRYPT_LIBS) \
           $(GNUTLS_LIBS) $(LIBSOUP_LIBS) $(LIBGSSDP_LIBS) -lgcrypt -lgpg-error  $(LIBXML_LIBS) $(LIBFFI_LIBS) $(SQLITE_LIBS) $(GMODULE_LIBS) $(ZLIB_LIBS) -lrfcapi -lsecure_wrapper
AM_CFLAGS+=$(GUPNP_CFLAGS) -D$(GUPNP_VERSION) ${IARM_CFLAGS} $(DBUS_CFLAGS) $(GTHREAD_CFLAGS) $(LIBSOUP_CFLAGS)\
    $(GCRYPT_CFLAGS) $(GNUTLS_CFLAGS) $(LIBGSSDP_CFLAGS) $(LIBXML_CFLAGS) $(LIBFFI_CFLAGS) $(SQLITE_CFLAGS) \
	-I$(top_srcdir)/include -I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rdk/iarmbus \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/directfb \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rdk/iarmmgrs-hal \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rdk/iarmmgrs/sysmgr \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rdk/iarmmgrs/ir \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/wdmp-c \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)
AM_LDFLAGS+=$(GUPNP_LIBS) $(IARMBUSLIB) $(IARMLIB) $(DBUS_LIBS) $(GTHREAD_LIBS) $(GCRYPT_LIBS) \
           $(GNUTLS_LIBS) $(LIBSOUP_LIBS) $(LIBGSSDP_LIBS) -lgcrypt -lgpg-error  $(LIBXML_LIBS) $(LIBFFI_LIBS) $(SQLITE_LIBS) $(GMODULE_LIBS) $(ZLIB_LIBS) -lrdkloggers
else
if BROADBAND_SUPPORT 
AM_CFLAGS=$(GUPNP_CFLAGS) -D$(GUPNP_VERSION)  $(GTHREAD_CFLAGS) $(LIBSOUP_CFLAGS)\
    $(GCRYPT_CFLAGS) $(GNUTLS_CFLAGS) $(LIBGSSDP_CFLAGS) $(LIBXML_CFLAGS) $(LIBFFI_CFLAGS) $(SQLITE_CFLAGS) \
	-I$(top_srcdir)/include 
AM_LDFLAGS=$(GUPNP_LIBS) $(GTHREAD_LIBS) $(GCRYPT_LIBS) \
           $(GNUTLS_LIBS) $(LIBSOUP_LIBS) $(LIBGSSDP_LIBS) -lgcrypt -lgpg-error -lccsp_common -lhal_platform -lhal_moca -lhal_msomgmt -lcm_mgnt -llmapi -lhal_ethsw $(LIBXML_LIBS) $(LIBFFI_LIBS) $(SQLITE_LIBS) $(GMODULE_LIBS) $(ZLIB_LIBS) -lsyscfg -lsecure_wrapper

AM_CFLAGS+=$(GUPNP_CFLAGS) -D$(GUPNP_VERSION) ${IARM_CFLAGS} $(DBUS_CFLAGS) $(GTHREAD_CFLAGS) $(LIBSOUP_CFLAGS)\
    $(GCRYPT_CFLAGS) $(GNUTLS_CFLAGS) $(LIBGSSDP_CFLAGS) $(LIBXML_CFLAGS) $(LIBFFI_CFLAGS) $(SQLITE_CFLAGS) \
	-I$(top_srcdir)/include -I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rdk/iarmbus \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/ccsp \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/directfb \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rdk/iarmmgrs-hal \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rdk/iarmmgrs/sysmgr \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rdk/iarmmgrs/ir
AM_LDFLAGS+=$(GUPNP_LIBS) $(IARMBUSLIB) $(IARMLIB) $(DBUS_LIBS) $(GTHREAD_LIBS) $(GCRYPT_LIBS) \
           $(GNUTLS_LIBS) $(LIBSOUP_LIBS) $(LIBGSSDP_LIBS) -lgcrypt -lgpg-error  $(LIBXML_LIBS) $(LIBFFI_LIBS) $(SQLITE_LIBS) $(GMODULE_LIBS) $(ZLIB_LIBS) -lrdkloggers
else
AM_CFLAGS=$(GUPNP_CFLAGS) -D$(GUPNP_VERSION) ${IARM_CFLAGS} $(DBUS_CFLAGS) $(GTHREAD_CFLAGS) $(LIBSOUP_CFLAGS)\
    $(GCRYPT_CFLAGS) $(GNUTLS_CFLAGS) $(LIBGSSDP_CFLAGS) $(LIBXML_CFLAGS) $(LIBFFI_CFLAGS) $(SQLITE_CFLAGS) \
	-I$(top_srcdir)/include -I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rdk/iarmbus \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/directfb \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rdk/iarmmgrs-hal \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rdk/iarmmgrs/sysmgr \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rdk/iarmmgrs/ir

AM_LDFLAGS=$(GUPNP_LIBS) $(IARMBUSLIB) $(IARMLIB) $(DBUS_LIBS) $(GTHREAD_LIBS) $(GCRYPT_LIBS) \
           $(GNUTLS_LIBS) $(LIBSOUP_LIBS) $(LIBGSSDP_LIBS) -lgcrypt -lgpg-error  $(LIBXML_LIBS) $(LIBFFI_LIBS) $(SQLITE_LIBS) $(GMODULE_LIBS) $(ZLIB_LIBS) -lrdkloggers
endif
endif
AM_CFLAGS+=$(BREAKPAD_CFLAGS)
AM_LDFLAGS+=$(BREAKPAD_LFLAGS)
AM_CFLAGS+=  -g3

if BROADBAND_SUPPORT
xcal_device_LDADD = $(top_builddir)/broadband/lib/libxdevice.la
if RDKB_INTER_DEVICE_MANAGER_SUPPORT
lib_LTLIBRARIES = libupnpidm.la
libupnpidm_la_SOURCES = idm_server.c idm_client.c idm_library.c
endif
endif
if VIDEO_SUPPORT
xcal_device_LDADD = $(top_builddir)/video/lib/libxdevice.la
endif
bin_PROGRAMS= xcal-device xdiscovery
if VIDEO_SUPPORT
xcal_device_SOURCES = ../xcal-device-main.c
else
if BROADBAND_SUPPORT
xcal_device_SOURCES = ../xcal-device-main.c
else
xcal_device_SOURCES = xcal-device.c
endif
endif
xdiscovery_SOURCES = xdiscovery.c

if GUPNP_GENERIC_MEDIA_RENDERER
xdiscovery_SOURCES += mediabrowser.c dlna-rpc/mbwsr_rpc_srv.c
AM_CFLAGS+=-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rbus
AM_LDFLAGS+=-lrbus
SUBDIRS += dlna-rpc
endif

if WITH_GTEST_SUPPORT
SUBDIRS += test
endif
