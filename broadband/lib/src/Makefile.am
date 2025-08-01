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
#SUBDIRS = lib 
AM_CFLAGS=$(GUPNP_CFLAGS) -D$(GUPNP_VERSION) ${IARM_CFLAGS} $(DBUS_CFLAGS) $(GTHREAD_CFLAGS) $(LIBSOUP_CFLAGS)\
    $(GCRYPT_CFLAGS) $(GNUTLS_CFLAGS) $(LIBGSSDP_CFLAGS) $(LIBXML_CFLAGS) $(LIBFFI_CFLAGS) $(SQLITE_CFLAGS) \
	-I$(top_srcdir)/include -I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rdk/iarmbus \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/directfb \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rdk/iarmmgrs-hal \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rdk/iarmmgrs/sysmgr \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/rdk/iarmmgrs/ir \
	-I$(top_srcdir)/broadband/lib/include \
	-I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/ccsp

AM_LDFLAGS=$(GUPNP_LIBS) $(IARMBUSLIB) $(IARMLIB) $(DBUS_LIBS) $(GTHREAD_LIBS) $(GCRYPT_LIBS) \
           $(GNUTLS_LIBS) $(LIBSOUP_LIBS) $(LIBGSSDP_LIBS) -lhal_platform -lgcrypt -lgpg-error  $(LIBXML_LIBS) $(LIBFFI_LIBS) $(SQLITE_LIBS) $(GMODULE_LIBS) $(ZLIB_LIBS)

noinst_LTLIBRARIES = libxdevice.la
libxdevice_la_SOURCES = xcal-device-library.c
