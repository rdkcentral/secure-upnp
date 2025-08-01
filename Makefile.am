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
if VIDEO_SUPPORT
SUBDIRS = video conf src include
DIST_SUBDIRS = video cfg conf src include
else
if BROADBAND_SUPPORT
SUBDIRS = broadband conf src include
DIST_SUBDIRS = cfg broadband conf src include
else
SUBDIRS = src include conf
DIST_SUBDIRS = cfg src include conf
endif
endif
distcleancheck_listfiles = *-libtool

## IPK Generation Support
IPK_GEN_PATH = $(abs_top_builddir)/ipk
IPK_GEN_STAGING_DIR=$(abs_top_builddir)/staging_dir
IPK_GEN_INPUT  = debian-binary control.tar.gz data.tar.gz
IPK_GEN_OUTPUT = xupnp.ipk

AM_CFLAGS = $(IARM_CFLAGS)

if BROADBAND_SUPPORT
package_ipk:
	@echo "Generating IPK Package"
	$(MAKE) prefix=${abs_top_builddir}/staging_dir install
	$(mkdir_p) $(IPK_GEN_STAGING_DIR)/etc/xupnp/
	$(mkdir_p) $(IPK_GEN_STAGING_DIR)/usr/bin/
	$(mkdir_p) $(IPK_GEN_STAGING_DIR)/lib/rdk/
	cp -af ${abs_top_builddir}/conf/*.xml $(IPK_GEN_STAGING_DIR)/etc/xupnp/
	cp -af ${abs_top_builddir}/conf/*.pem $(IPK_GEN_STAGING_DIR)/etc/xupnp/
	cp -af ${abs_top_builddir}/conf/broadband/start_upnp.sh $(IPK_GEN_STAGING_DIR)/lib/rdk/
	cp -af ${abs_top_builddir}/conf/broadband/start-upnp-service $(IPK_GEN_STAGING_DIR)/lib/rdk/
	cp -af ${abs_top_builddir}/conf/broadband/processPID.sh $(IPK_GEN_STAGING_DIR)/lib/rdk/
	cp -af $(IPK_GEN_STAGING_DIR)/bin/* $(IPK_GEN_STAGING_DIR)/usr/bin/
else
package_ipk:
	@echo "Generating IPK Package"
	$(MAKE) prefix=${abs_top_builddir}/staging_dir install
	$(mkdir_p) $(IPK_GEN_STAGING_DIR)/etc/Xupnp/
	$(mkdir_p) $(IPK_GEN_STAGING_DIR)/etc/xupnp/
	$(mkdir_p) $(IPK_GEN_STAGING_DIR)/usr/bin/
	$(mkdir_p) $(IPK_GEN_STAGING_DIR)/lib/systemd/system/
	cp -af ${abs_top_builddir}/conf/*.xml $(IPK_GEN_STAGING_DIR)/etc/xupnp/
	cp -af ${abs_top_builddir}/conf/systemd/xupnp.service $(IPK_GEN_STAGING_DIR)/lib/systemd/system/
	cp -af ${abs_top_builddir}/conf/*.pem $(IPK_GEN_STAGING_DIR)/etc/xupnp/
	cp -af ${abs_top_builddir}/conf/systemd/dpcg-s.sh $(IPK_GEN_STAGING_DIR)/etc/Xupnp/
	cp -af ${abs_top_builddir}/conf/systemd/dpcg.sh $(IPK_GEN_STAGING_DIR)/etc/Xupnp/
	cp -af $(IPK_GEN_STAGING_DIR)/bin/* $(IPK_GEN_STAGING_DIR)/usr/bin/
	rm -rf $(IPK_GEN_STAGING_DIR)/etc/*.xml
	tar -czvf $(IPK_GEN_PATH)/data.tar.gz -C $(IPK_GEN_STAGING_DIR) etc usr lib
	tar -czvf $(IPK_GEN_PATH)/control.tar.gz -C $(IPK_GEN_PATH) control postinst prerm
	cd $(IPK_GEN_PATH) && ar cr $(IPK_GEN_OUTPUT) $(IPK_GEN_INPUT) && cd -
	rm -rf ${abs_top_builddir}/staging_dir
	rm -rf $(abs_top_builddir)/ipk/control.tar.gz
	rm -rf $(abs_top_builddir)/ipk/data.tar.gz
endif
