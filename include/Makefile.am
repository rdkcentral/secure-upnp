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
EXTRA_DIST = xdiscovery.h

libxupnp_la_includedir = $(includedir)
libxupnp_la_include_HEADERS = xdiscovery.h
if GUPNP_GENERIC_MEDIA_RENDERER
   $(info GUPNP_GENERIC_MEDIA_RENDERER is defined)
   EXTRA_DIST += mediabrowser.h
   libxupnp_la_include_HEADERS += mediabrowser.h
else
   $(info GUPNP_GENERIC_MEDIA_RENDERER is not defined)
endif