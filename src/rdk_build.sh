#!/bin/bash
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

#######################################
#
# Build Framework standard script for
#
# xupnp component

# use -e to fail on any shell issue
# -e is the requirement from Build Framework
set -xe


# default PATHs - use `man readlink` for more info
# the path to combined build
export RDK_PROJECT_ROOT_PATH=${RDK_PROJECT_ROOT_PATH-`readlink -m ../../..`}
export COMBINED_ROOT=$RDK_PROJECT_ROOT_PATH

# path to build script (this script)
export RDK_SCRIPTS_PATH=${RDK_SCRIPTS_PATH-`readlink -m $0 | xargs dirname`}

# path to components sources and target
export RDK_SOURCE_PATH=${RDK_SOURCE_PATH-$RDK_SCRIPTS_PATH}
export RDK_TARGET_PATH=${RDK_TARGET_PATH-$RDK_SOURCE_PATH/..}

# fsroot and toolchain (valid for all devices)
export RDK_FSROOT_PATH=${RDK_FSROOT_PATH-`readlink -m $RDK_PROJECT_ROOT_PATH/sdk/fsroot/ramdisk`}
export RDK_TOOLCHAIN_PATH=${RDK_TOOLCHAIN_PATH-`readlink -m $RDK_PROJECT_ROOT_PATH/sdk/toolchain/staging_dir`}
export EXTRACT_SYMS_PATH=${EXTRACT_SYMS_PATH-${RDK_PROJECT_ROOT_PATH}/build/packager_scripts}


# default component name
export RDK_COMPONENT_NAME=${RDK_COMPONENT_NAME-xupnp}

UPLOAD=0
# parse arguments
INITIAL_ARGS=$@

function usage()
{
    set +x
    echo "Usage: `basename $0` [-h|--help] [-v|--verbose] [-u|--upload-symbols] [--platform-soc] [action]"
    echo "    -h    --help                  : this help"
    echo "    -v    --verbose               : verbose output"
    echo "    --platform-soc  =PLATFORM     : specify platform for xupnp"
    echo "    -u    --upload-symbols        : upload symbols"
    echo
    echo "Supported actions:"
    echo "      configure, clean, build (DEFAULT), rebuild, install"
}

# options may be followed by one colon to indicate they have a required argument
if ! GETOPT=$(getopt -n "build.sh" -o hvup: -l help,verbose,upload-symbols,platform-soc: -- "$@")
then
    usage
    exit 1
fi

eval set -- "$GETOPT"

while true; do
  case "$1" in
    -h | --help ) usage; exit 0 ;;
    -v | --verbose ) set -x ;;
    -u | --upload-symbols ) UPLOAD=1 ;;
    --platform-soc ) export RDK_PLATFORM_SOC="$2" ; shift ;;
    -- ) shift; break;;
    * ) break;;
  esac
  shift
done

ARGS=$@


# component-specific vars
if [ -z "$RDK_PLATFORM_SOC" ]; then
    usage
    echo "RDK_PLATFORM_SOC must be provided"
    exit 1
fi

export PLATFORM_SOC=$RDK_PLATFORM_SOC
# Do not override the build functions when hybrid selected; the configure script should be taking care of it.. ie DO source the rdk_init.sh only when legacy way of compilation is choosen
if [ "x$BUILD_CONFIG" == "xhybrid-legacy" ];then

# relative to generic/src
PLATFORM_INIT_FILE=${PLATFORM_INIT_FILE-$RDK_SCRIPTS_PATH/../../build_scripts/rdk_init.sh}
[ -f $PLATFORM_INIT_FILE ] && source $PLATFORM_INIT_FILE

fi

# functional modules

declare -f configure > /dev/null || function configure()
{
    if [ "x$BUILD_CONFIG" == "xhybrid-legacy" ];then
        true
        return
    fi

    cd ${RDK_SOURCE_PATH}
    ./rdk_build.sh.configure configure
}

declare -f clean > /dev/null || function clean()
{
    if [ "x$BUILD_CONFIG" == "xhybrid-legacy" ];then
        true
        return
    fi

    cd ${RDK_SOURCE_PATH}
    ./rdk_build.sh.configure clean
}

declare -f build > /dev/null || function build()
{
    cd ${RDK_SOURCE_PATH}
    if [ "x$BUILD_CONFIG" == "xhybrid-legacy" ];then
        make all install
        return
    fi

    ./rdk_build.sh.configure build
}

declare -f rebuild > /dev/null || function rebuild()
{
    cd ${RDK_SOURCE_PATH}
    if [ "x$BUILD_CONFIG" == "xhybrid-legacy" ];then
        make clean all install
        return
    fi

    ./rdk_build.sh.configure rebuild
}

declare -f install > /dev/null || function install()
{
    if [ "x$BUILD_CONFIG" == "xhybrid-legacy" ];then
        cd ${RDK_TARGET_PATH}

        library=$(ls ${RDK_TARGET_PATH}/src/*.so 2> /dev/null | wc -l)
        if [ $library != 0 ]; then
            cp src/*.so ${RDK_FSROOT_PATH}/usr/local/lib
        fi
        #cp -R lib/*.so ${RDK_FSROOT_PATH}lib
        cp -R bin/* ${RDK_FSROOT_PATH}/usr/local/bin
        CONF_PATH=${RDK_FSROOT_PATH}/etc/xupnp
        mkdir -p ${CONF_PATH}

        cp conf/*.xml ${CONF_PATH}
        conffiles=$(ls ${RDK_TARGET_PATH}/../conf/xd* 2> /dev/null | wc -l)
        if [ "$conffiles" != "0" ]; then
            cp ../conf/xd*.conf ${CONF_PATH}
        fi
        return
   fi

   cd ${RDK_SOURCE_PATH}
   ./rdk_build.sh.configure install
}


# run the logic

#these args are what left untouched after parse_args
HIT=false

for i in "$ARGS"; do
    case $i in
        configure)  HIT=true; configure ;;
        clean)      HIT=true; clean ;;
        build)      HIT=true; build ;;
        rebuild)    HIT=true; rebuild ;;
        install)    HIT=true; install ;;
        *)
            #skip unknown
        ;;
    esac
done

# if not HIT do build by default
if ! $HIT; then
  build
fi
