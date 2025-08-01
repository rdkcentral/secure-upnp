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
#ifndef DISABLE_BREAKPAD
#include <client/linux/handler/exception_handler.h>
#include "breakpad_wrapper.h"
#include "rfcapi.h"

// called by 'google_breakpad::ExceptionHandler' on every crash
namespace
{
bool breakpadCallback(const google_breakpad::MinidumpDescriptor& descriptor, void* context, bool succeeded)
{
  (void) descriptor;
  (void) context;
  return succeeded;
}
// Instantiate only one 'google_breakpad::ExceptionHandler'
// - "/opt/minidumps" is canonical path that should be in sync with uploadDumps.sh script
extern "C" void installExceptionHandler()
{
  static google_breakpad::ExceptionHandler* excHandler = NULL;
  delete excHandler;
  RFC_ParamData_t secValue;
  std::string minidump_path;
  WDMP_STATUS status = getRFCParameter("SecureCoreFile", "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.SecDump.Enable", &secValue);
  if ( ( WDMP_SUCCESS == status ) && ( 0 == strncmp(secValue.value, "falsee", 5) ) )
  {
		///RFC  Settings for SecureDump is : false
		minidump_path = "/opt/minidumps";
  }
  else
  {
		//"RFC Settings for SecureDump is : true
		minidump_path = "/opt/secure/minidumps";
  }
  google_breakpad::MinidumpDescriptor descriptor(minidump_path.c_str());
  excHandler = new google_breakpad::ExceptionHandler(descriptor, NULL, breakpadCallback, NULL, true, -1);
}
}
#endif

