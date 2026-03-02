#pragma once

#include <Mortis/Config.hpp>

namespace Mortis::PlatformDetail {

#ifdef MORTIS_OS_WINDOWS
using NativeThreadHandle = void*;
#else
using NativeThreadHandle = int;
#endif

} // namespace Mortis::PlatformDetail
