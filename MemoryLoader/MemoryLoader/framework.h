#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <Windows.h>
#include <Psapi.h>
#include <wincrypt.h>
#include <WinInet.h>

// c++ imports
#include <stdexcept>
#include <vector>
#include <string>
#include <iterator>
#include <filesystem>

// IDA imports
// 4267, 4244 and 4201 are convection related warning produced in IDA SDK
// we assume its OK, so we suppress them to get a clean compilation.
#pragma warning(push)
#pragma warning (disable: 4267)
#pragma warning (disable: 4244)
#pragma warning (disable: 4201)
#include "pro.h"
#include "kernwin.hpp"
#include "loader.hpp"
#include "nalt.hpp"
#include "typeinf.hpp"
#include "auto.hpp"
#include "funcs.hpp"
#include "ua.hpp"
#include "idaldr.h"
#pragma warning (pop)

// own includes
#include "Misc.h"

// 7zip lib imports
#include <bitextractor.hpp>
#include <bitarchiveitem.hpp>
#include <bitarchiveinfo.hpp>
#include <bitexception.hpp>
