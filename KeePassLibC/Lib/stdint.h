/*
  KeePass Password Safe - The Open-Source Password Manager
  Copyright (C) 2003-2022 Dominik Reichl <dominik.reichl@t-online.de>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef ___KP_STD_INT_H___
#define ___KP_STD_INT_H___

#pragma once

#include <stddef.h>
#include <limits.h>

#if (UCHAR_MAX == 0xFF)
typedef unsigned char uint8_t;
#else
typedef unsigned __int8 uint8_t;
#endif

#if (UINT_MAX == 0xFFFFFFFFU)
typedef unsigned int uint32_t;
#define UINT32_C(__x) __x##U
#elif (ULONG_MAX == 0xFFFFFFFFUL)
typedef unsigned long uint32_t;
#define UINT32_C(__x) __x##UL
#elif (USHRT_MAX == 0xFFFFFFFFU)
typedef unsigned short uint32_t;
#define UINT32_C(__x) __x
#else
typedef unsigned __int32 uint32_t;
#define UINT32_C(__x) __x##UI32
#endif

#define UINT32_MAX UINT32_C(0xFFFFFFFF)

#if (ULLONG_MAX == 0xFFFFFFFFFFFFFFFFULL)
typedef unsigned long long uint64_t;
#define UINT64_C(__x) __x##ULL
#else
typedef unsigned __int64 uint64_t;
#define UINT64_C(__x) __x##UI64
#endif

#define UINT64_MAX UINT64_C(0xFFFFFFFFFFFFFFFF)

#endif // ___KP_STD_INT_H___
