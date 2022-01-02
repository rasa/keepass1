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

#ifndef ___ALIGNED_BUFFER_H___
#define ___ALIGNED_BUFFER_H___

#pragma once

#include <windows.h>
#include <cstddef>
#include <boost/utility.hpp>

class CAlignedBuffer : boost::noncopyable
{
public:
	CAlignedBuffer(size_t cbSize, size_t cbAlignment,
		bool bZeroOnConstruct, bool bZeroOnDestruct);
	CAlignedBuffer(size_t cbSize, size_t cbAlignment,
		const BYTE* pbInit, bool bZeroOnDestruct);
	virtual ~CAlignedBuffer();

	BYTE* Data() { return m_pb; }

private:
	CAlignedBuffer();

	static BYTE* AllocAlignedMemory(size_t cbSize, size_t cbAlignment);

	BYTE* m_pb;
	size_t m_cb;

	bool m_bZeroOnDestruct;
};

#endif // ___ALIGNED_BUFFER_H___
