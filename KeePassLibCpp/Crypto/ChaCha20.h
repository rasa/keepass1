/*
  KeePass Password Safe - The Open-Source Password Manager
  Copyright (C) 2003-2024 Dominik Reichl <dominik.reichl@t-online.de>

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

#ifndef ___CHACHA20_H___
#define ___CHACHA20_H___

#pragma once

#include "../SysDefEx.h"
#include <boost/utility.hpp>
#include "CtrBlockCipher.h"

// Implementation of the ChaCha20 cipher with a 96-bit nonce,
// as specified in RFC 8439 (7539).
// https://datatracker.ietf.org/doc/html/rfc8439
class CChaCha20 : boost::noncopyable, public CCtrBlockCipher
{
public:
	CChaCha20(const BYTE* pbKey32, const BYTE* pbIV12, bool bLargeCounter);
	virtual ~CChaCha20();

	HRESULT Seek(INT64 iOffset, int sOrigin);

	static HRESULT Crypt(BYTE* pbMsg, size_t cbMsg, const BYTE* pbKey32,
		const BYTE* pbIV12 = NULL, bool bLargeCounter = true);

protected:
	virtual HRESULT NextBlock(BYTE* pbBlock);

private:
	UINT32 m_s[16];
	bool m_bLargeCounter;
};

#endif // ___CHACHA20_H___
