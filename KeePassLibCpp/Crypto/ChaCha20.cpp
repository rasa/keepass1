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

#include "StdAfx.h"
#include <boost/static_assert.hpp>
#include "SHA2/EDefs.h"
#include "../Util/MemUtil.h"
#include "ChaCha20.h"

#pragma intrinsic(_rotl, _rotr)

CChaCha20::CChaCha20(const BYTE* pbKey32, const BYTE* pbIV12, bool bLargeCounter) :
	CCtrBlockCipher(64), m_bLargeCounter(bLargeCounter)
{
	m_s[0] = 0x61707865;
	m_s[1] = 0x3320646E;
	m_s[2] = 0x79622D32;
	m_s[3] = 0x6B206574;

	BOOST_STATIC_ASSERT(PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN);
	memcpy(&m_s[4], pbKey32, 32); // m_s[4] to m_s[11]

	m_s[12] = 0; // Counter
	memcpy(&m_s[13], pbIV12, 12); // m_s[13] to m_s[15]
}

CChaCha20::~CChaCha20()
{
	mem_erase(&m_s[0], 16 * sizeof(UINT32));
}

HRESULT CChaCha20::NextBlock(BYTE* pbBlock)
{
	if(pbBlock == NULL) { ASSERT(FALSE); return E_POINTER; }

	UINT32* s = &m_s[0];
	UINT32* x = reinterpret_cast<UINT32*>(pbBlock);
	memcpy(x, s, 16 * sizeof(UINT32));

	// 10 * 8 quarter rounds = 20 rounds
	for(size_t i = 0; i < 10; ++i)
	{
		// Column quarter rounds
		x[ 0] += x[ 4];
		x[12] = _rotl(x[12] ^ x[ 0], 16);
		x[ 8] += x[12];
		x[ 4] = _rotl(x[ 4] ^ x[ 8], 12);
		x[ 0] += x[ 4];
		x[12] = _rotl(x[12] ^ x[ 0],  8);
		x[ 8] += x[12];
		x[ 4] = _rotl(x[ 4] ^ x[ 8],  7);

		x[ 1] += x[ 5];
		x[13] = _rotl(x[13] ^ x[ 1], 16);
		x[ 9] += x[13];
		x[ 5] = _rotl(x[ 5] ^ x[ 9], 12);
		x[ 1] += x[ 5];
		x[13] = _rotl(x[13] ^ x[ 1],  8);
		x[ 9] += x[13];
		x[ 5] = _rotl(x[ 5] ^ x[ 9],  7);

		x[ 2] += x[ 6];
		x[14] = _rotl(x[14] ^ x[ 2], 16);
		x[10] += x[14];
		x[ 6] = _rotl(x[ 6] ^ x[10], 12);
		x[ 2] += x[ 6];
		x[14] = _rotl(x[14] ^ x[ 2],  8);
		x[10] += x[14];
		x[ 6] = _rotl(x[ 6] ^ x[10],  7);

		x[ 3] += x[ 7];
		x[15] = _rotl(x[15] ^ x[ 3], 16);
		x[11] += x[15];
		x[ 7] = _rotl(x[ 7] ^ x[11], 12);
		x[ 3] += x[ 7];
		x[15] = _rotl(x[15] ^ x[ 3],  8);
		x[11] += x[15];
		x[ 7] = _rotl(x[ 7] ^ x[11],  7);

		// Diagonal quarter rounds
		x[ 0] += x[ 5];
		x[15] = _rotl(x[15] ^ x[ 0], 16);
		x[10] += x[15];
		x[ 5] = _rotl(x[ 5] ^ x[10], 12);
		x[ 0] += x[ 5];
		x[15] = _rotl(x[15] ^ x[ 0],  8);
		x[10] += x[15];
		x[ 5] = _rotl(x[ 5] ^ x[10],  7);

		x[ 1] += x[ 6];
		x[12] = _rotl(x[12] ^ x[ 1], 16);
		x[11] += x[12];
		x[ 6] = _rotl(x[ 6] ^ x[11], 12);
		x[ 1] += x[ 6];
		x[12] = _rotl(x[12] ^ x[ 1],  8);
		x[11] += x[12];
		x[ 6] = _rotl(x[ 6] ^ x[11],  7);

		x[ 2] += x[ 7];
		x[13] = _rotl(x[13] ^ x[ 2], 16);
		x[ 8] += x[13];
		x[ 7] = _rotl(x[ 7] ^ x[ 8], 12);
		x[ 2] += x[ 7];
		x[13] = _rotl(x[13] ^ x[ 2],  8);
		x[ 8] += x[13];
		x[ 7] = _rotl(x[ 7] ^ x[ 8],  7);

		x[ 3] += x[ 4];
		x[14] = _rotl(x[14] ^ x[ 3], 16);
		x[ 9] += x[14];
		x[ 4] = _rotl(x[ 4] ^ x[ 9], 12);
		x[ 3] += x[ 4];
		x[14] = _rotl(x[14] ^ x[ 3],  8);
		x[ 9] += x[14];
		x[ 4] = _rotl(x[ 4] ^ x[ 9],  7);
	}

	for(size_t i = 0; i < 16; ++i) x[i] += s[i];

	++s[12];
	if(s[12] == 0)
	{
		if(!m_bLargeCounter) { ASSERT(FALSE); return E_FAIL; }
		++s[13]; // Increment high half of large counter
	}

	return S_OK;
}

HRESULT CChaCha20::Seek(INT64 iOffset, int sOrigin)
{
	if((iOffset < 0) || ((iOffset & 63) != 0) ||
		((UINT64)(iOffset >> 6) > (UINT64)UINT32_MAX))
	{
		ASSERT(FALSE);
		return E_INVALIDARG;
	}
	if(sOrigin != SEEK_SET) { ASSERT(FALSE); return E_NOTIMPL; }

	m_s[12] = (UINT32)(iOffset >> 6);
	InvalidateBlock();

	return S_OK;
}

HRESULT CChaCha20::Crypt(BYTE* pbMsg, size_t cbMsg, const BYTE* pbKey32,
	const BYTE* pbIV12, bool bLargeCounter)
{
	if(pbMsg == NULL) { ASSERT(FALSE); return E_POINTER; }
	if(cbMsg == 0) return S_OK;
	if(pbKey32 == NULL) { ASSERT(FALSE); return E_POINTER; }

	BYTE aIV[12];
	if(pbIV12 != NULL) memcpy(aIV, pbIV12, 12);
	else memset(aIV, 0, 12);

	CChaCha20 c(pbKey32, aIV, bLargeCounter);
	return c.Encrypt(pbMsg, 0, cbMsg);
}
