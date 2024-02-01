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
#include "CtrBlockCipher.h"

CCtrBlockCipher::CCtrBlockCipher(size_t cbBlock)
{
	m_spBlock.reset(new CAlignedBuffer(cbBlock, 16, true, true));
	m_uBlockPos = cbBlock;
}

void CCtrBlockCipher::InvalidateBlock()
{
	m_uBlockPos = m_spBlock->Size();
}

HRESULT CCtrBlockCipher::Encrypt(BYTE* pb, size_t uOffset, size_t cb)
{
	if(pb == NULL) { ASSERT(FALSE); return E_POINTER; }

	const size_t cbBlock = m_spBlock->Size();
	BYTE* pbBlock = m_spBlock->Data();

	while(cb != 0)
	{
		ASSERT(m_uBlockPos <= cbBlock);
		if(m_uBlockPos == cbBlock)
		{
			const HRESULT hr = NextBlock(pbBlock);
			if(FAILED(hr)) return hr;
			m_uBlockPos = 0;
		}

		const size_t cbCopy = min(cbBlock - m_uBlockPos, cb);
		ASSERT(cbCopy != 0);

		for(size_t u = 0; u < cbCopy; ++u)
			pb[uOffset + u] ^= pbBlock[m_uBlockPos + u];

		m_uBlockPos += cbCopy;
		uOffset += cbCopy;
		cb -= cbCopy;
	}

	return S_OK;
}

HRESULT CCtrBlockCipher::Decrypt(BYTE* pb, size_t uOffset, size_t cb)
{
	return Encrypt(pb, uOffset, cb);
}
