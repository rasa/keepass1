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

#ifndef ___CTR_BLOCK_CIPHER_H___
#define ___CTR_BLOCK_CIPHER_H___

#pragma once

#include "../SysDefEx.h"
#include <boost/shared_ptr.hpp>
#include "../Util/AlignedBuffer.h"

class CCtrBlockCipher
{
public:
	CCtrBlockCipher(size_t cbBlock);
	virtual ~CCtrBlockCipher() { }

	HRESULT Encrypt(BYTE* pb, size_t uOffset, size_t cb);
	HRESULT Decrypt(BYTE* pb, size_t uOffset, size_t cb);

protected:
	void InvalidateBlock();
	virtual HRESULT NextBlock(BYTE* pbBlock) = 0;

private:
	boost::shared_ptr<CAlignedBuffer> m_spBlock;
	size_t m_uBlockPos;
};

#endif // ___CTR_BLOCK_CIPHER_H___
