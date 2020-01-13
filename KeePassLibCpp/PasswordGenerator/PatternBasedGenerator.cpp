/*
  KeePass Password Safe - The Open-Source Password Manager
  Copyright (C) 2003-2020 Dominik Reichl <dominik.reichl@t-online.de>

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
#include "PatternBasedGenerator.h"

#include <list>

PWG_ERROR PbgGenerate(std::vector<WCHAR>& vOutBuffer,
	const PW_GEN_SETTINGS_EX* pSettings, CNewRandom* pRandom)
{
	if(pSettings == NULL) { ASSERT(FALSE); return PWGE_NULL_PTR; }
	if(pRandom == NULL) { ASSERT(FALSE); return PWGE_NULL_PTR; }

	vOutBuffer.clear();

	std::basic_string<WCHAR> strPattern = pSettings->strPattern;
	if(strPattern.size() == 0) return PWGE_SUCCESS;

	WCharStream cs(strPattern.c_str());
	std::list<WCHAR> llGenerated;
	PwCharSet pcs;

	while(true)
	{
		WCHAR ch = cs.ReadChar();
		if(ch == L'\0') break;

		pcs.Clear();

		if(ch == L'\\')
		{
			ch = cs.ReadChar();
			if(ch == L'\0') return PWGE_INVALID_PATTERN;

			pcs.Add(ch); // Allow "{...}" support and char check
		}
		else if(ch == L'[')
		{
			if(!PbgReadCustomCharSet(cs, pcs))
				return PWGE_INVALID_PATTERN;
		}
		else
		{
			if(!pcs.AddCharSet(ch))
				return PWGE_INVALID_PATTERN;
		}

		int nCount = 1;
		if(cs.PeekChar() == L'{')
		{
			nCount = PbgReadCount(cs);
			if(nCount < 0) return PWGE_INVALID_PATTERN;
		}

		for(int i = 0; i < nCount; ++i)
		{
			if(!PwgPrepareCharSet(pcs, pSettings))
				return PWGE_INVALID_CHARSET;
			if(pSettings->bNoRepeat != FALSE)
			{
				for(std::list<WCHAR>::const_iterator it = llGenerated.begin();
					it != llGenerated.end(); ++it)
					pcs.Remove(*it);
			}

			const WCHAR chGen = PwgGenerateCharacter(pcs, pRandom);
			if(chGen == L'\0') return PWGE_TOO_FEW_CHARACTERS;

			llGenerated.push_back(chGen);
		}
	}

	const size_t cc = llGenerated.size();
	vOutBuffer.resize(cc + 1);
	std::list<WCHAR>::const_iterator it = llGenerated.begin();
	for(size_t i = 0; i < cc; ++i)
	{
		vOutBuffer[i] = *it;
		++it;
	}
	ASSERT(it == llGenerated.end());
	vOutBuffer[cc] = L'\0';

	if(pSettings->bPatternPermute != FALSE)
		PwgShufflePassword(vOutBuffer, pRandom);

	return PWGE_SUCCESS;
}

bool PbgReadCustomCharSet(WCharStream& cs, PwCharSet& pcsOut)
{
	ASSERT(cs.PeekChar() != L'['); // Consumed already
	ASSERT(pcsOut.Size() == 0);

	bool bAdd = true;
	while(true)
	{
		WCHAR ch = cs.ReadChar();
		if(ch == L'\0') return false;
		if(ch == L']') break;

		if(ch == L'\\')
		{
			ch = cs.ReadChar();
			if(ch == L'\0') return false;

			if(bAdd) pcsOut.Add(ch);
			else pcsOut.Remove(ch);
		}
		else if(ch == L'^')
		{
			if(bAdd) bAdd = false;
			else return false; // '^' toggles the mode only once
		}
		else
		{
			PwCharSet pcs;
			if(!pcs.AddCharSet(ch)) return false;

			std::basic_string<WCHAR> str = pcs.ToString();
			if(bAdd) pcsOut.Add(str.c_str());
			else pcsOut.Remove(str.c_str());
		}
	}

	return true;
}

int PbgReadCount(WCharStream& cs)
{
	if(cs.ReadChar() != L'{') { ASSERT(FALSE); return -1; }

	// Ensure not empty
	const WCHAR chFirst = cs.PeekChar();
	if((chFirst < L'0') || (chFirst > L'9')) return -1;

	INT64 n = 0;
	while(true)
	{
		const WCHAR ch = cs.ReadChar();
		if(ch == L'}') break;

		if((ch >= L'0') && (ch <= L'9'))
		{
			n = (n * 10) + static_cast<INT64>(ch - L'0');
			if(n > INT32_MAX) return -1;
		}
		else return -1;
	}

	return static_cast<int>(n);
}
