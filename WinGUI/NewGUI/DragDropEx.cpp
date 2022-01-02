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

#include "StdAfx.h"
#include "DragDropEx.h"

#include "../../KeePassLibCpp/Util/StrUtil.h"

using namespace std;

/* class CMyOleDataSource : public COleDataSource
{
public:
	virtual ~CMyOleDataSource()
	{
		TRACE("CMyOleDataSource destructed.\r\n");
	}
};

class CMyOleDropSource : public COleDropSource
{
public:
	virtual ~CMyOleDropSource()
	{
		TRACE("CMyOleDropSource destructed.\r\n");
	}
}; */

CDragDropEx::CDragDropEx()
{
}

void CDragDropEx::Perform(LPCTSTR lpText)
{
	if(lpText == NULL) { ASSERT(FALSE); lpText = _T(""); }

	COleDataSource* pDataSource = new COleDataSource();
	COleDropSource* pDropSource = new COleDropSource();

	const basic_string<char> strA = _StringToAnsiStl(lpText);
	const basic_string<WCHAR> strW = _StringToUnicodeStl(lpText);

	const size_t cbA = (strA.size() + 1) * sizeof(char);
	const size_t cbW = (strW.size() + 1) * sizeof(WCHAR);

	HGLOBAL hgA = GlobalAlloc(GHND, cbA);
	HGLOBAL hgW = GlobalAlloc(GHND, cbW);

	if(hgA != NULL)
	{
		LPVOID lp = GlobalLock(hgA);
		if(lp != NULL)
		{
			memcpy(lp, strA.c_str(), cbA);
			GlobalUnlock(hgA);

			pDataSource->CacheGlobalData(CF_TEXT, hgA);
		}
		else { ASSERT(FALSE); }
	}
	else { ASSERT(FALSE); }

	if(hgW != NULL)
	{
		LPVOID lp = GlobalLock(hgW);
		if(lp != NULL)
		{
			memcpy(lp, strW.c_str(), cbW);
			GlobalUnlock(hgW);

			pDataSource->CacheGlobalData(CF_UNICODETEXT, hgW);
		}
		else { ASSERT(FALSE); }
	}
	else { ASSERT(FALSE); }

	pDataSource->DoDragDrop(DROPEFFECT_MOVE | DROPEFFECT_COPY, NULL, pDropSource);

	// COleDataSource and COleDropSource derive from CCmdTarget,
	// and CCmdTarget::OnFinalRelease calls 'delete this';
	// sometimes (e.g. drag&drop into Chrome) there are multiple
	// references, so don't delete the objects directly;
	// https://sourceforge.net/p/keepass/discussion/329220/thread/09b9e64f55/
	const DWORD crDataSource = pDataSource->ExternalRelease();
	pDropSource->ExternalRelease();

	// pDataSource was the owner of the HGLOBALs
	if(crDataSource == 0)
	{
		ASSERT(GlobalSize(hgA) == 0);
		ASSERT(GlobalSize(hgW) == 0);
	}
}
