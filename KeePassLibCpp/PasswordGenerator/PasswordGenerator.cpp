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
#include "PasswordGenerator.h"
#include "CharSetBasedGenerator.h"
#include "PatternBasedGenerator.h"

#include <algorithm>
#include <boost/scoped_array.hpp>

#include "../Util/Base64.h"
#include "../Util/PwUtil.h"
#include "../Util/StrUtil.h"
#include "../Util/MemUtil.h"

using boost::scoped_array;

PWG_ERROR PwgGenerateEx(std::vector<TCHAR>& vOutPassword,
	const PW_GEN_SETTINGS_EX* pSettings, CNewRandom* pRandomSource)
{
	if(pSettings == NULL) { ASSERT(FALSE); return PWGE_NULL_PTR; }

	EraseTCharVector(vOutPassword, true);

	CNewRandom* pAllocatedRandom = NULL;
	CNewRandom* pRandom = pRandomSource;
	if(pRandom == NULL)
	{
		pAllocatedRandom = new CNewRandom();
		pRandom = pAllocatedRandom;
	}

	std::vector<WCHAR> vOutBuffer;

	PWG_ERROR e = PWGE_UNKNOWN_GENERATOR;
	if(pSettings->btGeneratorType == PWGT_CHARSET)
		e = CsbgGenerate(vOutBuffer, pSettings, pRandom);
	else if(pSettings->btGeneratorType == PWGT_PATTERN)
		e = PbgGenerate(vOutBuffer, pSettings, pRandom);
	else { ASSERT(FALSE); }

	if((vOutBuffer.size() == 0) || (std::find(vOutBuffer.begin(),
		vOutBuffer.end(), L'\0') == vOutBuffer.end()))
		vOutBuffer.push_back(L'\0'); // Terminate string

	ASSERT(vOutBuffer.size() > 0);
#ifdef _UNICODE
	vOutPassword.resize(vOutBuffer.size());
	memcpy(&vOutPassword[0], &vOutBuffer[0], vOutPassword.size() * sizeof(WCHAR));
#else
	char* pszAnsi = _StringToAnsi(&vOutBuffer[0]);
	vOutPassword.resize(szlen(pszAnsi) + 1);
	memcpy(&vOutPassword[0], pszAnsi, vOutPassword.size() * sizeof(char));
	mem_erase(pszAnsi, vOutPassword.size() * sizeof(char));
	SAFE_DELETE_ARRAY(pszAnsi);
#endif

	EraseWCharVector(vOutBuffer, false);
	SAFE_DELETE(pAllocatedRandom);
	return e;
}

WCHAR PwgGenerateCharacter(const PwCharSet& pcs, CNewRandom* pRandom)
{
	if(pRandom == NULL) { ASSERT(FALSE); return L'\0'; }
	if(pcs.Size() == 0) return L'\0';

	const UINT64 i = pRandom->GetRandomUInt64(pcs.Size());
	return pcs.GetAt(static_cast<unsigned int>(i));
}

bool PwgPrepareCharSet(PwCharSet& pcs, const PW_GEN_SETTINGS_EX* pSettings)
{
	if(pSettings == NULL) { ASSERT(FALSE); return false; }

	const unsigned int cc = pcs.Size();
	for(unsigned int i = 0; i < cc; ++i)
	{
		const WCHAR ch = pcs.GetAt(i);
		if((ch == L'\0') || (ch == L'\t') || (ch == L'\r') || (ch == L'\n') ||
			((ch >= L'\xD800') && (ch <= L'\xDFFF'))) // Surrogate
			return false;
	}

	if(pSettings->bNoConfusing != FALSE) pcs.Remove(PDCS_CONFUSING);

	if(pSettings->strExcludeChars.size() > 0)
		pcs.Remove(pSettings->strExcludeChars.c_str());

	return true;
}

void PwgShufflePassword(std::vector<WCHAR>& vBuffer, CNewRandom* pRandom)
{
	if(pRandom == NULL) { ASSERT(FALSE); return; }

	size_t cc = vBuffer.size();
	for(size_t i = 0; i < vBuffer.size(); ++i)
	{
		if(vBuffer[i] == L'\0')
		{
			cc = i;
			break;
		}
	}
	if(cc <= 1) return; // Nothing to shuffle

	for(size_t i = cc - 1; i >= 1; --i)
	{
		const size_t j = static_cast<size_t>(pRandom->GetRandomUInt64(i + 1));

		const WCHAR t = vBuffer[i];
		vBuffer[i] = vBuffer[j];
		vBuffer[j] = t;
	}

	ASSERT(wcslen(&vBuffer[0]) == cc);
}

LPCTSTR PwgErrorToString(PWG_ERROR uError)
{
	if(uError == PWGE_SUCCESS) return _T("Success");
	if(uError == PWGE_NULL_PTR) return _T("Internal error");
	if(uError == PWGE_UNKNOWN_GENERATOR) return _T("Internal error");
	if(uError == PWGE_TOO_FEW_CHARACTERS)
		return _T("There are too few characters in the character set to build up a password matching the specified rules");
	if(uError == PWGE_INVALID_CHARSET) return _T("The character set is invalid");
	if(uError == PWGE_INVALID_PATTERN) return _T("The pattern is invalid");

	return _T("Unknown error");
}

/* std::basic_string<WCHAR> HexStrToWCharStr(LPCTSTR lpString)
{
	std::basic_string<WCHAR> str;

	ASSERT(lpString != NULL); if(lpString == NULL) return str;

	DWORD dwLength = _tcslen(lpString), i = 0;
	if((dwLength & 3) != 0) { ASSERT(FALSE); return str; }

	BYTE bt1, bt2;

	while(true)
	{
		TCHAR ch1 = lpString[i], ch2 = lpString[i + 1];
		TCHAR ch3 = lpString[i + 2], ch4 = lpString[i + 3];

		ConvertStrToHex(ch1, ch2, bt1);
		ConvertStrToHex(ch3, ch4, bt2);

		str += (WCHAR)((((WCHAR)bt1) << 8) | ((WCHAR)bt2));

		i += 4;
		if(lpString[i] == 0) break;
	}

	return str;
}

std::basic_string<TCHAR> WCharVecToHexStr(const std::vector<WCHAR>& vec)
{
	std::basic_string<TCHAR> strOut;
	TCHAR ch1, ch2;

	for(DWORD i = 0; i < vec.size(); ++i)
	{
		ConvertHexToStr((BYTE)(vec[i] >> 8), ch1, ch2);
		strOut += ch1;
		strOut += ch2;

		ConvertHexToStr((BYTE)(vec[i] & 0xFF), ch1, ch2);
		strOut += ch1;
		strOut += ch2;
	}

	return strOut;
} */

std::basic_string<TCHAR> PwgProfileToString(const PW_GEN_SETTINGS_EX* pSettings)
{
	std::basic_string<TCHAR> strEmpty;

	ASSERT(pSettings != NULL);
	if(pSettings == NULL) return strEmpty;

	std::vector<BYTE> s;

	s.push_back(PWGD_VERSION_BYTE);

	UTF8_BYTE *pbName = _StringToUTF8(pSettings->strName.c_str());
	UTF8_BYTE *pb = pbName;
	while(*pb != 0) { s.push_back(*pb); ++pb; }
	s.push_back(0);
	SAFE_DELETE_ARRAY(pbName);

	s.push_back(pSettings->btGeneratorType);
	s.push_back((pSettings->bCollectUserEntropy == TRUE) ? (BYTE)'U' : (BYTE)'N');
	s.push_back((BYTE)((pSettings->dwLength >> 24) & 0xFF));
	s.push_back((BYTE)((pSettings->dwLength >> 16) & 0xFF));
	s.push_back((BYTE)((pSettings->dwLength >> 8) & 0xFF));
	s.push_back((BYTE)(pSettings->dwLength & 0xFF));

	PwCharSet pcs(pSettings->strCharSet.c_str());
	USHORT usFlags = pcs.PackAndRemoveCharRanges();
	s.push_back((BYTE)((usFlags >> 8) & 0xFF));
	s.push_back((BYTE)(usFlags & 0xFF));

	std::basic_string<WCHAR> strRemChars = pcs.ToString();
	for(unsigned int uCS = 0; uCS < strRemChars.size(); ++uCS)
	{
		s.push_back((BYTE)(strRemChars[uCS] >> 8));
		s.push_back((BYTE)(strRemChars[uCS] & 0xFF));
	}
	s.push_back(0);
	s.push_back(0);

	for(unsigned int uPat = 0; uPat < pSettings->strPattern.size(); ++uPat)
	{
		s.push_back((BYTE)(pSettings->strPattern[uPat] >> 8));
		s.push_back((BYTE)(pSettings->strPattern[uPat] & 0xFF));
	}
	s.push_back(0);
	s.push_back(0);

	s.push_back((BYTE)((pSettings->bNoConfusing == TRUE) ? 'N' : 'A'));
	s.push_back((BYTE)((pSettings->bPatternPermute == TRUE) ? 'P' : 'N'));
	s.push_back((BYTE)((pSettings->bNoRepeat == TRUE) ? 'N' : 'R'));

	for(unsigned int uExc = 0; uExc < pSettings->strExcludeChars.size(); ++uExc)
	{
		s.push_back((BYTE)(pSettings->strExcludeChars[uExc] >> 8));
		s.push_back((BYTE)(pSettings->strExcludeChars[uExc] & 0xFF));
	}
	s.push_back(0);
	s.push_back(0);

	DWORD dwOutSize = static_cast<DWORD>(s.size() * 4 + 12);
	BYTE *pBase64 = new BYTE[dwOutSize];
	if(CBase64Codec::Encode(&s[0], (DWORD)s.size(), pBase64, &dwOutSize) == false)
	{
		ASSERT(FALSE);
		return strEmpty;
	}

#ifdef _UNICODE
	TCHAR *lpFinal = _StringToUnicode((char *)pBase64);
#else
	TCHAR *lpFinal = (TCHAR *)pBase64;
#endif

	std::basic_string<TCHAR> strFinal = lpFinal;

	SAFE_DELETE_ARRAY(pBase64);
#ifdef _UNICODE
	SAFE_DELETE_ARRAY(lpFinal);
#endif

	return strFinal;
}

void PwgStringToProfile(const std::basic_string<TCHAR>& strProfile,
	PW_GEN_SETTINGS_EX* s)
{
	ASSERT(s != NULL); if(s == NULL) return;

	PwgGetDefaultProfile(s);

#ifdef _UNICODE
	const char *lpEncoded = _StringToAnsi(strProfile.c_str());
	std::basic_string<char> strEncoded = lpEncoded;
	SAFE_DELETE_ARRAY(lpEncoded);
#else
	std::basic_string<char> strEncoded = strProfile.c_str();
#endif

	DWORD dwDecodedSize = static_cast<DWORD>(strProfile.size() + 130);

	scoped_array<BYTE> pDecoded(new BYTE[dwDecodedSize]);
	memset(pDecoded.get(), 0, dwDecodedSize);

	if(CBase64Codec::Decode((BYTE *)strEncoded.c_str(),
		static_cast<DWORD>(strEncoded.size()), pDecoded.get(),
		&dwDecodedSize) == false) { ASSERT(FALSE); return; }

	ASSERT(pDecoded.get()[0] <= PWGD_VERSION_BYTE);

	TCHAR* lpName = _UTF8ToString(&pDecoded.get()[1]);
	s->strName = lpName;

	BYTE *pb = (BYTE *)memchr(pDecoded.get(), 0, dwDecodedSize);
	if(pb == NULL) { ASSERT(FALSE); return; }

	++pb;
	s->btGeneratorType = *pb; ++pb;
	s->bCollectUserEntropy = ((*pb == (BYTE)'U') ? TRUE : FALSE); ++pb;

	s->dwLength = (static_cast<DWORD>(*pb) << 24); ++pb;
	s->dwLength |= (static_cast<DWORD>(*pb) << 16); ++pb;
	s->dwLength |= (static_cast<DWORD>(*pb) << 8); ++pb;
	s->dwLength |= static_cast<DWORD>(*pb); ++pb;

	USHORT usFlags = (USHORT)(*pb) << 8; ++pb;
	usFlags |= (USHORT)(*pb); ++pb;

	PwCharSet pcs;
	pcs.UnpackCharRanges(usFlags);

	while(true)
	{
		BYTE bt1 = *pb; ++pb;
		BYTE bt2 = *pb; ++pb;
		if((bt1 == 0) && (bt2 == 0)) break;
		pcs.Add(((WCHAR)bt1 << 8) | (WCHAR)bt2);
	}
	s->strCharSet = pcs.ToString();

	while(true)
	{
		BYTE bt1 = *pb; ++pb;
		BYTE bt2 = *pb; ++pb;
		if((bt1 == 0) && (bt2 == 0)) break;
		s->strPattern += (WCHAR)(((WCHAR)bt1 << 8) | (WCHAR)bt2);
	}

	ASSERT((*pb == (BYTE)'N') || (*pb == (BYTE)'A'));
	s->bNoConfusing = ((*pb == (BYTE)'N') ? TRUE : FALSE); ++pb;
	ASSERT((*pb == (BYTE)'P') || (*pb == (BYTE)'N') || (*pb == 0));
	s->bPatternPermute = ((*pb == (BYTE)'P') ? TRUE : FALSE); ++pb;
	ASSERT((*pb == (BYTE)'N') || (*pb == (BYTE)'R') || (*pb == 0));
	s->bNoRepeat = ((*pb == (BYTE)'N') ? TRUE : FALSE); ++pb;

	while(true)
	{
		BYTE bt1 = *pb; ++pb;
		BYTE bt2 = *pb; ++pb;
		if((bt1 == 0) && (bt2 == 0)) break;
		s->strExcludeChars += (WCHAR)(((WCHAR)bt1 << 8) | (WCHAR)bt2);
	}

	SAFE_DELETE_ARRAY(lpName);
}

void PwgGetDefaultProfile(PW_GEN_SETTINGS_EX* s)
{
	ASSERT(s != NULL); if(s == NULL) return;

	s->strName.clear();

	s->btGeneratorType = PWGT_CHARSET;
	s->bCollectUserEntropy = FALSE;

	s->dwLength = 20;

	PwCharSet pcs;
	pcs.Add(PDCS_UPPER_CASE, PDCS_LOWER_CASE, PDCS_NUMERIC);
	s->strCharSet = pcs.ToString();

	s->strPattern.clear();
	s->bPatternPermute = FALSE;

	s->bNoConfusing = FALSE;
	s->bNoRepeat = FALSE;

	s->strExcludeChars.clear();
}

BOOL PwgHasSecurityReducingOption(const PW_GEN_SETTINGS_EX* pSettings)
{
	ASSERT(pSettings != NULL); if(pSettings == NULL) return FALSE;

	if(pSettings->bNoConfusing != FALSE) return TRUE;
	if(pSettings->bNoRepeat != FALSE) return TRUE;
	if(pSettings->strExcludeChars.size() > 0) return TRUE;

	return FALSE;
}
