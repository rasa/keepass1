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
#include "../SysDefEx.h"
#include <mmsystem.h>
#include "KeyTransform_BCrypt.h"
#include "../Util/AppUtil.h"
#include "../Util/MemUtil.h"

BOOL CKeyTransformBCrypt::g_bEnableBCrypt = TRUE;

CKeyTransformBCrypt::CKeyTransformBCrypt() :
	m_hLib(NULL)
{
	if(g_bEnableBCrypt == FALSE) return;

	// BCrypt.dll is only supported on >= Vista
	if(AU_IsAtLeastWinVistaSystem() == FALSE) return;

	m_hLib = AU_LoadLibrary(BCRYPT_DLLNAME);
	if(m_hLib == NULL) return;

	m_lpBCryptOpenAlgorithmProvider = (LPBCRYPTOPENALGORITHMPROVIDER)
		GetProcAddress(m_hLib, BCFN_OAP);
	m_lpBCryptCloseAlgorithmProvider = (LPBCRYPTCLOSEALGORITHMPROVIDER)
		GetProcAddress(m_hLib, BCFN_CAP);
	m_lpBCryptGetProperty = (LPBCRYPTGETPROPERTY)GetProcAddress(m_hLib, BCFN_GP);
	m_lpBCryptSetProperty = (LPBCRYPTSETPROPERTY)GetProcAddress(m_hLib, BCFN_SP);
	// m_lpBCryptGenerateSymmetricKey = (LPBCRYPTGENERATESYMMETRICKEY)
	//	GetProcAddress(m_hLib, BCFN_GSK);
	m_lpBCryptImportKey = (LPBCRYPTIMPORTKEY)GetProcAddress(m_hLib, BCFN_IK);
	m_lpBCryptDestroyKey = (LPBCRYPTDESTROYKEY)GetProcAddress(m_hLib, BCFN_DK);
	m_lpBCryptEncrypt = (LPBCRYPTENCRYPT)GetProcAddress(m_hLib, BCFN_E);

	if((m_lpBCryptOpenAlgorithmProvider == NULL) || (m_lpBCryptCloseAlgorithmProvider == NULL) ||
		(m_lpBCryptGetProperty == NULL) || (m_lpBCryptSetProperty == NULL) ||
		// (m_lpBCryptGenerateSymmetricKey == NULL) ||
		(m_lpBCryptImportKey == NULL) || (m_lpBCryptDestroyKey == NULL) ||
		(m_lpBCryptEncrypt == NULL))
	{
		ASSERT(FALSE);
		_FreeLib();
	}
}

CKeyTransformBCrypt::~CKeyTransformBCrypt()
{
	_FreeLib();
}

void CKeyTransformBCrypt::_FreeLib()
{
	if(m_hLib != NULL)
	{
		VERIFY(FreeLibrary(m_hLib));
		m_hLib = NULL;
	}
}

BOOL* CKeyTransformBCrypt::GetEnabledPtr()
{
	return &g_bEnableBCrypt;
}

#define KTBC_FAIL { ASSERT(FALSE); VERIFY(m_lpBCryptCloseAlgorithmProvider(hAes, \
	0) == 0); return false; }

bool CKeyTransformBCrypt::_InitBCrypt(BCRYPT_ALG_HANDLE& hAes, BCRYPT_KEY_HANDLE& hKey,
	boost::shared_ptr<CAlignedBuffer>& spKeyObj, const BYTE* pbKey32)
{
	if(m_lpBCryptOpenAlgorithmProvider(&hAes, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
	{
		ASSERT(FALSE);
		return false;
	}

	DWORD cbKeyObj = 0;
	ULONG uResult = 0;
	if(m_lpBCryptGetProperty(hAes, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObj,
		sizeof(DWORD), &uResult, 0) != 0) KTBC_FAIL;
	if(cbKeyObj == 0) KTBC_FAIL;

	spKeyObj.reset(new CAlignedBuffer(cbKeyObj, 16, true, true));
	if((spKeyObj.get() == NULL) || (spKeyObj->Data() == NULL)) KTBC_FAIL;

	BCRYPT_KEY_DATA_BLOB_32 keyBlob;
	ZeroMemory(&keyBlob, sizeof(BCRYPT_KEY_DATA_BLOB_32));
	keyBlob.dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
	keyBlob.dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
	keyBlob.cbKeyData = 32;
	memcpy(keyBlob.vKeyData, pbKey32, 32);

	// if(m_lpBCryptGenerateSymmetricKey(hAes, &hKey, (PUCHAR)pKeyObj.get(),
	//	dwKeyObjLen, const_cast<PUCHAR>(pbKey32), 32, 0) != 0) KTBC_FAIL;
	const NTSTATUS s = m_lpBCryptImportKey(hAes, NULL, BCRYPT_KEY_DATA_BLOB,
		&hKey, spKeyObj->Data(), cbKeyObj, (PUCHAR)&keyBlob,
		sizeof(BCRYPT_KEY_DATA_BLOB_32), 0);
	mem_erase(&keyBlob, sizeof(BCRYPT_KEY_DATA_BLOB_32));
	if(s != 0) KTBC_FAIL;

	if(m_lpBCryptSetProperty(hAes, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
		static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) * sizeof(wchar_t)), 0) != 0)
		KTBC_FAIL;

#ifdef _DEBUG
	DWORD cbKey = 0;
	VERIFY(m_lpBCryptGetProperty(hKey, BCRYPT_KEY_STRENGTH, (PUCHAR)&cbKey,
		sizeof(DWORD), &uResult, 0) == 0);
	VERIFY(cbKey == 256);

	BCRYPT_ALG_HANDLE hRef = NULL;
	VERIFY(m_lpBCryptGetProperty(hKey, BCRYPT_PROVIDER_HANDLE, (PUCHAR)&hRef,
		sizeof(BCRYPT_ALG_HANDLE), &uResult, 0) == 0);
	VERIFY(hRef == hAes);
#endif

	const size_t cbBuf = KTBC_BUF_BLOCKS * 16;
	m_spBufZero.reset(new CAlignedBuffer(cbBuf, 16, true, false));
	m_spBuf.reset(new CAlignedBuffer(cbBuf, 16, false, true));
	if((m_spBufZero.get() == NULL) || (m_spBufZero->Data() == NULL) ||
		(m_spBuf.get() == NULL) || (m_spBuf->Data() == NULL))
		KTBC_FAIL;

	return true;
}

void CKeyTransformBCrypt::_DestroyBCrypt(BCRYPT_ALG_HANDLE& hAes, BCRYPT_KEY_HANDLE& hKey)
{
	if(hKey != NULL) { VERIFY(m_lpBCryptDestroyKey(hKey) == 0); hKey = NULL; }
	if(hAes != NULL) { VERIFY(m_lpBCryptCloseAlgorithmProvider(hAes, 0) == 0); hAes = NULL; }

	m_spBufZero.reset();
	m_spBuf.reset();
}

bool CKeyTransformBCrypt::_Encrypt(BCRYPT_KEY_HANDLE hKey, BYTE* pbData16, UINT64 qwRounds)
{
	ASSERT(((uintptr_t)pbData16 & 15) == 0); // Should be aligned

	BYTE* pbBufIn = m_spBufZero->Data();
	BYTE* pbBufOut = m_spBuf->Data();

	while(qwRounds != 0)
	{
		const UINT64 r = min(qwRounds, KTBC_BUF_BLOCKS);
		const ULONG cb = static_cast<ULONG>(r) << 4;
		ULONG cbResult = 0;

		if(m_lpBCryptEncrypt(hKey, pbBufIn, cb, NULL, pbData16, 16,
			pbBufOut, cb, &cbResult, 0) != 0)
		{
			ASSERT(FALSE);
			return false;
		}

		ASSERT(*(UINT64*)pbBufIn == 0);
		ASSERT(memcmp(pbData16, pbBufOut + (cb - 16), 16) == 0);
		ASSERT(cbResult == cb);

		qwRounds -= r;
	}

	return true;
}

HRESULT CKeyTransformBCrypt::TransformKey(const BYTE* pbKey32, BYTE* pbData16,
	UINT64 qwRounds)
{
	if((pbKey32 == NULL) || (pbData16 == NULL)) { ASSERT(FALSE); return E_POINTER; }
	if(qwRounds == 0) return S_OK;
	if(m_hLib == NULL) return E_NOINTERFACE;

	BCRYPT_ALG_HANDLE hAes = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	boost::shared_ptr<CAlignedBuffer> spKeyObj;

	if(!_InitBCrypt(hAes, hKey, spKeyObj, pbKey32)) return E_FAIL;

	const bool bResult = _Encrypt(hKey, pbData16, qwRounds);

	_DestroyBCrypt(hAes, hKey);
	return (bResult ? S_OK : E_FAIL);
}

HRESULT CKeyTransformBCrypt::Benchmark(const BYTE* pbKey32, BYTE* pbData16,
	UINT64* pqwRounds, DWORD dwTimeMs)
{
	if((pbKey32 == NULL) || (pbData16 == NULL)) { ASSERT(FALSE); return E_POINTER; }
	if(pqwRounds == NULL) { ASSERT(FALSE); return E_POINTER; }
	if(m_hLib == NULL) return E_NOINTERFACE;

	BCRYPT_ALG_HANDLE hAes = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	boost::shared_ptr<CAlignedBuffer> spKeyObj;

	if(!_InitBCrypt(hAes, hKey, spKeyObj, pbKey32)) return E_FAIL;

	const UINT64 qwStep = 4096; // Cf. KTBC_BUF_BLOCKS
	const DWORD dwStartTime = timeGetTime();
	UINT64 qwRounds = 0;
	bool bResult = true;

	while((timeGetTime() - dwStartTime) < dwTimeMs)
	{
		if(!_Encrypt(hKey, pbData16, qwStep)) { bResult = false; break; }

		qwRounds += qwStep;
		if(qwRounds < qwStep) // Overflow
		{
			qwRounds = UINT64_MAX - 8;
			break;
		}
	}

	*pqwRounds = qwRounds;

	_DestroyBCrypt(hAes, hKey);
	return (bResult ? S_OK : E_FAIL);
}
