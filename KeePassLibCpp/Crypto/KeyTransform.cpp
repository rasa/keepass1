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
#include "KeyTransform.h"
#include "KeyTransform_BCrypt.h"

#include "Rijndael.h"
#include "../Util/AlignedBuffer.h"
#include "../Util/MemUtil.h"

CKeyTransform::CKeyTransform(UINT64 qwRounds, UINT8* pBuf, const UINT8* pKey)
{
	m_qwRounds = qwRounds;
	m_pBuf = pBuf;
	m_pKey = pKey;
	m_bSucceeded = false;
}

void CKeyTransform::Run()
{
	if(m_pBuf == NULL) { ASSERT(FALSE); return; }
	if(m_pKey == NULL) { ASSERT(FALSE); return; }

	CAlignedBuffer abData(16, 16, m_pBuf, true);
	BYTE* pbData = abData.Data();
	if(pbData == NULL) { ASSERT(FALSE); return; }

	CKeyTransformBCrypt ktBCrypt;
	if(FAILED(ktBCrypt.TransformKey(m_pKey, pbData, m_qwRounds)))
	{
		memcpy(pbData, m_pBuf, 16);

		CRijndael aes;
		if(aes.Init(CRijndael::ECB, CRijndael::EncryptDir, m_pKey,
			CRijndael::Key32Bytes, 0) != RIJNDAEL_SUCCESS) { ASSERT(FALSE); return; }

		for(UINT64 qw = m_qwRounds; qw != 0; --qw)
			aes.BlockEncrypt(pbData, 128, pbData);
	}

	memcpy(m_pBuf, pbData, 16);
	m_bSucceeded = true;
}

DWORD WINAPI CKeyTrf_ThreadProc(LPVOID lpParameter)
{
	CKeyTransform* p = (CKeyTransform*)lpParameter;
	if(p == NULL) { ASSERT(FALSE); return 0; }

	p->Run();
	return 0;
}

bool CKeyTransform::Transform256(UINT64 qwRounds, UINT8* pBuffer256,
	const UINT8* pKeySeed256)
{
	ASSERT(pBuffer256 != NULL); if(pBuffer256 == NULL) return false;
	ASSERT(pKeySeed256 != NULL); if(pKeySeed256 == NULL) return false;

	BYTE vBuf[32]; // Local copy of the data to be transformed
	memcpy(&vBuf[0], pBuffer256, 32);

	BYTE vKey[32]; // Local copy of the transformation key
	memcpy(&vKey[0], pKeySeed256, 32);

	CKeyTransform ktLeft(qwRounds, &vBuf[0], &vKey[0]);
	CKeyTransform ktRight(qwRounds, &vBuf[16], &vKey[0]);

	// No multi-threading support for _WIN32_WCE builds
#ifdef _WIN32_WCE
	ktLeft.Run();
	ktRight.Run();
#else
	DWORD dwThreadId = 0; // Pointer may not be NULL on Windows 9x/Me
	HANDLE hLeft = CreateThread(NULL, 0, CKeyTrf_ThreadProc,
		&ktLeft, 0, &dwThreadId);
	if(hLeft == NULL) { ASSERT(FALSE); return false; }

	ktRight.Run();

	VERIFY(WaitForSingleObject(hLeft, INFINITE) == WAIT_OBJECT_0);
	VERIFY(CloseHandle(hLeft) != FALSE);
#endif

	if(!ktLeft.Succeeded() || !ktRight.Succeeded()) { ASSERT(FALSE); return false; }

	memcpy(pBuffer256, &vBuf[0], 32);
	mem_erase(&vBuf[0], 32);
	mem_erase(&vKey[0], 32);
	return true;
}

UINT64 CKeyTransform::Benchmark(DWORD dwTimeMs)
{
	CKeyTransformBenchmark ktLeft(dwTimeMs), ktRight(dwTimeMs);

	// No multi-threading support for _WIN32_WCE builds
#ifdef _WIN32_WCE
	ktLeft.Run();
	return (ktLeft.GetComputedRounds() >> 1);
#else
	DWORD dwThreadId = 0; // Pointer may not be NULL on Windows 9x/Me
	HANDLE hLeft = CreateThread(NULL, 0, CKeyTrfBench_ThreadProc,
		&ktLeft, 0, &dwThreadId);
	if(hLeft == NULL) { ASSERT(FALSE); return false; }

	ktRight.Run();

	VERIFY(WaitForSingleObject(hLeft, INFINITE) == WAIT_OBJECT_0);
	VERIFY(CloseHandle(hLeft) != FALSE);

	const UINT64 qwLeft = ktLeft.GetComputedRounds();
	const UINT64 qwRight = ktRight.GetComputedRounds();
	const UINT64 qwSum = qwLeft + qwRight;
	if((qwSum < qwLeft) || (qwSum < qwRight)) // Overflow
		return max(qwLeft, qwRight);

	return (qwSum >> 1);
#endif
}

CKeyTransformBenchmark::CKeyTransformBenchmark(DWORD dwTimeMs)
{
	m_dwTimeMs = dwTimeMs;
	m_qwComputedRounds = 0;
}

void CKeyTransformBenchmark::Run()
{
	if(m_dwTimeMs == 0) { ASSERT(FALSE); return; }
	if(m_qwComputedRounds != 0) { ASSERT(FALSE); m_qwComputedRounds = 0; }

	BYTE vKey[32];
	memset(&vKey[0], 0x4B, 32);

	CAlignedBuffer abData(16, 16, false, false);
	BYTE* pbData = abData.Data();
	if(pbData == NULL) { ASSERT(FALSE); return; }
	memset(pbData, 0x7E, 16);

	CKeyTransformBCrypt ktBCrypt;
	if(SUCCEEDED(ktBCrypt.Benchmark(&vKey[0], pbData, &m_qwComputedRounds, m_dwTimeMs)))
		return;

	CRijndael aes;
	if(aes.Init(CRijndael::ECB, CRijndael::EncryptDir, &vKey[0],
		CRijndael::Key32Bytes, 0) != RIJNDAEL_SUCCESS) { ASSERT(FALSE); return; }

	const UINT64 qwStep = 1024;
	const DWORD dwStartTime = timeGetTime();

	while((timeGetTime() - dwStartTime) < m_dwTimeMs)
	{
		for(UINT64 qw = qwStep; qw != 0; --qw)
			aes.BlockEncrypt(pbData, 128, pbData);

		m_qwComputedRounds += qwStep;
		if(m_qwComputedRounds < qwStep) // Overflow
		{
			m_qwComputedRounds = UINT64_MAX - 8;
			break;
		}
	}
}

DWORD WINAPI CKeyTrfBench_ThreadProc(LPVOID lpParameter)
{
	CKeyTransformBenchmark* p = (CKeyTransformBenchmark*)lpParameter;
	if(p == NULL) { ASSERT(FALSE); return 0; }

	p->Run();
	return 0;
}
