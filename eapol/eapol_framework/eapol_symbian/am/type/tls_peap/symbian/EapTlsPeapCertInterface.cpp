/*
* Copyright (c) 2001-2006 Nokia Corporation and/or its subsidiary(-ies).
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of the License "Eclipse Public License v1.0"
* which accompanies this distribution, and is available
* at the URL "http://www.eclipse.org/legal/epl-v10.html".
*
* Initial Contributors:
* Nokia Corporation - initial contribution.
*
* Contributors:
*
* Description:  EAP and WLAN authentication protocols.
*
*/

/*
* %version: 38.1.28 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 390 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES
#include "EapTlsPeapCertInterface.h"
#include "EapTlsPeapUtils.h"
#include <x509keys.h>
#include <x509cert.h>
#include "eap_tlv_message_data.h"
#include "EapTraceSymbian.h"
#include "eap_automatic_variable.h"

#if defined(USE_EAP_TLS_PEAP_UNIFIED_KEY_STORE_CACHE)
	const TText8 KKeyStoreHandlePrefix[] = "EapTlsPeapKeyStoreHandler";
	const TText8 KKeyStoreHandleKey[] = "CEapTlsPeapCertInterface KeyStore handle";
#endif //#if defined(USE_EAP_TLS_PEAP_UNIFIED_KEY_STORE_CACHE)

enum TAlgorithmAndSignedType
{
	ERSASign = 1,
	EDSASign,
	ERSASignWithFixedDH,
	EDSASignWithFixedDH,
	ERSASignWithEphemeralDH,
	EDSASignWithEphemeralDH
};

enum eap_type_tlspeap_stored_e
{
	eap_type_tlspeap_stored_keystore_handle = 1
};

// ================= MEMBER FUNCTIONS =======================

// Completition functions should be moved to abstract IF

CEapTlsPeapCertInterface* CEapTlsPeapCertInterface::NewL(abs_eap_am_tools_c* const aTools, 
											   eap_am_type_tls_peap_symbian_c* const aParent)
{
	EAP_TRACE_DEBUG(
		aTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::NewL()\n")));

	EAP_TRACE_RETURN_STRING(aTools, "returns: CEapTlsPeapCertInterface::NewL()");


	CEapTlsPeapCertInterface* self = new(ELeave) CEapTlsPeapCertInterface(aTools, aParent);
	CleanupStack::PushL(self);
	self->ConstructL();
	CleanupStack::Pop();
	return self;
}

//--------------------------------------------------

CEapTlsPeapCertInterface::CEapTlsPeapCertInterface(abs_eap_am_tools_c* const aTools, eap_am_type_tls_peap_symbian_c* const aParent)
: CActive(CActive::EPriorityStandard)
, iParent(aParent)
, m_am_tools(aTools)
, iAllowedUserCerts(1)
, iEncodedCertificate(0)
, iCertPtr(0,0)
, iMatchingUserCertInfos(1)
, iCAIndex(0)
, iUseAutomaticCaCertificate(EFalse)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::CEapTlsPeapCertInterface()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapTlsPeapCertInterface::CEapTlsPeapCertInterface()");

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

void CEapTlsPeapCertInterface::ConstructL()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::ConstructL()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapTlsPeapCertInterface::ConstructL()");

	User::LeaveIfError(iFs.Connect());
	
	CActiveScheduler::Add(this);		
	
	iValidationResult = CPKIXValidationResult::NewL();
	
	iEncodedCertificate = HBufC8::NewL(0);
	iCertPtr.Set(iEncodedCertificate->Des());	

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface()");

	if(IsActive())
	{
		Cancel();		
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): iMatchingUserCerts.ResetAndDestroy(): count=%d\n"),
		iMatchingUserCerts.Count()));

	iMatchingUserCerts.ResetAndDestroy();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): iMatchingUserCertInfos.ResetAndDestroy(): count=%d\n"),
		iMatchingUserCertInfos.Count()));

	iMatchingUserCertInfos.ResetAndDestroy();
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): iAllowedUserCerts.ResetAndDestroy(): count=%d\n"),
		iAllowedUserCerts.Count()));

	iAllowedUserCerts.ResetAndDestroy();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): iAllowedCACerts.ResetAndDestroy(): count=%d\n"),
		iAllowedCACerts.Count()));

	iAllowedCACerts.ResetAndDestroy();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): iRootCerts.ResetAndDestroy(): count=%d\n"),
		iRootCerts.Count()));

	iRootCerts.ResetAndDestroy();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): iUserCertChain.ResetAndDestroy(): count=%d\n"),
		iUserCertChain.Count()));

	iUserCertChain.ResetAndDestroy();
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): iCertAuthorities.ResetAndDestroy(): count=%d\n"),
		iCertAuthorities.Count()));

	iCertAuthorities.ResetAndDestroy();
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): iCertInfos.Reset(): count=%d\n"),
		iCertInfos.Count()));

	TInt i(0);
	for (i = 0; i < iCertInfos.Count(); i++)
	{
		iCertInfos[i]->Release();
	}
	iCertInfos.Reset();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): iKeyInfos.Reset(): count=%d\n"),
		iKeyInfos.Count()));

	for (i = 0; i < iKeyInfos.Count(); i++)
	{
		iKeyInfos[i]->Release();
	}
	iKeyInfos.Reset();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): delete iCertFilter\n")));

	delete iCertFilter;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): delete iCertStore\n")));

	delete iCertStore;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): delete iCertChain\n")));

	delete iCertChain;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): delete iValidationResult\n")));

	delete iValidationResult;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): delete iInputCertChain\n")));

	delete iInputCertChain;	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): delete iEncodedCertificate\n")));

	delete iEncodedCertificate;	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): delete iDataIn\n")));

	delete iDataIn;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): delete iDataOut\n")));

	delete iDataOut;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): delete iSignature\n")));

	delete iSignature;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): delete iPtrOut\n")));

	delete iPtrOut;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): delete iSignaturePtr\n")));

	delete iSignaturePtr;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): delete iRSASignature\n")));

	delete iRSASignature;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): delete iDSASignature\n")));

	delete iDSASignature;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): delete iKeyFilter\n")));

	delete iKeyFilter;

#if !defined(USE_EAP_TLS_PEAP_UNIFIED_KEY_STORE_CACHE)

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): delete iKeyStore\n")));

	delete iKeyStore;

#endif //#if !defined(USE_EAP_TLS_PEAP_UNIFIED_KEY_STORE_CACHE)
	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): iFs.Close()\n")));

	iFs.Close();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): returns\n")));
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

void CEapTlsPeapCertInterface::GetMatchingCertificatesL(
	const RPointerArray<EapCertificateEntry>& aAllowedUserCerts,
	const TBool aUseCertAuthoritiesFilter,
	EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const aCertAuthorities,
	const TBool aUseCertTypesFilter,
	EAP_TEMPLATE_CONST eap_array_c<u8_t> * const aCertTypes,
	const TBool aUseAllowedCipherSuitesFilter,
	const RArray<TUint>& aAllowedCipherSuites)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::GetMatchingCertificatesL(): Total allowed user certs=%d, aAllowedUserCerts=0x%08x, iAllowedUserCerts=0x%08x, aCertAuthorities=0x%08x, aCertTypes=0x%08x, aAllowedCipherSuites=0x%08x\n"),
		aAllowedUserCerts.Count(),
		&aAllowedUserCerts,
		&iAllowedUserCerts,
		aCertAuthorities,
		aCertTypes,
		&aAllowedCipherSuites));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapTlsPeapCertInterface::GetMatchingCertificatesL()");

	iUseCertAuthoritiesFilter = aUseCertAuthoritiesFilter;
	
	iUseCertTypesFilter = aUseCertTypesFilter;
	
	iUseAllowedCipherSuitesFilter = aUseAllowedCipherSuitesFilter;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::GetMatchingCertificatesL(): iAllowedUserCerts.Count()=%d\n"),
		iAllowedUserCerts.Count()));

	iAllowedUserCerts.ResetAndDestroy();
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::GetMatchingCertificatesL(): UseCertAuthoritiesFilter=%d, UseCertTypesFilter=%d, UseAllowedCipherSuitesFilter=%d\n"),
		iUseCertAuthoritiesFilter,
		iUseCertTypesFilter,
		iUseAllowedCipherSuitesFilter));		
	
	for (TInt j = 0; j < aAllowedUserCerts.Count(); j++)
	{
		EapCertificateEntry * const copy_cert = aAllowedUserCerts[j]->Copy();
		if (copy_cert == 0)
		{
			User::Leave(KErrNoMemory);
		}

		iAllowedUserCerts.AppendL(copy_cert);

		EAP_TRACE_SETTINGS(copy_cert);
	}

	if (iCertAuthorities.Count() > 0)
	{
		iCertAuthorities.ResetAndDestroy();
	}

	if (aUseCertAuthoritiesFilter
		&& aCertAuthorities)
	{
		for (TUint i = 0; i < aCertAuthorities->get_object_count(); i++)
		{
			HBufC8* buf = HBufC8::NewLC((aCertAuthorities->get_object(i))->get_data_length());
			TPtr8 ptr = buf->Des();
			ptr.Copy((aCertAuthorities->get_object(i))->get_data((aCertAuthorities->get_object(i))->get_data_length()),
				(aCertAuthorities->get_object(i))->get_data_length());

			// Try to form distiguished name
			CX500DistinguishedName* tmp = 0;
			TRAPD(error, tmp = CX500DistinguishedName::NewL(ptr));
			if (error == KErrNone)
			{
				CleanupStack::PushL(tmp);
				// Distinguished name was found -> add it to array.
				User::LeaveIfError(iCertAuthorities.Append(tmp));
				CleanupStack::Pop(tmp);
			}
			CleanupStack::PopAndDestroy(buf);
		}
	}
	
	if (aUseCertTypesFilter)
	{
		iCertTypes = aCertTypes;
	}

	if (aUseAllowedCipherSuitesFilter)
	{	
		iRSACertsAllowed = EFalse; 
		iDSACertsAllowed = EFalse;
		
		for (TInt i = 0; i < aAllowedCipherSuites.Count(); i++)
		{
			if (EapTlsPeapUtils::CipherSuiteUseRSAKeys(static_cast<tls_cipher_suites_e>(aAllowedCipherSuites[i])))
			{
				iRSACertsAllowed = ETrue;
			}
			else if (EapTlsPeapUtils::CipherSuiteUseDSAKeys(static_cast<tls_cipher_suites_e>(aAllowedCipherSuites[i])))
			{
				iDSACertsAllowed = ETrue;
			}
		}
	}

	iState = EGetMatchingCertsInitStore;
	
	if (iCertStore == 0)
	{
		iCertStore = CUnifiedCertStore::NewL(iFs, EFalse);
		iCertStore->Initialize(iStatus);		
	}
	else
	{
		TRequestStatus* status = &iStatus;
		User::RequestComplete(status, KErrNone);		
	}		
	SetActive();	
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

void CEapTlsPeapCertInterface::ReadCertificateL(EapCertificateEntry& aCertInfo, const TBool aRetrieveChain)
{	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::ReadCertificateL()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapTlsPeapCertInterface::ReadCertificateL()");

	iCertInfo = aCertInfo;
	iRetrieveChain = aRetrieveChain;
	iState = EReadCertInitStore;
	
	if (iCertStore == 0)
	{
		iCertStore = CUnifiedCertStore::NewL(iFs, EFalse);
		iCertStore->Initialize(iStatus);		
	}
	else
	{
		TRequestStatus* status = &iStatus;
		User::RequestComplete(status, KErrNone);		
	}		
	SetActive();			
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

void CEapTlsPeapCertInterface::ReadCACertificateL(EapCertificateEntry& aCertInfo)
{	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::ReadCACertificateL()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapTlsPeapCertInterface::ReadCACertificateL()");

	iCertInfo = aCertInfo;
	iState = EReadCACertInitStore;
	
	if (iCertStore == 0)
	{
		iCertStore = CUnifiedCertStore::NewL(iFs, EFalse);
		iCertStore->Initialize(iStatus);		
	}
	else
	{
		TRequestStatus* status = &iStatus;
		User::RequestComplete(status, KErrNone);		
	}		
	SetActive();			
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}


//--------------------------------------------------

void CEapTlsPeapCertInterface::ValidateChainL(
	TDesC8& aCertChain,
	RPointerArray<EapCertificateEntry>& aAllowedCACerts,
	const TBool aUseAutomaticCaCertificate)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::ValidateChainL(): aUseAutomaticCaCertificate=%d\n"),
		aUseAutomaticCaCertificate));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapTlsPeapCertInterface::ValidateChainL()");

	iUseAutomaticCaCertificate = aUseAutomaticCaCertificate;
	iCAIndex = 0;
	iAllowedCACerts.ResetAndDestroy();

	if (!iUseAutomaticCaCertificate)
	{
		for (TInt j = 0; j < aAllowedCACerts.Count(); j++)
		{
			EapCertificateEntry * const copy_cert = aAllowedCACerts[j]->Copy();
			if (copy_cert == 0)
			{
				User::Leave(KErrNoMemory);
			}

			iAllowedCACerts.AppendL(copy_cert);

			EAP_TRACE_SETTINGS(copy_cert);
		}
	}

	delete iInputCertChain;

	iInputCertChain = 0;
	iInputCertChain = aCertChain.AllocL();
	iState = EValidateChainInitStore;

	if (iCertStore == 0)
	{
		iCertStore = CUnifiedCertStore::NewL(iFs, EFalse);
		iCertStore->Initialize(iStatus);		
	}
	else
	{
		TRequestStatus* status = &iStatus;
		User::RequestComplete(status, KErrNone);		
	}

	SetActive();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

void CEapTlsPeapCertInterface::DoCancel()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::DoCancel()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapTlsPeapCertInterface::DoCancel()");

	if (iCertStore != 0 && iCertStore->IsActive())
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapTlsPeapCertInterface::DoCancel(): calls iCertStore->CancelInitialize and other cancels()\n")));
	
		iCertStore->CancelInitialize();	
		iCertStore->CancelList();
		iCertStore->CancelGetCert();
		iCertStore->CancelRetrieve();
	}
	
	// We have to cancel singing if it is ongoing. Both for RSA and DSA.
	if(iRSASigner != 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapTlsPeapCertInterface::DoCancel(): calls iRSASigner->CancelSign()\n")));
	
		iRSASigner->CancelSign();
		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapTlsPeapCertInterface::DoCancel(): calls iRSASigner->Release()\n")));
		
		iRSASigner->Release(); // This seems to be needed.
	}

	if(iDSASigner != 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapTlsPeapCertInterface::DoCancel(): calls iDSASigner->CancelSign()\n")));
	
		iDSASigner->CancelSign();
		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapTlsPeapCertInterface::DoCancel(): calls iDSASigner->Release()\n")));
		
		iDSASigner->Release(); // This seems to be needed.		
	}

	// We have to cancel decrypting if it is ongoing.
	if(iDecryptor != 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapTlsPeapCertInterface::DoCancel(): calls iDecryptor->CancelDecrypt()\n")));
	
		iDecryptor->CancelDecrypt();
	}
	
	if (iKeyStore != 0 && iKeyStore->IsActive())
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapTlsPeapCertInterface::DoCancel(): calls iKeyStore->CancelOpen()\n")));

		iKeyStore->CancelOpen();
		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapTlsPeapCertInterface::DoCancel(): calls iKeyStore->Cancel()\n")));
		
		iKeyStore->Cancel();
	}

	if (iCertChain != 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapTlsPeapCertInterface::DoCancel(): calls iCertChain->CancelValidate()\n")));
	
		iCertChain->CancelValidate();
	}
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::DoCancel(): returns\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------
	
void CEapTlsPeapCertInterface::SignL(
	const TKeyIdentifier& aKeyId,
	const TDesC8& aHashIn,
	const TUint aSignatureLength)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::SignL()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapTlsPeapCertInterface::SignL()");

	iKeyIdentifier = aKeyId;
	if (aHashIn.Size() > KMaxHashLength)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Illegal hash size %d to SignL(), shoudbe <= %d.\n"),
			aHashIn.Size(),
			KMaxHashLength));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		User::Leave(KErrGeneral);		
	}
	iHashIn.Copy(aHashIn);

	delete iSignature;
	iSignature = 0;

	// Allocate space for the signature
	iSignature = HBufC8::NewL(aSignatureLength);

	delete iSignaturePtr;
	iSignaturePtr = 0;

	iSignaturePtr = new(ELeave) TPtr8(iSignature->Des());

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("SignL: aKeyId"),
														   aKeyId.Ptr(),
														   aKeyId.Length()));

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("SignL: aHashIn"),
														   aHashIn.Ptr(),
														   aHashIn.Length()));
	
	
	if (iKeyStore == 0)
	{

#if defined(USE_EAP_TLS_PEAP_UNIFIED_KEY_STORE_CACHE)

		// Try to get the keystore class pointer from memory store
		eap_variable_data_c key(m_am_tools);
		eap_status_e status = key.set_copy_of_buffer(KKeyStoreHandlePrefix, sizeof(KKeyStoreHandlePrefix));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			User::Leave(KErrNoMemory);
		}
		status = key.add_data(KKeyStoreHandleKey, sizeof(KKeyStoreHandleKey));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			User::Leave(KErrNoMemory);
		}
		
		eap_tlv_message_data_c tlv_data(m_am_tools);
		
		status = m_am_tools->memory_store_get_data(&key, &tlv_data);

		if (status != eap_status_ok)
		{

#endif //#if defined(USE_EAP_TLS_PEAP_UNIFIED_KEY_STORE_CACHE)


			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_TLSPEAP: CEapTlsPeapCertInterface::SignL(): cannot get previous CUnifiedKeyStore handle.\n")));


			// At this point we can set the passphrase timeout because it the passphrase 
			// cache in the FS token server is still empty. Passphrase timeout setting clears 
			// the cache.
			iState = ESignInitStore;
			
			iKeyStore = CUnifiedKeyStore::NewL(iFs);
			iKeyStore->Initialize(iStatus);		
			
#if defined(USE_EAP_TLS_PEAP_UNIFIED_KEY_STORE_CACHE)

			status = tlv_data.add_message_data(
				eap_type_tlspeap_stored_keystore_handle,
				sizeof(iKeyStore),
				&iKeyStore);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(KErrNoMemory);
			}		
			
			status = m_am_tools->memory_store_add_data(
				&key,
				&tlv_data,
				0);
			if (status != eap_status_ok)
			{			
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(KErrNoMemory);
			}
		}
		else
		{		
			
			status = m_am_tools->memory_store_get_data(&key, &tlv_data);
			
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_TLSPEAP: Found previous keystore handle.\n")));

			// Parse read data.
			eap_array_c<eap_tlv_header_c> tlv_blocks(m_am_tools);
				
			status = tlv_data.parse_message_data(&tlv_blocks);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(KErrGeneral);
			}

			if (tlv_blocks.get_object_count() > 0)
			{
				eap_tlv_header_c * const tlv = tlv_blocks.get_object(0);
				if (tlv != 0)
				{
					if (tlv->get_type() == eap_type_tlspeap_stored_keystore_handle)
					{
						iKeyStore = *(reinterpret_cast<CUnifiedKeyStore **>(tlv->get_value(tlv->get_value_length())));
						
						// Skip passphrase setting because it clears the passphrase cache
						iState = ESetPassphraseTimeout;
							
						TRequestStatus* status = &iStatus;
						User::RequestComplete(status, KErrNone);
						
					}
					else
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						User::Leave(KErrGeneral);
					}
				}
				else
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					User::Leave(KErrGeneral);
				}
			}
			else
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(KErrGeneral);
			}			
		}

#endif //#if defined(USE_EAP_TLS_PEAP_UNIFIED_KEY_STORE_CACHE)

	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_TLSPEAP: CEapTlsPeapCertInterface::SignL(): uses previous CUnifiedKeyStore handle.\n")));

		// Skip passphrase setting because it clears the passphrase cache
		iState = ESetPassphraseTimeout;

		TRequestStatus* status = &iStatus;
		User::RequestComplete(status, KErrNone);
	}		

	SetActive();


		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------
	
void CEapTlsPeapCertInterface::DecryptL(
	const TKeyIdentifier& aKeyId,
	const TDesC8& aDataIn)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::DecryptL()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapTlsPeapCertInterface::DecryptL()");

	iKeyIdentifier = aKeyId;

	delete iDataIn;
	iDataIn = 0;
	delete iDataOut;
	iDataOut = 0;

	iDataIn = HBufC8::NewL(aDataIn.Length());
	iDataOut = HBufC8::NewL(aDataIn.Length());
	
	delete iPtrOut;
	iPtrOut = 0;

	iPtrOut = new(ELeave) TPtr8(iDataOut->Des());
	TPtr8 ptrIn = iDataIn->Des();
	
	ptrIn.Copy(aDataIn);

	iState = EDecryptInitStore;
		
	// Try to get the keystore handler class from memory store 
	if (iKeyStore == 0)
	{

#if defined(USE_EAP_TLS_PEAP_UNIFIED_KEY_STORE_CACHE)

		// Try to get the keystore class pointer from memory store
		eap_variable_data_c key(m_am_tools);
		eap_status_e status = key.set_copy_of_buffer(KKeyStoreHandlePrefix, sizeof(KKeyStoreHandlePrefix));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			User::Leave(KErrNoMemory);
		}
		status = key.add_data(KKeyStoreHandleKey, sizeof(KKeyStoreHandleKey));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			User::Leave(KErrNoMemory);
		}
		
		eap_tlv_message_data_c tlv_data(m_am_tools);
		
		status = m_am_tools->memory_store_get_data(&key, &tlv_data);

		if (status != eap_status_ok)
		{

#endif //#if defined(USE_EAP_TLS_PEAP_UNIFIED_KEY_STORE_CACHE)

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_TLSPEAP: CEapTlsPeapCertInterface::DecryptL(): cannot get previous CUnifiedKeyStore handle.\n")));

			iKeyStore = CUnifiedKeyStore::NewL(iFs);
			iKeyStore->Initialize(iStatus);		
			
#if defined(USE_EAP_TLS_PEAP_UNIFIED_KEY_STORE_CACHE)

			status = tlv_data.add_message_data(
				eap_type_tlspeap_stored_keystore_handle,
				sizeof(iKeyStore),
				&iKeyStore);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(KErrNoMemory);
			}		
			
			status = m_am_tools->memory_store_add_data(
				&key,
				&tlv_data,
				0);
			if (status != eap_status_ok)
			{			
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(KErrNoMemory);
			}
		}
		else
		{		
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_TLSPEAP: CEapTlsPeapCertInterface::DecryptL(): Found previous keystore handle.\n")));

			// Parse read data.
			eap_array_c<eap_tlv_header_c> tlv_blocks(m_am_tools);
				
			status = tlv_data.parse_message_data(&tlv_blocks);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(KErrGeneral);
			}

			if (tlv_blocks.get_object_count() > 0)
			{
				eap_tlv_header_c * const tlv = tlv_blocks.get_object(0);
				if (tlv != 0)
				{
					if (tlv->get_type() == eap_type_tlspeap_stored_keystore_handle)
					{
						iKeyStore = *(reinterpret_cast<CUnifiedKeyStore **>(tlv->get_value(tlv->get_value_length())));
				
						TRequestStatus* status = &iStatus;
						User::RequestComplete(status, KErrNone);
						
					}
					else
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						User::Leave(KErrGeneral);
					}
				}
				else
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					User::Leave(KErrGeneral);
				}
			}
			else
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(KErrGeneral);
			}
		}

#endif //#if defined(USE_EAP_TLS_PEAP_UNIFIED_KEY_STORE_CACHE)

	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_TLSPEAP: CEapTlsPeapCertInterface::DecryptL(): uses previous CUnifiedKeyStore handle.\n")));

		TRequestStatus* status = &iStatus;
		User::RequestComplete(status, KErrNone);
	}		

	SetActive();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

void CEapTlsPeapCertInterface::RunL()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::RunL(): TEMP iStatus=%d, iState=%d\n"),
		iStatus.Int(),
		iState));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapTlsPeapCertInterface::RunL()");

	if (!(iStatus.Int() == KErrNone))
	{		
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: EAP-TLS certificate interface failed: error=%d.\n"),
			iStatus.Int()));
		iParent->SendErrorNotification(eap_status_user_cancel_authentication);
		
		if(iState == ESignOpenKeyStore)
		{
			// User probably cancelled the keystore password query.

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): ESignOpenKeyStore Failed\n")));

			if(iRSASigner != NULL)
			{
				iRSASigner->Release();
				
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapTlsPeapCertInterface::RunL(): iRSASigner->Release() OK\n")));
			}
			
			if(iDSASigner != NULL)
			{
				iDSASigner->Release(); 
				
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapTlsPeapCertInterface::RunL(): iDSASigner->Release() OK\n")));
			}		
		}
		
		return;
	}

	switch (iState)
	{

	case EGetMatchingCertsInitStore:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): EGetMatchingCertsInitStore\n")));

			// Set up filter
			delete iCertFilter;
			iCertFilter = 0;

			for (TInt i = 0; i < iCertInfos.Count(); i++)
			{
				iCertInfos[i]->Release();
			}
			iCertInfos.Reset();			
			
			TRAPD(error, iCertFilter = CCertAttributeFilter::NewL());
			if (error != KErrNone)
			{ 
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				
				RPointerArray<EapCertificateEntry> tmp(sizeof(EapCertificateEntry));

				m_am_tools->enter_global_mutex();
				
				iParent->complete_get_matching_certificates(tmp, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
				
				m_am_tools->leave_global_mutex();
				break;
			}
			
			iCertFilter->SetFormat(EX509Certificate);
			iCertFilter->SetOwnerType(EUserCertificate);

			iState = EGetMatchingCertsInitialize;
			iCertStore->List(
				iCertInfos,
				*iCertFilter, 
				iStatus);
			SetActive();
			
		}
		break;

	case EGetMatchingCertsInitialize:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): EGetMatchingCertsInitialize, Total Certs: iCertInfos.Count()=%d\n"),
				iCertInfos.Count()));

			iMatchingUserCertInfos.ResetAndDestroy();

			// Remove non-allowed
			TInt i(0);
			TInt j(0);
			for (i = 0; i < iCertInfos.Count(); i++)
			{
				for (j = 0; j < iAllowedUserCerts.Count(); j++)
				{				
					if ( (iCertInfos[i]->Label().Compare(*(iAllowedUserCerts[j]->GetLabel())) == 0
						 || iCertInfos[i]->Label().Length() == 0
						 || iAllowedUserCerts[j]->GetLabel()->Length() == 0)
						&& iCertInfos[i]->SubjectKeyId() == iAllowedUserCerts[j]->GetSubjectKeyId())
					{

						EAP_TRACE_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("RunL(): EGetMatchingCertsInitialize, Found a Matching USER cert\n")));

						EAP_TRACE_DATA_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("RunL(): EGetMatchingCertsInitialize, Label of matching cert"),
							iCertInfos[i]->Label().Ptr(),
							iCertInfos[i]->Label().Size()));

						EAP_TRACE_DATA_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("RunL(): EGetMatchingCertsInitialize, SubjectkeyID of matching cert"),
							iCertInfos[i]->SubjectKeyId().Ptr(),
							iCertInfos[i]->SubjectKeyId().Size()));

						break;
					}
				}
				if (j == iAllowedUserCerts.Count())
				{
					// Not allowed -> remove
					iCertInfos.Remove(i);
					i--;
				}
			}

			if (iCertInfos.Count() == 0)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapTlsPeapCertInterface::RunL(): EGetMatchingCertsInitialize - No matching Certificates.\n")));
			
				// No matching certs
			
				// Timeout handles error situation
				RPointerArray<EapCertificateEntry> empty(sizeof(EapCertificateEntry));

				m_am_tools->enter_global_mutex();

				iParent->complete_get_matching_certificates(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_certificate)); //Failure

				m_am_tools->leave_global_mutex();

				break;
			}

			// Get the first certificate
			iUserCertIndex = 0;

			iMatchingUserCerts.ResetAndDestroy();
							
			iState = EGetMatchingCertsLoop;

			iEncodedCertificate->Des().SetLength(0);
			
			HBufC8 * tmpCert = 0;
			TRAPD(error, tmpCert = iEncodedCertificate->ReAllocL(iCertInfos[iUserCertIndex]->Size()));
			if (error != KErrNone)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));

				RPointerArray<EapCertificateEntry> empty(sizeof(EapCertificateEntry));

				m_am_tools->enter_global_mutex();

				iParent->complete_get_matching_certificates(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure

				m_am_tools->leave_global_mutex();

				break;
			}

			iEncodedCertificate = tmpCert;

			iCertPtr.Set(iEncodedCertificate->Des());

			iCertStore->Retrieve(
				*(iCertInfos[iUserCertIndex]), 
				iCertPtr,
				iStatus);

			SetActive();						
		}		
		break;

	case EGetMatchingCertsLoop:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): EGetMatchingCertsLoop\n")));

			CX509Certificate* cert = 0;
			TRAPD(error, cert = CX509Certificate::NewL(iEncodedCertificate->Des()));
			if (error != KErrNone || cert == 0)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				
				RPointerArray<EapCertificateEntry> empty(sizeof(EapCertificateEntry));
											
				m_am_tools->enter_global_mutex();
				
				iParent->complete_get_matching_certificates(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
				
				m_am_tools->leave_global_mutex();

				break;
			}
				
			if (iMatchingUserCerts.Append(cert) != KErrNone)
			{
				delete cert;
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				
				RPointerArray<EapCertificateEntry> empty(sizeof(EapCertificateEntry));

				m_am_tools->enter_global_mutex();
				
				iParent->complete_get_matching_certificates(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
				
				m_am_tools->leave_global_mutex();
							
				break;
			}

			// No need to validate iCertInfos here as the execution doesn't come to this case if iCertInfos
			// is empty, check is done in the above case.

			EapCertificateEntry * entry = new EapCertificateEntry;
			if (entry == 0)
			{
				// Timeout handles error situation
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));					

				RPointerArray<EapCertificateEntry> empty(sizeof(EapCertificateEntry));

				m_am_tools->enter_global_mutex();
				
				iParent->complete_get_matching_certificates(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
				
				m_am_tools->leave_global_mutex();

				delete entry;

				break;
			}

			entry->SetLabel(iCertInfos[iUserCertIndex]->Label());
			entry->SetSubjectKeyId(iCertInfos[iUserCertIndex]->SubjectKeyId());
			
			TRAP(error, iMatchingUserCertInfos.AppendL(entry));
			if (error != KErrNone)
			{
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				
				RPointerArray<EapCertificateEntry> empty(sizeof(EapCertificateEntry));

				m_am_tools->enter_global_mutex();
				
				iParent->complete_get_matching_certificates(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
				
				m_am_tools->leave_global_mutex();
							
				delete entry;

				break;
			}

			iUserCertIndex++;

			if (iUserCertIndex >= static_cast<TUint>(iCertInfos.Count()))
			{				
				// Check each item in iMatchingUserCerts against filters
				TInt i(0);
				
				// CA filter
				if (iUseCertAuthoritiesFilter)
				{
					for (i = 0; i < iMatchingUserCerts.Count(); i++)
					{
						const CX500DistinguishedName& dn = iMatchingUserCerts[i]->IssuerName();
						
						TInt j(0);

						for (j = 0; j < iCertAuthorities.Count(); j++)
						{
							if (dn.ExactMatchL(*iCertAuthorities[j]))
							{
								// Matches
								break;
							}
						} // for()

						if (j == iCertAuthorities.Count())
						{						
							// No match. Remove
							delete iMatchingUserCerts[i];
							iMatchingUserCerts.Remove(i);
							delete iMatchingUserCertInfos[i];
							iMatchingUserCertInfos.Remove(i);
							i--;
							
							EAP_TRACE_DEBUG(
								m_am_tools,
								TRACE_FLAGS_DEFAULT,
								(EAPL("RunL(): EGetMatchingCertsLoop Using CertAuthoritiesFilter - no distinguished name matching - Matching cert removed\n")));
						}
					}
				}
				// Check Certificate types
				if (iUseCertTypesFilter
					&& iCertTypes != 0)
				{
					for (i = 0; i < (TInt) iMatchingUserCerts.Count(); i++)
					{
						// Get the public key algorithm
						const CSubjectPublicKeyInfo& public_key = iMatchingUserCerts[i]->PublicKey();
						TAlgorithmId algorithm = public_key.AlgorithmId();
						
						TUint j(0);
						for (j = 0; j < iCertTypes->get_object_count(); j++)
						{
							u8_t* val = iCertTypes->get_object(j);

							if (val != 0)
							{
								if (algorithm == ERSA 
									&& (*val == ERSASign
									|| *val == ERSASignWithFixedDH 
									|| *val == ERSASignWithEphemeralDH))
								{
									break;				
								}
								else if (algorithm == EDSA 
									&& (*val == EDSASign
									|| *val == EDSASignWithFixedDH 
									|| *val == EDSASignWithEphemeralDH))
								{
									break;				
								}
							}
						} // for()

						if (j == iCertTypes->get_object_count())
						{
							// No match. Remove
							delete iMatchingUserCerts[i];
							iMatchingUserCerts.Remove(i);
							delete iMatchingUserCertInfos[i];
							iMatchingUserCertInfos.Remove(i);
							i--;
							
							EAP_TRACE_DEBUG(
								m_am_tools,
								TRACE_FLAGS_DEFAULT,
								(EAPL("RunL(): EGetMatchingCertsLoop Using CertTypesFilter - Public key algorithm(%d) or Signing methods NOT matching - Matching cert removed\n"),
								algorithm));
						}					

					}
				}

				// Check cipher suites
				if (iUseAllowedCipherSuitesFilter)
				{
					for (i = 0; i < static_cast<TUint> (iMatchingUserCerts.Count()); i++)
					{
						// Get the public key algorithm
						const CSubjectPublicKeyInfo& public_key = iMatchingUserCerts[i]->PublicKey();
						TAlgorithmId algorithm = public_key.AlgorithmId();		
							
						// IF it is RSA certificate that is not allowed
						if (algorithm == ERSA && iRSACertsAllowed == EFalse
							// OR it is DSA certificate that is not allowed
							|| (algorithm == EDSA && iDSACertsAllowed == EFalse)
							// OR it is some other type
							|| (algorithm != ERSA && algorithm != EDSA))
						{
							// No match. Remove
							delete iMatchingUserCerts[i];
							iMatchingUserCerts.Remove(i);
							delete iMatchingUserCertInfos[i];
							iMatchingUserCertInfos.Remove(i);
							i--;
							
							EAP_TRACE_DEBUG(
								m_am_tools,
								TRACE_FLAGS_DEFAULT,
								(EAPL("RunL(): EGetMatchingCertsLoop Using AllowedCipherSuitesFilter -  Cert is NOT allowed (RSACertsAllowed=%d,DSACertsAllowed=%d) for this Public key algorithm(%d) - Matching cert removed\n"),
								iRSACertsAllowed, iDSACertsAllowed, algorithm));							
						}
					}
				}
				// Return the certificates.
				m_am_tools->enter_global_mutex();

				iParent->complete_get_matching_certificates(iMatchingUserCertInfos, eap_status_ok);				

				m_am_tools->leave_global_mutex();
			}
			else
			{
				
				iState = EGetMatchingCertsLoop;

				iEncodedCertificate->Des().SetLength(0);

				HBufC8 * tmpCert = 0;
				TRAPD(error, tmpCert = iEncodedCertificate->ReAllocL(iCertInfos[iUserCertIndex]->Size()));
				if (error != KErrNone)
				{
					EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				
					RPointerArray<EapCertificateEntry> empty(sizeof(EapCertificateEntry));

					m_am_tools->enter_global_mutex();
					
					iParent->complete_get_matching_certificates(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
					
					m_am_tools->leave_global_mutex();
					
					break;
				}

				iEncodedCertificate = tmpCert;
				
				iCertPtr.Set(iEncodedCertificate->Des());

				iCertStore->Retrieve(
					*(iCertInfos[iUserCertIndex]), 
					iCertPtr,
					iStatus);
							
				SetActive();
			}				
		}
		break;
	
	case EReadCertInitStore:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): EReadCertInitStore\n")));

			// Set up filter
			delete iCertFilter;
			iCertFilter = 0;

			for (TInt i = 0; i < iCertInfos.Count(); i++)
			{
				iCertInfos[i]->Release();
			}
			iCertInfos.Reset();			
			
			TRAPD(error, iCertFilter = CCertAttributeFilter::NewL());
			if (error != KErrNone || iCertFilter == 0)
			{ 
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				
				RPointerArray<CX509Certificate> empty;
				
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_own_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
				
				m_am_tools->leave_global_mutex();
				
				break;
			}
			
			iCertFilter->SetFormat(EX509Certificate);
			iCertFilter->SetOwnerType(EUserCertificate);
			iCertFilter->SetSubjectKeyId(iCertInfo.GetSubjectKeyId());

			if (iCertInfo.GetLabel()->Size() > 0)
			{
				iCertFilter->SetLabel(*(iCertInfo.GetLabel())); // We can not use Label in the filter as certificates saved
													   // by using SetConfigurationL (OMA DM etc uses it) will not have Label.
			}

			iState = EReadCertList;
			iCertStore->List(
				iCertInfos,
				*iCertFilter, 
				iStatus);
			SetActive();
			
		}	
		break;
	
	case EReadCertList:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): EReadCertList\n")));

			// Now we should have all the cert infos in iCertInfos.			
			if (iCertInfos.Count() == 0)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: EReadCertList iCertInfos.Count = 0.\n")));			
				
				RPointerArray<CX509Certificate> empty;
				
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_own_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_certificate)); //Failure
				
				m_am_tools->leave_global_mutex();

				break;
			}
			
			// Just take the first found certificate
			CCTCertInfo* info;
			info = iCertInfos[0];			

			iState = EReadCert;
			
			iEncodedCertificate->Des().SetLength(0);

			HBufC8 * tmpCert = 0;
			TRAPD(error, tmpCert = iEncodedCertificate->ReAllocL(info->Size()));
			if (error != KErrNone)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				
				RPointerArray<CX509Certificate> empty;
								
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_own_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
				
				m_am_tools->leave_global_mutex();
				
				break;
			}

			iEncodedCertificate = tmpCert;
				
			iCertPtr.Set(iEncodedCertificate->Des());
			
			iCertStore->Retrieve(
				*info, 
				iCertPtr,
				iStatus);
			
			SetActive();			
		}
		break;
	case EReadCert:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): EReadCert\n")));

			CX509Certificate* cert = 0;
			TRAPD(error, cert = CX509Certificate::NewL(iEncodedCertificate->Des()));
			if (error != KErrNone)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				
				RPointerArray<CX509Certificate> empty;
								
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_own_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
				
				m_am_tools->leave_global_mutex();
				
				break;
			}
			
			iUserCertChain.ResetAndDestroy();
			if (iUserCertChain.Append(cert) != KErrNone)
			{
				delete cert;
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				
				RPointerArray<CX509Certificate> empty;
								
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_own_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
				
				m_am_tools->leave_global_mutex();
				
				break;
			}
			
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL()-EReadCert: iRetrieveChain=%d\n"),
				iRetrieveChain));
			if (iRetrieveChain)
			{
				// Init Symbian store for cert fetching
				iState = ERetrieveChainInitStore;
				if (iCertStore == 0)
				{
					iCertStore = CUnifiedCertStore::NewL(iFs, EFalse);
					iCertStore->Initialize(iStatus);		
				}
				else
				{
					TRequestStatus* status = &iStatus;
					User::RequestComplete(status, KErrNone);		
				}
				SetActive();
				break;
			}
			
			// Note that parent handles cert deletion from now on.
			iParent->complete_read_own_certificate(iUserCertChain, eap_status_ok);
		}
		break;

	case ERetrieveChainInitStore:
		{		
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): ERetrieveChainInitStore\n")));

			// List all certificates
			delete iCertFilter;
			iCertFilter = 0;

			for (TInt i = 0; i < iCertInfos.Count(); i++)
			{
				iCertInfos[i]->Release();
			}
			iCertInfos.Reset();			
			
			TRAPD(error, iCertFilter = CCertAttributeFilter::NewL());
			if (error != KErrNone)
			{ 
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				
				RPointerArray<CX509Certificate> empty;
								
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_own_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
				
				m_am_tools->leave_global_mutex();
				
				break;
			}
			
			iCertFilter->SetFormat(EX509Certificate);
			iCertFilter->SetOwnerType(ECACertificate);

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): For chain init store, we  need CA certificates only\n")));			

			iState = EGetAllCerts;
			iCertStore->List(
				iCertInfos,
				*iCertFilter, 
				iStatus);
			SetActive();
		}
		break;

	case EGetAllCerts:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): EGetAllCerts\n")));

			// Now we should have all the cert infos in iCertInfos.
			
			iRootCerts.ResetAndDestroy();
			
			// Validate iCertInfos before using it.
			if (iCertInfos.Count() == 0)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapTlsPeapCertInterface::RunL(): EGetAllCerts - No matching Certificates.\n")));
			
				// No matching certs. The authentication should fail now. So complete the request with an 
				// empty chain.
				
				iUserCertChain.ResetAndDestroy();

				m_am_tools->enter_global_mutex();
				
				// Note that parent handles cert deletion from now on.
				iParent->complete_read_own_certificate(iUserCertChain, EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_certificate));

				m_am_tools->leave_global_mutex();

				break;
			}
			
			CCTCertInfo* info;
			info = iCertInfos[0];
			iCAIndex = 0;

			iState = ECreateCertChain;
			
			iEncodedCertificate->Des().SetLength(0);

			HBufC8 * tmpCert = 0;
			TRAPD(error, tmpCert = iEncodedCertificate->ReAllocL(info->Size()));
			if (error != KErrNone)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				
				RPointerArray<CX509Certificate> empty;
								
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_own_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
				
				m_am_tools->leave_global_mutex();
				
				break;
			}

			iEncodedCertificate = tmpCert;
				
			iCertPtr.Set(iEncodedCertificate->Des());
			
			iCertStore->Retrieve(
				*info, 
				iCertPtr,
				iStatus);
			
			SetActive();			
		}
		break;

	case ECreateCertChain:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): ECreateCertChain\n")));

			CX509Certificate* cert = 0;
			TRAPD(error, cert = CX509Certificate::NewL(iEncodedCertificate->Des()));
			if (error != KErrNone || cert == 0)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				
				RPointerArray<CX509Certificate> empty;
								
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_own_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
				
				m_am_tools->leave_global_mutex();
				
				break;
			}
			
#if defined(_DEBUG) || defined(DEBUG)
				
			{
				// No need to validate iCertInfos in here as it is done in case: EGetAllCerts
				CCTCertInfo* tempInfo;
				tempInfo = iCertInfos[iCAIndex];

				// These are for the trace debug.
				TCertLabel label = tempInfo->Label();				
				TKeyIdentifier SubjectKeyId = tempInfo->SubjectKeyId();
				TKeyIdentifier IssuerId = tempInfo->IssuerKeyId();
				TCertificateFormat format = tempInfo->CertificateFormat();
				TCertificateOwnerType ownerType = tempInfo->CertificateOwnerType();			
				
				EAP_TRACE_DEBUG_SYMBIAN((_L("\n CEapTlsPeapCertInterface::RunL() : About to retrieve Cert with details, Label = %S"),
					&label));

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("Other detials- Format=%d, Owner type=%d, IsDeletable=%d, Type UID=%d\n"),
					format,
					ownerType,
					tempInfo->IsDeletable(),
					tempInfo->Type()));
				
				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Subject key Id is"),
					SubjectKeyId.Ptr(),
					SubjectKeyId.Size()));

				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Issuer Id is"),
					IssuerId.Ptr(),
					IssuerId.Size()));
					
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapTlsPeapCertInterface::RunL()- NEW subject key id stuff\n")));				
			
				if( cert != NULL )
				{				
					const CX509CertExtension* certExt = cert->Extension(KSubjectKeyId);
					
					if (certExt)
					{
						const CX509SubjectKeyIdExt* subKeyExt = CX509SubjectKeyIdExt::NewLC(certExt->Data());
						EAP_UNREFERENCED_PARAMETER(subKeyExt);

						EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("NEW Subject key Id is:"),
							subKeyExt->KeyId().Ptr(),
							subKeyExt->KeyId().Size()));					

						CleanupStack::PopAndDestroy(); // subKeyIdExt
					}
					else
					{
						EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("WARNING: No extension for this certificate\n")));			
					}
				}
				else
				{
					EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: No Certs here!\n")));			
				}
			}

#endif
			
		
			// Signal completition
			if (iRootCerts.Append(cert) != KErrNone)
			{
				delete cert;
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				
				RPointerArray<CX509Certificate> empty;
								
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_own_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
				
				m_am_tools->leave_global_mutex();
				
				break;
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL()-ECreateCertChain: iCAIndex=%d, iRootCerts.Count()=%d, iUserCertChain.Count()= %d, iCertInfos-count=%d\n"),
				iCAIndex, iRootCerts.Count(), iUserCertChain.Count(), iCertInfos.Count()));

			iCAIndex++;
			if (iCAIndex >= static_cast<TUint>(iCertInfos.Count()))
			{
				if(iUserCertChain.Count() == 0)
				{
					iParent->complete_read_own_certificate(iUserCertChain, EAP_STATUS_RETURN(m_am_tools, eap_status_ca_certificate_unknown));
					break;
				}
			
				// We got all. Validate.
				TInt i(0);
				for (i = 0; i < iRootCerts.Count(); i++)
				{
					if (iUserCertChain[iUserCertChain.Count()-1]->IsSelfSignedL())
					{
						// The last cert in chain is self-signed. Our chain is ready.
						
						EAP_TRACE_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("CEapTlsPeapCertInterface::RunL()-ECreateCertChain: The last cert in chain is self-signed\n")));
						
						break;
					}
					if (iUserCertChain[iUserCertChain.Count()-1]->IssuerName().ExactMatchL(iRootCerts[i]->SubjectName()))
					{
						// DNs match. Check signature.
						if (iUserCertChain[iUserCertChain.Count()-1]->PublicKey().AlgorithmId() != iRootCerts[i]->PublicKey().AlgorithmId())
						{
							// The algorithms differ.
							continue;
						}
						CDSAParameters* dsaParams = 0;
						CSigningKeyParameters* signParams = 0;

						if (iUserCertChain[iUserCertChain.Count()-1]->PublicKey().AlgorithmId() == EDSA)
						{
							// DSA signing
							const CSubjectPublicKeyInfo& key = iRootCerts[i]->PublicKey();
							const TPtrC8 params = key.EncodedParams();	
							
							TRAPD(error, dsaParams = CX509DSAPublicKey::DSAParametersL(params));
							if (error != KErrNone)
							{				
				
								RPointerArray<CX509Certificate> empty;
								m_am_tools->enter_global_mutex();
								
								iParent->complete_read_own_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
								
								m_am_tools->leave_global_mutex();
				
								return;
							}					
									
							TRAP(error, signParams = CSigningKeyParameters::NewL());
							if (error != KErrNone)
							{				
								RPointerArray<CX509Certificate> empty;
				
								m_am_tools->enter_global_mutex();
								
								iParent->complete_read_own_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
								
								m_am_tools->leave_global_mutex();				

								delete dsaParams;
								return;
							}
							TRAP(error, signParams->SetDSAParamsL(*dsaParams));
							if (error != KErrNone)
							{				
								RPointerArray<CX509Certificate> empty;
								
								m_am_tools->enter_global_mutex();
								
								iParent->complete_read_own_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
								
								m_am_tools->leave_global_mutex();
				
								delete dsaParams;
								delete signParams;
								return;
							}

							TRAP(error, iUserCertChain[iUserCertChain.Count()-1]->SetParametersL(*signParams));
							if (error != KErrNone)
							{
								RPointerArray<CX509Certificate> empty;
								m_am_tools->enter_global_mutex();
								
								iParent->complete_read_own_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
								
								m_am_tools->leave_global_mutex();				
							
								delete dsaParams;
								delete signParams;
								return;
							}
						}						
						
						if (iUserCertChain[iUserCertChain.Count()-1]->VerifySignatureL(iRootCerts[i]->PublicKey().KeyData()))
						{
							// This is the next item in the chain.
							if (iUserCertChain.Append(iRootCerts[i]) != KErrNone)
							{
								delete dsaParams;
								delete signParams;
								EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));

								RPointerArray<CX509Certificate> empty;
								
								m_am_tools->enter_global_mutex();
								
								iParent->complete_read_own_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
								
								m_am_tools->leave_global_mutex();
				
								return;
							}
							// Remove the copied pointer from original list
							iRootCerts.Remove(i);
							i--;
						}
						// delete all
						delete dsaParams;
						delete signParams;
					}
				}
				
				iRootCerts.ResetAndDestroy();

				// The chain is complete
			m_am_tools->enter_global_mutex();
			
			// Note that parent handles cert deletion from now on.
			iParent->complete_read_own_certificate(iUserCertChain, eap_status_ok);

			m_am_tools->leave_global_mutex();

			}
			else // if (iCAIndex >= static_cast<TUint>(iCertInfos.Count()))
			{
				CCTCertInfo* info;
				info = iCertInfos[iCAIndex]; // No need to vvalidate iCertInfos, as execution comes 
											 // here only if iCertInfos has more items than iCAIndex

				iState = ECreateCertChain;
				
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapTlsPeapCertInterface::RunL()- ECreateCertChain - Before Retrieve(): iCAIndex=%d, size=%d\n"),
					iCAIndex, info->Size()));			

				iEncodedCertificate->Des().SetLength(0);

				HBufC8 * tmpCert = 0;
				TRAPD(error, tmpCert = iEncodedCertificate->ReAllocL(info->Size()));
				if (error != KErrNone)
				{
					EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				
					RPointerArray<CX509Certificate> empty;
					
					m_am_tools->enter_global_mutex();
					
					iParent->complete_read_ca_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
					
					m_am_tools->leave_global_mutex();
				
					break;
				}

				iEncodedCertificate = tmpCert;
				
				iCertPtr.Set(iEncodedCertificate->Des());
			
				iCertStore->Retrieve(
					*info, 
					iCertPtr,
					iStatus);
				
				SetActive();						
			}
		}
		break;

	case EReadCACertInitStore:
		{			 
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): EReadCACertInitStore\n")));

			// Set up filter
			delete iCertFilter;
			iCertFilter = 0;

			for (TInt i = 0; i < iCertInfos.Count(); i++)
			{
				iCertInfos[i]->Release();
			}
			iCertInfos.Reset();			
			
			TRAPD(error, iCertFilter = CCertAttributeFilter::NewL());
			if (error != KErrNone)
			{ 
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));

				RPointerArray<CX509Certificate> empty;
				
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_ca_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
				
				m_am_tools->leave_global_mutex();
				break;
			}
			
			iCertFilter->SetFormat(EX509Certificate);
			iCertFilter->SetOwnerType(ECACertificate);
			iCertFilter->SetSubjectKeyId(iCertInfo.GetSubjectKeyId());

			if (iCertInfo.GetLabel()->Size() > 0)
			{
				iCertFilter->SetLabel(*(iCertInfo.GetLabel()));// We can not use Label in the filter as certificates saved
													// by using SetConfigurationL (OMA DM etc uses it) will not have Label.
			}

			iState = EReadCACertList;
			iCertStore->List(
				iCertInfos,
				*iCertFilter, 
				iStatus);
			SetActive();
			
		}	
		break;
	
	case EReadCACertList:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): EReadCACertList\n")));

			// Now we should have all the cert infos in iCertInfos.			
			if (iCertInfos.Count() == 0)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: EReadCACertList iCertInfos.Count = 0.\n")));

				RPointerArray<CX509Certificate> empty;
				
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_ca_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
				
				m_am_tools->leave_global_mutex();
				break;
			}
			
			// Just take the first found certificate
			CCTCertInfo* info;
			info = iCertInfos[0];			

			iState = EReadCACert;
			
			iEncodedCertificate->Des().SetLength(0);

			HBufC8 * tmpCert = 0;
			TRAPD(error, tmpCert = iEncodedCertificate->ReAllocL(info->Size()));
			if (error != KErrNone)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			

				RPointerArray<CX509Certificate> empty;
				
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_ca_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
				
				m_am_tools->leave_global_mutex();
				break;
			}

			iEncodedCertificate = tmpCert;
				
			iCertPtr.Set(iEncodedCertificate->Des());
			
			iCertStore->Retrieve(
				*info, 
				iCertPtr,
				iStatus);
			
			SetActive();			
		}
		break;
		
	case EReadCACert:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): EReadCACert\n")));
				
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL():EncodedCertificate string size=%d\n"),
				iEncodedCertificate->Size()));		

			CX509Certificate* cert = 0;
			TRAPD(error, cert = CX509Certificate::NewL(iEncodedCertificate->Des()));
			if (error != KErrNone)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			

				RPointerArray<CX509Certificate> empty;
				
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_ca_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
				
				m_am_tools->leave_global_mutex();
				break;
			}
			
			// Use iUserCertChain on purpose for this anyway even though this is CA cert.
			iUserCertChain.ResetAndDestroy();
			if (iUserCertChain.Append(cert) != KErrNone)
			{
				delete cert;
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			

				RPointerArray<CX509Certificate> empty;
				
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_ca_certificate(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)); //Failure
				
				m_am_tools->leave_global_mutex();
				break;
			}
			
			// Note that parent handles cert deletion from now on.
			iParent->complete_read_ca_certificate(iUserCertChain, eap_status_ok);					
		}
		break;

	case EValidateChainInitStore:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): EValidateChainInitStore\n")));

			delete iCertFilter;
			iCertFilter = 0;

			for (TInt i = 0; i < iCertInfos.Count(); i++)
			{
				iCertInfos[i]->Release();
			}
			iCertInfos.Reset();			
			
			TRAPD(error, iCertFilter = CCertAttributeFilter::NewL());
			if (error != KErrNone)
			{ 
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));

				const CPKIXValidationResult * const empty = 0;
				
				m_am_tools->enter_global_mutex();

				iParent->complete_validate_chain(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_ca_certificate_unknown)); //Failure.

				m_am_tools->leave_global_mutex();
				break;
			}

			iCertFilter->SetOwnerType(ECACertificate);
			iCertFilter->SetFormat(EX509Certificate);

			iState = EValidateChainGetCACertList;

			iCertStore->List(
				iCertInfos,
				*iCertFilter, 
				iStatus);
			SetActive();		
		}
		break;

	case EValidateChainGetCACertList:
		{			
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): EValidateChainGetCACertList\n")));

			int index;			
			TIdentityRelation<EapCertificateEntry> comparator(&EapTlsPeapUtils::CompareSCertEntries);

			if (iUseAutomaticCaCertificate)
			{
				// All CA certificates are allowed.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapTlsPeapCertInterface::RunL(): EValidateChainGetCACertList: All CA certificates are allowed.\n")));
			}
			else
			{
				// Remove disallowed CA certs from the array
				for (TInt i = 0; i < iCertInfos.Count(); i++)
				{
					EapCertificateEntry certEntry;
					certEntry.SetLabel(iCertInfos[i]->Label());
					certEntry.SetSubjectKeyId(iCertInfos[i]->SubjectKeyId());
					index = iAllowedCACerts.Find(&certEntry, comparator);
					
					if (index == KErrNotFound)
					{
						// Remove					
						iCertInfos[i]->Release();
						iCertInfos.Remove(i);
						i--;
					}
				}
			}

			if (iCertInfos.Count() == 0)
			{	
				// Create new validation result for this failure case. 
				// CPKIXValidationResult does include a Reset-member function
				// but it is not in x500.lib as the documentation says.
				const CPKIXValidationResult * const empty = 0;

				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: No cert infos\n")));

				m_am_tools->enter_global_mutex();

				iParent->complete_validate_chain(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_ca_certificate_unknown)); //Failure.

				m_am_tools->leave_global_mutex();
				break;
			}

			{
				CCTCertInfo* info;
				info = iCertInfos[0];
				iCAIndex = 0;

				iState = EValidateChainGetCACert;

				iEncodedCertificate->Des().SetLength(0);

				HBufC8 * tmpCert = 0;
				TRAPD(error, tmpCert = iEncodedCertificate->ReAllocL(info->Size()));
				if (error != KErrNone)
				{
					EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
					
					const CPKIXValidationResult * const empty = 0;
					
					m_am_tools->enter_global_mutex();

					iParent->complete_validate_chain(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_ca_certificate_unknown)); //Failure.

					m_am_tools->leave_global_mutex();
					break;
				}

				iEncodedCertificate = tmpCert;

				iCertPtr.Set(iEncodedCertificate->Des());

				iCertStore->Retrieve(
					*info, 
					iCertPtr,
					iStatus);
				
				SetActive();
			}
		}
		break;

	case EValidateChainGetCACert:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): EValidateChainGetCACert\n")));

			CX509Certificate* cert = 0;
			TRAPD(error, cert = CX509Certificate::NewL(iEncodedCertificate->Des()));
			if (error != KErrNone)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));

				const CPKIXValidationResult * const empty = 0;
				
				m_am_tools->enter_global_mutex();

				iParent->complete_validate_chain(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_ca_certificate_unknown)); //Failure.

				m_am_tools->leave_global_mutex();
				break;
			}
		
			// Signal completition
			if (iRootCerts.Append(cert) != KErrNone)
			{
				delete cert;
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));

				const CPKIXValidationResult * const empty = 0;
				
				m_am_tools->enter_global_mutex();

				iParent->complete_validate_chain(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_ca_certificate_unknown)); //Failure.

				m_am_tools->leave_global_mutex();
				break;
			}

			iCAIndex++;
			if (iCAIndex >= static_cast<TUint>(iCertInfos.Count()))
			{
				delete iCertChain;
				iCertChain = 0;

				TRAPD(error, iCertChain = CPKIXCertChain::NewL(iFs, *iInputCertChain, iRootCerts));
				if (error != KErrNone)
				{
					EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: EAP-TLS error %d.\n"), error));

					const CPKIXValidationResult * const empty = 0;
					
					m_am_tools->enter_global_mutex();

					iParent->complete_validate_chain(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_ca_certificate_unknown)); //Failure.

					m_am_tools->leave_global_mutex();
					break;
				}

				// Set the current time
				iTime.UniversalTime();
				iState = EValidateChainEnd;

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapTlsPeapCertInterface::RunL(): EValidateChainGetCACert, calls iCertChain->ValidateL(), count of root CA certificates = %d\n"),
					iRootCerts.Count()));

				TRAP(error, iCertChain->ValidateL(*iValidationResult, iTime, iStatus));
				if (error != KErrNone)
				{
					EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Error in certificate validation in EAP-TLS, error = %d.\n"),
						error));

					const CPKIXValidationResult * const empty = 0;
					
					m_am_tools->enter_global_mutex();

					iParent->complete_validate_chain(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_ca_certificate_unknown)); //Failure.

					m_am_tools->leave_global_mutex();
					break;
				}
				SetActive();	// Validate.
			}
			else
			{
				CCTCertInfo* info;
				info = iCertInfos[iCAIndex];

				iState = EValidateChainGetCACert;
				
				iEncodedCertificate->Des().SetLength(0);

				HBufC8 * tmpCert = 0;
				TRAPD(error, tmpCert = iEncodedCertificate->ReAllocL(info->Size()));
				if (error != KErrNone)
				{
					EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));

					const CPKIXValidationResult * const empty = 0;
					
					m_am_tools->enter_global_mutex();

					iParent->complete_validate_chain(empty, EAP_STATUS_RETURN(m_am_tools, eap_status_ca_certificate_unknown)); //Failure.

					m_am_tools->leave_global_mutex();
					break;
				}

				iEncodedCertificate = tmpCert;
				
				iCertPtr.Set(iEncodedCertificate->Des());
			
				iCertStore->Retrieve(
					*info, 
					iCertPtr,
					iStatus);
				
				SetActive();						
			}
		}
		break;
	
	case EValidateChainEnd:

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapTlsPeapCertInterface::RunL(): EValidateChainEnd, iValidationResult->Error().iReason=%d\n"),
			iValidationResult->Error().iReason));
		
		m_am_tools->enter_global_mutex();

		iParent->complete_validate_chain(iValidationResult, eap_status_ok);

		m_am_tools->leave_global_mutex();
		// Ignore error because there is nothing that can be done.
		break;

	case ESignInitStore:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): ESignInitStore\n")));

			iState = ESetPassphraseTimeout;
			iKeyStore->SetPassphraseTimeout(-1 , iStatus);
			SetActive();
		}
		break;
	
	case ESetPassphraseTimeout:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): ESetPassphraseTimeout\n")));

			// Set up filter
			delete iKeyFilter;
			iKeyFilter = 0;
			
			iKeyFilter = new (ELeave) TCTKeyAttributeFilter;
			if (!iKeyFilter)
			{ 
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				RInteger tmp;
				iParent->complete_sign(tmp, tmp, EAP_STATUS_RETURN(m_am_tools, eap_status_key_error));
				break;
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("SignL: iKeyIdentifier"),
				iKeyIdentifier.Ptr(),
				iKeyIdentifier.Length()));
			
			iKeyFilter->iKeyId = iKeyIdentifier;
			iKeyFilter->iPolicyFilter = TCTKeyAttributeFilter::EUsableKeys;			

			iState = ESignList;
			iKeyStore->List(
				iKeyInfos,
				*iKeyFilter, 
				iStatus);
			SetActive();					
		}
		break;

	case ESignList:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): ESignList, iKeyInfos.Count=%d\n"),
				iKeyInfos.Count()));

			if(iKeyInfos.Count() <= 0)				
			{
				RInteger tmp;
				iParent->complete_sign(tmp, tmp, EAP_STATUS_RETURN(m_am_tools, eap_status_user_certificate_unknown)); // Failure
				break;
			}

			iState = ESignOpenKeyStore;

			CKeyInfoBase::EKeyAlgorithm rsa(static_cast<CKeyInfoBase::EKeyAlgorithm> (1));
			
			if (iKeyInfos[0]->Algorithm() == rsa)
			{	
				// Note to the CodeScanner users. This function does not return any value.
				(void)iKeyStore->Open(
					iKeyInfos[0]->Handle(), 
					iRSASigner, 
					iStatus);				
			}
			else
			{				
				// Note to the CodeScanner users. This function does not return any value.
				(void)iKeyStore->Open(
					iKeyInfos[0]->Handle(), 
					iDSASigner, 
					iStatus);
			}
			SetActive();			
		}
		break;

	case ESignOpenKeyStore:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): ESignOpenKeyStore, iKeyInfos.Count=%d\n"),
				iKeyInfos.Count()));

			if(iKeyInfos.Count() <= 0)				
			{
				RInteger tmp;
				iParent->complete_sign(tmp, tmp, EAP_STATUS_RETURN(m_am_tools, eap_status_user_certificate_unknown)); // Failure
				break;
			}

			iState = ESign;
			
			CKeyInfoBase::EKeyAlgorithm rsa(static_cast<CKeyInfoBase::EKeyAlgorithm> (1));
		
			if (iKeyInfos[0]->Algorithm() == rsa)
			{	
				iRSASigner->Sign(
					iHashIn, 
					iRSASignature, 
					iStatus);		
			}
			else
			{												
				iDSASigner->Sign(
					iHashIn, 
					iDSASignature, 
					iStatus);		
			}

			SetActive();
		}
		break;
		
	case ESign:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): ESign, iKeyInfos.Count=%d\n"),
				iKeyInfos.Count()));

			if(iKeyInfos.Count() <= 0)				
			{
				RInteger tmp;
				iParent->complete_sign(tmp, tmp, EAP_STATUS_RETURN(m_am_tools, eap_status_user_certificate_unknown)); // Failure
				break;
			}

			CKeyInfoBase::EKeyAlgorithm rsa(static_cast<CKeyInfoBase::EKeyAlgorithm> (1));
			
			if (iKeyInfos[0]->Algorithm() == rsa)
			{
				// This is just dummy integer. It is ignored in RSA case.
				RInteger R = RInteger::NewL();
				
				CleanupStack::PushL(R);
				
				iParent->complete_sign(R, reinterpret_cast<const RInteger&>(iRSASignature->S()), eap_status_ok);

				delete iRSASignature;
				iRSASignature = 0;
				
				CleanupStack::PopAndDestroy();
				
				iRSASigner->Release(); // This seems to be needed.
			}
			else
			{
				iParent->complete_sign(reinterpret_cast<const RInteger&>(iDSASignature->R()), 
					reinterpret_cast<const RInteger&>(iDSASignature->S()), eap_status_ok);

				delete iDSASignature;
				iDSASignature = 0;
				
				iDSASigner->Release(); // This seems to be needed.
			}			
		}
		break;
	
	case EDecryptInitStore:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): EDecryptInitStore\n")));

			// Set up filter
			delete iKeyFilter;
			iKeyFilter = 0;
			
			iKeyFilter = new (ELeave) TCTKeyAttributeFilter;
			if (!iKeyFilter)
			{ 
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				TBuf8<1> tmp;
				iParent->complete_decrypt(tmp, EAP_STATUS_RETURN(m_am_tools, eap_status_key_error));
				break;
			}
			
			iKeyFilter->iKeyId = iKeyIdentifier;
			iKeyFilter->iPolicyFilter = TCTKeyAttributeFilter::EUsableKeys;			

			iState = EDecryptList;
			iKeyStore->List(
				iKeyInfos,
				*iKeyFilter, 
				iStatus);
			SetActive();			
		}
		break;
		
	case EDecryptList:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): EDecryptList, iKeyInfos.Count=%d\n"),
				iKeyInfos.Count()));

			if(iKeyInfos.Count() <= 0)				
			{
				TBuf8<1> tmp;
				iParent->complete_decrypt(tmp, EAP_STATUS_RETURN(m_am_tools, eap_status_key_error));
				break;
			}

			iState = EDecryptOpenKeyStore;			
			
			// Note to the CodeScanner users. This function does not return any value.
			(void)iKeyStore->Open(
				iKeyInfos[0]->Handle(),
				iDecryptor,
				iStatus);
							
			SetActive();
		}
		break;
		
	case EDecryptOpenKeyStore:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): EDecryptOpenKeyStore\n")));

			iState = EDecrypt;
								
			iDecryptor->Decrypt(
				*iDataIn, 	
				*iPtrOut, 
				iStatus);	
			
			SetActive();
		}
		break;
		
	case EDecrypt:
		{			
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): EDecrypt\n")));

			iParent->complete_decrypt(*iPtrOut, eap_status_ok);
		}
		break;
	
	default:
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): unknown %d\n"),
				iState));
		break;
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return;
}

//--------------------------------------------------

void CEapTlsPeapCertInterface::CancelSignWithPrivateKey()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::CancelSignWithPrivateKey(): iState=%d (13=ESign)\n"),
		iState));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapTlsPeapCertInterface::CancelSignWithPrivateKey()");

	if(IsActive())
	{
		
		// We have to cancel singing if it is ongoing. Both for RSA and DSA.
		if(iRSASigner != 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::CancelSignWithPrivateKey(): calls iRSASigner->CancelSign()\n")));
		
			iRSASigner->CancelSign();
		}

		if(iDSASigner != 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::CancelSignWithPrivateKey(): calls iDSASigner->CancelSign()\n")));
		
			iDSASigner->CancelSign();
		}
	}	
}


//--------------------------------------------------
// End of file
