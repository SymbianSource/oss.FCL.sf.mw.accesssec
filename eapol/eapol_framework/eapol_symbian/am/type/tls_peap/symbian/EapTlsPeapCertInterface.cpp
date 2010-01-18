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
* %version: 42 %
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
#include "eap_am_trace_symbian.h"

const TText8 KKeyStoreHandlePrefix[] = "EapTlsPeapKeyStoreHandler";
const TText8 KKeyStoreHandleKey[] = "CEapTlsPeapCertInterface KeyStore handle";

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
	CEapTlsPeapCertInterface* self = new(ELeave) CEapTlsPeapCertInterface(aTools, aParent);
	CleanupStack::PushL(self);
	self->ConstructL();
	CleanupStack::Pop();
	return self;
}

//--------------------------------------------------

CEapTlsPeapCertInterface::CEapTlsPeapCertInterface(abs_eap_am_tools_c* const aTools, eap_am_type_tls_peap_symbian_c* const aParent)
: CActive(CActive::EPriorityStandard)
,iParent(aParent)
,m_am_tools(aTools)
,iAllowedUserCerts(1)
,iEncodedCertificate(0)
,iCertPtr(0,0)
,iMatchingUserCertInfos(1)
,iCAIndex(0)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

void CEapTlsPeapCertInterface::ConstructL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
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
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	iMatchingUserCerts.ResetAndDestroy();

	iMatchingUserCertInfos.Reset();
	
	iAllowedUserCerts.Reset();

	iRootCerts.ResetAndDestroy();
	iUserCertChain.ResetAndDestroy();
	
	iCertAuthorities.ResetAndDestroy();
	
	TInt i(0);
	for (i = 0; i < iCertInfos.Count(); i++)
	{
		iCertInfos[i]->Release();
	}
	iCertInfos.Reset();

	for (i = 0; i < iKeyInfos.Count(); i++)
	{
		iKeyInfos[i]->Release();
	}
	iKeyInfos.Reset();

	delete iCertFilter;
	delete iCertStore;
	delete iCertChain;
	delete iValidationResult;
	delete iInputCertChain;	
	delete iEncodedCertificate;	
	delete iDataIn;
	delete iDataOut;
	delete iSignature;
	delete iPtrOut;
	delete iSignaturePtr;
	
	iFs.Close();	
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::~CEapTlsPeapCertInterface(): returns\n")));
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

void CEapTlsPeapCertInterface::GetMatchingCertificatesL(
	const RArray<SCertEntry>& aAllowedUserCerts,
	const TBool aUseCertAuthoritiesFilter,
	EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const aCertAuthorities,
	const TBool aUseCertTypesFilter,
	EAP_TEMPLATE_CONST eap_array_c<u8_t> * const aCertTypes,
	const TBool aUseAllowedCipherSuitesFilter,
	const RArray<TUint>& aAllowedCipherSuites)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	iUseCertAuthoritiesFilter = aUseCertAuthoritiesFilter;
	
	iUseCertTypesFilter = aUseCertTypesFilter;
	
	iUseAllowedCipherSuitesFilter = aUseAllowedCipherSuitesFilter;

	iAllowedUserCerts.Reset();
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::GetMatchingCertificatesL: Total allowed user certs=%d\n"),
		aAllowedUserCerts.Count()));		
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::GetMatchingCertificatesL:UseCertAuthoritiesFilter=%d, UseCertTypesFilter=%d, UseAllowedCipherSuitesFilter=%d\n"),
		iUseCertAuthoritiesFilter,iUseCertTypesFilter,iUseAllowedCipherSuitesFilter));		
	
	for (TInt j = 0; j < aAllowedUserCerts.Count(); j++)
	{
		iAllowedUserCerts.AppendL(aAllowedUserCerts[j]);
		
#if defined(_DEBUG) || defined(DEBUG)

		// This is just for the debug prints.
		TCertLabel tempLabel = iAllowedUserCerts[j].iLabel;
		TKeyIdentifier tempSubjectKeyId = iAllowedUserCerts[j].iSubjectKeyId;
		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapTlsPeapCertInterface::GetMatchingCertificatesL: details of allowed user certs,Label=%S\n"),
		&tempLabel));		
		
		EAP_TRACE_DATA_DEBUG_SYMBIAN( ( "GetMatchingCertificatesL : Subject Key Id:",
		tempSubjectKeyId.Ptr(), tempSubjectKeyId.Size() ) );			
#endif
	}

	if (iCertAuthorities.Count() > 0)
	{
		iCertAuthorities.ResetAndDestroy();
	}
	if (aUseCertAuthoritiesFilter)
	{
		for (TUint i = 0; i < aCertAuthorities->get_object_count(); i++)
		{
			HBufC8* buf = HBufC8::NewLC((aCertAuthorities->get_object(i))->get_data_length());
			TPtr8 ptr = buf->Des();
			ptr.Copy((aCertAuthorities->get_object(i))->get_data((aCertAuthorities->get_object(i))->get_data_length()),
				(aCertAuthorities->get_object(i))->get_data_length());

			// Try to form distiguished name
			CX500DistinguishedName* tmp = 0;
			TRAPD(err, tmp = CX500DistinguishedName::NewL(ptr));
			if (err == KErrNone)
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
		iCertStore = CUnifiedCertStore::NewL(iFs, false);
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

void CEapTlsPeapCertInterface::ReadCertificateL(SCertEntry& aCertInfo, const TBool aRetrieveChain)
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	iCertInfo = aCertInfo;
	iRetrieveChain = aRetrieveChain;
	iState = EReadCertInitStore;
	
	if (iCertStore == 0)
	{
		iCertStore = CUnifiedCertStore::NewL(iFs, false);
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

void CEapTlsPeapCertInterface::ReadCACertificateL(SCertEntry& aCertInfo)
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapTlsPeapCertInterface::ReadCACertificateL.\n")));
	
	iCertInfo = aCertInfo;
	iState = EReadCACertInitStore;
	
	if (iCertStore == 0)
	{
		iCertStore = CUnifiedCertStore::NewL(iFs, false);
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

void CEapTlsPeapCertInterface::ValidateChainL(TDesC8& aCertChain, RArray<SCertEntry>& aAllowedCACerts)
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	
	iCAIndex = 0;
	iAllowedCACerts = aAllowedCACerts;
	delete iInputCertChain;

	iInputCertChain = 0;
	iInputCertChain = aCertChain.AllocL();
	iState = EValidateChainInitStore;
	if (iCertStore == 0)
	{
		iCertStore = CUnifiedCertStore::NewL(iFs, false);
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
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::DoCancel()\n")));

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
	TKeyIdentifier& aKeyId,
	const TDesC8& aHashIn,
	const TUint aSignatureLength)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	
	iKeyIdentifier = aKeyId;
	if (aHashIn.Size() > KMaxHashLength)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Illegal hash size to SignL.\n")));
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
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_TLSPEAP: cannot get previous keystore handle.\n")));


			// At this point we can set the passphrase timeout because it the passphrase 
			// cache in the FS token server is still empty. Passphrase timeout setting clears 
			// the cache.
			iState = ESignInitStore;
			
			iKeyStore = CUnifiedKeyStore::NewL(iFs);
			iKeyStore->Initialize(iStatus);		
			
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
	}
	else
	{
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
	TKeyIdentifier& aKeyId,
	const TDesC8& aDataIn)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	
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
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_TLSPEAP: cannot get previous keystore handle.\n")));

			iKeyStore = CUnifiedKeyStore::NewL(iFs);
			iKeyStore->Initialize(iStatus);		
			
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

void CEapTlsPeapCertInterface::RunL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);		
	
	EAP_TRACE_DEBUG_SYMBIAN(
	(_L("CEapTlsPeapCertInterface::RunL(): TEMP iStatus=%d, iState=%d"),
	iStatus.Int(), iState));
					
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::RunL(): iStatus %d\n"),
		iStatus.Int()));

	if (!(iStatus.Int() == KErrNone))
	{		
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: EAP-TLS certificate interface failed: %d.\n"),
			iStatus.Int()));
		iParent->SendErrorNotification(eap_status_user_cancel_authentication);
		
		if(iState == ESignOpenKeyStore)
		{
			// User probably cancelled the keystore password query.
			
			EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeapCertInterface::RunL(): ESignOpenKeyStore Failed")));
			
			if(iRSASigner != NULL)
			{
				iRSASigner->Release();
				
				EAP_TRACE_DEBUG_SYMBIAN(
				(_L("CEapTlsPeapCertInterface::RunL(): iRSASigner->Release() OK")));
				
			}
			
			if(iDSASigner != NULL)
			{
				iDSASigner->Release(); 
				
				EAP_TRACE_DEBUG_SYMBIAN(
				(_L("CEapTlsPeapCertInterface::RunL(): iDSASigner->Release() OK")));							
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
			
			TRAPD(err, iCertFilter = CCertAttributeFilter::NewL());
			if (err != KErrNone)
			{ 
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				
				CArrayFixFlat<SCertEntry> tmp(sizeof(SCertEntry));

				m_am_tools->enter_global_mutex();
				
				iParent->complete_get_matching_certificates(tmp, eap_status_allocation_error); //Failure
				
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

			iMatchingUserCertInfos.Reset();

			// Remove non-allowed
			TInt i(0);
			TInt j(0);
			for (i = 0; i < iCertInfos.Count(); i++)
			{
				for (j = 0; j < iAllowedUserCerts.Count(); j++)
				{				
					if ( (iCertInfos[i]->Label().Compare(iAllowedUserCerts[j].iLabel) == 0
						 || iCertInfos[i]->Label().Length() == 0
						 || iAllowedUserCerts[j].iLabel.Length() == 0)
						&& iCertInfos[i]->SubjectKeyId() == iAllowedUserCerts[j].iSubjectKeyId)
					{

						EAP_TRACE_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("RunL(): EGetMatchingCertsInitialize, Found a Matching USER cert\n")));

						EAP_TRACE_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("RunL(): EGetMatchingCertsInitialize,Label of matching cert=%S\n"),
							&(iCertInfos[i]->Label())));		
						
						EAP_TRACE_DATA_DEBUG_SYMBIAN(("RunL(): EGetMatchingCertsInitialize,SubjectkeyID of matching cert",
						iCertInfos[i]->SubjectKeyId().Ptr(), iCertInfos[i]->SubjectKeyId().Size()));			

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
				
				CArrayFixFlat<SCertEntry>* tmp = NULL;
				
				TRAPD(err, tmp = new (ELeave) CArrayFixFlat<SCertEntry>(1) );
				if (tmp == 0 || err != KErrNone)
				{
					// Timeout handles error situation
					EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));					
				}
				
				m_am_tools->enter_global_mutex();
				
				iParent->complete_get_matching_certificates(*tmp, eap_status_illegal_certificate); //Failure
				
				m_am_tools->leave_global_mutex();

				delete tmp;
				break;
			}

			// Get the first certificate
			iUserCertIndex = 0;

			iMatchingUserCerts.ResetAndDestroy();
							
			iState = EGetMatchingCertsLoop;

			iEncodedCertificate->Des().SetLength(0);
			
			TRAPD(err, iEncodedCertificate = iEncodedCertificate->ReAllocL(iCertInfos[iUserCertIndex]->Size()));
			if (err != KErrNone)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				
				CArrayFixFlat<SCertEntry> tmp(sizeof(SCertEntry));
											
				m_am_tools->enter_global_mutex();
				
				iParent->complete_get_matching_certificates(tmp, eap_status_allocation_error); //Failure
				
				m_am_tools->leave_global_mutex();

				break;
			}
			
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
			TRAPD(err, cert = CX509Certificate::NewL(iEncodedCertificate->Des()));
			if (err != KErrNone || cert == 0)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				
				CArrayFixFlat<SCertEntry> tmp(sizeof(SCertEntry));
											
				m_am_tools->enter_global_mutex();
				
				iParent->complete_get_matching_certificates(tmp, eap_status_allocation_error); //Failure
				
				m_am_tools->leave_global_mutex();

				break;
			}
				
			if (iMatchingUserCerts.Append(cert) != KErrNone)
			{
				delete cert;
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				
				CArrayFixFlat<SCertEntry> tmp(sizeof(SCertEntry));

				m_am_tools->enter_global_mutex();
				
				iParent->complete_get_matching_certificates(tmp, eap_status_allocation_error); //Failure
				
				m_am_tools->leave_global_mutex();
							
				break;
			}
			
			// No need to validate iCertInfos here as the execution doesn't come to this case if iCertInfos
			// is empty, check is done in the above case.
						
			SCertEntry entry;
			entry.iLabel.Copy(iCertInfos[iUserCertIndex]->Label());
			entry.iSubjectKeyId = iCertInfos[iUserCertIndex]->SubjectKeyId();
			
			TRAP(err, iMatchingUserCertInfos.AppendL(entry));
			if (err != KErrNone)
			{
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				
				CArrayFixFlat<SCertEntry> tmp(sizeof(SCertEntry));
				
				m_am_tools->enter_global_mutex();
				
				iParent->complete_get_matching_certificates(tmp, eap_status_allocation_error); //Failure
				
				m_am_tools->leave_global_mutex();
							
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
						}
						if (j == iCertAuthorities.Count())
						{						
							// No match. Remove
							delete iMatchingUserCerts[i];
							iMatchingUserCerts.Remove(i);
							iMatchingUserCertInfos.Delete(i);
							i--;
							
							EAP_TRACE_DEBUG(
								m_am_tools,
								TRACE_FLAGS_DEFAULT,
								(EAPL("RunL(): EGetMatchingCertsLoop Using CertAuthoritiesFilter - no distinguished name matching - Matching cert removed\n")));
						}
					}
				}
				// Check Certificate types
				if (iUseCertTypesFilter)
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
							if (algorithm == ERSA 
								&& (*val == ERSASign
								|| *val == ERSASignWithFixedDH 
								|| *val == ERSASignWithEphemeralDH))
							{
								break;				
							}
							if (algorithm == EDSA 
								&& (*val == EDSASign
								|| *val == EDSASignWithFixedDH 
								|| *val == EDSASignWithEphemeralDH))
							{
								break;				
							}
						}
						if (j == iCertTypes->get_object_count())
						{
							// No match. Remove
							delete iMatchingUserCerts[i];
							iMatchingUserCerts.Remove(i);
							iMatchingUserCertInfos.Delete(i);
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
							iMatchingUserCertInfos.Delete(i);
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

				TRAPD(err, iEncodedCertificate = iEncodedCertificate->ReAllocL(iCertInfos[iUserCertIndex]->Size()));
				if (err != KErrNone)
				{
					EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				
					CArrayFixFlat<SCertEntry> tmp(sizeof(SCertEntry));

					m_am_tools->enter_global_mutex();
					
					iParent->complete_get_matching_certificates(tmp, eap_status_allocation_error); //Failure
					
					m_am_tools->leave_global_mutex();
					
					break;
				}
				
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
			
			TRAPD(err, iCertFilter = CCertAttributeFilter::NewL());
			if (err != KErrNone || iCertFilter == 0)
			{ 
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				
				RPointerArray<CX509Certificate> tmp;
				
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_own_certificate(tmp, eap_status_allocation_error); //Failure
				
				m_am_tools->leave_global_mutex();
				
				break;
			}
			
			iCertFilter->SetFormat(EX509Certificate);
			iCertFilter->SetOwnerType(EUserCertificate);
			iCertFilter->SetSubjectKeyId(iCertInfo.iSubjectKeyId);
			if (iCertInfo.iLabel.Size()>0)
				iCertFilter->SetLabel(iCertInfo.iLabel); // We can not use Label in the filter as certificates saved
													   // by using SetConfigurationL (OMA DM etc uses it) will not have Label.

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
				
				RPointerArray<CX509Certificate> tmp;
				
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_own_certificate(tmp, eap_status_illegal_certificate); //Failure
				
				m_am_tools->leave_global_mutex();

				break;
			}
			
			// Just take the first found certificate
			CCTCertInfo* info;
			info = iCertInfos[0];			

			iState = EReadCert;
			
			iEncodedCertificate->Des().SetLength(0);

			TRAPD(err, iEncodedCertificate = iEncodedCertificate->ReAllocL(info->Size()));
			if (err != KErrNone)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				
				RPointerArray<CX509Certificate> tmp;
								
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_own_certificate(tmp, eap_status_allocation_error); //Failure
				
				m_am_tools->leave_global_mutex();
				
				break;
			}
				
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
			TRAPD(err, cert = CX509Certificate::NewL(iEncodedCertificate->Des()));
			if (err != KErrNone)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				
				RPointerArray<CX509Certificate> tmp;
								
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_own_certificate(tmp, eap_status_allocation_error); //Failure
				
				m_am_tools->leave_global_mutex();
				
				break;
			}
			
			iUserCertChain.ResetAndDestroy();
			if (iUserCertChain.Append(cert) != KErrNone)
			{
				delete cert;
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				
				RPointerArray<CX509Certificate> tmp;
								
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_own_certificate(tmp, eap_status_allocation_error); //Failure
				
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
					iCertStore = CUnifiedCertStore::NewL(iFs, false);
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
			
			TRAPD(err, iCertFilter = CCertAttributeFilter::NewL());
			if (err != KErrNone)
			{ 
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				
				RPointerArray<CX509Certificate> tmp;
								
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_own_certificate(tmp, eap_status_allocation_error); //Failure
				
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
				iParent->complete_read_own_certificate(iUserCertChain, eap_status_illegal_certificate);

				m_am_tools->leave_global_mutex();

				break;
			}
			
			CCTCertInfo* info;
			info = iCertInfos[0];
			iCAIndex = 0;

			iState = ECreateCertChain;
			
			iEncodedCertificate->Des().SetLength(0);
			TRAPD(err, iEncodedCertificate = iEncodedCertificate->ReAllocL(info->Size()));
			if (err != KErrNone)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				
				RPointerArray<CX509Certificate> tmp;
								
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_own_certificate(tmp, eap_status_allocation_error); //Failure
				
				m_am_tools->leave_global_mutex();
				
				break;
			}
				
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
			TRAPD(err, cert = CX509Certificate::NewL(iEncodedCertificate->Des()));
			if (err != KErrNone || cert == 0)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				
				RPointerArray<CX509Certificate> tmp;
								
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_own_certificate(tmp, eap_status_allocation_error); //Failure
				
				m_am_tools->leave_global_mutex();
				
				break;
			}
			
#if defined(_DEBUG) || defined(DEBUG)
				
				// No need to validate iCertInfos in here as it is done in case: EGetAllCerts
				CCTCertInfo* tempInfo;
				tempInfo = iCertInfos[iCAIndex];

				// These are for the trace debug.
				TCertLabel label = tempInfo->Label();				
				TKeyIdentifier KeyIdentifier = tempInfo->SubjectKeyId();
				TKeyIdentifier IssuerId = tempInfo->IssuerKeyId();
				TCertificateFormat format = tempInfo->CertificateFormat();
				TCertificateOwnerType ownerType = tempInfo->CertificateOwnerType();			
				
				EAP_TRACE_DEBUG_SYMBIAN((_L("\n CEapTlsPeapCertInterface::RunL() : About to retrieve Cert with details, Label = %S"), &label));
				EAP_TRACE_DEBUG_SYMBIAN((_L("Other detials- Format=%d, Owner type=%d, IsDeletable=%d, Type UID=%d"),
									format, ownerType, tempInfo->IsDeletable(), tempInfo->Type()));
				
				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Subject key Id is"),
					KeyIdentifier.Ptr(),
					KeyIdentifier.Size()));

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
						EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("WARNING: No extension for this certificate\n")));			
					}
				}
				else
				{
					EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: No Certs here!\n")));			
				}
					
#endif
			
		
			// Signal completition
			if (iRootCerts.Append(cert) != KErrNone)
			{
				delete cert;
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				
				RPointerArray<CX509Certificate> tmp;
								
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_own_certificate(tmp, eap_status_allocation_error); //Failure
				
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
					iParent->complete_read_own_certificate(iUserCertChain, eap_status_ca_certificate_unknown);
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
							
							TRAPD(err, dsaParams = CX509DSAPublicKey::DSAParametersL(params));
							if (err != KErrNone)
							{				
				
								RPointerArray<CX509Certificate> tmp;
								m_am_tools->enter_global_mutex();
								
								iParent->complete_read_own_certificate(tmp, eap_status_allocation_error); //Failure
								
								m_am_tools->leave_global_mutex();
				
								return;
							}					
									
							TRAP(err, signParams = CSigningKeyParameters::NewL());
							if (err != KErrNone)
							{				
								RPointerArray<CX509Certificate> tmp;
				
								m_am_tools->enter_global_mutex();
								
								iParent->complete_read_own_certificate(tmp, eap_status_allocation_error); //Failure
								
								m_am_tools->leave_global_mutex();				

								delete dsaParams;
								return;
							}
							TRAP(err, signParams->SetDSAParamsL(*dsaParams));
							if (err != KErrNone)
							{				
								RPointerArray<CX509Certificate> tmp;
								
								m_am_tools->enter_global_mutex();
								
								iParent->complete_read_own_certificate(tmp, eap_status_allocation_error); //Failure
								
								m_am_tools->leave_global_mutex();
				
								delete dsaParams;
								delete signParams;
								return;
							}

							TRAP(err, iUserCertChain[iUserCertChain.Count()-1]->SetParametersL(*signParams));
							if (err != KErrNone)
							{
								RPointerArray<CX509Certificate> tmp;
								m_am_tools->enter_global_mutex();
								
								iParent->complete_read_own_certificate(tmp, eap_status_allocation_error); //Failure
								
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
								RPointerArray<CX509Certificate> tmp;
								
								m_am_tools->enter_global_mutex();
								
								iParent->complete_read_own_certificate(tmp, eap_status_allocation_error); //Failure
								
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
				TRAPD(err, iEncodedCertificate = iEncodedCertificate->ReAllocL(info->Size()));
				if (err != KErrNone)
				{
					EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				
					RPointerArray<CX509Certificate> tmp;
					
					m_am_tools->enter_global_mutex();
					
					iParent->complete_read_ca_certificate(tmp, eap_status_allocation_error); //Failure
					
					m_am_tools->leave_global_mutex();
				
					break;
				}
				
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
			
			TRAPD(err, iCertFilter = CCertAttributeFilter::NewL());
			if (err != KErrNone)
			{ 
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				RPointerArray<CX509Certificate> tmp;
				
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_ca_certificate(tmp, eap_status_allocation_error); //Failure
				
				m_am_tools->leave_global_mutex();
				break;
			}
			
			iCertFilter->SetFormat(EX509Certificate);
			iCertFilter->SetOwnerType(ECACertificate);
			iCertFilter->SetSubjectKeyId(iCertInfo.iSubjectKeyId);
			if (iCertInfo.iLabel.Size()>0)
				iCertFilter->SetLabel(iCertInfo.iLabel);// We can not use Label in the filter as certificates saved
													// by using SetConfigurationL (OMA DM etc uses it) will not have Label.

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
				RPointerArray<CX509Certificate> tmp;
				
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_ca_certificate(tmp, eap_status_allocation_error); //Failure
				
				m_am_tools->leave_global_mutex();
				break;
			}
			
			// Just take the first found certificate
			CCTCertInfo* info;
			info = iCertInfos[0];			

			iState = EReadCACert;
			
			iEncodedCertificate->Des().SetLength(0);

			TRAPD(err, iEncodedCertificate = iEncodedCertificate->ReAllocL(info->Size()));
			if (err != KErrNone)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				RPointerArray<CX509Certificate> tmp;
				
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_ca_certificate(tmp, eap_status_allocation_error); //Failure
				
				m_am_tools->leave_global_mutex();
				break;
			}
				
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
			TRAPD(err, cert = CX509Certificate::NewL(iEncodedCertificate->Des()));
			if (err != KErrNone)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				RPointerArray<CX509Certificate> tmp;
				
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_ca_certificate(tmp, eap_status_allocation_error); //Failure
				
				m_am_tools->leave_global_mutex();
				break;
			}
			
			// Use iUserCertChain on purpose for this anyway even though this is CA cert.
			iUserCertChain.ResetAndDestroy();
			if (iUserCertChain.Append(cert) != KErrNone)
			{
				delete cert;
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				RPointerArray<CX509Certificate> tmp;
				
				m_am_tools->enter_global_mutex();
				
				iParent->complete_read_ca_certificate(tmp, eap_status_allocation_error); //Failure
				
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
			
			TRAPD(err, iCertFilter = CCertAttributeFilter::NewL());
			if (err != KErrNone)
			{ 
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				CPKIXValidationResult* tmp = 0;
				
				m_am_tools->enter_global_mutex();

				iParent->complete_validate_chain(*tmp, eap_status_ca_certificate_unknown); //Failure.

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
			TIdentityRelation<SCertEntry> comparator(&EapTlsPeapUtils::CompareSCertEntries);
			// Remove disallowed CA certs from the array
			for (TInt i = 0; i < iCertInfos.Count(); i++)
			{
				SCertEntry certEntry;
				certEntry.iLabel.Copy(iCertInfos[i]->Label());
				certEntry.iSubjectKeyId.Copy(iCertInfos[i]->SubjectKeyId());
				index = iAllowedCACerts.Find(certEntry, comparator);
				
				if (index == KErrNotFound)
				{
					// Remove					
					iCertInfos[i]->Release();
					iCertInfos.Remove(i);
					i--;
				}
			}
			if (iCertInfos.Count() == 0)
			{	
				// Create new validation result for this failure case. 
				// CPKIXValidationResult does include a Reset-member function
				// but it is not in x500.lib as the documentation says.
				CPKIXValidationResult* validationResult = 0;
				TRAPD(err, validationResult = CPKIXValidationResult::NewL());
				if (err != KErrNone)
				{
					// Do nothing. Session timeout takes care of cleanup...
					EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				}
				m_am_tools->enter_global_mutex();

				iParent->complete_validate_chain(*validationResult, eap_status_ca_certificate_unknown); //Failure.

				m_am_tools->leave_global_mutex();
				delete validationResult;
				break;
			}
			
			CCTCertInfo* info;
			info = iCertInfos[0];
			iCAIndex = 0;

			iState = EValidateChainGetCACert;
			
			iEncodedCertificate->Des().SetLength(0);
			TRAPD(err, iEncodedCertificate = iEncodedCertificate->ReAllocL(info->Size()));
			if (err != KErrNone)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				
				CPKIXValidationResult* tmp = 0;
				
				m_am_tools->enter_global_mutex();

				iParent->complete_validate_chain(*tmp, eap_status_ca_certificate_unknown); //Failure.

				m_am_tools->leave_global_mutex();
				break;
			}
				
			iCertPtr.Set(iEncodedCertificate->Des());			

			iCertStore->Retrieve(
				*info, 
				iCertPtr,
				iStatus);
			
			SetActive();			
		}
		break;

	case EValidateChainGetCACert:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapTlsPeapCertInterface::RunL(): EValidateChainGetCACert\n")));

			CX509Certificate* cert = 0;
			TRAPD(err, cert = CX509Certificate::NewL(iEncodedCertificate->Des()));
			if (err != KErrNone)
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				CPKIXValidationResult* tmp = 0;
				
				m_am_tools->enter_global_mutex();

				iParent->complete_validate_chain(*tmp, eap_status_ca_certificate_unknown); //Failure.

				m_am_tools->leave_global_mutex();
				break;
			}
		
			// Signal completition
			if (iRootCerts.Append(cert) != KErrNone)
			{
				delete cert;
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
				CPKIXValidationResult* tmp = 0;
				
				m_am_tools->enter_global_mutex();

				iParent->complete_validate_chain(*tmp, eap_status_ca_certificate_unknown); //Failure.

				m_am_tools->leave_global_mutex();
				break;
			}

			iCAIndex++;
			if (iCAIndex >= static_cast<TUint>(iCertInfos.Count()))
			{
				delete iCertChain;
				iCertChain = 0;

				TRAPD(err, iCertChain = CPKIXCertChain::NewL(iFs, *iInputCertChain, iRootCerts));
				if (err != KErrNone)
				{
					EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: EAP-TLS error %d.\n"), err));
					CPKIXValidationResult* tmp = 0;
					
					m_am_tools->enter_global_mutex();

					iParent->complete_validate_chain(*tmp, eap_status_ca_certificate_unknown); //Failure.

					m_am_tools->leave_global_mutex();
					break;
				}
				// Set the current time
				iTime.UniversalTime();
				iState = EValidateChainEnd;
				TRAP(err, iCertChain->ValidateL(*iValidationResult, iTime, iStatus));
				if (err != KErrNone)
				{
					EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Error in certificate validation in EAP-TLS.\n")));			
					CPKIXValidationResult* tmp = 0;
					
					m_am_tools->enter_global_mutex();

					iParent->complete_validate_chain(*tmp, eap_status_ca_certificate_unknown); //Failure.

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
				TRAPD(err, iEncodedCertificate = iEncodedCertificate->ReAllocL(info->Size()));
				if (err != KErrNone)
				{
					EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));			
					CPKIXValidationResult* tmp = 0;
					
					m_am_tools->enter_global_mutex();

					iParent->complete_validate_chain(*tmp, eap_status_ca_certificate_unknown); //Failure.

					m_am_tools->leave_global_mutex();
					break;
				}
				
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
			(EAPL("CEapTlsPeapCertInterface::RunL(): EValidateChainEnd\n")));
		
		m_am_tools->enter_global_mutex();
		
		iParent->complete_validate_chain(*iValidationResult, eap_status_ok);

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
			
			TRAPD(err, iKeyFilter = new (ELeave) TCTKeyAttributeFilter);
			if (err != KErrNone)
			{ 
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				RInteger tmp;
				iParent->complete_sign(tmp, tmp, eap_status_key_error);
				break;
			}
			
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
				iParent->complete_sign(tmp, tmp, eap_status_key_error);
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
				iParent->complete_sign(tmp, tmp, eap_status_key_error);
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
				iParent->complete_sign(tmp, tmp, eap_status_key_error);
				break;
			}

			CKeyInfoBase::EKeyAlgorithm rsa(static_cast<CKeyInfoBase::EKeyAlgorithm> (1));
			
			if (iKeyInfos[0]->Algorithm() == rsa)
			{
				// This is just dummy integer. It is ignored in RSA case.
				RInteger R = RInteger::NewL();
				
				CleanupStack::PushL(R);
				
				iParent->complete_sign(R, reinterpret_cast<const RInteger&>(iRSASignature->S()), eap_status_ok);
				
				CleanupStack::PopAndDestroy();
				
				iRSASigner->Release(); // This seems to be needed.
			}
			else
			{
				iParent->complete_sign(reinterpret_cast<const RInteger&>(iDSASignature->R()), 
					reinterpret_cast<const RInteger&>(iDSASignature->S()), eap_status_ok);
				
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
			
			TRAPD(err, iKeyFilter = new (ELeave) TCTKeyAttributeFilter);
			if (err != KErrNone)
			{ 
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Out of memory in EAP-TLS.\n")));
				TBuf8<1> tmp;
				iParent->complete_decrypt(tmp, eap_status_key_error);
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
				iParent->complete_decrypt(tmp, eap_status_key_error);
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

void CEapTlsPeapCertInterface::CancelSignWithPrivateKey()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapTlsPeapCertInterface::CancelSignWithPrivateKey():Cancelling Signing - iState=%d (13=ESign)\n"),
		iState));		

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

// End of file
