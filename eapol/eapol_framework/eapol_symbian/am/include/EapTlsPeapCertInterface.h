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
* %version: 23 %
*/

#ifndef _EAPTLSPEAPCERTINTERFACE_H_
#define _EAPTLSPEAPCERTINTERFACE_H_

// INCLUDES
#include <e32base.h>
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPTLSPEAPCERTINTERFACE_H)
	#define EAP_CLASS_VISIBILITY_EAPTLSPEAPCERTINTERFACE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPTLSPEAPCERTINTERFACE_H 
	#define EAP_C_FUNC_VISIBILITY_EAPTLSPEAPCERTINTERFACE_H 
	#define EAP_FUNC_EXPORT_EAPTLSPEAPCERTINTERFACE_H 
	#define EAP_C_FUNC_EXPORT_EAPTLSPEAPCERTINTERFACE_H 
#elif defined(EAP_EXPORT_EAPTLSPEAPCERTINTERFACE_H)
	#define EAP_CLASS_VISIBILITY_EAPTLSPEAPCERTINTERFACE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPTLSPEAPCERTINTERFACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPTLSPEAPCERTINTERFACE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPTLSPEAPCERTINTERFACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPTLSPEAPCERTINTERFACE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPTLSPEAPCERTINTERFACE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPTLSPEAPCERTINTERFACE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPTLSPEAPCERTINTERFACE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPTLSPEAPCERTINTERFACE_H 
	#define EAP_C_FUNC_EXPORT_EAPTLSPEAPCERTINTERFACE_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_tools.h"
#include "eap_am_type_tls_peap_symbian.h"
#include <unifiedcertstore.h>
#include <mctwritablecertstore.h>
#include <unifiedkeystore.h>
#include <pkixcertchain.h>
#include <x509cert.h>
#include "EapTlsPeapUtils.h"

const TInt KMaxHashLength = 128;
// FORWARD DECLARATIONS


// CLASS DECLARATION
class EAP_CLASS_VISIBILITY_EAPTLSPEAPCERTINTERFACE_H CEapTlsPeapCertInterface 
: public CActive
{
public:
	
	static CEapTlsPeapCertInterface* NewL(abs_eap_am_tools_c* const aTools, 
		eap_am_type_tls_peap_symbian_c* const aParent);	

	virtual ~CEapTlsPeapCertInterface();	
	
	void ReadCertificateL(EapCertificateEntry& aCertInfo, const TBool aRetrieveChain);
	
	void ReadCACertificateL(EapCertificateEntry& aCertInfo);
	
	void ReadPrivateKeyL(TKeyIdentifier& aHash);
	
	void ValidateChainL(
		TDesC8& aCertChain,
		RPointerArray<EapCertificateEntry>& aCACerts,
		const TBool aUseAutomaticCaCertificate);

	
	void GetMatchingCertificatesL(
		const RPointerArray<EapCertificateEntry>& aAllowedUserCerts,
		const TBool aUseCertAuthoritiesFilter,
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const aCertAuthorities,
		const TBool aUseCertTypesFilter,
		EAP_TEMPLATE_CONST eap_array_c<u8_t> * const aCertTypes,
		const TBool aUseAllowedCipherSuitesFilter,
		const RArray<TUint>& aAllowedCipherSuites);		

	void SignL(
		const TKeyIdentifier& aKeyId,
		const TDesC8& aHashIn,
		const TUint aSignatureLength);

	void DecryptL(
		const TKeyIdentifier& aKeyId,
		const TDesC8& aData);
		
	void CancelSignWithPrivateKey();		

protected:
	
	CEapTlsPeapCertInterface(abs_eap_am_tools_c* const aTools, eap_am_type_tls_peap_symbian_c* const aParent);
	
	void ConstructL();
	
	void RunL();
	
	void DoCancel();

private:

	enum TState
	{
		EReadCertInitStore,
		EReadCertList,
		EReadCert,		
		EValidateChainInitStore,
		EValidateChainGetCACertList,
		EValidateChainGetCACert,		
		EValidateChainEnd,
		EGetMatchingCertsInitStore,
		EGetMatchingCertsInitialize,
		EGetMatchingCertsLoop,
		ESignInitStore,
		ESignList,
		ESignOpenKeyStore,
		ESign,
		EDecryptInitStore,
		EDecryptList,
		EDecryptOpenKeyStore,
		EDecrypt,		
		EGetAllCerts,
		ECreateCertChain,
		ERetrieveChainInitStore,		
		ESetPassphraseTimeout,
		EReadCACertInitStore,
		EReadCACertList,
		EReadCACert
	};
	
	TState iState;
	
	eap_am_type_tls_peap_symbian_c * const iParent;
	
	abs_eap_am_tools_c * const m_am_tools;	
	
	CUnifiedCertStore* iCertStore;	
	
	MRSASigner* iRSASigner;
	
	MDSASigner* iDSASigner;
	
	MCTDecryptor* iDecryptor;
	
	RFs iFs;
	
	RPointerArray<EapCertificateEntry> iAllowedUserCerts;

	TBool iUseCertAuthoritiesFilter;
	
	TBool iUseCertTypesFilter;
	
	TBool iUseAllowedCipherSuitesFilter;

	TBool iRSACertsAllowed;

	TBool iDSACertsAllowed;

	RPointerArray<CX500DistinguishedName> iCertAuthorities;

	const eap_array_c<u8_t>* iCertTypes;

	RMPointerArray<CCTCertInfo> iCertInfos;
	
	RMPointerArray<CCTKeyInfo> iKeyInfos;
	
	HBufC8* iEncodedCertificate;
	TPtr8 iCertPtr;

	CCertAttributeFilter* iCertFilter;
	
	TCTKeyAttributeFilter* iKeyFilter;
	
	CPKIXCertChain* iCertChain;
	
	CPKIXValidationResult* iValidationResult;
	
	TTime iTime;
	
	RPointerArray<CX509Certificate> iRootCerts;

	RPointerArray<CX509Certificate> iMatchingUserCerts;

	RPointerArray<CX509Certificate> iUserCertChain;
	
	RPointerArray<EapCertificateEntry> iMatchingUserCertInfos;

	TUint iCAIndex;

	TUint iUserCertIndex;
	
	RPointerArray<EapCertificateEntry> iAllowedCACerts;
	
	HBufC8* iInputCertChain;

	EapCertificateEntry iCertInfo;

	TAny *iResArray;	

	// SignL
	TKeyIdentifier iKeyIdentifier;

	TBuf8<KMaxHashLength> iHashIn;

	HBufC8* iDataIn;
	
	HBufC8* iDataOut;

	HBufC8* iSignature;
	
	CRSASignature* iRSASignature;
	
	CDSASignature* iDSASignature;
	
	TPtr8* iSignaturePtr;

	TPtr8* iPtrOut;

	CUnifiedKeyStore* iKeyStore;

	TBool iRetrieveChain;

	TBool iUseAutomaticCaCertificate;

}; 

#endif // _EAPTLSPEAPCERTINTERFACE_H_

// End of file
