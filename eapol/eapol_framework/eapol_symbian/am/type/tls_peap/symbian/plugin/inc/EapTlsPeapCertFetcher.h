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
* %version: 24 %
*/

#ifndef _EAPTLSPEAPCERTFETCHER_H_
#define _EAPTLSPEAPCERTFETCHER_H_

// INCLUDES
#include <e32base.h>
#include <unifiedcertstore.h>
#include <mctwritablecertstore.h>
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPTLSPEAPCERTFETCHER_H)
	#define EAP_CLASS_VISIBILITY_EAPTLSPEAPCERTFETCHER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPTLSPEAPCERTFETCHER_H 
	#define EAP_C_FUNC_VISIBILITY_EAPTLSPEAPCERTFETCHER_H 
	#define EAP_FUNC_EXPORT_EAPTLSPEAPCERTFETCHER_H 
	#define EAP_C_FUNC_EXPORT_EAPTLSPEAPCERTFETCHER_H 
#elif defined(EAP_EXPORT_EAPTLSPEAPCERTFETCHER_H)
	#define EAP_CLASS_VISIBILITY_EAPTLSPEAPCERTFETCHER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPTLSPEAPCERTFETCHER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPTLSPEAPCERTFETCHER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPTLSPEAPCERTFETCHER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPTLSPEAPCERTFETCHER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPTLSPEAPCERTFETCHER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPTLSPEAPCERTFETCHER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPTLSPEAPCERTFETCHER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPTLSPEAPCERTFETCHER_H 
	#define EAP_C_FUNC_EXPORT_EAPTLSPEAPCERTFETCHER_H 
#endif
// End: added by script change_export_macros.sh.
#include "EapTlsPeapUtils.h"


class CAbsEapCertificateFetcher;

// CLASS DECLARATION
class EAP_CLASS_VISIBILITY_EAPTLSPEAPCERTFETCHER_H CEapTlsPeapCertFetcher 
: public CActive
{

public:

	static CEapTlsPeapCertFetcher* NewL(CAbsEapCertificateFetcher* const aParent);
	
	virtual ~CEapTlsPeapCertFetcher();	
	
	void GetCertificatesL();

	// DON'T USE THESE. ONLY USED FOR EapTlsPeapUtils.
	static CEapTlsPeapCertFetcher* NewL();	
	void GetSymbianSubjectKeyIdL( TDes8& aSubjectKeyId, EapCertificateEntry aCertEntry );
	
protected:
	
	CEapTlsPeapCertFetcher(CAbsEapCertificateFetcher* const aParent);
	
	void ConstructL();
	
	void RunL();
	
	void DoCancel();
	
private:

	// DON'T USE THIS. ONLY USED FOR EapTlsPeapUtils.
	CEapTlsPeapCertFetcher();	

	void InitializeQuery();

private:

	enum TState
	{
		EGetCertificatesNone,
		EGetCertificatesInitStore,
		EGetCertificatesGetCertList,
		EGetCertificatesGetUserCertList,
		EGetCertificatesRetrieveCert,
		EGetSymbianSubjectKeyId // DON'T USE THIS. ONLY USED FOR EapTlsPeapUtils.		
	};
	
	TState iState;
	
	CAbsEapCertificateFetcher* const iParent;

	RMPointerArray<CCTCertInfo> iCertInfos;
	
	CUnifiedCertStore* iCertStore;
	
	RFs iFs;

	CCertAttributeFilter* iCertFilter;

	RPointerArray<EapCertificateEntry> iUserCerts;
	
	RPointerArray<EapCertificateEntry> iCACerts;
	
	HBufC8* iEncodedCertificate;
	TPtr8 iCertPtr;

	TCertificateOwnerType iOwnertype;
	TInt iCertInfoIndex;
	
}; 

#endif // _EAPTLSPEAPCERTFETCHER_H_

// End of file
