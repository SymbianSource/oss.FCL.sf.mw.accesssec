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
* %version: 13.1.2 %
*/

#ifndef _EAPTLSPEAPCERTFETCHER_H_
#define _EAPTLSPEAPCERTFETCHER_H_

// INCLUDES
#include <e32base.h>
#include <unifiedcertstore.h>
#include <mctwritablecertstore.h>
#include "EapTlsPeapUtils.h"


class CEapTlsPeapUiCertificates;

// CLASS DECLARATION
class CEapTlsPeapCertFetcher 
: public CActive
{
public:
	static CEapTlsPeapCertFetcher* NewL(CEapTlsPeapUiCertificates* const aParent);	
	
	virtual ~CEapTlsPeapCertFetcher();	
	
	void GetCertificatesL();

	// DON'T USE THESE. ONLY USED FOR EapTlsPeapUtils.
	static CEapTlsPeapCertFetcher* NewL();	
	void GetSymbianSubjectKeyIdL( TDes8& aSubjectKeyId, CertificateEntry aCertEntry );
	
protected:
	
	CEapTlsPeapCertFetcher(CEapTlsPeapUiCertificates* const aParent);
	
	void ConstructL();
	
	void RunL();
	
	void DoCancel();
	
private:

	// DON'T USE THIS. ONLY USED FOR EapTlsPeapUtils.
	CEapTlsPeapCertFetcher();	

private:

	enum TState
	{
		EGetCertificatesInitStore,
		EGetCertificatesGetCertList,
		EGetCertificatesRetrieveCert,
		EGetSymbianSubjectKeyId // DON'T USE THIS. ONLY USED FOR EapTlsPeapUtils.		
	};
	
	TState iState;
	
	CEapTlsPeapUiCertificates* const iParent;

	RMPointerArray<CCTCertInfo> iCertInfos;
	
	CUnifiedCertStore* iCertStore;
	
	RFs iFs;

	CCertAttributeFilter* iCertFilter;

	RArray<SCertEntry> iUserCerts;
	
	RArray<SCertEntry> iCACerts;
	
    // For wrapping asynchronous calls.
    CActiveSchedulerWait iWait;
    
	HBufC8* iEncodedCertificate;
	TPtr8 iCertPtr;

	
}; 

#endif // _EAPTLSPEAPCERTFETCHER_H_

// End of file
