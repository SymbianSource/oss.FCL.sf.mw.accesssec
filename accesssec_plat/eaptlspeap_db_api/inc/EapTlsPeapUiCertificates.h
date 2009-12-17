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


#ifndef _EAPTLSPEAPUICERTIFICATES_H_
#define _EAPTLSPEAPUICERTIFICATES_H_

#include <CertEntry.h>
#include <e32base.h>

class CEapTlsPeapUiConnection;
class TEapTlsPeapUiCertificate;
class CEapTlsPeapCertFetcher;
class MEapTlsPeapUiCertificates;

class CEapTlsPeapUiCertificates : public CBase
{

public:

    CEapTlsPeapUiCertificates(CEapTlsPeapUiConnection * const aUiConn, MEapTlsPeapUiCertificates * const aParent);

    ~CEapTlsPeapUiCertificates();

    TInt Open();

	TInt GetCertificates(CArrayFixFlat<TEapTlsPeapUiCertificate> ** aUserCerts,
						 CArrayFixFlat<TEapTlsPeapUiCertificate> ** aCACerts);
    
    TInt Update();

    TInt Close();
    
    void CompleteReadCertificatesL(
		const RArray<SCertEntry>& aUserCerts, 
		const RArray<SCertEntry>& aCACerts);


private:

    TBool iIsOpened;

    CEapTlsPeapUiConnection * iUiConn;

    RDbNamedDatabase iDatabase;

    CArrayFixFlat<TEapTlsPeapUiCertificate> * iUserCerts;

    CArrayFixFlat<TEapTlsPeapUiCertificate> * iCACerts;

    TRequestStatus iStatus;
	
	CEapTlsPeapCertFetcher* iCertFetcher;
	
	MEapTlsPeapUiCertificates* iParent;
	
private:

	void FetchDataL(
		const TDesC& aTableName,
		const RArray<SCertEntry>& aAvailableCerts,
		CArrayFixFlat<TEapTlsPeapUiCertificate> * const aArray);    
    
    void UpdateL();
};

#endif // _EAPTLSPEAPUICERTIFICATES_H_

// End of file
