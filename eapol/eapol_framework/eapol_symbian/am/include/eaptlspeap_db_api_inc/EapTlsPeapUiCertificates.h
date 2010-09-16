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
* %version: 30 %
*/

#ifndef _EAPTLSPEAPUICERTIFICATES_H_
#define _EAPTLSPEAPUICERTIFICATES_H_

#include <e32base.h>
#include <AbsEapCertificateFetcher.h>


class CEapTlsPeapUiConnection;
class CEapGeneralSettings;
class MEapTlsPeapUiCertificates;
class CEapType;


class CEapTlsPeapUiCertificates
: public CBase
//, public CAbsEapCertificateFetcher
{

public:

    CEapTlsPeapUiCertificates(CEapTlsPeapUiConnection * const aUiConn, MEapTlsPeapUiCertificates * const aParent);

    ~CEapTlsPeapUiCertificates();

    TInt Open();

	TInt GetCertificates(RPointerArray<EapCertificateEntry> ** aUserCerts,
						 RPointerArray<EapCertificateEntry> ** aCACerts);
    
    TInt Update();

    TInt Close();

private:

    TBool iIsOpened;

    CEapTlsPeapUiConnection * iUiConn;

    RPointerArray<EapCertificateEntry> * iUserCerts;

    RPointerArray<EapCertificateEntry> * iCACerts;

    TRequestStatus iStatus;
	
	CEapGeneralSettings *iEapGeneralSettings;
	
	MEapTlsPeapUiCertificates* iParent;
	
    CEapType* iEapTypeConnection; 

private:

	void SelectActiveCertificatesL();

	void FetchDataL(
		const RPointerArray<EapCertificateEntry>& aAvailableCerts,
		RPointerArray<EapCertificateEntry> * const aArray);    

    void UpdateL();

	void SelectCertificatesL(
		const EapCertificateEntry::TCertType aCertType,
		const EAPSettings & aSettings,
		RPointerArray<EapCertificateEntry>& aAvailableCerts);

	void SaveCertificatesL(
		const EapCertificateEntry::TCertType aCertType,
		const RPointerArray<EapCertificateEntry>* const aAvailableCerts,
		EAPSettings & aSettings);
};

#endif // _EAPTLSPEAPUICERTIFICATES_H_

// End of file
