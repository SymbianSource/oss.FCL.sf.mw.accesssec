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
* %version: 4 %
*/

#ifndef _ABS_EAP_CERTIFICATE_FETCHER_H_
#define _ABS_EAP_CERTIFICATE_FETCHER_H_

// INCLUDES
#include <e32base.h>
#include "EapSettings.h"


// CLASS DECLARATION
class CAbsEapCertificateFetcher: public CBase
{
public:

	CAbsEapCertificateFetcher()
	{
	}

	virtual ~CAbsEapCertificateFetcher()
	{
	}

	virtual void CompleteReadCertificatesL(
		const RPointerArray<EapCertificateEntry>& aUserCerts, 
		const RPointerArray<EapCertificateEntry>& aCACerts) = 0;
};

#endif // _ABS_EAP_CERTIFICATE_FETCHER_H_

// End of file
