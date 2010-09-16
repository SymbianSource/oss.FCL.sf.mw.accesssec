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
* %version: 15 %
*/

#ifndef _EAPTLSPEAPUICIPHERSUITES_H_
#define _EAPTLSPEAPUICIPHERSUITES_H_

#include <e32base.h>

class CEapTlsPeapUiConnection;
class TEapTlsPeapUiCipherSuite;
class CEapType;


class CEapTlsPeapUiCipherSuites : public CBase
{

public:

    CEapTlsPeapUiCipherSuites(CEapTlsPeapUiConnection * const aUiConn);

    ~CEapTlsPeapUiCipherSuites();

    TInt Open();

    TInt GetCipherSuites(RPointerArray<TEapTlsPeapUiCipherSuite> ** aDataPtr);
   	
    TInt Update();

    TInt Close();

private:

    TBool iIsOpened;

    CEapTlsPeapUiConnection * iUiConn;

	RPointerArray<TEapTlsPeapUiCipherSuite>* iDataPtr;

    CEapType* iEapTypeConnection;

private:

    void FetchDataL();
    
    void UpdateL();
};

#endif //_EAPTLSPEAPUICIPHERSUITES_H_

// End of file
