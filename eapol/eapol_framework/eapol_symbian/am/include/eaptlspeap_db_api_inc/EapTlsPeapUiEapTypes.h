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
* %version: 16 %
*/

#ifndef _EAPTLSPEAPUIEAPTYPES_H_
#define _EAPTLSPEAPUIEAPTYPES_H_

#include <e32base.h>

class CEapTlsPeapUiConnection;
class TEapTlsPeapUiEapType;
class CEapType;


class CEapTlsPeapUiEapTypes : public CBase
{

public:

    CEapTlsPeapUiEapTypes(CEapTlsPeapUiConnection * const aUiConn);

    ~CEapTlsPeapUiEapTypes();

    TInt Open();

    TInt GetEapTypes(RPointerArray<TEapTlsPeapUiEapType> ** aDataPtr);
   	
    TInt Update();

    TInt Close();

private:

    TBool iIsOpened;

    CEapTlsPeapUiConnection * iUiConn;

    RPointerArray<TEapTlsPeapUiEapType>* iDataPtr;    
    
    CEapType * iEapTypeConnection;

private:


    void FetchExpandedDataL();
    
    void UpdateExpandedDataL();
    
};

#endif // _EAPTLSPEAPUIEAPTYPES_H_

// End of file
