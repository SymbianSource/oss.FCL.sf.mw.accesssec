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
* %version: 18 %
*/

#ifndef _EAPTLSPEAPUIDATACONNECTION_H_
#define _EAPTLSPEAPUIDATACONNECTION_H_

#include <e32base.h>

class CEapTlsPeapUiConnection;
class CEapTlsPeapUiTlsPeapData;
class CEapType;


class CEapTlsPeapUiDataConnection : public CBase
{

public:

    CEapTlsPeapUiDataConnection(CEapTlsPeapUiConnection * aUiConn);

    ~CEapTlsPeapUiDataConnection();

    TInt Open();

    TInt GetData(CEapTlsPeapUiTlsPeapData ** aDataPtr);

   	TInt Update();

    TInt Close();

protected:

    TBool iIsOpened;

    CEapTlsPeapUiConnection * iUiConn;

    CEapTlsPeapUiTlsPeapData * iDataPtr;

private:
	// Functions.
	
    //void FetchDataL();
    //void UpdateDataL();
    
private:	
	// Member variables.

   // Only used with EAP-FAST. Can't use the flag here.
    CDbColSet *  iFastSpecificColSet;

    CEapType * iEapTypeConnection; 
};

#endif // _EAPTLSPEAPUIDATACONNECTION_H_

// End of file
