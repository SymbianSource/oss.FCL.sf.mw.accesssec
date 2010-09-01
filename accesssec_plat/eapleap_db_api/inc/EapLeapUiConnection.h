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
* %version: 6.1.2 %
*/

#ifndef _EAPLEAPUICONNECTION_H_
#define _EAPLEAPUICONNECTION_H_

#include <e32std.h>
#include <e32base.h>
#include <d32dbms.h>
#include <EapType.h>


class CEapLeapUiDataConnection;

class CEapLeapUiConnection : public CBase
{

public:

    CEapLeapUiConnection(
        const TIndexType iIndexType,
        const TInt iIndex,
        const TInt iTunnelingType);

    ~CEapLeapUiConnection();

    TInt Connect();

    TInt Close();

    CEapLeapUiDataConnection * GetDataConnection();

    TIndexType GetIndexType();

    TInt GetIndex();

    TInt GetTunnelingType();

    TInt GetDatabase(RDbNamedDatabase & aDatabase);

protected:

    // Bearer type
	TIndexType iIndexType;
	
	// Unique index
	TInt iIndex;

	// Tunneling type
	TInt iTunnelingType;
	
    TBool iIsConnected;	

    // database names, handlers etc...

    CEapLeapUiDataConnection * iDataConn;

    RDbNamedDatabase iDbNamedDatabase;

    RDbs iDbs;
};


#endif
