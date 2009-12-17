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


#ifndef _EAPSIMUICONNECTION_H_
#define _EAPSIMUICONNECTION_H_

#include <e32std.h>
#include <e32base.h>
#include <d32dbms.h>
#include <EapType.h>

class CEapSimUiDataConnection;

class CEapSimUiConnection : public CBase
{

public:

    CEapSimUiConnection(
        const TIndexType iIndexType,
        const TInt iIndex,
        const TInt iTunnelingType);

    ~CEapSimUiConnection();

    TInt Connect();

    TInt Close();

    CEapSimUiDataConnection * GetDataConnection();

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

    // database names, handlers etc...

    TBool iIsConnected;
        
    CEapSimUiDataConnection * iDataConn;

    RDbNamedDatabase iDbNamedDatabase;

    RDbs iDbs;
};


#endif
