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


#ifndef _EAPMSCHAPV2UICONNECTION_H_
#define _EAPMSCHAPV2UICONNECTION_H_

#include <e32std.h>
#include <e32base.h>
#include <d32dbms.h>
#include <EapType.h>

class CEapMsChapV2UiDataConnection;

class CEapMsChapV2UiConnection : public CBase
{

public:

    CEapMsChapV2UiConnection(
	    const TIndexType aIndexType,
	    const TInt aIndex,
	    const TInt aTunnelingType,
	    const TInt aEAPType);

    ~CEapMsChapV2UiConnection();

    TInt Connect();

    TInt Close();

    CEapMsChapV2UiDataConnection * GetDataConnection();

    TIndexType GetIndexType();

    TInt GetIndex();

    TInt GetTunnelingType();

    TInt GetDatabase(RDbNamedDatabase & aDatabase);
    
    TInt GetBearerEAPType();

protected:

    // Bearer type
	TIndexType iIndexType;
	
	// Unique index
	TInt iIndex;

	// Tunneling type
	TInt iTunnelingType;

    TBool iIsConnected;
    
    // database names, handlers etc...

    CEapMsChapV2UiDataConnection * iDataConn;

    RDbNamedDatabase iDbNamedDatabase;

    RDbs iDbs;
    
    // Holds the bearer EAP type.
    TInt iEAPType;
};


#endif

// End of file

