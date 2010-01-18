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
* %version: 11.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 213 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include "EapSimDbUtils.h"
#include <EapSimUiConnection.h>
#include <EapSimUiDataConnection.h>

CEapSimUiConnection::CEapSimUiConnection(
    const TIndexType aIndexType,
    const TInt aIndex,
    const TInt aTunnelingType)
    : iIndexType(aIndexType)
    , iIndex(aIndex)
    , iTunnelingType(aTunnelingType)
    , iIsConnected(EFalse)
    , iDataConn(NULL)
{
}


CEapSimUiConnection::~CEapSimUiConnection()
{
}


TInt CEapSimUiConnection::Connect()
{
#ifdef USE_EAP_EXPANDED_TYPES

	eap_type_value_e tunnelingType(static_cast<eap_type_ietf_values_e>(iTunnelingType));

#else

	eap_type_value_e tunnelingType = static_cast<eap_type_value_e>(iTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	TRAPD(err, EapSimDbUtils::OpenDatabaseL(
		iDbNamedDatabase, 
		iDbs, 
		iIndexType, 
		iIndex, 
		tunnelingType));
    if (err == KErrNone)
    {
        iIsConnected = ETrue;
    }

    return err;
}


TInt CEapSimUiConnection::Close()
{
    if (iIsConnected)
    {
        iDbNamedDatabase.Close();
        iDbs.Close();
    }
    iIsConnected = EFalse;

    return KErrNone;
}


CEapSimUiDataConnection * CEapSimUiConnection::GetDataConnection()
{
    if (!iDataConn)
    {
        iDataConn = new CEapSimUiDataConnection(this);
    }

    return iDataConn;
}

TInt CEapSimUiConnection::GetDatabase(RDbNamedDatabase & aDatabase)
{
    if (iIsConnected == EFalse)
    {
        return KErrSessionClosed;
    }

    aDatabase = iDbNamedDatabase;
    return KErrNone;
}


TIndexType CEapSimUiConnection::GetIndexType()
{
    return iIndexType;
}


TInt CEapSimUiConnection::GetIndex()
{
    return iIndex;
}


TInt CEapSimUiConnection::GetTunnelingType()
{
    return iTunnelingType;
}

// End of file
