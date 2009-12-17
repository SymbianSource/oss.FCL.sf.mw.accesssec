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


// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 339 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include "EapGtcDbUtils.h"
#include <EapGtcUiConnection.h>
#include <EapGtcUiDataConnection.h>

CEapGtcUiConnection::CEapGtcUiConnection(
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


CEapGtcUiConnection::~CEapGtcUiConnection()
{
}


TInt CEapGtcUiConnection::Connect()
{
#ifdef USE_EAP_EXPANDED_TYPES

	eap_type_value_e tunnelingType(static_cast<eap_type_ietf_values_e>(iTunnelingType));

#else

	eap_type_value_e tunnelingType = static_cast<eap_type_value_e>(iTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	TRAPD(err, EapGtcDbUtils::OpenDatabaseL(
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


TInt CEapGtcUiConnection::Close()
{
    if (iIsConnected)
    {
        iDbNamedDatabase.Close();
        iDbs.Close();
    }
    iIsConnected = EFalse;

    return KErrNone;
}


CEapGtcUiDataConnection * CEapGtcUiConnection::GetDataConnection()
{
    if (!iDataConn)
    {
        iDataConn = new CEapGtcUiDataConnection(this);
    }

    return iDataConn;
}

TInt CEapGtcUiConnection::GetDatabase(RDbNamedDatabase & aDatabase)
{
    if (iIsConnected == EFalse)
    {
        return KErrSessionClosed;
    }

    aDatabase = iDbNamedDatabase;
    return KErrNone;
}


TIndexType CEapGtcUiConnection::GetIndexType()
{
    return iIndexType;
}


TInt CEapGtcUiConnection::GetIndex()
{
    return iIndex;
}


TInt CEapGtcUiConnection::GetTunnelingType()
{
    return iTunnelingType;
}

// End of File
