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
	#define EAP_FILE_NUMBER_ENUM 298 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include "EapMsChapV2DbUtils.h"
#include <EapMsChapV2UiConnection.h>
#include <EapMsChapV2UiDataConnection.h>

CEapMsChapV2UiConnection::CEapMsChapV2UiConnection(
    const TIndexType aIndexType,
    const TInt aIndex,
    const TInt aTunnelingType,
    const TInt aEAPType)
    : iIndexType(aIndexType)
    , iIndex(aIndex)
    , iTunnelingType(aTunnelingType)
    , iIsConnected(EFalse)
    , iDataConn(NULL)
    , iEAPType(aEAPType)
{
}


CEapMsChapV2UiConnection::~CEapMsChapV2UiConnection()
{
}


TInt CEapMsChapV2UiConnection::Connect()
{
#ifdef USE_EAP_EXPANDED_TYPES

	eap_type_value_e tunnelingType(static_cast<eap_type_ietf_values_e>(iTunnelingType));

#else

	eap_type_value_e tunnelingType = static_cast<eap_type_value_e>(iTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	TRAPD(err, EapMsChapV2DbUtils::OpenDatabaseL(
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


TInt CEapMsChapV2UiConnection::Close()
{
    if (iIsConnected)
    {
        iDbNamedDatabase.Close();
        iDbs.Close();
    }
    iIsConnected = EFalse;

    return KErrNone;
}


CEapMsChapV2UiDataConnection * CEapMsChapV2UiConnection::GetDataConnection()
{
    if (!iDataConn)
    {
        iDataConn = new CEapMsChapV2UiDataConnection(this);
    }

    return iDataConn;
}

TInt CEapMsChapV2UiConnection::GetDatabase(RDbNamedDatabase & aDatabase)
{
    if (iIsConnected == EFalse)
    {
        return KErrSessionClosed;
    }

    aDatabase = iDbNamedDatabase;
    return KErrNone;
}


TIndexType CEapMsChapV2UiConnection::GetIndexType()
{
    return iIndexType;
}


TInt CEapMsChapV2UiConnection::GetIndex()
{
    return iIndex;
}


TInt CEapMsChapV2UiConnection::GetTunnelingType()
{
    return iTunnelingType;
}

TInt CEapMsChapV2UiConnection::GetBearerEAPType()
{
	return iEAPType;
}

// End of file


