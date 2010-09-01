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
* %version: 10.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 182 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include "EapAkaDbUtils.h"
#include <EapAkaUiConnection.h>
#include <EapAkaUiDataConnection.h>
#include "eap_header.h"

CEapAkaUiConnection::CEapAkaUiConnection(
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


CEapAkaUiConnection::~CEapAkaUiConnection()
{
}


TInt CEapAkaUiConnection::Connect()
{
#ifdef USE_EAP_EXPANDED_TYPES

	eap_type_value_e tunnelingType(static_cast<eap_type_ietf_values_e>(iTunnelingType));

#else

	eap_type_value_e tunnelingType = static_cast<eap_type_value_e>(iTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	TRAPD(err, EapAkaDbUtils::OpenDatabaseL(
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


TInt CEapAkaUiConnection::Close()
{
    if (iIsConnected)
    {
        iDbNamedDatabase.Close();
        iDbs.Close();
    }
    iIsConnected = EFalse;

    return KErrNone;
}


CEapAkaUiDataConnection * CEapAkaUiConnection::GetDataConnection()
{
    if (!iDataConn)
    {
        iDataConn = new CEapAkaUiDataConnection(this);
    }

    return iDataConn;
}

TInt CEapAkaUiConnection::GetDatabase(RDbNamedDatabase & aDatabase)
{
    if (iIsConnected == EFalse)
    {
        return KErrSessionClosed;
    }

    aDatabase = iDbNamedDatabase;
    return KErrNone;
}


TIndexType CEapAkaUiConnection::GetIndexType()
{
    return iIndexType;
}


TInt CEapAkaUiConnection::GetIndex()
{
    return iIndex;
}


TInt CEapAkaUiConnection::GetTunnelingType()
{
    return iTunnelingType;
}
