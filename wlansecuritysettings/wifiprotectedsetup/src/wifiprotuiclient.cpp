/*
* Copyright (c) 2001-2009 Nokia Corporation and/or its subsidiary(-ies).
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
* Description: Implementation of class CWiFiProtUiClient.  
*
*/


// INCLUDE FILES

#include <wifiprotuiclient.h>

#include "wifiprotuiclientimpl.h"
#include "wifiprotlogger.h"


// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWiFiProtUiClient::NewL
// ---------------------------------------------------------
//
EXPORT_C CWiFiProtUiClient* CWiFiProtUiClient::NewL()
    {
    CLOG_ENTERFN( "CWiFiProtUiClient::NewL" );
    CWiFiProtUiClient* wifi = new ( ELeave ) CWiFiProtUiClient();
    CleanupStack::PushL( wifi );
    wifi->iImpl = CWiFiProtUiClientImpl::NewL();
    CleanupStack::Pop( wifi );
    CLOG_LEAVEFN( "CWiFiProtUiClient::NewL" ); 
    return wifi;
    }


// ---------------------------------------------------------
// CWiFiProtUiClient::~CWiFiProtUiClient
// ---------------------------------------------------------
//
EXPORT_C CWiFiProtUiClient::~CWiFiProtUiClient()
    {
    CLOG_ENTERFN( "CWiFiProtUiClient::~CWiFiProtUiClient" );
    delete iImpl;
    CLOG_LEAVEFN( "CWiFiProtUiClient::~CWiFiProtUiClient" );
    }

// ---------------------------------------------------------
// CWiFiProtUiClient::StartWiFiProtL
// ---------------------------------------------------------
//
EXPORT_C void CWiFiProtUiClient::StartWiFiProtL( const TWlanSsid& aSSid,
                                                 TBool aConnectionNeeded,
                                                 RArray<TUint32>& aUidsReturned,
                                                 WiFiProt::TWiFiReturn& aReturnValue,
                                                 TRequestStatus& aStatus )
    {
    CLOG_ENTERFN( "CWiFiProtUiClient::StartWiFiProtL" );
    iImpl->StartWiFiProtL( aSSid, aConnectionNeeded, aUidsReturned, aReturnValue, aStatus );
    CLOG_LEAVEFN( "CWiFiProtUiClient::StartWiFiProtL" );
    }

// ---------------------------------------------------------
// CWiFiProtUiClient::StartWiFiProtL
// ---------------------------------------------------------
//
EXPORT_C WiFiProt::TWiFiReturn CWiFiProtUiClient::StartWiFiProtSyncL(
 const TWlanSsid& aSSid, TBool aConnectionNeeded,RArray<TUint32>& aUidsReturned )
    {
    CLOG_WRITE( "CWiFiProtUiClient::StartWiFiProtSyncL" );
    return iImpl->StartWiFiProtSyncL( aSSid, aConnectionNeeded, aUidsReturned );
    }

// ---------------------------------------------------------
// CWiFiProtUiClient::CancelWiFiProt
// ---------------------------------------------------------
//
EXPORT_C void CWiFiProtUiClient::CancelWiFiProt()
    {
    CLOG_ENTERFN( "CWiFiProtUiClient::CancelWiFiProt" );
    iImpl->CancelWiFiProt();
    CLOG_LEAVEFN( "CWiFiProtUiClient::CancelWiFiProt" );
    }

// ---------------------------------------------------------
// CWiFiProtUiClient::StartWiFiProtConnL
// ---------------------------------------------------------
//
EXPORT_C void CWiFiProtUiClient::StartWiFiProtConnL( const TWlanSsid& aSSid,
                                      TWlanProtectedSetupCredentialAttribute&
                                        aNetworkSettings,
                                      WiFiProt::TWiFiReturn& aReturnValue,
                                      TRequestStatus& aStatus )
    {
    CLOG_ENTERFN( "CWiFiProtUiClient::StartWiFiProtConnL" );
    iImpl->StartWiFiProtConnL( aSSid, aNetworkSettings, aReturnValue, aStatus );
    CLOG_LEAVEFN( "CWiFiProtUiClient::StartWiFiProtConnL" );
    }
// End of File
