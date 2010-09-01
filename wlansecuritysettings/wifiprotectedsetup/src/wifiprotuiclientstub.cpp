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
* Description: Stub implementation of class CWiFiProtUiClient for 
*              non-WLAN products to support linking.  
*
*/

/*
* %version: 1 %
*/

// INCLUDE FILES

#include <wifiprotuiclient.h>
#include "wifiprotsyncclient.h"

// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWiFiProtUiClient::NewL
// ---------------------------------------------------------
//
EXPORT_C CWiFiProtUiClient* CWiFiProtUiClient::NewL()
    {
    User::Leave(KErrNotSupported);
    return NULL;
    }


// ---------------------------------------------------------
// CWiFiProtUiClient::~CWiFiProtUiClient
// ---------------------------------------------------------
//
EXPORT_C CWiFiProtUiClient::~CWiFiProtUiClient()
    {
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
    }

// ---------------------------------------------------------
// CWiFiProtUiClient::StartWiFiProtL
// ---------------------------------------------------------
//
EXPORT_C WiFiProt::TWiFiReturn CWiFiProtUiClient::StartWiFiProtSyncL(
 const TWlanSsid& aSSid, TBool aConnectionNeeded,RArray<TUint32>& aUidsReturned )
    {
    return WiFiProt::TWiFiReturn(EWiFiCancel);
    }

// ---------------------------------------------------------
// CWiFiProtUiClient::CancelWiFiProt
// ---------------------------------------------------------
//
EXPORT_C void CWiFiProtUiClient::CancelWiFiProt()
    {
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
    }
    
// ---------------------------------------------------------
// Stubs for CWiFiProtSyncClient
// ---------------------------------------------------------
//

CWiFiProtSyncClient* CWiFiProtSyncClient::NewL( RWiFiProtSession& aClient,
                    TInt aPriority )
    {
    User::Leave(KErrNotSupported);
    return NULL;
    }
    
    CWiFiProtSyncClient::CWiFiProtSyncClient( RWiFiProtSession& aClient,
                                          TInt aPriority ) 
                                         : CActive( aPriority ),
                                           iClient( aClient )
    {
    }

CWiFiProtSyncClient::~CWiFiProtSyncClient()
    {
    }
    

void CWiFiProtSyncClient::RunL()
    {
    }
    
void CWiFiProtSyncClient::DoCancel()
    {
    }
    
// End of File
