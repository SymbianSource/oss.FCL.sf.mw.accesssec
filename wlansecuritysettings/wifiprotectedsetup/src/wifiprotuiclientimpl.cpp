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
* Description: Implementation of class CWiFiProtUiClientImpl.     
*
*/

/*
* %version: tr1cfwln#11 %
*/

// INCLUDE FILES

#include <bautils.h>
#include <StringLoader.h>
#include <commdb.h>
#include <aknnotewrappers.h>
#include <wifiprotuiclient.h>
#include <AknsUtils.h>

#ifndef __WINS__
#include <wlanmgmtclient.h>
#include <WlanCdbCols.h>
#endif  // ! __WINS__
#include <data_caging_path_literals.hrh>

#include "wifiprotuiclientimpl.h"
#include "wifiprotlogger.h"


// ================= MEMBER FUNCTIONS =======================

// --------------------------------------------------------------------------
// CWiFiProtUiClientImpl::NewL
// --------------------------------------------------------------------------
//
CWiFiProtUiClientImpl* CWiFiProtUiClientImpl::NewL()
    {
    CLOG_ENTERFN( "CWiFiProtUiClientImpl::NewL" );
    CWiFiProtUiClientImpl* clientImpl = 
                                new ( ELeave ) CWiFiProtUiClientImpl();
    CleanupStack::PushL( clientImpl );
    clientImpl->ConstructL();
    CleanupStack::Pop( clientImpl );
    CLOG_LEAVEFN( "CWiFiProtUiClientImpl::NewL" );
    return clientImpl;
    }

// --------------------------------------------------------------------------
// CWiFiProtUiClientImpl::~CWiFiProtUiClientImpl
// --------------------------------------------------------------------------
//
CWiFiProtUiClientImpl::~CWiFiProtUiClientImpl()
    {  
    CLOG_ENTERFN( "CWiFiProtUiClientImpl::~CWiFiProtUiClientImpl" );  
    delete iWiFiProtSyncClient;
    iNotif.Close();
    CLOG_LEAVEFN( "CWiFiProtUiClientImpl::~CWiFiProtUiClientImpl" );
    }
    
// --------------------------------------------------------------------------
// CWiFiProtUiClientImpl::StartWiFiProtL
// --------------------------------------------------------------------------
//
void CWiFiProtUiClientImpl::StartWiFiProtL( const TWlanSsid& aSSid,
                                         TBool aConnectionNeeded,
                                         RArray<TUint32>& aUidsReturned,
                                         WiFiProt::TWiFiReturn& aReturnValue,
                                         TRequestStatus& aStatus )
    {
    CLOG_ENTERFN( "CWiFiProtUiClientImpl::StartWiFiProtL" );
    iNotif.StartWiFiProtL( aSSid, aConnectionNeeded,
                           aUidsReturned, aReturnValue, aStatus );
    CLOG_LEAVEFN( "CWiFiProtUiClientImpl::StartWiFiProtL" );        
    }
    
 // --------------------------------------------------------------------------
// CWiFiProtUiClientImpl::StartWiFiProtSyncL
// --------------------------------------------------------------------------
//
WiFiProt::TWiFiReturn 
CWiFiProtUiClientImpl::StartWiFiProtSyncL( const TWlanSsid& aSSid,
                                         TBool aConnectionNeeded,
                                         RArray<TUint32>& aUidsReturned )
    {
    CLOG_WRITE( "CWiFiProtUiClientImpl::StartWiFiProtSyncL" );
    if (iWiFiProtSyncClient == NULL)
        {
        iWiFiProtSyncClient = CWiFiProtSyncClient::NewL( iNotif );
        }
    return iWiFiProtSyncClient->StartWiFiProtL( aSSid,
                                         aConnectionNeeded, aUidsReturned );
    }

// ---------------------------------------------------------
// CWiFiProtUiClientImpl::StartWiFiProtConnL
// ---------------------------------------------------------
//
void CWiFiProtUiClientImpl::StartWiFiProtConnL( const TWlanSsid& aSSid,
                                      TWlanProtectedSetupCredentialAttribute&
                                        aNetworkSettings,
                                      WiFiProt::TWiFiReturn& aReturnValue,
                                      TRequestStatus& aStatus )
    {
    CLOG_ENTERFN( "CWiFiProtUiClientImpl::StartWiFiProtConnL" );
    iNotif.StartWiFiProtConnL( aSSid, aNetworkSettings, aReturnValue, aStatus );
    CLOG_LEAVEFN( "CWiFiProtUiClientImpl::StartWiFiProtConnL" );
    }
    
// --------------------------------------------------------------------------
// CWiFiProtUiClientImpl::CancelWiFiProt
// --------------------------------------------------------------------------
//
void CWiFiProtUiClientImpl::CancelWiFiProt(  )
    {
    CLOG_ENTERFN( "CWiFiProtUiClientImpl::CancelWiFiProt()" );
    iNotif.CancelWiFiProt( );
    CLOG_LEAVEFN( "CWiFiProtUiClientImpl::CancelWiFiProt()" );        
    }

// --------------------------------------------------------------------------
// CWiFiProtUiClientImpl::CWiFiProtUiClientImpl
// --------------------------------------------------------------------------
//
CWiFiProtUiClientImpl::CWiFiProtUiClientImpl()
    {
    }

// --------------------------------------------------------------------------
// CWiFiProtUiClientImpl::ConstructL
// --------------------------------------------------------------------------
//
void CWiFiProtUiClientImpl::ConstructL()
    {
    CLOG_ENTERFN( "CWiFiProtUiClientImpl::ConstructL" );
    User::LeaveIfError( iNotif.Connect() );
    CLOG_LEAVEFN( "CWiFiProtUiClientImpl::ConstructL" ); 
    }    
// End of File
