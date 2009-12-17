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
* Description: Implementation of CWifiProtUiInProcess.
*
*/


// INCLUDE FILES

#include <cmmanagerext.h>
#include <wifiprotreturn.h>
#include <wifiprotuiinprocess.h>

#include "wifiprotdlgsplugin.h"
#include "wifiprotlogger.h"

using namespace WiFiProt;

// =========================== MEMBER FUNCTIONS =============================

// --------------------------------------------------------------------------
// CWifiProtUiInProcess* CWifiProtUiInProcess::NewL()
// --------------------------------------------------------------------------
//
EXPORT_C CWifiProtUiInProcess* CWifiProtUiInProcess::NewL( RCmManagerExt*
                                                              aCmManagerExt )
    {
    CLOG_ENTERFN( "WiFiProtDlgsPlugin::NewL" );
    
    CWifiProtUiInProcess* self = new ( ELeave ) CWifiProtUiInProcess();
    CleanupStack::PushL( self );
    self->ConstructL( aCmManagerExt );
    CleanupStack::Pop();
    CLOG_LEAVEFN( "WiFiProtDlgsPlugin::NewL" );
    return self;
    }


// --------------------------------------------------------------------------
// CWifiProtUiInProcess::~CWifiProtUiInProcess
// --------------------------------------------------------------------------
//
CWifiProtUiInProcess::~CWifiProtUiInProcess( )

    {    
    CLOG_ENTERFN( "WiFiProtDlgsPlugin::~CWifiProtUiInProcess" );
    delete iWiFiProtDlgsPlugin; 
    CLOG_LEAVEFN( "WiFiProtDlgsPlugin::~CWifiProtUiInProcess" );
    }
        
// --------------------------------------------------------------------------
// WiFiProt::TWiFiReturn CWifiProtUiInProcess::StartFromUiL
// --------------------------------------------------------------------------
//
EXPORT_C WiFiProt::TWiFiReturn CWifiProtUiInProcess::StartFromUiL(
                                             const TWlanSsid& aSSid,
                                             TBool aConnectionNeeded,
                                             RArray<TUint32>& aUidsReturned )
   {
    CLOG_ENTERFN( "WiFiProtDlgsPlugin::StartFromUiL" );
    
    WiFiProt::TWiFiReturn ret =
         iWiFiProtDlgsPlugin->StartFromUiL( aSSid,
                                            aConnectionNeeded,
                                            aUidsReturned );
    
    CLOG_LEAVEFN( "WiFiProtDlgsPlugin::StartFromUiL" );
    
    return ret;
    }
    
    
// --------------------------------------------------------------------------
// CWifiProtUiInProcess::CWifiProtUiInProcess
// --------------------------------------------------------------------------
//
CWifiProtUiInProcess::CWifiProtUiInProcess( ):
                                iWiFiProtDlgsPlugin(NULL)
    {    
    CLOG_ENTERFN( "WiFiProtDlgsPlugin::CWifiProtUiInProcess" );
    CLOG_LEAVEFN( "WiFiProtDlgsPlugin::CWifiProtUiInProcess" );
    }

// --------------------------------------------------------------------------
// void CWifiProtUiInProcess::ConstructL( )
// --------------------------------------------------------------------------
//
void CWifiProtUiInProcess::ConstructL( RCmManagerExt* aCmManagerExt )
    {
    CLOG_ENTERFN( "WiFiProtDlgsPlugin::ConstructL" );
    
    iWiFiProtDlgsPlugin = CWiFiProtDlgsPlugin::NewL( ETrue, aCmManagerExt );
    
    CLOG_LEAVEFN( "WiFiProtDlgsPlugin::ConstructL" );
    
    }    
// End of File
