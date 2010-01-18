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
* Description: Stub implementation of wifiprotplugin for 
*              non-WLAN products to support linking.
*
*/

/*
* %version: 1 %
*/

// INCLUDE FILES

#include <cmmanagerext.h>
#include <wifiprotreturn.h>
#include <wifiprotuiinprocess.h>

#include "wifiprotplugin.h"
#include "wifiprotdlgsplugin.h"
#include "wifiprotactiverunner.h"

using namespace WiFiProt;


// ===================== STUB FOR wifiprotplugin.cpp ========================
    
// --------------------------------------------------------------------------
// NotifierArray()
// Lib main entry point
// --------------------------------------------------------------------------
//
EXPORT_C CArrayPtr<MEikSrvNotifierBase2>* NotifierArray()
    {
    return NULL;
    }



// =================== STUB FOR wifiprotuiinprocess.cpp =====================

// --------------------------------------------------------------------------
// CWifiProtUiInProcess* CWifiProtUiInProcess::NewL()
// --------------------------------------------------------------------------
//
EXPORT_C CWifiProtUiInProcess* CWifiProtUiInProcess::NewL( RCmManagerExt*
                                                              aCmManagerExt )
    {
    User::Leave(KErrNotSupported);
    return NULL;
    }


// --------------------------------------------------------------------------
// CWifiProtUiInProcess::~CWifiProtUiInProcess
// --------------------------------------------------------------------------
//
CWifiProtUiInProcess::~CWifiProtUiInProcess( )

    {    
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
    return EWiFiCancel;
    }


// =================== STUB FOR wifiprotdlgsplugin.cpp ======================

// --------------------------------------------------------------------------
// CWiFiProtDlgsPlugin* CWiFiProtDlgsPlugin::NewL()
// --------------------------------------------------------------------------
//
CWiFiProtDlgsPlugin* CWiFiProtDlgsPlugin::NewL( 
                             const TBool aResourceFileResponsible,
                                      RCmManagerExt* aCmManagerExt )

    {
    User::Leave(KErrNotSupported);
    return NULL;
    }

CWiFiProtDlgsPlugin* CWiFiProtDlgsPlugin::NewL( 
                                       const TBool aResourceFileResponsible )
    {
    User::Leave(KErrNotSupported);
    return NULL;
    }
    
// --------------------------------------------------------------------------
// CWiFiProtDlgsPlugin::~CWiFiProtDlgsPlugin
// --------------------------------------------------------------------------
//
CWiFiProtDlgsPlugin::~CWiFiProtDlgsPlugin( )

    { 
    }
    
// --------------------------------------------------------------------------
// CWiFiProtDlgsPlugin::TNotifierInfo 
//                                  CWiFiProtDlgsPlugin::Info() const
// --------------------------------------------------------------------------
//
CWiFiProtDlgsPlugin::TNotifierInfo CWiFiProtDlgsPlugin::Info() const
    {
    return iInfo;
    }

// --------------------------------------------------------------------------
// TPtrC8 CWiFiProtDlgsPlugin::StartL()
// --------------------------------------------------------------------------
//
TPtrC8 CWiFiProtDlgsPlugin::StartL( const TDesC8& /*aBuffer*/ )
    {
    return NULL;
    }

// --------------------------------------------------------------------------
// void CWiFiProtDlgsPlugin::Cancel()
// --------------------------------------------------------------------------
//
void CWiFiProtDlgsPlugin::Cancel()
    {
    }
    
// --------------------------------------------------------------------------
// void CWiFiProtDlgsPlugin::Release()
// --------------------------------------------------------------------------
//
void CWiFiProtDlgsPlugin::Release()
    {
    }

// --------------------------------------------------------------------------
// TPtrC8 CWiFiProtDlgsPlugin::UpdateL()
// --------------------------------------------------------------------------
//
TPtrC8 CWiFiProtDlgsPlugin::UpdateL(const TDesC8& /*aBuffer*/)
    {
    return NULL;
    }

// --------------------------------------------------------------------------
// CWiFiProtDlgsPlugin::TNotifierInfo CWiFiProtDlgsPlugin::RegisterL()
// --------------------------------------------------------------------------
//
CWiFiProtDlgsPlugin::TNotifierInfo CWiFiProtDlgsPlugin::RegisterL()
    {
    return iInfo;
    }

// --------------------------------------------------------------------------
// void CWiFiProtDlgsPlugin::StartL
// --------------------------------------------------------------------------
//
void CWiFiProtDlgsPlugin::StartL( const TDesC8& aBuffer, 
                                  TInt aReplySlot,
                                  const RMessagePtr2& aMessage )
    {
    }



// =================== STUB FOR wifiprotactiverunner.cpp ======================

CWiFiProtActiveRunner* CWiFiProtActiveRunner::NewL(
        CWiFiProtDlgsPlugin* aParent, TInt aPriority )
    {
    User::Leave(KErrNotSupported);
    return NULL;
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::~CWiFiProtActiveRunner
// --------------------------------------------------------------------------
//
CWiFiProtActiveRunner::~CWiFiProtActiveRunner()
    {
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::DoCancel
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::DoCancel()
    { 
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::RunL
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::RunL()
    {
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::PinQueryExitL
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::PinQueryExitL( TInt aResponse )
    {
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::DialogDismissedL
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::DialogDismissedL( TInt aButtonId )
    {
    }

// End of File
