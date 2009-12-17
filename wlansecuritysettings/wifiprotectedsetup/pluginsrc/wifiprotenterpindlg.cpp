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
* Description: Implementation of class CWiFiProtEnterPinDlg.
*
*/


// INCLUDE FILES
//system includes
#include <uikon/eiksrvui.h>

//user includes
#include "wifiprotenterpindlg.h"
#include "wifiprotactiverunnercallback.h"
#include "wifiprotplugin.hrh"


// FORWARD DECLARATIONS
//class MActiveRunnerCallback;

// ================= MEMBER FUNCTIONS =======================
//
// --------------------------------------------------------------------------
// CWiFiProtEnterPinDlg::CWiFiProtEnterPinDlg
// --------------------------------------------------------------------------
//
CWiFiProtEnterPinDlg::CWiFiProtEnterPinDlg(
                              MActiveRunnerCallback& aActiveRunnerCallback ):
                              iActiveRunnerCallback ( aActiveRunnerCallback )
    {
    }
    
    
// --------------------------------------------------------------------------
// CWiFiProtEnterPinDlg::~CWiFiProtEnterPinDlg
// --------------------------------------------------------------------------
//
CWiFiProtEnterPinDlg::~CWiFiProtEnterPinDlg()
    {
    STATIC_CAST( CEikServAppUi*, 
                CCoeEnv::Static()->AppUi() )->SuppressAppSwitching( EFalse );
    }

// --------------------------------------------------------------------------
// CWiFiProtInitiateEasySetupDlg::ProcessCommandL()
// --------------------------------------------------------------------------
//    
void CWiFiProtEnterPinDlg::ProcessCommandL( TInt aCommandId )
    {
    switch ( aCommandId )
        {
        case EWiFiSoftkeyContinue: 
            {
            TryExitL(aCommandId);           
            break;              
            }
        default:
            {
            CAknQueryDialog::ProcessCommandL( aCommandId );
            break;
            }
        }    
    }

// --------------------------------------------------------------------------
// CWiFiProtEnterPinDlg::OkToExitL
// --------------------------------------------------------------------------
//
TBool CWiFiProtEnterPinDlg::OkToExitL( TInt aButtonId )
    {
    if (aButtonId == EAknSoftkeyEmpty)
        {
        return EFalse;
        }
    else
        {
        TInt status = KErrCancel;
        if (   aButtonId == EAknSoftkeyOk
            || aButtonId == EAknSoftkeyYes
            || aButtonId == EAknSoftkeyDone
            || aButtonId == EWiFiSoftkeyContinue )
            {
            status = KErrNone;
            }
        iActiveRunnerCallback.PinQueryExitL( status );
        return ETrue;
        }
    }
    
    
// --------------------------------------------------------------------------
// CWiFiProtEnterPinDlg::PreLayoutDynInitL()
// --------------------------------------------------------------------------
//
void CWiFiProtEnterPinDlg::PreLayoutDynInitL()
    {
    CAknQueryDialog::PreLayoutDynInitL();
    STATIC_CAST( CEikServAppUi*, 
                CCoeEnv::Static()->AppUi() )->SuppressAppSwitching( ETrue );
    }

// --------------------------------------------------------------------------
// CWiFiProtEnterPinDlg::RemoveCancel
// --------------------------------------------------------------------------
//
void CWiFiProtEnterPinDlg::RemoveCancel()
    {
    CEikButtonGroupContainer& cba = ButtonGroupContainer();
    TRAP_IGNORE( cba.SetCommandL( CEikButtonGroupContainer::ERightSoftkeyPosition,
                     EAknSoftkeyEmpty, KNullDesC) );
    cba.DrawNow();                           
    }

// End of File
