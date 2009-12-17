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
* Description: Implementation of class CWiFiProtConfirmationNoteDlg.
*
*/


// INCLUDE FILES
//system includes
#include <uikon/eiksrvui.h>

//user includes
#include "wifiprotconfirmationnotedlg.h"
#include "wifiprotdlgsplugin.h"
#include "wifiprotplugin.hrh"

// ========================== MEMBER FUNCTIONS ==============================
//
// --------------------------------------------------------------------------
// CWiFiProtConfirmationNoteDlg::CWiFiProtConfirmationNoteDlg
// --------------------------------------------------------------------------
//
CWiFiProtConfirmationNoteDlg::CWiFiProtConfirmationNoteDlg(
                                                   TRequestStatus& aStatus ):
                                                    iRequestStatus( aStatus )
    {
    iRequestStatus = KRequestPending;
    }
    
    
// --------------------------------------------------------------------------
// CWiFiProtConfirmationNoteDlg::~CWiFiProtConfirmationNoteDlg
// --------------------------------------------------------------------------
//
CWiFiProtConfirmationNoteDlg::~CWiFiProtConfirmationNoteDlg()
    {
    STATIC_CAST( CEikServAppUi*, 
                CCoeEnv::Static()->AppUi() )->SuppressAppSwitching( EFalse );
    }

// --------------------------------------------------------------------------
// CWiFiProtInitiateEasySetupDlg::ProcessCommandL()
// --------------------------------------------------------------------------
//    
void CWiFiProtConfirmationNoteDlg::ProcessCommandL( TInt aCommandId )
    {
    switch ( aCommandId )
        {
        case EWiFiSoftkeyContinue: //should use callback but it doesn't work
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
// CWiFiProtConfirmationNoteDlg::OkToExitL
// --------------------------------------------------------------------------
//
TBool CWiFiProtConfirmationNoteDlg::OkToExitL( TInt aButtonId )
    {
    TInt status = KErrCancel;
    if (aButtonId == EAknSoftkeyOk
         || aButtonId == EAknSoftkeyYes
         || aButtonId == EAknSoftkeyDone 
         || aButtonId == EWiFiSoftkeyContinue )
        {
        status = KErrNone;
        }
    else if ( aButtonId == EAknSoftkeyNo )
        {
        status = KErrCancel; // no selected
        }
    else
        {
        status = KErrAbort; // end key pressed
        }
     
    TRequestStatus* pS = &iRequestStatus;                
    User::RequestComplete( pS, status ); 
    return ETrue;
    }
    
    
// --------------------------------------------------------------------------
// CWiFiProtConfirmationNoteDlg::PreLayoutDynInitL()
// --------------------------------------------------------------------------
//
void CWiFiProtConfirmationNoteDlg::PreLayoutDynInitL()
    {
    CAknQueryDialog::PreLayoutDynInitL();
    STATIC_CAST( CEikServAppUi*, 
                CCoeEnv::Static()->AppUi() )->SuppressAppSwitching( ETrue );
    }


// End of File
