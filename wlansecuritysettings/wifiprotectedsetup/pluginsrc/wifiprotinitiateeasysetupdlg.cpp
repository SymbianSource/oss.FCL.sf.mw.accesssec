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
* Description: Implementation of class CWiFiProtInitiateEasySetupDlg.
*
*/

/*
* %version: tr1cfwln#10 %
*/

// INCLUDE FILES
//system includes
#include <uikon/eiksrvui.h>
#include <StringLoader.h>
#include <wifiprotplugin.rsg>

//user includes
#include "wifiprotinitiateeasysetupdlg.h"
#include "wifiprotdlgsplugin.h"
#include "wifiprotplugin.hrh"
#include "wifiprotlogger.h"

// ========================= MEMBER FUNCTIONS ===============================
//
// --------------------------------------------------------------------------
// CWiFiProtInitiateEasySetupDlg::CWiFiProtInitiateEasySetupDlg
// --------------------------------------------------------------------------
//
CWiFiProtInitiateEasySetupDlg::CWiFiProtInitiateEasySetupDlg(
                                                   TRequestStatus& aStatus ):
                                     iButtonGroupPreviouslyChanged( EFalse ),
                                     iRequestStatus( aStatus )
    {
    CLOG_ENTERFN(
     "CWiFiProtInitiateEasySetupDlg::CWiFiProtInitiateEasySetupDlg" );
    
    iRequestStatus = KRequestPending;
    
    CLOG_LEAVEFN(
     "CWiFiProtInitiateEasySetupDlg::CWiFiProtInitiateEasySetupDlg" );
    
    }
    
    
// --------------------------------------------------------------------------
// CWiFiProtInitiateEasySetupDlg::~CWiFiProtInitiateEasySetupDlg
// --------------------------------------------------------------------------
//
CWiFiProtInitiateEasySetupDlg::~CWiFiProtInitiateEasySetupDlg()
    {
    CLOG_ENTERFN(
     "CWiFiProtInitiateEasySetupDlg::~CWiFiProtInitiateEasySetupDlg" );
  
    STATIC_CAST( CEikServAppUi*, 
                CCoeEnv::Static()->AppUi() )->SuppressAppSwitching( EFalse );
    CLOG_LEAVEFN(
     "CWiFiProtInitiateEasySetupDlg::~CWiFiProtInitiateEasySetupDlg" );
    
    }


// --------------------------------------------------------------------------
// CWiFiProtInitiateEasySetupDlg::OkToExitL
// --------------------------------------------------------------------------
//
TBool CWiFiProtInitiateEasySetupDlg::OkToExitL( TInt aButtonId )
    {
    CLOG_ENTERFN( "CWiFiProtInitiateEasySetupDlg::OkToExitL" );
    
    TInt status = KErrCancel;
    if ( aButtonId == EAknSoftkeyOk
         || aButtonId == EAknSoftkeyYes
         || aButtonId == EAknSoftkeyDone
         || aButtonId == EWiFiSoftkeyContinue
         || aButtonId == EAknSoftkeySelect )
        {
        status = KErrNone;
        }
    // if aButtonId == EAknSoftkeyView then we have to destroy the dialog
    // afterwards, not from the callback. In this case we do not complete
    // the client, it was completed before, just exit
        
    if ( !(aButtonId == EAknSoftkeyView ))    
        {
        // this is called when we can destroy the dialog
        // and complete the client (activerunner) the same time
        TRequestStatus* pS = &iRequestStatus;                
        User::RequestComplete( pS, status ); 
        }
    CLOG_LEAVEFN( "CWiFiProtInitiateEasySetupDlg::OkToExitL" );
    return ETrue;
    }

    
// --------------------------------------------------------------------------
// CWiFiProtInitiateEasySetupDlg::TryExitL()
// --------------------------------------------------------------------------
//
void CWiFiProtInitiateEasySetupDlg::TryExitL( TInt aButtonId )
    {
    CLOG_ENTERFN( "CWiFiProtInitiateEasySetupDlg::TryExitL" );
    
    CAknMessageQueryDialog::TryExitL( aButtonId );

    CLOG_LEAVEFN( "CWiFiProtInitiateEasySetupDlg::TryExitL" );

    }      
    
// --------------------------------------------------------------------------
// CWiFiProtInitiateEasySetupDlg::PreLayoutDynInitL()
// --------------------------------------------------------------------------
//
void CWiFiProtInitiateEasySetupDlg::PreLayoutDynInitL()
    {
    CLOG_ENTERFN( "CWiFiProtInitiateEasySetupDlg::PreLayoutDynInitL" );
   
    STATIC_CAST( CEikServAppUi*, 
                CCoeEnv::Static()->AppUi() )->SuppressAppSwitching( ETrue );
    CAknMessageQueryDialog::PreLayoutDynInitL();
    
    CLOG_LEAVEFN( "CWiFiProtInitiateEasySetupDlg::PreLayoutDynInitL" );
    
    }

// --------------------------------------------------------------------------
// CConfirmationQuery::OfferKeyEventL()
// --------------------------------------------------------------------------
//
TKeyResponse CWiFiProtInitiateEasySetupDlg::OfferKeyEventL(
                                                 const TKeyEvent& aKeyEvent, 
                                                 TEventCode aModifiers )
    {
    CLOG_ENTERFN( "CWiFiProtInitiateEasySetupDlg::OfferKeyEventL" );
    TKeyResponse answer = EKeyWasNotConsumed;
    TInt code = aKeyEvent.iCode;
    switch ( code )
        {
        // both keys are handled the same way
        // they mean 'movement in the list'
        case EKeyUpArrow: 
        case EKeyDownArrow:
            {
            CAknMessageQueryControl* messageQueryControl = STATIC_CAST( 
                                    CAknMessageQueryControl*, 
                                    Control( EAknMessageQueryContentId ) );
            if ( messageQueryControl )
                {
                answer = messageQueryControl->OfferKeyEventL( 
                                                    aKeyEvent, aModifiers );
                if ( answer == EKeyWasConsumed )
                    {
                    if ( messageQueryControl->LinkHighLighted() ) 
                        {
                        if ( !iButtonGroupPreviouslyChanged )
                            {
                            CEikButtonGroupContainer& cba = 
                                                     ButtonGroupContainer();

                            ButtonGroupContainer().AddCommandSetToStackL( 
                                          R_SOFTKEYS_SELECT_CANCEL__SELECT );
                            cba.UpdateCommandObserverL( 
                              CEikButtonGroupContainer::ELeftSoftkeyPosition,
                                                                     *this );

                            cba.UpdateCommandObserverL( 
                            CEikButtonGroupContainer::EMiddleSoftkeyPosition,
                                                                     *this );

                            cba.DrawNow();
 
                            iButtonGroupPreviouslyChanged = ETrue;
                            }
                        }
                    else if ( iButtonGroupPreviouslyChanged )
                        {                            
                        CEikButtonGroupContainer& cba =
                             ButtonGroupContainer();

                        cba.RemoveCommandObserver( 
                            CEikButtonGroupContainer::ELeftSoftkeyPosition );

                        cba.RemoveCommandObserver( 
                          CEikButtonGroupContainer::EMiddleSoftkeyPosition );

                        cba.RemoveCommandFromStack( 
                            CEikButtonGroupContainer::ELeftSoftkeyPosition,
                            EAknSoftkeyView );

                        cba.RemoveCommandFromStack( 
                            CEikButtonGroupContainer::EMiddleSoftkeyPosition, 
                            EAknSoftkeyView );

                        cba.RemoveCommandFromStack( 
                            CEikButtonGroupContainer::ERightSoftkeyPosition, 
                            EAknSoftkeyNo );

                        cba.DrawNow();

                        iButtonGroupPreviouslyChanged = EFalse;
                        }
                    }
                }
            break;      
            }

        default:
            {
            answer = CAknMessageQueryDialog::OfferKeyEventL( aKeyEvent,
                                                             aModifiers );
            break; 
            }
        }
        
    CLOG_LEAVEFN( "CWiFiProtInitiateEasySetupDlg::OfferKeyEventL" );
        
    return answer;
    }
  
// End of File
