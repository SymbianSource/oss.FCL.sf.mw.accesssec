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
* Description: Implementation of class CWiFiProtSelectNetworkDlg.
*
*/


// INCLUDE FILES
//system includes
#include <uikon/eiksrvui.h>
#include <StringLoader.h>
#include <wifiprotplugin.rsg>
#include <badesca.h>

//user includes
#include "wifiprotselectnetworkdlg.h"
#include "wifiprotdlgsplugin.h"
#include "wifiprotplugin.hrh"
// ========================== MEMBER FUNCTIONS ==============================
//
// --------------------------------------------------------------------------
// CWiFiProtSelectNetworkDlg::CWiFiProtSelectNetworkDlg
// --------------------------------------------------------------------------
//
CWiFiProtSelectNetworkDlg::CWiFiProtSelectNetworkDlg(
                                        TRequestStatus& aStatus ,
                                        TInt& aSelected ,
                                        CDesCArrayFlat* aItems,
                                        CArrayPtr<CGulIcon>* aIcons ):
                                           CAknListQueryDialog( &aSelected ),
                                           iRequestStatus( aStatus ),
                                           iSelected( aSelected ),
                                           iIcons( aIcons ),
                                           iItems( aItems )
    {
    iRequestStatus = KRequestPending;
    }
    
    
// --------------------------------------------------------------------------
// CWiFiProtSelectNetworkDlg::~CWiFiProtSelectNetworkDlg
// --------------------------------------------------------------------------
//
CWiFiProtSelectNetworkDlg::~CWiFiProtSelectNetworkDlg()
    {
  
    STATIC_CAST( CEikServAppUi*, 
                CCoeEnv::Static()->AppUi() )->SuppressAppSwitching( EFalse );
    delete iIcons;
    delete iItems;
    }

// --------------------------------------------------------------------------
// void CSelectDestinationDlg::PrepareAndRunLD
// --------------------------------------------------------------------------
//
void CWiFiProtSelectNetworkDlg::PrepareAndRunLD()
    {
    PrepareLC(R_CONN_LIST_QUERY);
    // Set the description field on the query
    HBufC* desc = StringLoader::LoadLC(
                 R_QTN_NETW_CONSET_WPS_DETAIL_SELECT_NETWORK );
    //ownership transferred                 
    SetItemTextArray( iItems ); 
    iItems = NULL;
    //ownership transferred
    SetIconArrayL( iIcons );
    iIcons = NULL;

    MessageBox()->SetMessageTextL( desc );
    CleanupStack::PopAndDestroy( desc );                
    RunLD();
    }


// --------------------------------------------------------------------------
// CWiFiProtSelectNetworkDlg::OkToExitL
// --------------------------------------------------------------------------
//
TBool CWiFiProtSelectNetworkDlg::OkToExitL( TInt aButtonId )
    {
    TInt status = KErrCancel;
    if ( aButtonId == EAknSoftkeyOk
      || aButtonId == EAknSoftkeyYes
      || aButtonId == EAknSoftkeyDone
      || aButtonId == EAknSoftkeySelect )
        {
        // This should be done automatically
        // I have no idea why iSelected isn't updated
        iSelected = ListBox()->CurrentItemIndex();
        status = KErrNone;
        }
    TRequestStatus* pS = &iRequestStatus;                
    User::RequestComplete( pS, status ); 

    return ETrue;
    }
        
// --------------------------------------------------------------------------
// CWiFiProtSelectNetworkDlg::PreLayoutDynInitL()
// --------------------------------------------------------------------------
//
void CWiFiProtSelectNetworkDlg::PreLayoutDynInitL()
    {
    CAknListQueryDialog::PreLayoutDynInitL();
    STATIC_CAST( CEikServAppUi*, 
                CCoeEnv::Static()->AppUi() )->SuppressAppSwitching( ETrue );
                
    }
    
// --------------------------------------------------------------------------
// void CSelectDestinationDlg::HandleResourceChange
// --------------------------------------------------------------------------
//
void CWiFiProtSelectNetworkDlg::HandleResourceChange( TInt aType )
    {
    if ( aType == KAknsMessageSkinChange )
        {
        CAknListQueryDialog::HandleResourceChange( aType );

        TRAP_IGNORE( SetIconArrayL( iIcons ) );

        SizeChanged();
        }
    else
        {
        if ( aType == KEikDynamicLayoutVariantSwitch )
            {
            TRect mainPaneRect;
            AknLayoutUtils::LayoutMetricsRect( AknLayoutUtils::EMainPane,
                                               mainPaneRect );

            TAknLayoutRect layoutRect;
            layoutRect.LayoutRect( TRect( TPoint( 0, 0 ), 
                                   mainPaneRect.Size() ),
                                   AKN_LAYOUT_WINDOW_list_gen_pane( 0 ) );

            ListBox()->SetRect( layoutRect.Rect() );
            }

        // Base call
        CAknListQueryDialog::HandleResourceChange( aType );
        }
    }    
// End of File
