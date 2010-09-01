/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description: Implementation of EAP Mschapv2 UI settings dialog
*
*/

/*
* %version: 29 %
*/

// INCLUDE FILES
#include <eikdialg.h>
#include <AknDialog.h>
#include <aknlists.h>
#include "EapMschapv2UiView.h"
#include "EapMschapv2Ui.hrh"
#include <eapmschapv2ui.rsg>
#include <akntextsettingpage.h>
#include <aknsettingitemlist.h>
#include "EapMschapv2UiSettingArray.h"
#include <aknnavide.h>
#include <aknnotewrappers.h> 
#include <EapMsChapV2UiConnection.h>
#include <EapMsChapV2UiDataConnection.h>
#include <EapMsChapV2UiMsChapV2Data.h>

#include <featmgr.h>
#include <hlplch.h>
#include <csxhelp/cp.hlp.hrh>


// CONSTANTS
// UID of general settings app, in which help texts are included
const TUid KHelpUidPlugin = { 0x100058EC };

_LIT( KEmptyString, "" );

static const TInt KEapMsChapv2Id = 26;

// MODULE DATA STRUCTURES
enum 
    {
    EUsernameItem=0,
    EPasswordPromptItem,
    EPasswordItem
    };


// ============================ MEMBER FUNCTIONS ===============================

// -----------------------------------------------------------------------------
// CEapMsChapV2UiDialog::CEapMsChapV2UiDialog
// -----------------------------------------------------------------------------
//
CEapMsChapV2UiDialog::CEapMsChapV2UiDialog( 
                                        CEapMsChapV2UiConnection* aConnection,
								        TInt& aButtonId )
: CAknDialog(),
  iConnection( aConnection ),
  iUiData( 0 ), 
  iDataConnection( 0 ), 
  iSettingArray( 0 ), 
  iSettingListBox( 0 ), 
  iSettingListItemDrawer( 0 ), 
  iPassPrompt( EFalse ),
  iNaviPane( 0 ), 
  iNaviDecorator( 0 ), 
  iPreviousText( 0 ), 
  iButtonId( &aButtonId ),
  iIsUIConstructionCompleted( EFalse )
    {
    }


// --------------------------------------------------z-------
// CEapMsChapV2UiDialog::ConstructAndRunLD
// ---------------------------------------------------------
//
TInt CEapMsChapV2UiDialog::ConstructAndRunLD( TInt aResourceId )
    {
    CleanupStack::PushL( this );

    iSettingArray = CEapMsChapV2SettingItemArray::NewL();

    User::LeaveIfError( iConnection->Connect() );

    iDataConnection = iConnection->GetDataConnection();
    if ( iDataConnection == 0 )
        {
        User::Leave( KErrNoMemory );
        }

    User::LeaveIfError( iDataConnection->Open() );
    User::LeaveIfError( iDataConnection->GetData( &iUiData ) );

    FeatureManager::InitializeLibL();

    ConstructL( R_MSCHAPV2_MENUBAR );
    
    // ExecuteLD will PushL( this ), so we have to Pop it...
    CleanupStack::Pop( this ); // this
    
    return CAknDialog::ExecuteLD( aResourceId );
    }


// -----------------------------------------------------------------------------
// CEapMsChapV2UiDialog::~CEapMsChapV2UiDialog
// -----------------------------------------------------------------------------
//
CEapMsChapV2UiDialog::~CEapMsChapV2UiDialog()
    {
    if ( iNaviDecorator )
        {
        delete iNaviDecorator;
        iNaviDecorator = NULL;
        }

    if ( iSettingArray )
        {
        iSettingArray->Array()->ResetAndDestroy();
        delete iSettingArray;
        }

    if ( iSettingListBox )
        {
        iSettingListBox = 0;
        }

    if ( iSettingListItemDrawer )
        {
        iSettingListItemDrawer = 0;
        }

    if ( iDataConnection )
        {
        iDataConnection->Close();
        delete iDataConnection;
        }

    if ( iConnection )
        {
        iConnection->Close();
        }

    delete iPreviousText;
    
    FeatureManager::UnInitializeLib();
    }


// ---------------------------------------------------------
// CEapMsChapV2UiDialog::HandleListBoxEventL
// ---------------------------------------------------------
//
void CEapMsChapV2UiDialog::HandleListBoxEventL( CEikListBox* /*aListBox*/,
                                                   TListBoxEvent aEventType )
    {
    switch ( aEventType )
        {
        case EEventEnterKeyPressed:
        case EEventItemSingleClicked:
            {
            OkToExitL( EMschapv2UiCmdChange );         
            break;
            }

        case EEventItemActioned:
        case EEventEditingStarted:
        case EEventEditingStopped:
        case EEventPenDownOnItem:
        case EEventItemDraggingActioned:
            {
            break;
            }

        default:
            {
            break;
            };
        };
    }    


// -----------------------------------------------------------------------------
// CEapMsChapV2UiDialog::PreLayoutDynInitL
// -----------------------------------------------------------------------------
//
void CEapMsChapV2UiDialog::PreLayoutDynInitL()
    {
    ChangeTitleL( ETrue );
    
    TUid naviPaneUid;
    naviPaneUid.iUid = EEikStatusPaneUidNavi;
    CEikStatusPane* statusPane = iEikonEnv->AppUiFactory()->StatusPane();
    CEikStatusPaneBase::TPaneCapabilities subPane = 
                                statusPane->PaneCapabilities( naviPaneUid );
    if ( subPane.IsPresent() && subPane.IsAppOwned() )
        {
        iNaviPane = static_cast<CAknNavigationControlContainer*>( 
                                        statusPane->ControlL(naviPaneUid) );
        // Set empty text to hide tabs.
        iNaviDecorator = iNaviPane->CreateNavigationLabelL( KEmptyString );
        iNaviPane->PushL( *iNaviDecorator );
        }            
            
    iSettingListBox = static_cast<CAknSettingStyleListBox*>(
                                    ControlOrNull( EMschapv2SettingsListBox) );
    iSettingListItemDrawer = static_cast<CSettingsListBoxItemDrawer*>( 
                                    iSettingListBox->ItemDrawer() ); 

    iSettingListBox->SetMopParent( this );
    iSettingListBox->CreateScrollBarFrameL( ETrue );
    iSettingListBox->ScrollBarFrame()->SetScrollBarVisibilityL(
                                                CEikScrollBarFrame::EOff,
                                                CEikScrollBarFrame::EAuto );
    iSettingListBox->SetListBoxObserver( this );                                                                                                
    DrawSettingsListL();
    
    iIsUIConstructionCompleted = ETrue;
    }


// -----------------------------------------------------------------------------
// CEapMsChapV2UiDialog::ShowSettingPageL
// -----------------------------------------------------------------------------
//
void CEapMsChapV2UiDialog::ShowSettingPageL( TInt aCalledFromMenu ) 
    {
    TInt index = iSettingListBox->CurrentItemIndex();

    CAknSettingItem* item = iSettingArray->Array()->At( index );
    item->EditItemL( aCalledFromMenu );
    item->StoreL();

    if ( index == EPasswordPromptItem )
        {
        if ( !iPassPrompt )
            *iUiData->GetPasswordPrompt() = EFalse;
        else
            *iUiData->GetPasswordPrompt() = ETrue;
        }

    DrawNow();
    }


// -----------------------------------------------------------------------------
// CEapMsChapV2UiDialog::OkToExitL
// -----------------------------------------------------------------------------
//
TBool CEapMsChapV2UiDialog::OkToExitL( TInt aButtonId )
    {
    TBool ret( EFalse );
    switch ( aButtonId )
        {
        case EEikBidOk:
            {
            if( iIsUIConstructionCompleted )
                {
                if ( iSettingListBox->IsFocused() )
                    {
                    ShowSettingPageL( EFalse );
                    }
                }
            else
                {
                #if defined(_DEBUG) || defined(DEBUG)
				RDebug::Print(_L("CEapMsChapV2UiDialog::OkToExitL - UI not ready - Ignoring key press.\n") );
				#endif
                }
            break;
            }

        case EAknSoftkeyOptions:
            {
            DisplayMenuL();
            break;
            }

        case EAknSoftkeyBack:
        case EAknCmdExit:
            {
            if( iIsUIConstructionCompleted )
                {
                iDataConnection->Update();
                ChangeTitleL( EFalse );
                ret = ETrue;
                }
            break;
            }
        
        case EMschapv2UiCmdChange:
            {
            if( iIsUIConstructionCompleted )
				{
    			ShowSettingPageL( EFalse );
				}
			else
			    {
				#if defined(_DEBUG) || defined(DEBUG)
				RDebug::Print(_L("CEapMsChapV2UiDialog::ProcessCommandL - UI not ready - Ignoring key press.\n") );
				#endif						
			    }
            break;
            }

        default:
            {
            break;
            }
        }

    if ( ret )
        {
        *iButtonId = aButtonId;
        }

    return ret;
    }


// -----------------------------------------------------------------------------
// CEapMsChapV2UiDialog::DrawSettingsListL
// -----------------------------------------------------------------------------
//
void CEapMsChapV2UiDialog::DrawSettingsListL()
    {  
    iSettingArray->Array()->ResetAndDestroy();

    TInt ordinal = 0;
    iSettingArray->AddTextItemL( iUiData->GetUsername(), 
                                EMschapv2SettingPageUserName,
                                R_MSCHAPV2_USERNAME_STRING,
                                R_MSCHAPV2_USERNAME_PAGE,
                                NULL,
                                ordinal++ );
    
    if ( *iUiData->GetPasswordPrompt() )
        {
        iPassPrompt = ETrue;
        }
    else{
        iPassPrompt = EFalse;
        }

    iSettingArray->AddBinarySettingItemL( R_MSCHAPV2_DISPLAY_YESNO_PAGE,
                                          R_MSCHAPV2_PASSPROMPT_STRING, 
                                          R_MSCHAPV2_YESNO_TEXTS,
                                          ordinal++,
                                          iPassPrompt );    

    iSettingArray->AddPasswordItemL( iUiData->GetPassword(), 
                                     EMschapv2SettingPagePassword,
                                     R_MSCHAPV2_PASSWORD_STRING,
                                     R_MSCHAPV2_PASSWORD_PAGE,
                                     NULL,
                                     ordinal++ );


    iSettingListBox->Model()->SetItemTextArray( iSettingArray->Array() );    
    iSettingListBox->Model()->SetOwnershipType( ELbmDoesNotOwnItemArray );
    iSettingArray->Array()->RecalculateVisibleIndicesL();
    iSettingListBox->HandleItemAdditionL();
    iSettingListBox->UpdateScrollBarsL();
    }


// -----------------------------------------------------------------------------
// CEapMsChapV2UiDialog::ChangeTitleL
// -----------------------------------------------------------------------------
//
void CEapMsChapV2UiDialog::ChangeTitleL( TBool aIsStarted )
    {
    TUid titlePaneUid;
    titlePaneUid.iUid = EEikStatusPaneUidTitle;

    CEikStatusPane* statusPane = iEikonEnv->AppUiFactory()->StatusPane();
    CEikStatusPaneBase::TPaneCapabilities subPane = 
                                statusPane->PaneCapabilities( titlePaneUid );
    
    if ( subPane.IsPresent() && subPane.IsAppOwned())
        {
        CAknTitlePane* titlePane = static_cast<CAknTitlePane*>( 
                                        statusPane->ControlL( titlePaneUid ) );
        if ( aIsStarted )
            { 
            // Store previous application title text
            const TDesC* prevText = titlePane->Text();    

            iPreviousText = HBufC::NewL( prevText->Length() );
            iPreviousText->Des().Append( *prevText );

            // EAGN-6QZD6U
            // Loadd different titles for plain MSCHAPv2 and EAP-MSCHAPv2
            TDesC* titleText;
            if( iConnection->GetBearerEAPType() == KEapMsChapv2Id )
                {
                titleText = iEikonEnv->AllocReadResourceLC( 
                                                R_MSCHAPV2_SETTINGS_TITLE );
                }
            else
                {
                titleText = iEikonEnv->AllocReadResourceLC( 
                                                R_PLAIN_MSCHAPV2_SETTINGS_TITLE );
                }
            titlePane->SetTextL( *titleText );
            CleanupStack::PopAndDestroy( titleText ); 
            }
        else
            {
            // Set calling application title text back
            titlePane->SetTextL( *iPreviousText );    
            // pop navidecorator when exiting
            iNaviPane->Pop( iNaviDecorator );    
            }    
        }
    }


// -----------------------------------------------------------------------------
// CEapMsChapV2UiDialog::DynInitMenuPaneL
// -----------------------------------------------------------------------------
//
void CEapMsChapV2UiDialog::DynInitMenuPaneL( TInt aResourceId, 
                                             CEikMenuPane* aMenuPane )
    {
    CAknDialog::DynInitMenuPaneL( aResourceId, aMenuPane );

    if ( aResourceId == R_MSCHAPV2_MENU_PANE )
        {
        if ( aMenuPane && !FeatureManager::FeatureSupported( KFeatureIdHelp ) )
            {
            aMenuPane->DeleteMenuItem( EAknCmdHelp );
            }
        }
    }


// -----------------------------------------------------------------------------
// CEapMsChapV2UiDialog::ProcessCommandL
// -----------------------------------------------------------------------------
//
void CEapMsChapV2UiDialog::ProcessCommandL( TInt aCommand )
    {
    if ( MenuShowing() )
        {
        HideMenu();
        }

    switch( aCommand )
        {
        case EAknCmdExit:
            {
            TryExitL( aCommand );
            break;
            }

        case EAknCmdHelp:
            {
            HlpLauncher::LaunchHelpApplicationL( iEikonEnv->WsSession(),
                                    iEikonEnv->EikAppUi()->AppHelpContextL() );
            break;
            }

        case EMschapv2UiCmdChange:
            {
            if( iIsUIConstructionCompleted )
				{
    			ShowSettingPageL( ETrue );
				}
			else
			    {
				#if defined(_DEBUG) || defined(DEBUG)
				RDebug::Print(_L("CEapMsChapV2UiDialog::ProcessCommandL - UI not ready - Ignoring key press.\n") );
				#endif						
			    }
            break;
            }

        default:
            {
            break;
            }
        }
    }


// -----------------------------------------------------------------------------
// CEapMsChapV2UiDialog::GetHelpContext
// -----------------------------------------------------------------------------
//
void CEapMsChapV2UiDialog::GetHelpContext( TCoeHelpContext& aContext ) const
    {
    aContext.iMajor = KHelpUidPlugin;
    if( iConnection->GetBearerEAPType() == KEapMsChapv2Id )
        {
        aContext.iContext = KSET_HLP_WLAN_EAP_MSCHAPV2;
        }
    else
        {
        aContext.iContext = KSET_HLP_WLAN_EAP_PLAIN_MSCHAP;
        }
    }
    

//  End of File
