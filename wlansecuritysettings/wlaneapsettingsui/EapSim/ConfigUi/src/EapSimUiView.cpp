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
* Description: Implementation of EAP SIM UI settings dialog
*
*/



// INCLUDE FILES
#include <eikdialg.h>
#include <AknDialog.h>
#include <aknlists.h>
#include "EapSimUiView.h"
#include "EapSimUi.hrh"
#include <EapSimUi.rsg>
#include <akntextsettingpage.h>
#include <aknsettingitemlist.h>
#include "EapSimUiSettingArray.h"
#include <aknnotewrappers.h> // For info message
#include <aknnavide.h>
#include <EapSimUiConnection.h>
#include <EapSimUiDataConnection.h>
#include <EapSimUiSimData.h>

#include <FeatMgr.h>
#include <hlplch.h>
#include <csxhelp/cp.hlp.hrh>


// CONSTANTS
// UID of general settings app, in which help texts are included
const TUid KHelpUidPlugin = { 0x100058EC };

_LIT( KEmptyString, "" );

// MODULE DATA STRUCTURES
enum 
    {
    EUsernameInUseItem = 0,
    EUsernameItem,
    ERealmInUseItem,
    ERealmItem
    };


// ============================ MEMBER FUNCTIONS ===============================

// -----------------------------------------------------------------------------
// CEapSimUiDialog::CEapSimUiDialog
// -----------------------------------------------------------------------------
//
CEapSimUiDialog::CEapSimUiDialog( CEapSimUiConnection* aConnection, 
								  TInt& aButtonId ) 
: CAknDialog(),
  iConnection( aConnection ),
  iUiData( 0 ), 
  iDataConnection( 0 ), 
  iSettingArray( 0 ), 
  iSettingListBox( 0 ), 
  iSettingListItemDrawer( 0 ), 
  iNaviPane( 0 ), 
  iNaviDecorator( 0 ), 
  iPreviousText( 0 ), 
  iButtonId( &aButtonId ),
  iIsUIConstructionCompleted( EFalse )
    {
    }


// ---------------------------------------------------------
// CEapSimUiDialog::ConstructAndRunLD
// ---------------------------------------------------------
//
TInt CEapSimUiDialog::ConstructAndRunLD( TInt aResourceId )
    {
    CleanupStack::PushL( this );

    iSettingArray = CEapSimSettingItemArray::NewL();

    User::LeaveIfError( iConnection->Connect() );
    iDataConnection = iConnection->GetDataConnection();
    if ( iDataConnection == 0 )
        {
        User::Leave( KErrNoMemory );
        }

    User::LeaveIfError( iDataConnection->Open() );
    User::LeaveIfError( iDataConnection->GetData( &iUiData ) );

    FeatureManager::InitializeLibL();
    
    ConstructL( R_SIM_MENUBAR );
    
    // ExecuteLD will PushL( this ), so we have to Pop it...
    CleanupStack::Pop( this ); // this
    
    return CAknDialog::ExecuteLD( aResourceId );
    }


// -----------------------------------------------------------------------------
// CEapSimUiDialog::~CEapSimUiDialog
// -----------------------------------------------------------------------------
//
CEapSimUiDialog::~CEapSimUiDialog()
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
// CEapSimUiDialog::HandleListBoxEventL
// ---------------------------------------------------------
//
void CEapSimUiDialog::HandleListBoxEventL( CEikListBox* /*aListBox*/,
                                                   TListBoxEvent aEventType )
    {
    switch ( aEventType )
        {
        case EEventEnterKeyPressed:
        case EEventItemSingleClicked:
            {
            OkToExitL( ESimUiCmdChange );         
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
// CEapSimUiDialog::PreLayoutDynInitL
// -----------------------------------------------------------------------------
//
void CEapSimUiDialog::PreLayoutDynInitL()
    {
    ChangeTitleL( ETrue );
    
    TUid naviPaneUid;
    naviPaneUid.iUid = EEikStatusPaneUidNavi;
    CEikStatusPane* statusPane = iEikonEnv->AppUiFactory()->StatusPane();
    CEikStatusPaneBase::TPaneCapabilities subPane = 
                                statusPane->PaneCapabilities( naviPaneUid );
    if ( subPane.IsPresent()&&subPane.IsAppOwned() )
        {
        iNaviPane = static_cast<CAknNavigationControlContainer*>( 
                                        statusPane->ControlL( naviPaneUid ) );

        // Set empty text to hide tabs.
        iNaviDecorator = iNaviPane->CreateNavigationLabelL( KEmptyString );
        iNaviPane->PushL( *iNaviDecorator );
        }            
        
    iSettingListBox = static_cast<CAknSettingStyleListBox*>( 
                                        ControlOrNull( ESimSettingsListBox ) );
    iSettingListItemDrawer=static_cast<CSettingsListBoxItemDrawer*>( 
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
// CEapSimUiDialog::ShowSettingPageL
// -----------------------------------------------------------------------------
//
void CEapSimUiDialog::ShowSettingPageL( TInt aCalledFromMenu ) 
    {
    TInt index = iSettingListBox->CurrentItemIndex();
    CAknSettingItem* item = iSettingArray->Array()->At( index );
    item->EditItemL( aCalledFromMenu );
    item->StoreL();
    DrawNow();
    }


// -----------------------------------------------------------------------------
// CEapSimUiDialog::OkToExitL
// -----------------------------------------------------------------------------
//
TBool CEapSimUiDialog::OkToExitL( TInt aButtonId )
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
				RDebug::Print(_L("CEapSimUiDialog::OkToExitL - UI not ready - Ignoring key press.\n") );
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
        
        case ESimUiCmdChange:
            {
            if( iIsUIConstructionCompleted )
				{
    			ShowSettingPageL( EFalse );
				}
			else
			    {
				#if defined(_DEBUG) || defined(DEBUG)
				RDebug::Print(_L("CEapSimUiDialog::ProcessCommandL - UI not ready - Ignoring key press.\n") );
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
// CEapSimUiDialog::DrawSettingsListL
// -----------------------------------------------------------------------------
//
void CEapSimUiDialog::DrawSettingsListL()
    {  
    iSettingArray->Array()->ResetAndDestroy();
    TInt ordinal = 0;
    iSettingArray->AddBinarySettingItemL( R_SIM_DISPLAY_AUTOUSECONF_PAGE,
                                          R_SIM_USERNAME_INUSESTRING, 
                                          R_SIM_USERNAME_AUTOUSECONF_TEXTS,
                                          ordinal++,
                                          *iUiData->GetUseManualUsername() );

    iSettingArray->AddTextItemL( iUiData->GetManualUsername(),
                                 ESimSettingPageUsername,
                                 R_SIM_USERNAME_STRING,
                                 R_SIM_USERNAME_PAGE,
                                 NULL,
                                 ordinal++ );

    iSettingArray->AddBinarySettingItemL( R_SIM_DISPLAY_AUTOUSECONF_PAGE,
                                          R_SIM_REALM_INUSESTRING, 
                                          R_SIM_REALM_AUTOUSECONF_TEXTS,
                                          ordinal++,
                                          *iUiData->GetUseManualRealm() );

    iSettingArray->AddTextItemL( iUiData->GetManualRealm(),
                                 ESimSettingUsernameSettingId,
                                 R_SIM_REALM_STRING,
                                 R_SIM_REALM_PAGE,
                                 NULL,
                                 ordinal++ );

    iSettingListBox->Model()->SetItemTextArray( iSettingArray->Array() );
    iSettingListBox->Model()->SetOwnershipType( ELbmDoesNotOwnItemArray );
    iSettingArray->Array()->RecalculateVisibleIndicesL();
    iSettingListBox->HandleItemAdditionL();
    iSettingListBox->UpdateScrollBarsL();
    }


// -----------------------------------------------------------------------------
// CEapSimUiDialog::ChangeTitleL
// -----------------------------------------------------------------------------
//
void CEapSimUiDialog::ChangeTitleL( TBool aIsStarted )
    {
    TUid titlePaneUid;
    titlePaneUid.iUid = EEikStatusPaneUidTitle;

    CEikStatusPane* statusPane = iEikonEnv->AppUiFactory()->StatusPane();
    CEikStatusPaneBase::TPaneCapabilities subPane = 
                                statusPane->PaneCapabilities( titlePaneUid );
    
    if ( subPane.IsPresent() && subPane.IsAppOwned() )
        {
        CAknTitlePane* titlePane = static_cast<CAknTitlePane*>( 
                                        statusPane->ControlL( titlePaneUid ) );
        if ( aIsStarted )
            {
            // Store previous application title text
            const TDesC* prevText = titlePane->Text();    

            iPreviousText = HBufC::NewL( prevText->Length() );
            iPreviousText->Des().Append( *prevText );
            TDesC* titleText = iEikonEnv->AllocReadResourceLC( 
                                                        R_SIM_SETTINGS_TITLE );
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
// CEapSimUiDialog::DynInitMenuPaneL
// -----------------------------------------------------------------------------
//
void CEapSimUiDialog::DynInitMenuPaneL( TInt aResourceId, 
                                         CEikMenuPane* aMenuPane )
    {
    CAknDialog::DynInitMenuPaneL( aResourceId, aMenuPane );

    if ( aResourceId == R_SIM_MENU_PANE )
        {
        if ( aMenuPane && !FeatureManager::FeatureSupported( KFeatureIdHelp ) )
            {
            aMenuPane->DeleteMenuItem( EAknCmdHelp );
            }
        }
    }


// -----------------------------------------------------------------------------
// CEapSimUiDialog::ProcessCommandL
// -----------------------------------------------------------------------------
//
void CEapSimUiDialog::ProcessCommandL( TInt aCommand )
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

        case ESimUiCmdChange:
            {
            if( iIsUIConstructionCompleted )
				{
    			ShowSettingPageL( ETrue );
				}
			else
			    {
				#if defined(_DEBUG) || defined(DEBUG)
				RDebug::Print(_L("CEapSimUiDialog::ProcessCommandL - UI not ready - Ignoring key press.\n") );
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
// CEapSimUiDialog::GetHelpContext
// -----------------------------------------------------------------------------
//
void CEapSimUiDialog::GetHelpContext( TCoeHelpContext& aContext ) const
    {
    aContext.iMajor = KHelpUidPlugin;
    aContext.iContext = KSET_HLP_WLAN_EAP_SIM;
    }
    

//  End of File
