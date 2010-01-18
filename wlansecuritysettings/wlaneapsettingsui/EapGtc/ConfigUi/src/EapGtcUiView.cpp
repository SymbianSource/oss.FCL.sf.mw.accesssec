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
* Description: Implementation of EAP GTC UI settings dialog
*
*/

/*
* %version: 27 %
*/

// INCLUDE FILES
#include <eikdialg.h>
#include <AknDialog.h>
#include <aknlists.h>
#include <EapGtcUi.rsg>
#include <akntextsettingpage.h>
#include <aknsettingitemlist.h>
#include <aknnavide.h>
#include <aknnotewrappers.h> // TEMPORARY, for info message...
#include <EapGtcUiConnection.h>
#include <EapGtcUiDataConnection.h>
#include <EapGtcUiGtcData.h>

#include "EapGtcUiView.h"
#include "EapGtcUi.hrh"
#include "EapGtcUiSettingArray.h"

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
    EUsernameItem = 0
    };


// ============================ MEMBER FUNCTIONS ===============================

// -----------------------------------------------------------------------------
// CEapGtcUiDialog::CEapGtcUiDialog
// -----------------------------------------------------------------------------
//
CEapGtcUiDialog::CEapGtcUiDialog( CEapGtcUiConnection* aConnection, 
								  TInt& aButtonId ) 
: CAknDialog(),
  iConnection( aConnection ),
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
// CEapGtcUiDialog::ConstructAndRunLD
// ---------------------------------------------------------
//
TInt CEapGtcUiDialog::ConstructAndRunLD( TInt aResourceId )
    {
    CleanupStack::PushL( this );
    iSettingArray = CEapGtcSettingItemArray::NewL();

    User::LeaveIfError( iConnection->Connect() );

    iDataConnection = iConnection->GetDataConnection();
    if ( iDataConnection == 0 )
        {
        User::Leave( KErrNoMemory );
        }
    User::LeaveIfError( iDataConnection->Open() );
    User::LeaveIfError( iDataConnection->GetData( &iUiData ) );

    FeatureManager::InitializeLibL();

    ConstructL( R_GTC_MENUBAR );
    
    // ExecuteLD will PushL( this ), so we have to Pop it...
    CleanupStack::Pop( this ); // this
    
    return CAknDialog::ExecuteLD( aResourceId );
    }


// -----------------------------------------------------------------------------
// CEapGtcUiDialog::~CEapGtcUiDialog
// -----------------------------------------------------------------------------
//
CEapGtcUiDialog::~CEapGtcUiDialog()
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
// CEapGtcUiDialog::HandleListBoxEventL
// ---------------------------------------------------------
//
void CEapGtcUiDialog::HandleListBoxEventL( CEikListBox* /*aListBox*/,
                                                   TListBoxEvent aEventType )
    {
    switch ( aEventType )
        {
        case EEventEnterKeyPressed:
        case EEventItemSingleClicked:
            {
            OkToExitL( EGtcUiCmdChange );         
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
// CEapGtcUiDialog::PreLayoutDynInitL
// -----------------------------------------------------------------------------
//
void CEapGtcUiDialog::PreLayoutDynInitL()
    {
    TUid naviPaneUid;
    naviPaneUid.iUid = EEikStatusPaneUidNavi;
    CEikStatusPane* statusPane = iEikonEnv->AppUiFactory()->StatusPane();
    CEikStatusPaneBase::TPaneCapabilities subPane = 
                                statusPane->PaneCapabilities( naviPaneUid );

    if ( subPane.IsPresent() && subPane.IsAppOwned() )
        {
        iNaviPane = static_cast<CAknNavigationControlContainer*>( 
                                        statusPane->ControlL( naviPaneUid ) );

        // Set empty text to hide tabs.
        iNaviDecorator = iNaviPane->CreateNavigationLabelL( KEmptyString );   
        iNaviPane->PushL( *iNaviDecorator );
        }

    // Change title
    ChangeTitleL( ETrue );

    iSettingListBox = static_cast<CAknSettingStyleListBox*>( 
                                        ControlOrNull( EGtcSettingsListBox ) );
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
// CEapGtcUiDialog::ShowSettingPageL
// -----------------------------------------------------------------------------
//
void CEapGtcUiDialog::ShowSettingPageL( TInt aCalledFromMenu ) 
    {
    TInt index = iSettingListBox->CurrentItemIndex();
    CAknSettingItem* item = iSettingArray->Array()->At( index );
    item->EditItemL( aCalledFromMenu );
    item->StoreL();
    DrawSettingsListL();
    }


// -----------------------------------------------------------------------------
// CEapGtcUiDialog::OkToExitL
// -----------------------------------------------------------------------------
//
TBool CEapGtcUiDialog::OkToExitL( TInt aButtonId )
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
				RDebug::Print(_L("CEapGtcUiDialog::OkToExitL - UI not ready - Ignoring key press.\n") );
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
            
        case EGtcUiCmdChange:
            {
            if( iIsUIConstructionCompleted )
				{
    			ShowSettingPageL( EFalse );
				}
			else
			    {
				#if defined(_DEBUG) || defined(DEBUG)
				RDebug::Print(_L("CEapGtcUiDialog::ProcessCommandL - UI not ready - Ignoring key press.\n") );
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
// CEapGtcUiDialog::DrawSettingsListL
// -----------------------------------------------------------------------------
//
void CEapGtcUiDialog::DrawSettingsListL()
    {  
    iSettingArray->Array()->ResetAndDestroy();
    TInt ordinal = 0;
    iSettingArray->AddTextItemL( iUiData->GetIdentity(),
                                EGtcSettingPageUsername,
                                R_GTC_USERNAME_STRING,
                                R_GTC_USERNAME_PAGE,
                                NULL,
                                ordinal++ );

    iSettingListBox->Model()->SetItemTextArray( iSettingArray->Array() );    
    iSettingListBox->Model()->SetOwnershipType( ELbmDoesNotOwnItemArray );
    iSettingArray->Array()->RecalculateVisibleIndicesL();
    iSettingListBox->HandleItemAdditionL();
    iSettingListBox->UpdateScrollBarsL();
    }


// -----------------------------------------------------------------------------
// CEapGtcUiDialog::ChangeTitleL
// -----------------------------------------------------------------------------
//
void CEapGtcUiDialog::ChangeTitleL( TBool aIsStarted )
    {
    TUid titlePaneUid;
    titlePaneUid.iUid = EEikStatusPaneUidTitle;

    CEikStatusPane* statusPane = iEikonEnv->AppUiFactory()->StatusPane();
    CEikStatusPaneBase::TPaneCapabilities subPane = 
                                statusPane->PaneCapabilities( titlePaneUid );

    if (subPane.IsPresent()&&subPane.IsAppOwned())
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
                                                        R_GTC_SETTINGS_TITLE );
            titlePane->SetTextL( *titleText );
            CleanupStack::PopAndDestroy( titleText ); 
            }
        else
            {
            // Set calling application title text back
            titlePane->SetTextL( *iPreviousText );  
            iNaviPane->Pop( iNaviDecorator );
            }
        }
    }


// -----------------------------------------------------------------------------
// CEapGtcUiDialog::DynInitMenuPaneL
// -----------------------------------------------------------------------------
//
void CEapGtcUiDialog::DynInitMenuPaneL( TInt aResourceId, 
                                         CEikMenuPane* aMenuPane )
    {
    CAknDialog::DynInitMenuPaneL( aResourceId, aMenuPane );

    if ( aResourceId == R_GTC_MENU_PANE )
        {
        if ( aMenuPane && !FeatureManager::FeatureSupported( KFeatureIdHelp ) )
            {
            aMenuPane->DeleteMenuItem( EAknCmdHelp );
            }
        }
    }


// -----------------------------------------------------------------------------
// CEapGtcUiDialog::ProcessCommandL
// -----------------------------------------------------------------------------
//
void CEapGtcUiDialog::ProcessCommandL( TInt aCommand )
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

        case EGtcUiCmdChange:
            {
            if( iIsUIConstructionCompleted )
				{
    			ShowSettingPageL( ETrue );
				}
			else
			    {
				#if defined(_DEBUG) || defined(DEBUG)
				RDebug::Print(_L("CEapGtcUiDialog::ProcessCommandL - UI not ready - Ignoring key press.\n") );
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
// CEapGtcUiDialog::GetHelpContext
// -----------------------------------------------------------------------------
//
void CEapGtcUiDialog::GetHelpContext( TCoeHelpContext& aContext ) const
    {
    aContext.iMajor = KHelpUidPlugin;
    aContext.iContext = KSET_HLP_WLAN_EAP_GTC;
    }


//  End of File
