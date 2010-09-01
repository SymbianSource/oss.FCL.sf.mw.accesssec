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
* Description: Implementation of PAP UI settings dialog
*
*/

/*
* %version: 13 %
*/

// INCLUDE FILES
#include "papuiview.h"
#include "papuisettingarray.h"
#include "papuipwsettingitem.h"
#include "papui.hrh"
#include <papui.rsg>
#include <eikdialg.h>
#include <AknDialog.h>
#include <aknlists.h>
#include <akntextsettingpage.h>
#include <aknsettingitemlist.h>
#include <aknnavi.h>
#include <aknnavide.h>
#include <aknnotewrappers.h>
#include <StringLoader.h>
#include <EapTlsPeapUiConnection.h>
#include <EapTlsPeapUiDataConnection.h>
#include <EapTlsPeapUiTlsPeapData.h>
#include <featmgr.h>
#include <hlplch.h>
#include <csxhelp/cp.hlp.hrh>


// CONSTANTS
// UID of general settings app, in which help texts are included
const TUid KHelpUidPlugin = { 0x100058EC };
 
// MODULE DATA STRUCTURES
enum TSettingIds
    {
    EUsernameItem=0,
    EPasswordPromptItem,
    EPasswordItem
    };


// ============================ MEMBER FUNCTIONS ===============================

// -----------------------------------------------------------------------------
// CPapUiDialog::CPapUiDialog
// -----------------------------------------------------------------------------
//
CPapUiDialog::CPapUiDialog( CEapTlsPeapUiConnection* aConnection, 
                              TInt& aButtonId ) 
: CAknDialog(),
  iConnection( aConnection ),
  iNaviPane( 0 ), 
  iNaviDecorator( 0 ),   
  iButtonId( &aButtonId ),
  iSettingPwPrompt( ETrue ),
  iIsUIConstructionCompleted( EFalse ),
  iUsernameCancelled( EFalse )
    {    
    }


// ---------------------------------------------------------
// CPapUiDialog::ConstructAndRunLD
// ---------------------------------------------------------
//
TInt CPapUiDialog::ConstructAndRunLD( TInt aResourceId )
    {
    CleanupStack::PushL( this );

    iSettingArray = CPapSettingItemArray::NewL();
    
    User::LeaveIfError( iConnection->Connect() );

    // Basic data
    iDataConnection = iConnection->GetDataConnection();
    if ( iDataConnection == 0 )
        {
        User::Leave( KErrNoMemory );
        }
    User::LeaveIfError( iDataConnection->Open() );
    User::LeaveIfError( iDataConnection->GetData( &iUiData ) );
        
    //Copy the eapol UI data to the temporary data shown on the setting UI
    iSettingUsername.Copy( iUiData->GetPapUserName() );
    iSettingPwPrompt = *( iUiData->GetPapPasswordPrompt() );
    iSettingPassword.Copy( iUiData->GetPapPassword() );    

    #if defined(_DEBUG) || defined(DEBUG)    
    RDebug::Print(_L("When read from eapol, iSettingUsername = %S"), &iSettingUsername );
    RDebug::Print(_L("When read from eapol, iSettingPwPrompt = %d"), iSettingPwPrompt );
    RDebug::Print(_L("When read from eapol, iSettingPassword = %S"), &iSettingPassword );
    #endif    
    
    FeatureManager::InitializeLibL();
    
    ConstructL( R_PAP_MENUBAR );
    
    // ExecuteLD will PushL( this ), so we have to Pop it first...
    CleanupStack::Pop( this );
    
    return CAknDialog::ExecuteLD( aResourceId );
    }
    

// -----------------------------------------------------------------------------
// CPapUiDialog::~CPapUiDialog
// -----------------------------------------------------------------------------
//
CPapUiDialog::~CPapUiDialog()
    {

    delete iNaviDecorator;
            
    if ( iSettingArray )
        {
        iSettingArray->Array()->ResetAndDestroy();
        delete iSettingArray;
        }

    iSettingListBox = NULL;

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
// CPapUiDialog::HandleListBoxEventL
// ---------------------------------------------------------
//
void CPapUiDialog::HandleListBoxEventL( CEikListBox* /*aListBox*/,
                                                   TListBoxEvent aEventType )
    {
    switch ( aEventType )
        {
        case EEventEnterKeyPressed:
        case EEventItemSingleClicked:
            {
            OkToExitL( EPapUiCmdChange );         
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
// CPapUiDialog::PreLayoutDynInitL
// -----------------------------------------------------------------------------
//
void CPapUiDialog::PreLayoutDynInitL()
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
        iNaviDecorator = iNaviPane->CreateNavigationLabelL( KNullDesC );
        iNaviPane->PushL( *iNaviDecorator );
        }           

    
    // Initialize setting page 
    iSettingListBox = static_cast<CAknSettingStyleListBox*>( 
                                    ControlOrNull( EPapSettingsListBox ) );
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
// CPapUiDialog::ChangeTitleL
// -----------------------------------------------------------------------------
//
void CPapUiDialog::ChangeTitleL( TBool aIsStarted )
    {
    TUid titlePaneUid;
    titlePaneUid.iUid = EEikStatusPaneUidTitle;

    CEikStatusPane* statusPane = iEikonEnv->AppUiFactory()->StatusPane();
    CEikStatusPaneBase::TPaneCapabilities subPane = 
                                statusPane->PaneCapabilities( titlePaneUid );
    
    if ( subPane.IsPresent() && subPane.IsAppOwned() )
        {
        CAknTitlePane* titlePane = static_cast<CAknTitlePane*>(
                                        statusPane->ControlL( titlePaneUid) );
        if ( aIsStarted )
            {
            // Store previous application title text
            const TDesC* prevText = titlePane->Text();    
            iPreviousText = HBufC::NewL( prevText->Length() );
            iPreviousText->Des().Append( *prevText );
            TDesC* titleText = iEikonEnv->AllocReadResourceLC( 
                                                    R_PAP_SETTINGS_TITLE );
            titlePane->SetTextL( *titleText );
            CleanupStack::PopAndDestroy( titleText ); 
            }
        else
            {
            // Set calling application title text back
            titlePane->SetTextL( *iPreviousText );    
            }    
        }
    }


// -----------------------------------------------------------------------------
// CPapUiDialog::OkToExitL
// -----------------------------------------------------------------------------
//
TBool CPapUiDialog::OkToExitL( TInt aButtonId )
    {
    #if defined(_DEBUG) || defined(DEBUG)
    RDebug::Print(_L("CPapUiDialog::OkToExitL") );
    #endif   
    
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
				RDebug::Print(_L("CPapUiDialog::OkToExitL - UI not ready - Ignoring key press.\n") );
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
            UpdateEapolData();
            ChangeTitleL( EFalse );
            ret = ETrue;
            break;
            }
        
        case EPapUiCmdChange:
            {
            if( iIsUIConstructionCompleted )
    			{
        		ShowSettingPageL( EFalse );
    			}
    	    else
    			{
    			#if defined(_DEBUG) || defined(DEBUG)
    			RDebug::Print(_L("CPapUiDialog::ProcessCommandL - UI not ready - Ignoring key press.\n") );
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
// CPapUiDialog::DrawSettingsListL
// -----------------------------------------------------------------------------
//
void CPapUiDialog::DrawSettingsListL()
    {
    iSettingArray->Array()->ResetAndDestroy();
    TInt ordinal = 0;
    
    // ---------------------------------------------------------------
    // Username setting item. If the username has never been set,
    // shows "(not defined)", otherwise shows the username.
    iSettingArray->AddTextItemL( iSettingUsername,
                                 EPapSettingPageUserName,
                                 R_PAP_USERNAME_SETTING_TITLE,
                                 R_PAP_USERNAME_PAGE,
                                 NULL,
                                 ordinal++ );
                                 
    // ---------------------------------------------------------------
    // Password prompt setting item. Radio buttons Prompt/User defined.                                
    iSettingArray->AddBinarySettingItemL( R_PAP_PASSWORD_POPUP_PAGE,
                                          R_PAP_PASSWORD_SETTING_TITLE, 
                                          R_PAP_PASSWORD_PROMPT_CHOICES,
                                          ordinal++,
                                          iSettingPwPrompt );
                                          
    // ---------------------------------------------------------------
    // Password setting item. Never visible in the setting list, but the
    // setting page opens when the user selects "User defined" in the
    // password prompt setting item.
    iSettingArray->AddPasswordItemL( iSettingPassword,
                                 EPapSettingPagePassword,
                                 R_PAP_PASSWORD_SETTING_TITLE,
                                 R_PAP_PASSWORD_SETTING_PAGE,
                                 NULL,
                                 ordinal++ );
                                 
    // Set the last item hidden
    CAknSettingItem* item = iSettingArray->Array()->At( EPasswordItem );
    item->SetHidden( ETrue );
                           
                                                                                                           
    iSettingListBox->Model()->SetItemTextArray( iSettingArray->Array() );    
    iSettingListBox->Model()->SetOwnershipType( ELbmDoesNotOwnItemArray );
    iSettingArray->Array()->RecalculateVisibleIndicesL();
    iSettingListBox->HandleItemAdditionL();
    iSettingListBox->UpdateScrollBarsL();
    }


// -----------------------------------------------------------------------------
// CPapUiDialog::DynInitMenuPaneL
// -----------------------------------------------------------------------------
//
void CPapUiDialog::DynInitMenuPaneL( TInt aResourceId, 
                                         CEikMenuPane* aMenuPane )
    {
    CAknDialog::DynInitMenuPaneL( aResourceId, aMenuPane );

    if ( aResourceId == R_PAP_MENU_PANE )
        {
        if ( aMenuPane && !FeatureManager::FeatureSupported( KFeatureIdHelp ) )
            {
            aMenuPane->DeleteMenuItem( EAknCmdHelp );
            }

        }
    }

// -----------------------------------------------------------------------------
// CPapUiDialog::UpdateEapolData
// -----------------------------------------------------------------------------
//
void CPapUiDialog::UpdateEapolData()
    {
    #if defined(_DEBUG) || defined(DEBUG)
    RDebug::Print(_L("CPapUiDialog::UpdateEapolData") );    
    RDebug::Print(_L("Saving username: %S"), &iSettingUsername );
    RDebug::Print(_L("Saving pwprompt: %d"), iSettingPwPrompt );
    RDebug::Print(_L("Saving password: %S"), &iSettingPassword );    
    #endif
        
    // username
    if ( iSettingUsername.Length() )
        {
        ( iUiData->GetPapUserName() ).Copy( iSettingUsername );
        }
    
        
    // pwprompt
    *( iUiData->GetPapPasswordPrompt() ) = iSettingPwPrompt;
       
    // password
    ( iUiData->GetPapPassword() ).Copy( iSettingPassword );
        
    iDataConnection->Update();
    }


// -----------------------------------------------------------------------------
// CPapUiDialog::ProcessCommandL
// -----------------------------------------------------------------------------
//
void CPapUiDialog::ProcessCommandL( TInt aCommand )
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

        case EPapUiCmdChange:
            {
            if( iIsUIConstructionCompleted )
    			{
        		ShowSettingPageL( ETrue );
    			}
    		else
    			{
    		    #if defined(_DEBUG) || defined(DEBUG)
    			RDebug::Print(_L("CPapUiDialog::ProcessCommandL - UI not ready - Ignoring key press.\n") );
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
// CPapUiDialog::ShowSettingPageL
// -----------------------------------------------------------------------------
//
void CPapUiDialog::ShowSettingPageL( TInt aCalledFromMenu ) 
    {
    #if defined(_DEBUG) || defined(DEBUG)
    RDebug::Print(_L("CPapUiDialog::ShowSettingPageL") );
    #endif    
    
    TInt index = iSettingListBox->CurrentItemIndex();
    
    if ( index == EUsernameItem )
        {
        ShowUsernameSettingPageL();
        }
    
    else if ( index == EPasswordPromptItem )
        {
        // The previous value is needed for comparison,
        // after the user has done the editing
        TBool oldChoice = iSettingPwPrompt;
        
        // Show the radio button page and let the user edit
        CAknSettingItem* item = iSettingArray->Array()->At( index );
        item->EditItemL( aCalledFromMenu );
        item->StoreL();
        
        // Check the new value
        TBool newChoice = iSettingPwPrompt;
        
        // Prompt -> User defined
        if ( oldChoice && !newChoice )
            {
            // Ask to set a password
            ShowPasswordSettingPageL();
            
            // If the password item was cancelled,
            // or if username was prompted and cancelled,
            // restore "Prompt" for the password prompt setting
            if ( iSettingArray->IsPwItemCancelled() || iUsernameCancelled )
                {
                // Toggle the setting back to Prompt without showing the page
                item->EditItemL( EFalse );
                item->StoreL();
                }
            }
        
        // User defined -> User defined        
        else if ( !oldChoice && !newChoice )
           {
           // Ask to set a new password
           ShowPasswordSettingPageL();
           }
        
        // Prompt -> Prompt
        else if ( oldChoice && newChoice )
            {
            // Do nothing
            }

        // User defined -> Prompt       
        else if ( !oldChoice && newChoice )
            {
            // Remove the password
            CPapUiPwSettingItem* pwItem =
                static_cast< CPapUiPwSettingItem* >(
                    iSettingArray->Array()->At( EPasswordItem ) );
            pwItem->DeletePasswordL();
            
            }
            
        else
            {
            // It shouldn't be possible to end up here
            }
        
        }
        
    else
        {
        // shouldn't end up here
        }                

    DrawNow();
    }
    
// -----------------------------------------------------------------------------
// CPapUiDialog::ShowUsernameSettingPageL
// -----------------------------------------------------------------------------
//
void CPapUiDialog::ShowUsernameSettingPageL() 
    {
    #if defined(_DEBUG) || defined(DEBUG)
    RDebug::Print(_L("CPapUiDialog::ShowUsernameSettingPageL") );
    #endif
    
    iUsernameCancelled = EFalse;
    
    CAknSettingItem* item = iSettingArray->Array()->At( EUsernameItem );
    item->EditItemL( EFalse );
    item->StoreL(); 
    }

// -----------------------------------------------------------------------------
// CPapUiDialog::ShowPasswordSettingPageL
// -----------------------------------------------------------------------------
//
void CPapUiDialog::ShowPasswordSettingPageL() 
    {
    #if defined(_DEBUG) || defined(DEBUG)
    RDebug::Print(_L("CPapUiDialog::ShowPasswordSettingPageL") );
    #endif  
    
    CAknSettingItem* item = iSettingArray->Array()->At( EPasswordItem );
    
    item->EditItemL( EFalse );
    item->StoreL();
    DrawNow();

    // If password is set, then username must also be defined    
    if ( !iSettingUsername.Length() && !iSettingArray->IsPwItemCancelled() )
        {
        // Show an info note about missing username
        HBufC* message = NULL;
        message = StringLoader::LoadLC( R_PAP_DEFINE_USERNAME_INFO_NOTE );
 	    CAknInformationNote* note = new( ELeave ) CAknInformationNote( ETrue );
        note->ExecuteLD( *message );
		CleanupStack::PopAndDestroy( message );
		
		ShowUsernameSettingPageL();
		
		// If the username is still empty, it can only mean that the user has
		// cancelled the operation -> remove the temporarily accepted password
		if ( !iSettingUsername.Length() )
		    {
		    iUsernameCancelled = ETrue;
		    // Remove the password
            CPapUiPwSettingItem* pwItem =
                static_cast< CPapUiPwSettingItem* >(
                    iSettingArray->Array()->At( EPasswordItem ) );
            pwItem->DeletePasswordL();
		    }
        }
    
    }

// -----------------------------------------------------------------------------
// CPapUiDialog::GetHelpContext
// -----------------------------------------------------------------------------
//
void CPapUiDialog::GetHelpContext( TCoeHelpContext& aContext ) const
    {
    aContext.iMajor = KHelpUidPlugin;    
    aContext.iContext = KSET_HLP_WLAN_EAP_PAP;
    }

//  End of File
