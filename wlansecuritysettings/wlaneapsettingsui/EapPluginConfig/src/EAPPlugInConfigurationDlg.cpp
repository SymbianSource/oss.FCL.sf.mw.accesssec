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
* Description: Implementation of EAP Plugin Configuration dialog
*
*/

/*
* %version: 20.1.14 %
*/

// INCLUDE FILES
#include <akntitle.h>
#include <eikspane.h>
#include <aknmfnesettingpage.h>
#include <AknIconArray.h>
#include <AknsUtils.h>
#include <StringLoader.h>
#include <aknnotewrappers.h>
#include <EapType.h>

#include <EAPPluginConfigRes.rsg>
#include "EAPPluginConfig.hrh"

#include <avkon.mbg>

#include "EAPPluginList.h"
#include "EAPPlugInConfigurationDlg.h"
#include "EAPPluginConfigurationModel.h"


#include <FeatMgr.h>
#include <hlplch.h>
#include <eikappui.h>
#include <csxhelp/cp.hlp.hrh>


// CONSTANTS
// UID of general settings app, in which help texts are included
const TUid KHelpUidPlugin = { 0x100058EC };


// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CEAPPluginConfigurationDlg::CEAPPluginConfigurationDlg
// ---------------------------------------------------------
//
CEAPPluginConfigurationDlg::CEAPPluginConfigurationDlg( TInt& aButtonId,
                                        CEAPPluginConfigurationModel& aModel,
                                        const TUint32 aIapId )
: CAknSelectionListDialog( iDummy, &aModel, NULL ),
  iButtonId( &aButtonId ),
  iModel( &aModel ),
  iIapId( aIapId ),
  iExiting( EFalse )
    {
    // Passing a dummy (iDummy) for selection index.
    // Base class was made for 'select and dismiss' behaviour only, and does
    // not work properly in our case (when only "Back" press dismissed the
    // dialog and more selections are possible).
    //
    // iModel (the UI model) should really be owned by this dialog, but
    // can't do that due to the malformed API of CAknSelectionListDialog.
    }


// ---------------------------------------------------------
// CEAPPluginConfigurationDlg::~CEAPPluginConfigurationDlg
// ---------------------------------------------------------
//
CEAPPluginConfigurationDlg::~CEAPPluginConfigurationDlg()
    {
    if ( iTitlePane )
        {
        // set old text back, if we have it...
        if ( iOldTitleText )
            {
            TRAP_IGNORE( iTitlePane->SetTextL( *iOldTitleText ) );
            delete iOldTitleText;
            }
        }
        
    FeatureManager::UnInitializeLib();
    }


// ---------------------------------------------------------
// CEAPPluginConfigurationDlg::ConstructAndRunLD
// ---------------------------------------------------------
//
TInt CEAPPluginConfigurationDlg::ConstructAndRunLD( 
                                               const REAPPluginList& aPlugins,
                                               const TDesC& aTitle )
    {
    CleanupStack::PushL( this );

    iPlugins = aPlugins;
    iConnectionName = aTitle;

    FeatureManager::InitializeLibL();
    
    ConstructL( R_WPA_EAP_PLUGIN_MENUBAR );
    
    // ExecuteLD will PushL( this ), so we have to Pop it...
    CleanupStack::Pop( this ); // this
    
    return CAknSelectionListDialog::ExecuteLD( R_WPA_EAP_CONFIG_DIALOG );
    }



// ---------------------------------------------------------
// CEAPPluginConfigurationDlg::OkToExitL
// ---------------------------------------------------------
//
TBool CEAPPluginConfigurationDlg::OkToExitL( TInt aButtonId )
    {
    // Translate the button presses into commands for the appui & current
    // view to handle
    TBool retval( EFalse );
    if ( aButtonId == EAknSoftkeyOptions )
        {
        DisplayMenuL();
        }
    else if ( aButtonId == EEikCmdExit || 
              aButtonId == EAknCmdExit ||
              aButtonId == EAknSoftkeyBack )
        {
        *iButtonId = aButtonId;
        retval = ETrue;
        }
    else if( aButtonId == EWPAEAPPluginCmdConfigure )
        {
        ProcessCommandL( aButtonId );
        }
    else if( aButtonId == EWPAEAPPluginCmdEnable )
        {
        ProcessCommandL( aButtonId );
        }
        

    return retval;
    }
    
// ---------------------------------------------------------
// CEAPPluginConfigurationDlg::HandleListBoxEventL
// ---------------------------------------------------------
//
void CEAPPluginConfigurationDlg::HandleListBoxEventL( CEikListBox* /*aListBox*/,
                                                   TListBoxEvent aEventType )
    {
    switch ( aEventType )
        {
        case EEventEnterKeyPressed:
        case EEventItemSingleClicked:
            {
            TInt current = ListBox()->CurrentItemIndex();
            if ( iPlugins[current].iEnabled )            
                {
                ConfigureL(ETrue);
                }
            else
                {
                ProcessCommandL( EWPAEAPPluginCmdEnable );
                }                
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

// ---------------------------------------------------------
// CEAPPluginConfigurationDlg::HandleDialogPageEventL
// ---------------------------------------------------------
//
void CEAPPluginConfigurationDlg::HandleDialogPageEventL( TInt aEventID )
    {
     CAknDialog::HandleDialogPageEventL( aEventID );
         if( iExiting )
             {        
             // Exit requested, exit with ok. 
             TryExitL( EAknCmdExit );
             }   

     }

// ---------------------------------------------------------
// CEAPPluginConfigurationDlg::ConfigureL
// ---------------------------------------------------------
//
void CEAPPluginConfigurationDlg::ConfigureL( TBool aQuick )
    {
    CEapType* eapType = CEapType::NewL( 
            iPlugins[ListBox()->CurrentItemIndex()].iInfo->DataType(), 
            ELan, 
            iIapId );

    CleanupStack::PushL( eapType );

    TInt buttonId = eapType->InvokeUiL();
    CleanupStack::PopAndDestroy( eapType );

    if ( buttonId == EAknCmdExit || buttonId == EEikCmdExit )
        {
        if (aQuick == EFalse)
            {
            TryExitL( buttonId );
            }
        else
            {
            iExiting = ETrue;
            // Don't exit here. Framework command chain will
            // cause a KERN-EXEC 3 panic. Handle the exit in 
            // HandleDialogPageEventL(). 
            }
        }
    }

// ---------------------------------------------------------
// CEAPPluginConfigurationDlg::ProcessCommandL
// ---------------------------------------------------------
//
void CEAPPluginConfigurationDlg::ProcessCommandL( TInt aCommandId )
    {
    if ( MenuShowing() )
        {
        HideMenu();
        }

    switch ( aCommandId )
        {
        case EAknCmdOpen:
        case EWPAEAPPluginCmdConfigure:
            {
            ConfigureL(EFalse);
            break;
            }

        case EWPAEAPPluginCmdEnable:
            {
            TInt cur = ListBox()->CurrentItemIndex();
            iPlugins[cur].iEnabled = ETrue;

            // enabling moves item to the top of the list
            iPlugins.MovePos( cur, 0 );

            // Highlight follows movement.
            ListBox()->SetCurrentItemIndex( 0 );

            // load the new CBA from resource
            ButtonGroupContainer().SetCommandSetL( 
                            R_WPA_EAP_CONFIG_SOFTKEYS_OPTIONS_BACK_CONFIGURE );                            
            ButtonGroupContainer().DrawDeferred();
            DrawNow();
            break;
            }

        case EWPAEAPPluginCmdDisable:
            {
            if ( iModel->MdcaEnabledCount() > 1 )
                {
                TInt cur = ListBox()->CurrentItemIndex();

                // disabling moves item just after the last enabled one,
                // so find that position
                TInt next = cur;
                
                while ( next < iModel->MdcaCount() - 1 &&
                        iPlugins[next].iEnabled )
                    {
                    ++next;
                    }

                if ( next > cur && !iPlugins[next].iEnabled ) 
                    {
                    --next;
                    }


                iPlugins[cur].iEnabled = EFalse;

                // move item if needed
                iPlugins.MovePos( cur, next );

                // Highlight follows movement.
                ListBox()->SetCurrentItemIndex( next );
                
                // load the new CBA from resource
                ButtonGroupContainer().SetCommandSetL( 
                               R_WPA_EAP_CONFIG_SOFTKEYS_OPTIONS_BACK_ENABLE );
                ButtonGroupContainer().DrawDeferred();
                DrawNow();
                }
            else
                {
                HBufC* stringLabel;
                
                stringLabel = StringLoader::LoadL( R_INFO_CANNOT_DISABLE,
                                                   iEikonEnv );

                CleanupStack::PushL( stringLabel );

                CAknInformationNote* dialog = new ( ELeave )
                                                CAknInformationNote( ETrue );
                dialog->ExecuteLD( *stringLabel );

                CleanupStack::PopAndDestroy( stringLabel );
                }

            break;
            }

        case EWPAEAPPluginCmdPriorityUp:
            {
            TInt cur = ListBox()->CurrentItemIndex();
            iPlugins.MovePos( cur, cur - 1 );

            // Highlight follows movement.
            ListBox()->SetCurrentItemIndexAndDraw( cur - 1 );
            break;
            }

        case EWPAEAPPluginCmdPriorityDown:
            {
            TInt cur = ListBox()->CurrentItemIndex();

            iPlugins.MovePos( cur, cur + 1 );
            // Highlight follows movement.
            ListBox()->SetCurrentItemIndexAndDraw( cur + 1 );

            break;
            }

        case EAknCmdHelp:
            {
            HlpLauncher::LaunchHelpApplicationL( iEikonEnv->WsSession(),
                                    iEikonEnv->EikAppUi()->AppHelpContextL() );
            break;
            }

        case EAknSoftkeyBack:
        case EAknCmdExit:
        case EEikCmdExit:
            {
            TryExitL( aCommandId );
            break;
            }

        default:
            {
            CAknSelectionListDialog::ProcessCommandL( aCommandId );
            break;
            }
        }
    }


// ---------------------------------------------------------
// CEAPPluginConfigurationDlg::PreLayoutDynInitL
// ---------------------------------------------------------
//
void CEAPPluginConfigurationDlg::PreLayoutDynInitL()
    {
    CAknSelectionListDialog::PreLayoutDynInitL();

    // first get StatusPane
    CEikStatusPane* statusPane = iEikonEnv->AppUiFactory()->StatusPane();

    // then get TitlePane
    iTitlePane = ( CAknTitlePane* ) statusPane->ControlL( TUid::Uid( 
                                                    EEikStatusPaneUidTitle ) );
    // if not already stored, store it for restoring
    if ( !iOldTitleText )
        {
        iOldTitleText = iTitlePane->Text()->AllocL();
        }

    // set new titlepane text
    iTitlePane->SetTextL( iConnectionName );

    SetIconsL();
    }


// ---------------------------------------------------------
// CEAPPluginConfigurationDlg::SetIconsL()
// ---------------------------------------------------------
//
void CEAPPluginConfigurationDlg::SetIconsL()
    {
    CArrayPtr< CGulIcon >* icons = new( ELeave ) CAknIconArray( 1 );
    CleanupStack::PushL( icons );

    MAknsSkinInstance* skinInstance = AknsUtils::SkinInstance();

    CGulIcon* icon = CGulIcon::NewLC();
    CFbsBitmap* bitmap = NULL;
    CFbsBitmap* mask = NULL;    
    AknsUtils::CreateColorIconL( skinInstance,
                                 KAknsIIDQgnIndiMarkedAdd, 
                                 KAknsIIDQsnIconColors, 
                                 EAknsCIQsnIconColorsCG13, 
                                 bitmap, 
                                 mask, 
                                 AknIconUtils::AvkonIconFileName(),
                                 EMbmAvkonQgn_indi_marked_add, 
                                 EMbmAvkonQgn_indi_marked_add_mask,
                                 KRgbBlack );
    icon->SetBitmap( bitmap );
    icon->SetMask( mask );    
    icons->AppendL( icon );
                
    CleanupStack::Pop( icon ); 

    SetIconArrayL( icons );

    CleanupStack::Pop( icons );
    }


// ---------------------------------------------------------
// CEAPPluginConfigurationDlg::DynInitMenuPaneL
// ---------------------------------------------------------
//
void CEAPPluginConfigurationDlg::DynInitMenuPaneL( TInt aResourceId, 
                                                CEikMenuPane* aMenuPane )
    {
    CAknSelectionListDialog::DynInitMenuPaneL( aResourceId, aMenuPane );
    if ( aMenuPane && aResourceId == R_WPA_EAP_PLUGIN_MENU )
        {
        if ( !FeatureManager::FeatureSupported( KFeatureIdHelp ) )
            {
            aMenuPane->DeleteMenuItem( EAknCmdHelp );
            }
        if ( !iModel->MdcaCount() )
            {
            // if no plug-ins then dim the whole menu.
            aMenuPane->SetItemDimmed( EWPAEAPPluginCmdConfigure, ETrue );
            aMenuPane->SetItemDimmed( EWPAEAPPluginCmdEnable, ETrue );
            aMenuPane->SetItemDimmed( EWPAEAPPluginCmdDisable, ETrue );
            aMenuPane->SetItemDimmed( EWPAEAPPluginCmdPriorityUp, ETrue );
            aMenuPane->SetItemDimmed( EWPAEAPPluginCmdPriorityDown, ETrue );
            }
        else
            {
            TInt current = ListBox()->CurrentItemIndex();
            TBool enabled = iPlugins[current].iEnabled;
            
            // Hide either "Enable" or "Disable", as appropriate.
            aMenuPane->SetItemDimmed( EWPAEAPPluginCmdEnable, enabled );
            aMenuPane->SetItemDimmed( EWPAEAPPluginCmdDisable, !enabled );
            
            // Don't display "Configure" for disabled items
            aMenuPane->SetItemDimmed( EWPAEAPPluginCmdConfigure, !enabled );
            
            // Don't display "Raise priority" nor "Lower priority" for 
            // disabled items
            aMenuPane->SetItemDimmed( EWPAEAPPluginCmdPriorityUp, !enabled );
            aMenuPane->SetItemDimmed( EWPAEAPPluginCmdPriorityDown, !enabled );
            
            
            if ( enabled )
                {
                if ( current == 0 )
                    {
                    // Can't go higher than top.
                    aMenuPane->SetItemDimmed( EWPAEAPPluginCmdPriorityUp, 
                                              ETrue );
                    }
                
                if ( current == iModel->MdcaCount() - 1 || 
                        ( current < iModel->MdcaCount() - 1 && 
                        !iPlugins[current + 1].iEnabled ) )
                    {
                    // Can't go lower than the last enabled item
                    aMenuPane->SetItemDimmed( EWPAEAPPluginCmdPriorityDown, 
                                              ETrue );
                    }
                }            
            }
        }
    }


// ---------------------------------------------------------
// CEAPPluginConfigurationDlg::OfferKeyEventL
// ---------------------------------------------------------
//
TKeyResponse CEAPPluginConfigurationDlg::OfferKeyEventL( 
                                                const TKeyEvent& aKeyEvent, 
                                                TEventCode aType )
    {
    TKeyResponse result( EKeyWasNotConsumed );
    
    if ( aType == EEventKey )
        {
        
        // Exit handling 
        if ( aKeyEvent.iCode == EKeyEscape )
            {
            TryExitL( EEikCmdExit );
            return EKeyWasConsumed;
            }
        
        TInt current = ListBox()->CurrentItemIndex();
        
        // Handle Enter key here, since it doesn't seem to convert into
        // the proper command id via the normal route
        // (maybe some Avkon support for Enter key is still missing in
        // S60 3.2 2008_wk22)
        if ( aKeyEvent.iCode == EKeyEnter )
            {
            if ( iPlugins[current].iEnabled )
                {
                OkToExitL( EWPAEAPPluginCmdConfigure );
                }
            else
                {
                OkToExitL( EWPAEAPPluginCmdEnable );
                }
                
            result = EKeyWasConsumed;
            }
        else
            {
            result = CAknDialog::OfferKeyEventL( aKeyEvent, aType );
            }
                
        TInt next = ListBox()->CurrentItemIndex();

        if ( current != next &&
             ( iPlugins[current].iEnabled && !iPlugins[next].iEnabled ||
               !iPlugins[current].iEnabled && iPlugins[next].iEnabled ) )
            {
            // status is different, the CBA must be changed
            CEikButtonGroupContainer& cba = ButtonGroupContainer();

            // load the new set from resource
            if ( iPlugins[next].iEnabled )
                {
                cba.SetCommandSetL(  
                            R_WPA_EAP_CONFIG_SOFTKEYS_OPTIONS_BACK_CONFIGURE );                           
                }
            else
                {
                cba.SetCommandSetL(  
                            R_WPA_EAP_CONFIG_SOFTKEYS_OPTIONS_BACK_ENABLE );
                }

            cba.DrawDeferred();
            }
        }
    else
        {
        // pass event up the hierarchy
        result = CAknDialog::OfferKeyEventL( aKeyEvent, aType );        
        }
        
    
   
    return result;
    }


// ----------------------------------------------------------------------------
// CEAPPluginConfigurationDlg::HandleResourceChange
// ----------------------------------------------------------------------------
//
void CEAPPluginConfigurationDlg::HandleResourceChange( TInt aType )
    {
    CAknSelectionListDialog::HandleResourceChange( aType );

    if ( aType == KAknsMessageSkinChange )
        {
        TRAP_IGNORE( SetIconsL() );
        SizeChanged();
        }
    }


// ---------------------------------------------------------
// CEAPPluginConfigurationDlg::GetHelpContext
// ---------------------------------------------------------
//
void CEAPPluginConfigurationDlg::GetHelpContext( 
                                            TCoeHelpContext& aContext ) const
    {
    aContext.iMajor = KHelpUidPlugin;
    aContext.iContext = KSET_HLP_WLAN_EAP_PLUGINS_IAP;
    }


// End of File
