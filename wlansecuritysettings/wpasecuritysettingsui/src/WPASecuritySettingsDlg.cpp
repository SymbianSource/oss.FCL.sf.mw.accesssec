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
* Description: Implementation of dialog.  
*
*/

/*
* %version: tr1cfwln#33 %
*/

// INCLUDE FILES
#include "WPASecuritySettingsDlg.h"
#include "WPASecuritySettingsUiPanic.h"

#include "WPASecuritySettingsUI.hrh"

#include "WPASecuritySettingsDefs.h"

#include <csxhelp/cp.hlp.hrh>
#include <hlplch.h>

#include <featmgr.h>

#include <akntitle.h>
#include <aknradiobuttonsettingpage.h>
#include <StringLoader.h>
#include <aknnotewrappers.h>
#include <akntextsettingpage.h>
#include <EAPPluginConfigurationIf.h>

#include <WPASecuritySettingsUI.rsg>


// CONSTANT DECLARATIONS

// Number of fields of main view
LOCAL_D const TInt KNumOfFieldsMain = 3;     

// Menu List item format
_LIT( KTxtMenuListItemFormat, " \t%S\t\t" ); 

// Number of spaces and tabs in KTxtMenuListItemFormat string
LOCAL_D const TInt KSpaceAndTabsLength = 4;  



// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWPASecuritySettingsDlg::CWPASecuritySettingsDlg
// ---------------------------------------------------------
//
CWPASecuritySettingsDlg::CWPASecuritySettingsDlg( TInt& aEventStore, 
                                          const TUint32 aIapId,
                                          CEAPPluginConfigurationIf* aPlugin )
: iEventStore( &aEventStore ),
  iIapId( aIapId ),
  iPlugin( aPlugin )
    {
    }


// ---------------------------------------------------------
// CWPASecuritySettingsDlg::~CWPASecuritySettingsDlg
// ---------------------------------------------------------
//
CWPASecuritySettingsDlg::~CWPASecuritySettingsDlg()
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
// CWPASecuritySettingsDlg::NewL
// ---------------------------------------------------------
//
CWPASecuritySettingsDlg* CWPASecuritySettingsDlg::NewL( TInt& aEventStore, 
                                        const TUint32 aIapId,
                                        CEAPPluginConfigurationIf* aPlugin )
    {
    CWPASecuritySettingsDlg* secSett = new ( ELeave )CWPASecuritySettingsDlg(
                                                aEventStore, aIapId, aPlugin );
    return secSett;
    }


// ---------------------------------------------------------
// CWPASecuritySettingsDlg::ConstructAndRunLD
// ---------------------------------------------------------
//
TInt CWPASecuritySettingsDlg::ConstructAndRunLD( 
                                CWPASecuritySettingsImpl* aSecuritySettings,
                                const TDesC& aTitle )
    {
	CleanupStack::PushL( this );

    const TInt Titles_Wpa_Main[KNumOfFieldsMain+2] =
        {
        R_WPA_MODE,
        R_WPA_EAP_CONFIG,
        R_WPA_MODE_PRESHARED_KEY,
        R_WPA_TKIP_CIPHER,
        R_WPA_UNENCRYPTED_CONN
        };

    const TInt Fields_Wpa_Main[KNumOfFieldsMain+2] =
        {
        EWpaMode,
        EWpaEapConfig,
        EWpaPreSharedKey,
        EWpaWpa2Only,
        EWpaUnencryptedConn
        };

    iSecuritySettings = aSecuritySettings;
    iConnectionName = aTitle;

    iFieldsMain = ( TWpaMember* ) Fields_Wpa_Main;
    iTitlesMain = MUTABLE_CAST( TInt*, Titles_Wpa_Main );

    if ( !iSecuritySettings->WPAMode() && !iPlugin )
        {
        iSecuritySettings->SetWPAMode( ETrue );
        *iEventStore |= CWPASecuritySettings::EModified;
        }

    FeatureManager::InitializeLibL();

    ConstructL( R_WPA_SECURITY_SETTINGS_MENUBAR );
    
    // ExecuteLD will PushL( this ), so we have to Pop it...
    CleanupStack::Pop( this ); // this
	
    return ExecuteLD( R_WPASETTINGS_DIALOG );
    }



// ---------------------------------------------------------
// CWPASecuritySettingsDlg::OkToExitL
// ---------------------------------------------------------
//
TBool CWPASecuritySettingsDlg::OkToExitL( TInt aButtonId )
    {
    // Translate the button presses into commands for the appui & current
    // view to handle
    TBool retval( EFalse );
    if ( aButtonId == EAknSoftkeyOptions )
        {
        DisplayMenuL();
        }
    else if ( aButtonId == EEikCmdExit )        // ShutDown requested
        {
        *iEventStore |= CWPASecuritySettings::EShutDownReq;
        retval = ETrue;
        }
    else if ( aButtonId == EAknSoftkeyBack || aButtonId == EAknCmdExit )
        {
        if ( iSecuritySettings->WPAMode() )
            {
            if ( iSecuritySettings->IsValid() ) 
                {
                *iEventStore |= CWPASecuritySettings::EValid;
                retval = ETrue;
                }
            else if ( aButtonId == EAknSoftkeyBack )
                {
                HBufC* stringHolder = StringLoader::LoadL(
                                R_WPA_PRESHARED_KEYDATA_MISSING, iEikonEnv );
                CleanupStack::PushL( stringHolder );

                CAknQueryDialog *queryDialog = new (ELeave) CAknQueryDialog();

                queryDialog->PrepareLC( R_WPA_SEC_SETT_CONF_QUERY );
                queryDialog->SetPromptL( stringHolder->Des() );
                retval = queryDialog->RunLD();

                CleanupStack::PopAndDestroy( stringHolder );   // stringHolder
                }
            else
                {
                retval = ETrue;
                }
            }
        else 
            {
            *iEventStore |= CWPASecuritySettings::EValid;
            retval = ETrue;
            }

        if ( aButtonId == EAknCmdExit )
            {
            *iEventStore |= CWPASecuritySettings::EExitReq;
            }
        }
    
    else if( aButtonId == EWpaSelCmdChange )
        {
        ChangeSettingsL( ETrue );
        retval = EFalse; // don't exit the dialog
        }

    return retval;
    }


// ---------------------------------------------------------
// CWPASecuritySettingsDlg::OfferKeyEventL
// ---------------------------------------------------------
//
TKeyResponse CWPASecuritySettingsDlg::OfferKeyEventL( 
                                const TKeyEvent& aKeyEvent, TEventCode aType )
    {
    TKeyResponse retval( EKeyWasNotConsumed );

    // Only interested in standard key events
    if ( aType == EEventKey )
        {
        // If a menu is showing offer key events to it.
        if ( CAknDialog::MenuShowing() )
            {
            retval = CAknDialog::OfferKeyEventL( aKeyEvent, aType );
            }
        else
            {
            if ( iList )
                {
                // as list IS consuming, must handle because it IS the SHUTDOWN...
                // or, a view switch is shutting us down...
                if ( aKeyEvent.iCode == EKeyEscape )
                    {
                    ProcessCommandL( EEikCmdExit );
                    retval = EKeyWasConsumed;
                    }
                else
                    {
                    retval = iList->OfferKeyEventL( aKeyEvent, aType );
                    if ( *iEventStore & CWPASecuritySettings::EShutDownReq )
                        {
                        ProcessCommandL( EEikCmdExit );
                        }
                    else if ( *iEventStore & CWPASecuritySettings::EExitReq )
                        {
                        ProcessCommandL( EAknCmdExit );
                        }
                    }
                }
            else
                {
                if ( aKeyEvent.iCode == EKeyOK )
                    {
                    ProcessCommandL( EWpaSelCmdChange );
                    retval = EKeyWasConsumed;
                    }
                }
            }
        }

    return retval;
    }

// ---------------------------------------------------------
// CWPASecuritySettingsDlg::HandleDialogPageEventL
// ---------------------------------------------------------
//
void CWPASecuritySettingsDlg::HandleDialogPageEventL( TInt aEventID )
    {
     CAknDialog::HandleDialogPageEventL( aEventID );
         if( *iEventStore & CWPASecuritySettings::EExitReq )
             {        
             // Exit requested, exit with EAknCmdExit. 
             TryExitL( EAknCmdExit );
             }   

     }

// ---------------------------------------------------------
// CWPASecuritySettingsDlg::HandleListboxDataChangeL
// ---------------------------------------------------------
//
void CWPASecuritySettingsDlg::HandleListboxDataChangeL()
    {
    // fill up our new list with data
    CDesCArrayFlat* itemArray = new ( ELeave ) CDesCArrayFlat( 4 );
    CleanupStack::PushL( itemArray );

    FillListWithDataL( *itemArray, *iFieldsMain, iTitlesMain );

    iList->Model()->SetItemTextArray( itemArray );

    CleanupStack::Pop( itemArray ); // now it is owned by the LB, so pop it
    iItemArray = itemArray;

    iList->HandleItemAdditionL();
    }


// ---------------------------------------------------------
// CWPASecuritySettingsDlg::ProcessCommandL
// ---------------------------------------------------------
//
void CWPASecuritySettingsDlg::ProcessCommandL( TInt aCommandId )
    {
    if ( MenuShowing() )
        {
        HideMenu();
        }

    switch ( aCommandId )
        {
        case EWpaSelCmdChange:
            {
            ChangeSettingsL( EFalse );
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
            // silently ignore it
            break;
            }
        }
    }


// ---------------------------------------------------------
// CWPASecuritySettingsDlg::HandleListBoxEventL
// ---------------------------------------------------------
//
void CWPASecuritySettingsDlg::HandleListBoxEventL( CEikListBox* /*aListBox*/,
                                                   TListBoxEvent aEventType )
    {
    switch ( aEventType )
        {
        case EEventEnterKeyPressed:
        case EEventItemSingleClicked:
            {
            ChangeSettingsL( ETrue );
            break;
            }

        case EEventEditingStarted:
        case EEventEditingStopped:
        case EEventPenDownOnItem:
        case EEventItemDraggingActioned:
            {
            break;
            }

        default:
            {
            // New events like
            // EEventPanningStarted
            // EEventPanningStopped
            // EEventFlickStarted
            // EEventFlickStopped
            // EEventEmptyListClicked
            // EEventEmptyAreaClicked
            break;
            };
        };
    }


// ---------------------------------------------------------
// CWPASecuritySettingsDlg::PreLayoutDynInitL()
// ---------------------------------------------------------
//
void CWPASecuritySettingsDlg::PreLayoutDynInitL()
    {
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

    iList = STATIC_CAST( CAknSettingStyleListBox*, 
                                        Control( KWpaMainSettingsListboxId ) );

    iList->CreateScrollBarFrameL( ETrue );
    iList->ScrollBarFrame()->SetScrollBarVisibilityL
        ( CEikScrollBarFrame::EOff, CEikScrollBarFrame::EAuto );

    HandleListboxDataChangeL();

    iList->SetCurrentItemIndex( 0 );
    iList->SetListBoxObserver( this );
    }



// ---------------------------------------------------------
// CWPASecuritySettingsDlg::DynInitMenuPaneL
// ---------------------------------------------------------
//
void CWPASecuritySettingsDlg::DynInitMenuPaneL( TInt aResourceId, 
                                                CEikMenuPane* aMenuPane )
    {
    CAknDialog::DynInitMenuPaneL( aResourceId, aMenuPane );
    if ( aResourceId == R_WPA_SECURITY_SETTINGS_MENU )
        {
        if ( aMenuPane && !FeatureManager::FeatureSupported( KFeatureIdHelp ) )
            {
            aMenuPane->DeleteMenuItem( EAknCmdHelp );
            }
        }
    }


//----------------------------------------------------------
// CWPASecuritySettingsDlg::FillListWithDataL
//----------------------------------------------------------
//
void CWPASecuritySettingsDlg::FillListWithDataL( CDesCArrayFlat& aItemArray,
                                                 const TWpaMember& arr, 
                                                 const TInt* aRes )
    {
    TWpaMember* wpaMember = MUTABLE_CAST( TWpaMember*, &arr );

    TInt numOfFields = iSecuritySettings->SecurityMode() == ESecurityModeWpa ? 
                                        KNumOfFieldsMain : KNumOfFieldsMain-1;

    for( TInt i = 0; i < numOfFields; i++ )
        {
        // 802.1x has no WpaMode (PSK not supported) and no Wpa2Only selection
        if ( iSecuritySettings->SecurityMode() == ESecurityMode8021x && 
                    (*wpaMember == EWpaMode ||*wpaMember == EWpaWpa2Only ) )
            {
            wpaMember++;
            aRes++;
            }
        // If PSK in use, EAP plug-in configuration is not shown
        if ( *wpaMember == EWpaEapConfig && iSecuritySettings->WPAMode() )
            {
            wpaMember++;
            aRes++;
            }
            
        if ( *wpaMember == EWpaEapConfig )
            {
            // Define a heap descriptor to hold all the item text
            // HBufC is non-modifiable
            HBufC* title = iEikonEnv->AllocReadResourceLC( *aRes );

            // Define a heap descriptor to hold all the item text
            HBufC* itemText = HBufC::NewLC( title->Length() + 
                                            KSpaceAndTabsLength );

            // Define a modifiable pointer descriptor to be able to append
            // text to the non-modifiable heap descriptor itemText
            TPtr itemTextPtr = itemText->Des();
            itemTextPtr.Format( KTxtMenuListItemFormat, title );

            aItemArray.AppendL( *itemText );

            CleanupStack::PopAndDestroy( 2, title );   // itemText, title
            
            // If Eap in use, PreSharedKey is not shown
            wpaMember++;
            aRes++;
            }
        else            // EWpaMode, EWpaPreSharedKey, EWpaWpa2Only, EWpaUnencryptedConn:
            {
            if (( *wpaMember != EWpaUnencryptedConn ) || 
                (FeatureManager::FeatureSupported( KFeatureIdFfWlanAuthenticationOnlySupport ) ) )
                {
                HBufC* itemText = CreateTextualListBoxItemL( *wpaMember, *aRes );
                CleanupStack::PushL( itemText );
                aItemArray.AppendL( itemText->Des() );
                CleanupStack::PopAndDestroy( itemText );
                }
            }

        wpaMember++;
        aRes++;
        }
    }


//----------------------------------------------------------
// CWPASecuritySettingsDlg::UpdateTextualListBoxItemL
//----------------------------------------------------------
//
void CWPASecuritySettingsDlg::UpdateTextualListBoxItemL( TWpaMember aMember,
                                                         TInt aRes, TInt aPos )
    {
    HBufC* itemText;
    HBufC* title;

    if ( aMember == EWpaEapConfig )
        {
        title = iEikonEnv->AllocReadResourceLC( aRes );

        // Define a heap descriptor to hold all the item text
        itemText = HBufC::NewLC( title->Length() + KSpaceAndTabsLength );

        // Define a modifiable pointer descriptor to be able to append
        // text to the non-modifiable heap descriptor itemText
        TPtr itemTextPtr = itemText->Des();
        itemTextPtr.Format( KTxtMenuListItemFormat, title );
        }
    else
        {
        itemText = CreateTextualListBoxItemL( aMember, aRes );
        CleanupStack::PushL( itemText );
        }

    // first try to add, if Leaves, list will be untouched
    iItemArray->InsertL( aPos, itemText->Des() );
    // if successful, previous item is scrolled up with one,
    // so delete that one...
    if ( ++aPos < iItemArray->MdcaCount() )
        {
        iItemArray->Delete( aPos );
        }

    CleanupStack::PopAndDestroy( itemText );

    if ( aMember == EWpaEapConfig )
        {
        CleanupStack::PopAndDestroy( title );   // title
        }
    }


//----------------------------------------------------------
// CWPASecuritySettingsDlg::CreateTextualListBoxItemL
//----------------------------------------------------------
//
HBufC* CWPASecuritySettingsDlg::CreateTextualListBoxItemL( TWpaMember aMember,
                                                           TInt aRes )
    {
    // Define a heap descriptor to hold all the item text
    // HBufC is non-modifiable
    HBufC* title = iEikonEnv->AllocReadResourceLC( aRes );

    // both variables needed independently of the following conditions so I
    // must declare them here...
    HBufC16* value;
    TUint32 valueResourceID;

    switch ( aMember )
        {
        case EWpaMode:
            {
            valueResourceID = iSecuritySettings->WPAMode() ?
                              R_WPA_MODE_PRESHARED_KEY : R_WPA_MODE_EAP;
            break;
            }
        
        case EWpaWpa2Only:
            {
            valueResourceID = iSecuritySettings->Wpa2Only() ?
                              R_WPA_CIPHER_NOT_ALLOWED : R_WPA_CIPHER_ALLOWED;
            break;
            }

        case EWpaUnencryptedConn:
            {
            valueResourceID = iSecuritySettings->WPAUnencryptedConn() ?
                              R_WPA_UNENCRYPTED_CONN_ALLOW : R_WPA_UNENCRYPTED_CONN_NOT_ALLOW;
            break;
            }
            
        case EWpaPreSharedKey:
            {
            valueResourceID = 
                        iSecuritySettings->WPAPreSharedKey()->Length() == 0 ?
                        R_WPA_PRESHARED_KEY_MUST_BE_DEFINED : 0;

            break;
            }

        default:
            {
            valueResourceID = 0;
            break;
            }
        }

    _LIT( KStars, "****" );
    _LIT( KTxtListItemFormat, " \t%S\t\t%S" );
    _LIT( KTxtCompulsory, "\t*" );

    if ( valueResourceID )
        {
        // Read up value text from resource
        value = iEikonEnv->AllocReadResourceLC( valueResourceID );
        }
    else
        {
        value = HBufC::NewLC( KStars().Length() );
        value->Des().Copy( KStars ); 
        }

    // Define a heap descriptor to hold all the item text
    // +4 for space and tab characters
    TInt length = title->Length() + value->Length() + KSpaceAndTabsLength;    
    if ( aMember == EWpaPreSharedKey )  // Compulsory
        {
        length += KTxtCompulsory().Length();
        }

    HBufC* itemText = HBufC::NewLC( length );

    // Define a modifiable pointer descriptor to be able to append text to the
    // non-modifiable heap descriptor itemText
    TPtr itemTextPtr = itemText->Des();
    itemTextPtr.Format( KTxtListItemFormat, title, value );
    if ( aMember == EWpaPreSharedKey )  // Compulsory
        {
        itemTextPtr.Append( KTxtCompulsory );
        }
    CleanupStack::Pop( itemText );    // itemtext,

    CleanupStack::PopAndDestroy( 2 ); // title, value

    return itemText;
    }



//----------------------------------------------------------
// CWPASecuritySettingsDlg::ShowPopupSettingPageL
//----------------------------------------------------------
//
TBool CWPASecuritySettingsDlg::ShowPopupSettingPageL( TWpaMember aData )
    {
    TInt currvalue( 0 );
    TBool retval( EFalse );
    TInt attr_resid( 0 );
    
    CDesCArrayFlat* items = FillPopupSettingPageLC( aData,  currvalue );

    
    if ( aData == EWpaUnencryptedConn)
        {
        attr_resid = R_WPA_UNENCRYPTED_CONN;
        }
    else
        {
        attr_resid = aData == EWpaMode ? R_WPA_MODE : R_WPA_TKIP_CIPHER;
        }

    HBufC* titlebuf = iEikonEnv->AllocReadResourceLC( attr_resid );
    CAknRadioButtonSettingPage* dlg = new ( ELeave )CAknRadioButtonSettingPage(
                            R_RADIO_BUTTON_SETTING_PAGE, currvalue, items );
    CleanupStack::PushL( dlg ); 
    TPtrC ptr( titlebuf->Des() );
    dlg->SetSettingTextL( ptr );
    CleanupStack::Pop( dlg ); // dlg
        
    if ( dlg->ExecuteLD( CAknSettingPage::EUpdateWhenAccepted ) )
        {
    	retval = UpdateFromPopupSettingPage( aData, ( TBool )currvalue );
	    }

    CleanupStack::PopAndDestroy( titlebuf );
    CleanupStack::PopAndDestroy( items );   // items. It deletes also all 
                                            // elements in the array.
    return retval;
    }



//----------------------------------------------------------
// CWPASecuritySettingsDlg::ShowPopupTextSettingPageL
//----------------------------------------------------------
//
TBool CWPASecuritySettingsDlg::ShowPopupTextSettingPageL()
    {
    TBool retval( EFalse );

    HBufC16* bufKeyData = HBufC16::NewLC( EMaxLengthOfPreSharedKey );
    TPtr16 ptrKeyData( bufKeyData->Des() );

    TBool showPage( ETrue );
    while ( showPage )
        {
        CAknTextSettingPage* settingPage = 
                new( ELeave )CAknTextSettingPage( R_TEXT_SETTING_PAGE_KEY_DATA,
                ptrKeyData, EAknSettingPageNoOrdinalDisplayed );

        if ( settingPage->ExecuteLD( CAknSettingPage::EUpdateWhenAccepted ) )
            {
            HBufC8* buf8 = HBufC8::NewLC( bufKeyData->Des().Length() );
            buf8->Des().Copy( bufKeyData->Des() ); 

            if ( bufKeyData->Des().Length() < EMinLengthOfPreSharedKeyAscii )
                {
                HBufC* stringLabel;
                
                stringLabel = StringLoader::LoadL( 
                                                R_INFO_PRESHARED_KEY_TOO_SHORT,
                                                iEikonEnv );

                CleanupStack::PushL( stringLabel );

	            CAknInformationNote* dialog = new ( ELeave )
                                                CAknInformationNote( ETrue );
	            dialog->ExecuteLD( *stringLabel );

                CleanupStack::PopAndDestroy( stringLabel );   // stringLabel

                ptrKeyData.Zero();
                }
            else
                {
                if ( iSecuritySettings->SetWPAPreSharedKey( ptrKeyData ) != 
                                                                     KErrNone )
                    {
                    HBufC* stringLabel;
                    stringLabel = StringLoader::LoadL( 
                                                R_INFO_PRESHARED_KEY_NOT_HEX );
                    CleanupStack::PushL( stringLabel );

    	            CAknInformationNote* dialog = new ( ELeave )
                                                  CAknInformationNote( ETrue );
                    CleanupStack::Pop( stringLabel );
                    	
      	            dialog->ExecuteLD( *stringLabel );
      	            
                    delete stringLabel;
                    }
                else
                    {
                    retval = ETrue;
                    showPage = EFalse;
                    }

                }

            CleanupStack::PopAndDestroy( buf8 ); // buf8
            }
        else
            {
            showPage = EFalse;
            }
        }

    CleanupStack::PopAndDestroy( bufKeyData ); // bufKeyData

    return retval;
    }



// ---------------------------------------------------------
// CWPASecuritySettingsDlg::FillPopupSettingPageLC
// ---------------------------------------------------------
//
CDesCArrayFlat* CWPASecuritySettingsDlg::FillPopupSettingPageLC( 
                                                            TWpaMember aData,
                                                            TInt& aCurrvalue )
    {
    CDesCArrayFlat* items = new( ELeave)CDesCArrayFlat( 1 );
    CleanupStack::PushL( items );

    if ( aData == EWpaMode )
        {
        if ( iPlugin )
            {
            aCurrvalue = iSecuritySettings->WPAMode();

            items->AppendL( *iEikonEnv->AllocReadResourceLC( R_WPA_MODE_EAP ) );
            CleanupStack::PopAndDestroy();
            }
        else
            {
            aCurrvalue = 0;
            }

        items->AppendL( *iEikonEnv->AllocReadResourceLC( 
                                                R_WPA_MODE_PRESHARED_KEY ) );
        CleanupStack::PopAndDestroy();
        }
    else if ( aData == EWpaWpa2Only )
        {
        items->AppendL( *iEikonEnv->AllocReadResourceLC( 
                                                R_WPA_CIPHER_ALLOWED ) );
        CleanupStack::PopAndDestroy();
        items->AppendL( *iEikonEnv->AllocReadResourceLC( 
                                                R_WPA_CIPHER_NOT_ALLOWED ) );
        CleanupStack::PopAndDestroy();

        aCurrvalue = iSecuritySettings->Wpa2Only();
        }
    else    // EWpaUnencryptedConn
        {
        items->AppendL( *iEikonEnv->AllocReadResourceLC( 
                                            R_WPA_UNENCRYPTED_CONN_NOT_ALLOW ) );
        CleanupStack::PopAndDestroy();
        items->AppendL( *iEikonEnv->AllocReadResourceLC( 
                                            R_WPA_UNENCRYPTED_CONN_ALLOW ) );
        CleanupStack::PopAndDestroy();

        aCurrvalue = iSecuritySettings->WPAUnencryptedConn();
        }
    
    return items;
    }


// ---------------------------------------------------------
// CWPASecuritySettingsDlg::UpdateFromPopupSettingPage
// ---------------------------------------------------------
//
TBool CWPASecuritySettingsDlg::UpdateFromPopupSettingPage( TWpaMember aData,
                                                           TBool aCurrvalue )
    {
    TBool retVal( EFalse );

    if ( aData == EWpaMode )
        {
        if ( !iPlugin )
            {
            aCurrvalue = ETrue;
            }

        if ( iSecuritySettings->WPAMode() != aCurrvalue )
            {
            iSecuritySettings->SetWPAMode( aCurrvalue );
            retVal = ETrue;
            }
        }
    else if ( aData == EWpaWpa2Only )
        {
        if ( iSecuritySettings->Wpa2Only() != aCurrvalue )
            {   
            iSecuritySettings->SetWpa2Only( aCurrvalue );
            retVal = ETrue;
            }
        }
    else  // EWpaUnencryptedConn
        {
        if ( iSecuritySettings->WPAUnencryptedConn() != aCurrvalue )
            {   
            iSecuritySettings->SetWPAUnencryptedConn( aCurrvalue );
            retVal = ETrue;
            }
        }

    return retVal;
    }




//----------------------------------------------------------
// CWPASecuritySettingsDlg::ChangeSettingsL
//----------------------------------------------------------
//
void CWPASecuritySettingsDlg::ResetEapConfigFlag( TAny* aPtr )
    {
    CWPASecuritySettingsDlg* self = 
                         static_cast<CWPASecuritySettingsDlg*>( aPtr );
                         
    self->iEapConfigActive = EFalse;
    }


//----------------------------------------------------------
// CWPASecuritySettingsDlg::ChangeSettingsL
//----------------------------------------------------------
//
void CWPASecuritySettingsDlg::ChangeSettingsL( TBool aQuick )
    {
    TInt itemIndex;
    TInt shift;

    itemIndex = ( Max( iList->CurrentItemIndex(), 0 ) );

    //In 802.1x the first item is EapConfig and second item is UncryptedConn
    if (iSecuritySettings->SecurityMode() == ESecurityMode8021x)
        {
        shift = ( itemIndex == EWpaMode ) ? 1 : 3;
        }
    else
        {
        shift = ( itemIndex >= EWpaWpa2Only || 
                ( itemIndex == EWpaEapConfig && 
                        iSecuritySettings->WPAMode() ) ) ? 1 : 0;
        }
    
    TWpaMember* ptr = iFieldsMain + itemIndex + shift;
    TInt* titPtr = iTitlesMain + itemIndex + shift;

    switch ( *ptr  )
        {
        case EWpaMode:
            { // Pop-up setting item
            TBool changed( ETrue );
            if ( aQuick )
                {
                if ( iPlugin )
                    {
                    iSecuritySettings->SetWPAMode( 
                                            !iSecuritySettings->WPAMode() );
                    }
                else
                    {
                    changed = EFalse;
                    }
                }
            else
                {
                changed = ShowPopupSettingPageL( EWpaMode );
                }

            if ( changed )
                {
                UpdateTextualListBoxItemL( *ptr, *titPtr, itemIndex );
                *iEventStore |= CWPASecuritySettings::EModified;

                TInt shiftItem = iSecuritySettings->WPAMode() ? 2 : 1;

                ptr += shiftItem;
                titPtr += shiftItem;

                UpdateTextualListBoxItemL( *ptr, *titPtr, itemIndex+1 );
                iList->SetCurrentItemIndexAndDraw( itemIndex+1 );
                }
            break;
            }

        case EWpaWpa2Only:
            { // Setting item with two available values
            TBool changed( ETrue );
            if ( aQuick )
                {
                iSecuritySettings->SetWpa2Only( 
                                            !iSecuritySettings->Wpa2Only() );
                }
            else
                {
                changed = ShowPopupSettingPageL( EWpaWpa2Only );
                }

            if ( changed )
                {
                UpdateTextualListBoxItemL( *ptr, *titPtr, itemIndex );
                *iEventStore |= CWPASecuritySettings::EModified;
                }
            break;
            }

        case EWpaUnencryptedConn:
             { // Setting item with two available values
             TBool changed( ETrue );
             if ( aQuick )
                 {
                 iSecuritySettings->SetWPAUnencryptedConn( 
                                             !iSecuritySettings->WPAUnencryptedConn() );
                 }
             else
                 {
                 changed = ShowPopupSettingPageL( EWpaUnencryptedConn );
                 }

             if ( changed )
                 {
                 UpdateTextualListBoxItemL( *ptr, *titPtr, itemIndex );
                 *iEventStore |= CWPASecuritySettings::EModified;
                 }
             break;
             }

        case EWpaPreSharedKey:
            { // Text setting item
            if ( ShowPopupTextSettingPageL() )
                {
                UpdateTextualListBoxItemL( *ptr, *titPtr, itemIndex );
                *iEventStore |= CWPASecuritySettings::EModified;
                }
            break;
            }

        case EWpaEapConfig:
            {
            if ( iPlugin && !iEapConfigActive )
                {
                iEapConfigActive = ETrue;
                CleanupStack::PushL( TCleanupItem( ResetEapConfigFlag, this ) );
                

                // using expanded EAP types
                iEnabledPluginList = (
                               iSecuritySettings->WPAEnabledEAPPlugin()? 
                                    (TDesC8&)*iSecuritySettings->WPAEnabledEAPPlugin(): 
                                    KNullDesC8 );
                                    
                iDisabledPluginList = (
                               iSecuritySettings->WPADisabledEAPPlugin()?
                                    (TDesC8&)*iSecuritySettings->WPADisabledEAPPlugin():
                                    KNullDesC8 );

                TInt buttonId = iPlugin->EAPPluginConfigurationL( 
                                                     iEnabledPluginList, 
                                                     iDisabledPluginList, 
                                                     iIapId,
                                                     iConnectionName );

                CleanupStack::PopAndDestroy( 1 ); // ResetEapConfigFlag
                
                if ( buttonId == EEikCmdExit )        // ShutDown requested
                    {
                    *iEventStore |= CWPASecuritySettings::EShutDownReq;
                    }
                else if ( buttonId == EAknCmdExit )
                    {
                    *iEventStore |= CWPASecuritySettings::EExitReq;
                    }

                if ( !iSecuritySettings->WPAEnabledEAPPlugin() || 
                     iEnabledPluginList != 
                                    *iSecuritySettings->WPAEnabledEAPPlugin() )
                    {
                    User::LeaveIfError( 
                        iSecuritySettings->SetWPAEnabledEAPPlugin( 
                                                        iEnabledPluginList ) );
                    *iEventStore |= CWPASecuritySettings::EModified;
                    }
    
                if ( !iSecuritySettings->WPADisabledEAPPlugin() ||
                     iDisabledPluginList != 
                                   *iSecuritySettings->WPADisabledEAPPlugin() )
                    {
                    User::LeaveIfError( 
                        iSecuritySettings->SetWPADisabledEAPPlugin( 
                                                        iDisabledPluginList ) );
                    *iEventStore |= CWPASecuritySettings::EModified;
                    }

                // If exiting from the menu, pass it on 
                if( buttonId == EAknCmdExit )
                    {
                    if (aQuick == EFalse)
                        {
                            TryExitL( buttonId );
                        }
                        // Don't exit here if aQuick==ETrue. 
                        // Framework command chain will
                        // cause a KERN-EXEC 3 panic. Handle the exit in 
                        // HandleDialogPageEventL(). 
                    }
                }
            
            return;
            }


        default:
            {
            __ASSERT_DEBUG( EFalse, Panic( EUnknownCase ) );
            break;
            }
        }

    iList->ScrollToMakeItemVisible( itemIndex );
    iList->SetCurrentItemIndexAndDraw( itemIndex );
    }



// ---------------------------------------------------------
// CWPASecuritySettingsDlg::GetHelpContext
// ---------------------------------------------------------
//
void CWPASecuritySettingsDlg::GetHelpContext( TCoeHelpContext& aContext ) const
    {
    aContext.iMajor = KWPASecuritySettingsUiHelpMajor;
    if ( iSecuritySettings->SecurityMode() == ESecurityModeWpa )
        {
        aContext.iContext = KSET_HLP_WLAN_WPA_MAIN;
        }
    else    // iSecuritySettings->SecurityMode() == ESecurityMode8021x
        {
        aContext.iContext = KSET_HLP_WLAN_8021X_MAIN;
        }
    }


// End of File
