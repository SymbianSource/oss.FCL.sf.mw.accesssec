/*
* ============================================================================
*  Name     : wapisecuritysettingsdlg.cpp
*  Part of  : WAPI Security Settings UI
*
*  Description:
*     Implementation of dialog.
*
*  Version: %version:  16 %
*
*  Copyright (C) 2008 Nokia Corporation.
*  This material, including documentation and any related 
*  computer programs, is protected by copyright controlled by 
*  Nokia Corporation. All rights are reserved. Copying, 
*  including reproducing, storing,  adapting or translating, any 
*  or all of this material requires the prior written consent of 
*  Nokia Corporation. This material also contains confidential 
*  information which may not be disclosed to others without the 
*  prior written consent of Nokia Corporation.
*
* ============================================================================
*/

// INCLUDE FILES
#include <aknnavide.h>
#include <akntitle.h>
#include <aknradiobuttonsettingpage.h>
#include <akntextsettingpage.h>
#include <aknmfnesettingpage.h>
#include <barsread.h>
#include <StringLoader.h>
#include <aknnotewrappers.h>

#include <wapisecuritysettingsui.h>
#include <wapisecuritysettingsui.rsg>
#include "wapisecuritysettingsimpl.h"
#include "wapisecuritysettingsuipanic.h"
#include "wapisecuritysettingsdlg.h"
#include "wapisecuritysettingsui.hrh"

#include <hlplch.h>
#include <csxhelp/wapi.hlp.hrh>

#include <featmgr.h>


// CONSTANT DECLARATIONS

// Number of fields of main view
LOCAL_D const TInt KNumOfFieldsMain = 3;

LOCAL_D const TInt KTitles_Wapi_Main_Cert[KNumOfFieldsMain] =
                   {
                   R_WAPI_AUTH,
                   R_WAPI_CLIENT_CERT,
                   R_WAPI_ROOT_CERT
                   };
LOCAL_D const TInt KFields_Wapi_Main_Cert[KNumOfFieldsMain] =
                   {
                   CWAPISecuritySettingsDlg::EWapiAuth,
                   CWAPISecuritySettingsDlg::EWapiUserCert,
                   CWAPISecuritySettingsDlg::EWapiCACert
                   };

LOCAL_D const TInt KTitles_Wapi_Main_PSK[KNumOfFieldsMain] =
                   {
                   R_WAPI_AUTH,
                   R_WAPI_PRESHARED_KEY_FORMAT,
                   R_WAPI_PRESHARED_KEY
                   };
LOCAL_D const TInt KFields_Wapi_Main_PSK[KNumOfFieldsMain] =
                   {
                   CWAPISecuritySettingsDlg::EWapiAuth,
                   CWAPISecuritySettingsDlg::EWapiPSKFormat,
                   CWAPISecuritySettingsDlg::EWapiPSK
                   };


// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWAPISecuritySettingsDlg::CWAPISecuritySettingsDlg
// ---------------------------------------------------------
//
CWAPISecuritySettingsDlg::CWAPISecuritySettingsDlg( TInt& aEventStore )
: iEventStore( &aEventStore )
    {
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsDlg::~CWAPISecuritySettingsDlg
// ---------------------------------------------------------
//
CWAPISecuritySettingsDlg::~CWAPISecuritySettingsDlg()
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
// CWAPISecuritySettingsDlg::NewL
// ---------------------------------------------------------
//
CWAPISecuritySettingsDlg* CWAPISecuritySettingsDlg::NewL( TInt& aEventStore )
    {
    CWAPISecuritySettingsDlg* secSett = 
                        new ( ELeave )CWAPISecuritySettingsDlg( aEventStore );
    return secSett;
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsDlg::ConstructAndRunLD
// ---------------------------------------------------------
//
TInt CWAPISecuritySettingsDlg::ConstructAndRunLD( 
                                CWAPISecuritySettingsImpl* aSecuritySettings,
                                const TDesC& aTitle )
    {
	CleanupStack::PushL( this );

	iSecuritySettings = aSecuritySettings;
    iConnectionName = aTitle;

    // Build menu according to current authentication scheme.
    if (iSecuritySettings->GetAuthentication() == EWapiAuthPSK)
        {
        iFieldsMain = ( TWapiMember* ) KFields_Wapi_Main_PSK;
        iTitlesMain = MUTABLE_CAST( TInt*, KTitles_Wapi_Main_PSK );
        }
    else // ... == EWapiAuthCert
        {
        iFieldsMain = ( TWapiMember* ) KFields_Wapi_Main_Cert;
        iTitlesMain = MUTABLE_CAST( TInt*, KTitles_Wapi_Main_Cert );
        }
    
    //Let's fetch pointers to the certificate arrays

    iSecuritySettings->GetCertificateLabels( iUserCertificates, iCACertificates );

    #if defined( _DEBUG ) || defined( DEBUG )
    if ( iUserCertificates )
        {
        RDebug::Print(_L("CWAPISecuritySettingsDlg::ConstructAndRunLD, %d user certs"), iUserCertificates->Count() );
        }
    else
        {
        RDebug::Print(_L("CWAPISecuritySettingsDlg::ConstructAndRunLD, no user certs") );
        }
    
    if ( iCACertificates )
        {
        RDebug::Print(_L("CWAPISecuritySettingsDlg::ConstructAndRunLD, %d ca certs"), iCACertificates->Count() );
        }
    else
        {
        RDebug::Print(_L("CWAPISecuritySettingsDlg::ConstructAndRunLD, no ca certs") );
        }
    #endif
    
    FeatureManager::InitializeLibL();

    ConstructL( R_WAPI_SECURITY_SETTINGS_MENUBAR );
    
    // ExecuteLD will PushL( this ), so we have to Pop it...
    CleanupStack::Pop( this ); // this
    return ExecuteLD( R_WAPISETTINGS_DIALOG );
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsDlg::OkToExitL
// ---------------------------------------------------------
//
TBool CWAPISecuritySettingsDlg::OkToExitL( TInt aButtonId )
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
        *iEventStore |= CWAPISecuritySettings::EShutDownReq;
        retval = ETrue;
        }
    else if ( aButtonId == EAknSoftkeyBack || aButtonId == EAknCmdExit )
        {
        if (iSecuritySettings->GetAuthentication() == EWapiAuthPSK)
            {
            if (iSecuritySettings->IsValid())
                {
                *iEventStore |= CWAPISecuritySettings::EValid;
                retval = ETrue;
                }
            else if ( aButtonId == EAknSoftkeyBack )
                {
                HBufC* stringHolder = StringLoader::LoadL(
                                R_WAPI_QUEST_PRESHARED_KEY_DATA_MISSING, iEikonEnv );
                CleanupStack::PushL( stringHolder );
    
                CAknQueryDialog *queryDialog = new (ELeave) CAknQueryDialog();
    
                queryDialog->PrepareLC( R_WAPI_SEC_SETT_CONF_QUERY );
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
            *iEventStore |= CWAPISecuritySettings::EValid;
            retval = ETrue;
            }
        
        if ( aButtonId == EAknCmdExit )
            {
            *iEventStore |= CWAPISecuritySettings::EExitReq;
            }
        
        }
    else if( aButtonId == EWapiSelCmdChange )
        {
        ChangeSettingsL();
        retval = EFalse; // don't exit the dialog
        }

    return retval;
}


// ---------------------------------------------------------
// CWAPISecuritySettingsDlg::OfferKeyEventL
// ---------------------------------------------------------
//
TKeyResponse CWAPISecuritySettingsDlg::OfferKeyEventL( 
                                const TKeyEvent& aKeyEvent, TEventCode aType )
    {
    TKeyResponse retval( EKeyWasNotConsumed );
    TChar charCode( aKeyEvent.iCode );

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
                // as list IS consuming, must handle because it IS 
                //the SHUTDOWN or, a view switch is shutting us down...
                if ( aKeyEvent.iCode == EKeyEscape )
                    {
                    ProcessCommandL( EEikCmdExit );
                    retval = EKeyWasConsumed;
                    }
                else
                    {
                    retval = iList->OfferKeyEventL( aKeyEvent, aType );
                    }
                }
            else
                {
                if ( aKeyEvent.iCode == EKeyOK )
                    {
                    ProcessCommandL( EWapiSelCmdChange );
                    retval = EKeyWasConsumed;
                    }
                }
            }
        }
    return retval;
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsDlg::HandleListboxDataChangeL
// ---------------------------------------------------------
//
void CWAPISecuritySettingsDlg::HandleListboxDataChangeL()
    {
    // fill up our new list with data
    CDesCArrayFlat* itemArray = new ( ELeave ) CDesCArrayFlat( 4 );
    CleanupStack::PushL( itemArray );

    FillListWithDataL( *itemArray, *iFieldsMain, KNumOfFieldsMain, 
            iTitlesMain );

    iList->Model()->SetItemTextArray( itemArray );
    
    CleanupStack::Pop( itemArray ); // now it is owned by the LB, so pop it
    iItemArray = itemArray;

    iList->HandleItemAdditionL();
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsDlg::ProcessCommandL
// ---------------------------------------------------------
//
void CWAPISecuritySettingsDlg::ProcessCommandL( TInt aCommandId )
    {
    if ( MenuShowing() )
        {
        HideMenu();
        }

    switch ( aCommandId )
        {
        case EWapiSelCmdChange:
            {
            ChangeSettingsL();
            break;
            }

        case EWapiSelCmdReset:
            {
            TRAPD( err, iSecuritySettings->ResetCertificateStoreL() );

            HBufC* label;
                            
            if ( err == KErrNone )
                {
                //Certificate store was emptied, RARRAY's were closed,
                //pointer's were freed and certificates's in use were set
                //to "None" when ResetcertificateStoreL was called.
                //So we have to update the selections on the screen to
                //"(Not defined)" and redraw
                
                //refresh pointers
                iSecuritySettings->GetCertificateLabels( 
                                      iUserCertificates, iCACertificates );
                
                
                for ( TInt i = 0; i < KNumOfFieldsMain; i++ )
                    {

                    TWapiMember* ptr = iFieldsMain + i;
                    TInt* tptr = iTitlesMain + i;
                    
                    UpdateListBoxItemL( *ptr, *tptr, i );
                    *iEventStore |= CWAPISecuritySettings::EModified;

                    iList->ScrollToMakeItemVisible( i );
                    iList->DrawItem( i );
                    }


                
                label = StringLoader::LoadL( R_WAPI_DONE, iEikonEnv );
                }
            else
                {
                label = StringLoader::LoadL( R_WAPI_FAILURE, iEikonEnv );
                }

            CleanupStack::PushL( label );
            
            CAknInformationNote* dialog = new (ELeave)CAknInformationNote( 
                    ETrue );
            dialog->ExecuteLD( *label );
            
            CleanupStack::PopAndDestroy( label );         

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
// CWAPISecuritySettingsDlg::HandleListBoxEventL
// ---------------------------------------------------------
//
void CWAPISecuritySettingsDlg::HandleListBoxEventL( CEikListBox* /*aListBox*/,
                                                   TListBoxEvent aEventType )
    {
    switch ( aEventType )
        {
        case EEventEnterKeyPressed:
        case EEventItemSingleClicked:
            {
            ChangeSettingsL();
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
            __ASSERT_DEBUG( EFalse, Panic( EUnknownCase ) );
            break;
            };
        };
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsDlg::PreLayoutDynInitL()
// ---------------------------------------------------------
//
void CWAPISecuritySettingsDlg::PreLayoutDynInitL()
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
                         Control( KWapiMainSettingsListboxId ) );

    iList->CreateScrollBarFrameL( ETrue );
    iList->ScrollBarFrame()->SetScrollBarVisibilityL
        ( CEikScrollBarFrame::EOff, CEikScrollBarFrame::EAuto );

    HandleListboxDataChangeL();

    iList->SetCurrentItemIndex( 0 );
    iList->SetListBoxObserver( this );
    }



// ---------------------------------------------------------
// CWAPISecuritySettingsDlg::DynInitMenuPaneL
// ---------------------------------------------------------
//
void CWAPISecuritySettingsDlg::DynInitMenuPaneL( TInt aResourceId, 
                                                 CEikMenuPane* aMenuPane )
    {
    CAknDialog::DynInitMenuPaneL( aResourceId, aMenuPane );
    if ( aResourceId == R_WAPI_SECURITY_SETTINGS_MENU )
        {
        if( !FeatureManager::FeatureSupported( KFeatureIdHelp ) )
            {
            aMenuPane->DeleteMenuItem( EAknCmdHelp );
            }
        }
    }


//----------------------------------------------------------
// CWAPISecuritySettingsDlg::FillListWithDataL
//----------------------------------------------------------
//
void CWAPISecuritySettingsDlg::FillListWithDataL( CDesCArrayFlat& aItemArray,
                                                  const TWapiMember& arr, 
                                                  TInt aLength,
                                                  const TInt* aRes )
    {
    TWapiMember* wapiMember = MUTABLE_CAST( TWapiMember*, &arr );

    for( TInt i = 0; i < aLength; i++ )
        {
        HBufC* itemText = CreateTextualListBoxItemL( *wapiMember, 
                                                         *aRes );         
        CleanupStack::PushL( itemText );
        aItemArray.AppendL( itemText->Des() );
        CleanupStack::PopAndDestroy( itemText );

        wapiMember++;
        aRes++;
        }
    }


//----------------------------------------------------------
// CWAPISecuritySettingsDlg::UpdateListBoxItemL
//----------------------------------------------------------
//
void CWAPISecuritySettingsDlg::UpdateListBoxItemL( TWapiMember aMember, 
                                                   TInt aRes, TInt aPos )
    {
    HBufC* itemText = CreateTextualListBoxItemL( aMember, aRes );
    CleanupStack::PushL( itemText );
    // first try to add, if Leaves, list will be untouched
    iItemArray->InsertL( aPos, itemText->Des() );
    // if successful, previous item is scrolled up with one,
    // so delete that one...
    if ( ++aPos < iItemArray->MdcaCount() )
        {
        iItemArray->Delete( aPos );
        }
    CleanupStack::PopAndDestroy( itemText );
    }


//----------------------------------------------------------
// CWAPISecuritySettingsDlg::CreateTextualListBoxItemL
//----------------------------------------------------------
//
HBufC* CWAPISecuritySettingsDlg::CreateTextualListBoxItemL( 
                                            TWapiMember aMember, TInt aRes )
    {
    #if defined( _DEBUG ) || defined( DEBUG )
    RDebug::Print(_L("CWAPISecuritySettingsDlg::CreateTextualListBoxItemL") );
    #endif
    
    
    // Define a heap descriptor to hold title text
    // that are "WAPI client certificate" or
    // "WAPI root certificate"
    HBufC* titleText = iEikonEnv->AllocReadResourceLC( aRes );
//
//    TInt certIndex = KNone;
//    TPtrC certPtr;   

    HBufC* optText = NULL;


    switch ( aMember )
        {
        case EWapiAuth:
            {
            if (iSecuritySettings->GetAuthentication() == EWapiAuthPSK)
                {
                optText = iEikonEnv->AllocReadResourceLC(R_WAPI_AUTH_PSK);
                }
            else // ... == EWapiAuthCert
                {
                optText = iEikonEnv->AllocReadResourceLC(R_WAPI_AUTH_CERT);
                }
            }
            break;
        case EWapiUserCert:
        case EWapiCACert:
            {
            optText = FormatCertTextualListBoxItemL(aMember, aRes);
            break;
            }
        case EWapiPSKFormat:
            {
            if (iSecuritySettings->GetKeyFormat() == CWAPISecuritySettings::EWapiKeyAscii)
                {
                optText = iEikonEnv->AllocReadResourceLC(R_WAPI_PRESHARED_KEY_FORMAT_ASCII);                
                }
            else // ... == EWapiKeyHex
                {
                optText = iEikonEnv->AllocReadResourceLC(R_WAPI_PRESHARED_KEY_FORMAT_HEX);
                }
            break;
            }
        case EWapiPSK:
            {
            if (!iSecuritySettings->hasWapiPSKKey())
                {
                // PSK key not set.
                optText = iEikonEnv->AllocReadResourceLC(R_WAPI_PRESHARED_KEY_NOT_DEFINED);
                }
            else
                {
                // PSK key set.
                _LIT( KStars, "****" );
                optText = HBufC::NewLC( KStars().Length() );
                optText->Des().Copy( KStars ); 

                }
            break;
            }
        default:
            {
            __ASSERT_DEBUG( EFalse, Panic( EUnknownCase ) );
            break;
            }
        }
    _LIT( KTxtListItemFormat, " \t%S\t\t%S" );
    const TInt KSpaceAndTabsLength = 4;
        
    // Define a heap descriptor to hold all the item text
    // +4 for space and tab characters

    TInt length = titleText->Length() + optText->Length() 
                  + KSpaceAndTabsLength;
    
    HBufC* itemText = HBufC::NewLC( length );

    // Define a modifiable pointer descriptor to be able to append the title
    // text and the certificate label to the non-modifiable heap descriptor
    // itemText
    TPtr itemTextPtr = itemText->Des();
    itemTextPtr.Format( KTxtListItemFormat, titleText, optText );
 
    CleanupStack::Pop( itemText ); // itemtext is popped

    CleanupStack::PopAndDestroy( 2, titleText ); // optText, titleText
    return itemText;
    }

//----------------------------------------------------------
// CWAPISecuritySettingsDlg::FormatCertTextualListBoxItemL
//----------------------------------------------------------
//
HBufC* CWAPISecuritySettingsDlg::FormatCertTextualListBoxItemL( 
                                            TWapiMember aMember, TInt /* aRes */ )
    {
    #if defined( _DEBUG ) || defined( DEBUG )
    RDebug::Print(_L("CWAPISecuritySettingsDlg::FormatCertTextualListBoxItemL") );
    #endif
    
    TInt certIndex = KCertNone;
    TPtrC certPtr;   

    //Check that pointers are not null for example after
    //certificate store has been reset.
    switch ( aMember )
        {
        case EWapiUserCert:
            {
            #if defined( _DEBUG ) || defined( DEBUG )
            RDebug::Print(_L("user certIndex = %d"), certIndex );
            #endif
                
            if ( iUserCertificates )
                {
                iSecuritySettings->GetUserCertInUse( certIndex );
                certPtr.Set ((*iUserCertificates)[certIndex]);
                }
                
            #if defined( _DEBUG ) || defined( DEBUG )
            RDebug::Print(_L("user certIndex = %d"), certIndex );
            #endif
                
            break;
            }

        case EWapiCACert:
            {
            #if defined( _DEBUG ) || defined( DEBUG )
            RDebug::Print(_L("ca certIndex = %d"), certIndex );
            #endif
                
            if ( iCACertificates )
                {
                iSecuritySettings->GetCACertInUse( certIndex );
                certPtr.Set ((*iCACertificates)[certIndex]);
                }
                
            #if defined( _DEBUG ) || defined( DEBUG )
            RDebug::Print(_L("ca certIndex = %d"), certIndex );
            #endif
                
            break;
            }
        default:
            {
            __ASSERT_DEBUG( EFalse, Panic( EUnknownCase ) );
            break;
            }
        }
 
    // Define a heap descriptor to hold the certificate label text
    HBufC16* certText;
    
    if ( certIndex == KCertNone )
        {
        // If "None" is selected from pop up setting page then 
        // "(Not defined)" is shown on the main screen. This item
        // has to localized text so read it from resource file.
        certText = iEikonEnv->AllocReadResourceLC( R_WAPI_CERT_NOT_DEFINED );
        }
    else
        {
        //Use certificate text found from certificate array
        //(pointer was set in switch case above)
        certText = HBufC::NewLC( (certPtr.Length()) ); //pushes pointer 
                                                       //to Cleanup stack
        certText->Des().Copy( certPtr ); 
        }

    return certText;
    }


//----------------------------------------------------------
// CWAPISecuritySettingsDlg::ShowPopupSettingPageL
//----------------------------------------------------------
//
TBool CWAPISecuritySettingsDlg::ShowPopupSettingPageL( TWapiMember aData )
    {
    TInt currvalue( 0 );
    TBool retval( EFalse );
    CDesCArrayFlat* items = FillPopupSettingPageLC( aData,  currvalue );
    
    #if defined( _DEBUG ) || defined( DEBUG )
    RDebug::Print(_L("CWAPISecuritySettingsDlg::ShowPopupSettingPageL, %d items"), items->Count() );
    #endif

    TInt attr_resid( 0 );

    switch ( aData )
        {
        case EWapiUserCert:
            {
            attr_resid = R_WAPI_CLIENT_CERT;
            break;
            }

        case EWapiCACert:
            {
            attr_resid = R_WAPI_ROOT_CERT;
            break;
            }
  
        default:
            {
            __ASSERT_DEBUG( EFalse, Panic( EUnknownCase ) );
            attr_resid = 0;
            break;
            }
        }

    HBufC* titlebuf;
    CAknRadioButtonSettingPage* dlg;
    if ( attr_resid )
        {
        titlebuf = iEikonEnv->AllocReadResourceLC( attr_resid );
        dlg = new ( ELeave )CAknRadioButtonSettingPage( 
                            R_RADIO_BUTTON_SETTING_PAGE, currvalue, items );
        CleanupStack::PushL( dlg ); 
        TPtrC ptr( titlebuf->Des() );
        dlg->SetSettingTextL( ptr );
        CleanupStack::Pop( dlg ); // dlg
        }
    else
        {
        dlg = new ( ELeave )CAknRadioButtonSettingPage( 
                            R_RADIO_BUTTON_SETTING_PAGE, currvalue, items );
        }
    if ( dlg->ExecuteLD( CAknSettingPage::EUpdateWhenAccepted ) )
        {
    	retval = UpdateFromPopupSettingPage( aData, currvalue );
	    }

    if ( attr_resid )
        {
        CleanupStack::PopAndDestroy( titlebuf ); // titlebuf
        }

    CleanupStack::PopAndDestroy( items );   // items. It deletes also all 
                                            // elements in the array.
    return retval;
    }

//----------------------------------------------------------
// CWAPISecuritySettingsDlg::ShowPopupPSKSettingPageL
//----------------------------------------------------------
//
TBool CWAPISecuritySettingsDlg::ShowPopupPSKSettingPageL()
    {
    TBool retval( EFalse );

    HBufC16* bufKeyData = HBufC16::NewLC( KWapiMaxKeyLength );
    TPtr16 ptrKeyData( bufKeyData->Des() );

    TBool showPage( ETrue );
    while ( showPage )
        {
        CAknTextSettingPage* settingPage = 
                new( ELeave )CAknTextSettingPage( R_PSK_SETTING_PAGE_KEY_DATA,
                ptrKeyData, EAknSettingPageNoOrdinalDisplayed );

        if ( settingPage->ExecuteLD( CAknSettingPage::EUpdateWhenAccepted ) )
            {
            HBufC8* buf8 = HBufC8::NewLC( bufKeyData->Des().Length() );
            buf8->Des().Copy( bufKeyData->Des() ); 

            if ( iSecuritySettings->SetWapiPSKKeyL(ptrKeyData) != KErrNone )
                {
                TInt resourceId = R_WAPI_INFO_PRESHARED_KEY_ILLEGAL_CHARS;
                if ( (iSecuritySettings->GetKeyFormat()
                        == CWAPISecuritySettings::EWapiKeyHex)
                        && (ptrKeyData.Length() % 2 != 0))
                    {
                    resourceId = R_WAPI_INFO_PRESHARED_KEY_NOT_EVEN;
                    }
                HBufC* stringLabel;
                stringLabel = StringLoader::LoadL( resourceId );
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
// CWAPISecuritySettingsDlg::FillPopupSettingPageLC
// ---------------------------------------------------------
//
CDesCArrayFlat* CWAPISecuritySettingsDlg::FillPopupSettingPageLC( 
                                                            TWapiMember aData,
                                                            TInt& aCurrvalue )
    {
    TInt certIndex = KCertNone;
    CDesCArrayFlat* items = new( ELeave)CDesCArrayFlat( 1 );
    CleanupStack::PushL( items );

    
    // "None" item is not read from the certificate table as it has to be 
    // localized string
     RBuf16 resourceText( iEikonEnv->AllocReadResourceL( R_WAPI_NONE ) );
     items->AppendL( resourceText );
     resourceText.Close();
    
    switch ( aData )
        {
        case EWapiUserCert:
            {
            // Let's add user certificate labels from RARRAY
            if ( iUserCertificates )
                {
                #if defined( _DEBUG ) || defined( DEBUG )
                RDebug::Print(_L("CWAPISecuritySettingsDlg::FillPopupSettingPageLC, %d user certificates"), iUserCertificates->Count() );
                #endif
                
                TPtrC ptr;
                for ( TInt i = 1; i < iUserCertificates->Count(); i++ )
                    {
                    ptr.Set ((*iUserCertificates)[i]); // AppendL needs a pointer
                    items->AppendL( ptr );
                    }
                }       
            iSecuritySettings->GetUserCertInUse( certIndex );   
            break;
            }
            
        case EWapiCACert:
            {
          //Lets add CA certificate labels from RARRAY
            if (iCACertificates)
                {
                TPtrC ptr;
                for ( TInt i = 1; i < iCACertificates->Count(); i++ )
                    {
                    ptr.Set((*iCACertificates)[i]); // AppendL needs a pointer
                    items->AppendL( ptr );
                    }
                }            
            iSecuritySettings->GetCACertInUse( certIndex );
            break;
            }

        default:
            {
            __ASSERT_DEBUG( EFalse, Panic ( EUnknownCase ) );
            break;
            }
        }
    aCurrvalue = certIndex; //Set current choice
    return items;
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsDlg::UpdateFromPopupSettingPage
// ---------------------------------------------------------
//
TBool CWAPISecuritySettingsDlg::UpdateFromPopupSettingPage( TWapiMember aData,
                                                            TInt aCurrvalue )
    {
    #if defined( _DEBUG ) || defined( DEBUG )
    RDebug::Print(_L("CWAPISecuritySettingsImpl::UpdateFromPopupSettingPage, aCurrvalue = %d"), aCurrvalue );
    #endif
    
    TInt certIndex;
    TBool retVal( EFalse );

    switch ( aData )
        {
        case EWapiUserCert:
            {
            //Fetch the current certificate in use
            iSecuritySettings->GetUserCertInUse( certIndex );
            
            if ( certIndex != aCurrvalue )
                {
                iSecuritySettings->SetUserCertInUse( aCurrvalue );
                retVal = ETrue;
                }
            break;
            }

        case EWapiCACert:
            {
            //Fetch the current certificate in use
            iSecuritySettings->GetCACertInUse( certIndex );
            
            if ( certIndex != aCurrvalue )
                {
                iSecuritySettings->SetCACertInUse( aCurrvalue );
                retVal = ETrue;
                }
             break;
  
            }

        default:
            {
            __ASSERT_DEBUG( EFalse, Panic( EUnknownCase ) );
            break;
            }
        }
    return retVal;
    }


//----------------------------------------------------------
// CWAPISecuritySettingsDlg::ChangeSettingsL
//----------------------------------------------------------
//
void CWAPISecuritySettingsDlg::ChangeSettingsL()
    {
    TInt itemIndex = Max( iList->CurrentItemIndex(), 0 );
    TWapiMember* ptr = iFieldsMain + itemIndex;
    TInt* tptr = iTitlesMain + itemIndex;

    switch ( *ptr )
        {
        case EWapiAuth:
            {
            if (iSecuritySettings->GetAuthentication() == EWapiAuthCert)
                {
                iSecuritySettings->SetAuthentication( EWapiAuthPSK );
                iFieldsMain = ( TWapiMember* ) KFields_Wapi_Main_PSK;
                iTitlesMain = MUTABLE_CAST( TInt*, KTitles_Wapi_Main_PSK );
                }
            else // ... == EWapiAuthPSK
                {
                iSecuritySettings->SetAuthentication( EWapiAuthCert );
                iFieldsMain = ( TWapiMember* ) KFields_Wapi_Main_Cert;
                iTitlesMain = MUTABLE_CAST( TInt*, KTitles_Wapi_Main_Cert );
                }
            HandleListboxDataChangeL();
            *iEventStore |= CWAPISecuritySettings::EModified;
            break;
            }
        case EWapiCACert:
        case EWapiUserCert:
            {
            if ( ShowPopupSettingPageL( *ptr ) )
                {
                UpdateListBoxItemL( *ptr, *tptr, itemIndex );
                *iEventStore |= CWAPISecuritySettings::EModified;
                }
            break;
            }
        case EWapiPSKFormat:
            {
            if (iSecuritySettings->GetKeyFormat() == CWAPISecuritySettings::EWapiKeyAscii)
                {
                iSecuritySettings->SetKeyFormat(CWAPISecuritySettings::EWapiKeyHex);
                }
            else // ... == EWapiKeyHex
                {
                iSecuritySettings->SetKeyFormat(CWAPISecuritySettings::EWapiKeyAscii);
                }
            UpdateListBoxItemL( *ptr, *tptr, itemIndex );
            *iEventStore |= CWAPISecuritySettings::EModified;
            break;
            }
        case EWapiPSK:
            {
            if ( ShowPopupPSKSettingPageL())
                {
                UpdateListBoxItemL(*ptr, *tptr, itemIndex);
                *iEventStore |= CWAPISecuritySettings::EModified;
                }
            break;
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
// CWAPISecuritySettingsDlg::GetHelpContext
// ---------------------------------------------------------
//
void CWAPISecuritySettingsDlg::GetHelpContext( TCoeHelpContext& aContext ) const
    {
    aContext.iMajor = KWAPISecuritySettingsUiHelpMajor;
    aContext.iContext = KSET_HLP_WLAN_WAPI_MAIN;
    
    }

// End of File
