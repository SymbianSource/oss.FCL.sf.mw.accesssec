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
* Description: Implementation of dialog.  
*
*/

/*
* %version: tr1cfwln#8.1.22.1.1 %
*/

// INCLUDE FILES
#include <aknnavide.h>
#include <akntitle.h>
#include <aknradiobuttonsettingpage.h>
#include <aknmfnesettingpage.h>
#include <barsread.h>
#include <akntabgrp.h>
#include <StringLoader.h>
#include <aknnotewrappers.h>
#include <WEPSecuritySettingsUI.h>

#include <WEPSecuritySettingsUI.rsg>

#include "WEPSecuritySettingsImpl.h"
#include "WEPSecuritySettingsUiPanic.h"
#include "WEPSecuritySettingsDlg.h"
#include "WepKeyDataTextSettingPage.h"

#include "WEPSecuritySettingsUI.hrh"

#include <hlplch.h>

#include <featmgr.h>


// CONSTANT DECLARATIONS

// Number of fields of main view
LOCAL_D const TInt KNumOfFieldsMain = 3;

// Number of fields of key configuration view
LOCAL_D const TInt KNumOfFieldsKeyConfiguration = 3;

// Ratio of ascii and hex key sizes
LOCAL_D const TInt KAsciiHexRatio = 2;


// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWEPSecuritySettingsDlg::CWEPSecuritySettingsDlg
// ---------------------------------------------------------
//
CWEPSecuritySettingsDlg::CWEPSecuritySettingsDlg( TInt& aEventStore )
: iNaviPane( NULL ), 
iTabGroup( NULL ),
iActiveTab( 0 ),
iLevel( 0 ),
iEventStore( &aEventStore )
    {
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsDlg::~CWEPSecuritySettingsDlg
// ---------------------------------------------------------
//
CWEPSecuritySettingsDlg::~CWEPSecuritySettingsDlg()
    {
    if ( iNaviDecoratorEmpty )
        {
        delete iNaviDecoratorEmpty;
        }

    if ( iNaviDecoratorTabbed )
        {
        delete iNaviDecoratorTabbed;
        }

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
// CWEPSecuritySettingsDlg::NewL
// ---------------------------------------------------------
//
CWEPSecuritySettingsDlg* CWEPSecuritySettingsDlg::NewL( TInt& aEventStore )
    {
    CWEPSecuritySettingsDlg* secSett = 
                        new ( ELeave )CWEPSecuritySettingsDlg( aEventStore );
    return secSett;
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsDlg::ConstructAndRunLD
// ---------------------------------------------------------
//
TInt CWEPSecuritySettingsDlg::ConstructAndRunLD( 
                                CWEPSecuritySettingsImpl* aSecuritySettings,
                                const TDesC& aTitle )
    {
	CleanupStack::PushL( this );

    const TInt Titles_Wep_Main[KNumOfFieldsMain] =
        {
        R_WEP_KEY_IN_USE,
        R_WEP_AUTHENTICATION,
        R_WEP_KEY_CONFIGURATION
        };

    const TInt Fields_Wep_Main[KNumOfFieldsMain] =
        {
        CWEPSecuritySettings::EWepKeyInUse,
        CWEPSecuritySettings::EWepAuthentication,
        CWEPSecuritySettings::EWepKeyConfiguration
        };

    const TInt Fields_Wep_Key_Configuration[KNumOfFieldsKeyConfiguration] =
        {
        CWEPSecuritySettings::EWepKeyLength,
        CWEPSecuritySettings::EWepKeyFormat,
        CWEPSecuritySettings::EWepKeyData
        };

    const TInt Titles_Wep_Key_Configuration[KNumOfFieldsKeyConfiguration] =
        {
        R_WEP_KEY_LENGTH,
        R_WEP_KEY_FORMAT,
        R_WEP_KEY_DATA
        };

    iSecuritySettings = aSecuritySettings;
    iConnectionName = aTitle;

    iFieldsMain = ( CWEPSecuritySettings::TWepMember* ) Fields_Wep_Main;
    iTitlesMain = MUTABLE_CAST( TInt*, Titles_Wep_Main );

    iFieldsKeyConfiguration = ( CWEPSecuritySettings::TWepMember* ) 
                                                  Fields_Wep_Key_Configuration;
    iTitlesKeyConfiguration = MUTABLE_CAST( TInt*, 
                                                Titles_Wep_Key_Configuration );

    FeatureManager::InitializeLibL();

    ConstructL( R_WEP_SECURITY_SETTINGS_MENUBAR );
    
    // ExecuteLD will PushL( this ), so we have to Pop it...
    CleanupStack::Pop( this ); // this
	
    return ExecuteLD( R_WEPSETTINGS_DIALOG );
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsDlg::OkToExitL
// ---------------------------------------------------------
//
TBool CWEPSecuritySettingsDlg::OkToExitL( TInt aButtonId )
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
        *iEventStore |= CWEPSecuritySettings::EShutDownReq;
        retval = ETrue;
        }
    else if ( aButtonId == EAknSoftkeyBack || aButtonId == EAknCmdExit )
        {
        if ( iSecuritySettings->IsValid() )
            {
            *iEventStore |= CWEPSecuritySettings::EValid;
            retval = ETrue;
            }
        else if ( aButtonId == EAknSoftkeyBack )
            {
            HBufC* stringHolder = StringLoader::LoadL( 
                                        R_WEP_DATA_MISSING, iEikonEnv );
            CleanupStack::PushL( stringHolder );

            CAknQueryDialog *queryDialog = new (ELeave) CAknQueryDialog();

            queryDialog->PrepareLC( R_WEP_SEC_SETT_CONF_QUERY );
            queryDialog->SetPromptL( stringHolder->Des() );
            if ( queryDialog->RunLD() )
                {
                retval = ETrue;
                }
            else
                {
                iActiveTab = iSecuritySettings->KeyInUse();
                iTabGroup->SetActiveTabByIndex( iActiveTab );
                HandleListboxDataChangeL();
                }
            CleanupStack::PopAndDestroy( stringHolder );   // stringHolder
            }
        else
            {
            retval = ETrue;
            }

        if ( aButtonId == EAknCmdExit )
            {
            *iEventStore |= CWEPSecuritySettings::EExitReq;
            }
        }
    else if( aButtonId == EWepSelCmdChange )
        {
        ChangeSettingsL( ETrue );
        retval = EFalse; // don't exit the dialog
        }

    return retval;
}


// ---------------------------------------------------------
// CWEPSecuritySettingsDlg::OfferKeyEventL
// ---------------------------------------------------------
//
TKeyResponse CWEPSecuritySettingsDlg::OfferKeyEventL( 
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
                // as list IS consuming, must handle because it IS the SHUTDOWN...
                // or, a view switch is shutting us down...
                if ( aKeyEvent.iCode == EKeyEscape )
                    {
                    ProcessCommandL( EEikCmdExit );
                    retval = EKeyWasConsumed;
                    }
                else if ( iLevel && ( charCode == EKeyLeftArrow || 
                                      charCode == EKeyRightArrow ) )
                    {
                    if ( iTabGroup )
                        {
                        return iTabGroup->OfferKeyEventL( aKeyEvent, aType );
                        }
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
                    ProcessCommandL( EWepSelCmdChange );
                    retval = EKeyWasConsumed;
                    }
                }
            }
        }

    return retval;
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsDlg::HandleListboxDataChangeL
// ---------------------------------------------------------
//
void CWEPSecuritySettingsDlg::HandleListboxDataChangeL()
    {
    // fill up our new list with data
    CDesCArrayFlat* itemArray = new ( ELeave ) CDesCArrayFlat( 4 );
    CleanupStack::PushL( itemArray );

    if ( iLevel )
        {
        FillListWithDataL( *itemArray, *iFieldsKeyConfiguration,
                           KNumOfFieldsKeyConfiguration,
                           iTitlesKeyConfiguration );

        iNaviPane->ReplaceL( *iNaviDecoratorEmpty, *iNaviDecoratorTabbed );
        }
    else
        {
        FillListWithDataL( *itemArray, *iFieldsMain, KNumOfFieldsMain, 
                           iTitlesMain );
        iNaviPane->ReplaceL( *iNaviDecoratorTabbed, *iNaviDecoratorEmpty );
        }

    iList->Model()->SetItemTextArray( itemArray );
    
    CleanupStack::Pop( itemArray ); // now it is owned by the LB, so pop it
    iItemArray = itemArray;

    iList->HandleItemAdditionL();
    }



// ---------------------------------------------------------
// CWEPSecuritySettingsDlg::ProcessCommandL
// ---------------------------------------------------------
//
void CWEPSecuritySettingsDlg::ProcessCommandL( TInt aCommandId )
    {
    if ( MenuShowing() )
        {
        HideMenu();
        }

    switch ( aCommandId )
        {
        case EWepSelCmdChange:
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
// CWEPSecuritySettingsDlg::HandleListBoxEventL
// ---------------------------------------------------------
//
void CWEPSecuritySettingsDlg::HandleListBoxEventL( CEikListBox* /*aListBox*/,
                                                   TListBoxEvent aEventType )
    {
    switch ( aEventType )
        {
        case EEventEnterKeyPressed:
            // both handled in the same way for now...
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
            __ASSERT_DEBUG( EFalse, Panic( EUnknownCase ) );
            break;
            };
        };
    }




// ---------------------------------------------------------
// CWEPSecuritySettingsDlg::PreLayoutDynInitL()
// ---------------------------------------------------------
//
void CWEPSecuritySettingsDlg::PreLayoutDynInitL()
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

    // Fetch pointer to the default navi pane control
    iNaviPane = ( CAknNavigationControlContainer* ) 
                    statusPane->ControlL( TUid::Uid( EEikStatusPaneUidNavi ) );

    _LIT( KEmpty, "" );
    if ( !iNaviDecoratorEmpty )
        {
        iNaviDecoratorEmpty = iNaviPane->CreateNavigationLabelL( KEmpty );
        }

    if ( !iNaviDecoratorTabbed )
        {
        iNaviDecoratorTabbed = iNaviPane->CreateTabGroupL();
        
        if (iNaviDecoratorTabbed)
            {
            iTabGroup = static_cast< CAknTabGroup* >
                                    ( iNaviDecoratorTabbed->DecoratedControl() );
            
            HBufC16* tabText = iEikonEnv->AllocReadResourceLC( R_WEP_TAB_KEY_1 );
            TPtr localizedTabText( tabText->Des() );
            AknTextUtils::LanguageSpecificNumberConversion( localizedTabText );
            iTabGroup->AddTabL( EWEPSecuritySettingsTab1, *tabText );
            CleanupStack::PopAndDestroy( tabText ); // tabText
            
            tabText = iEikonEnv->AllocReadResourceLC( R_WEP_TAB_KEY_2 );
            localizedTabText.Set( tabText->Des() );
            AknTextUtils::LanguageSpecificNumberConversion( localizedTabText );
            iTabGroup->AddTabL( EWEPSecuritySettingsTab2, *tabText );
            CleanupStack::PopAndDestroy( tabText ); // tabText
            
            tabText = iEikonEnv->AllocReadResourceLC( R_WEP_TAB_KEY_3 );
            localizedTabText.Set( tabText->Des() );
            AknTextUtils::LanguageSpecificNumberConversion( localizedTabText );
            iTabGroup->AddTabL( EWEPSecuritySettingsTab3, *tabText );
            CleanupStack::PopAndDestroy( tabText ); // tabText
            
            tabText = iEikonEnv->AllocReadResourceLC( R_WEP_TAB_KEY_4 );
            localizedTabText.Set( tabText->Des() );
            AknTextUtils::LanguageSpecificNumberConversion( localizedTabText );
            iTabGroup->AddTabL( EWEPSecuritySettingsTab4, *tabText );
            CleanupStack::PopAndDestroy( tabText ); // tabText
            
            iTabGroup->SetTabFixedWidthL( EAknTabWidthWithFourTabs );
            iTabGroup->SetActiveTabByIndex( 0 );
                
            iTabGroup->SetObserver( this );
            }
        }

    iNaviPane->PushL( *iNaviDecoratorEmpty );
    iList = STATIC_CAST( CAknSettingStyleListBox*, 
                                        Control( KWepMainSettingsListboxId ) );

    iList->CreateScrollBarFrameL( ETrue );
    iList->ScrollBarFrame()->SetScrollBarVisibilityL
        ( CEikScrollBarFrame::EOff, CEikScrollBarFrame::EAuto );

    HandleListboxDataChangeL();

    iList->SetCurrentItemIndex( 0 );
    iList->SetListBoxObserver( this );
    }



// ---------------------------------------------------------
// CWEPSecuritySettingsDlg::DynInitMenuPaneL
// ---------------------------------------------------------
//
void CWEPSecuritySettingsDlg::DynInitMenuPaneL( TInt aResourceId, 
                                                CEikMenuPane* aMenuPane )
    {
    CAknDialog::DynInitMenuPaneL( aResourceId, aMenuPane );
    if ( aResourceId == R_WEP_SECURITY_SETTINGS_MENU )
        {
        if( !FeatureManager::FeatureSupported( KFeatureIdHelp ) )
            {
            aMenuPane->DeleteMenuItem( EAknCmdHelp );
            }
        }
    }


//----------------------------------------------------------
// CWEPSecuritySettingsDlg::FillListWithDataL
//----------------------------------------------------------
//
void CWEPSecuritySettingsDlg::FillListWithDataL( CDesCArrayFlat& aItemArray,
                                   const CWEPSecuritySettings::TWepMember& arr, 
                                   TInt aLength,
                                   const TInt* aRes )
    {
    _LIT( KTxtMenuListItemFormat, " \t%S\t\t" );
    const TInt KSpaceAndTabsLength = 4;

    CWEPSecuritySettings::TWepMember* wepMember = 
                       MUTABLE_CAST( CWEPSecuritySettings::TWepMember*, &arr );

    for( TInt i = 0; i < aLength; i++ )
        {
        if ( *wepMember == CWEPSecuritySettings::EWepKeyConfiguration )
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
            }
        else
            {
            HBufC* itemText = CreateTextualListBoxItemL( *wepMember, 
                                                         *aRes );
            CleanupStack::PushL( itemText );
            aItemArray.AppendL( itemText->Des() );
            CleanupStack::PopAndDestroy( itemText );
            }

        wepMember++;
        aRes++;
        }
    }


//----------------------------------------------------------
// CWEPSecuritySettingsDlg::UpdateListBoxItemL
//----------------------------------------------------------
//
void CWEPSecuritySettingsDlg::UpdateListBoxItemL( 
                                    CWEPSecuritySettings::TWepMember aMember, 
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
// CWEPSecuritySettingsDlg::CreateTextualListBoxItemL
//----------------------------------------------------------
//
HBufC* CWEPSecuritySettingsDlg::CreateTextualListBoxItemL( 
                                      CWEPSecuritySettings::TWepMember aMember,
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
        case CWEPSecuritySettings::EWepKeyInUse:
            {
            switch ( iSecuritySettings->KeyInUse() )
                {
                case CWEPSecuritySettings::EKeyNumber1:
                    {
                    valueResourceID = R_WEP_KEY_NUMBER_1;
                    break;
                    }

                case CWEPSecuritySettings::EKeyNumber2:
                    {
                    valueResourceID = R_WEP_KEY_NUMBER_2;
                    break;
                    }

                case CWEPSecuritySettings::EKeyNumber3:
                    {
                    valueResourceID = R_WEP_KEY_NUMBER_3;
                    break;
                    }

                case CWEPSecuritySettings::EKeyNumber4:
                    {
                    valueResourceID = R_WEP_KEY_NUMBER_4;
                    break;
                    }

                default:
                    {
                    valueResourceID = 0;
                    break;
                    }
                }
            break;
            }
        
        case CWEPSecuritySettings::EWepAuthentication:
            {
            switch ( iSecuritySettings->Authentication() )
                {
                case CWEPSecuritySettings::EAuthOpen:
                    {
                    valueResourceID = R_WEP_AUTHENTICATION_OPEN;
                    break;
                    }

                case CWEPSecuritySettings::EAuthShared:
                    {
                    valueResourceID = R_WEP_AUTHENTICATION_SHARED;
                    break;
                    }

                default:
                    {
                    valueResourceID = 0;
                    break;
                    }
                }
            break;
            }

        case CWEPSecuritySettings::EWepKeyLength:
            {
            switch ( iSecuritySettings->KeyLength( iActiveTab ) )
                {
                case CWEPSecuritySettings::E40Bits:
                    {
                    valueResourceID = R_WEP_KEY_LENGTH_64_BITS;
                    break;
                    }

                case CWEPSecuritySettings::E104Bits:
                    {
                    valueResourceID = R_WEP_KEY_LENGTH_128_BITS;
                    break;
                    }

                case CWEPSecuritySettings::E232Bits:
                    {
                    valueResourceID = iSecuritySettings->WEP256Enabled() ? 
                                                R_WEP_KEY_LENGTH_256_BITS : 0;
                    break;
                    }

                default:
                    {
                    valueResourceID = 0;
                    break;
                    }
                }
            break;
            }

        case CWEPSecuritySettings::EWepKeyFormat:
            {
            switch ( iSecuritySettings->KeyFormat( iActiveTab ) )
                {
                case CWEPSecuritySettings::EAscii:
                    {
                    valueResourceID = R_WEP_KEY_FORMAT_ASCII;
                    break;
                    }

                case CWEPSecuritySettings::EHexadecimal:
                    {
                    valueResourceID = R_WEP_KEY_FORMAT_HEX;
                    break;
                    }

                default:
                    {
                    valueResourceID = 0;
                    break;
                    }
                }
            break;
            }

        case CWEPSecuritySettings::EWepKeyData:
            {
            if ( !iSecuritySettings->KeyData( iActiveTab )->Length() )
                {
                valueResourceID = R_WEP_KEY_DATA_MUST_BE_DEFINED;
                }
            else
                {
                valueResourceID = 0;
                }

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
    const TInt KSpaceAndTabsLength = 4;
    _LIT( KTxtCompulsory, "\t*" );

    if ( valueResourceID )
        {
        // Read up value text from resource
        value = iEikonEnv->AllocReadResourceLC( valueResourceID );
        if( aMember == CWEPSecuritySettings::EWepKeyInUse )
            {
            TPtr localizedValue( value->Des() );
            AknTextUtils::LanguageSpecificNumberConversion( localizedValue );
            }
        }
    else
        {
        value = HBufC::NewLC( KStars().Length() );
        value->Des().Copy( KStars ); 
        }

    // Define a heap descriptor to hold all the item text
    // +4 for space and tab characters
    TInt length = title->Length() + value->Length() + KSpaceAndTabsLength;
    if ( aMember == CWEPSecuritySettings::EWepKeyData )  // Compulsory
        {
        length += KTxtCompulsory().Length();
        }

    HBufC* itemText = HBufC::NewLC( length );

    // Define a modifiable pointer descriptor to be able to append text to the
    // non-modifiable heap descriptor itemText
    TPtr itemTextPtr = itemText->Des();
    itemTextPtr.Format( KTxtListItemFormat, title, value );
    if ( aMember == CWEPSecuritySettings::EWepKeyData )  // Compulsory
        {
        itemTextPtr.Append( KTxtCompulsory );
        }
    CleanupStack::Pop( itemText );    // itemtext,

    CleanupStack::PopAndDestroy( 2, title ); // title, value

    return itemText;
    }



//----------------------------------------------------------
// CWEPSecuritySettingsDlg::ShowPopupSettingPageL
//----------------------------------------------------------
//
TBool CWEPSecuritySettingsDlg::ShowPopupSettingPageL( 
                                       CWEPSecuritySettings::TWepMember aData )
    {
    TInt currvalue( 0 );
    TBool retval( EFalse );
    CDesCArrayFlat* items = FillPopupSettingPageLC( aData,  currvalue );

    TInt attr_resid( 0 );

    // not text based ones:
    switch ( aData )
        {
        case CWEPSecuritySettings::EWepKeyInUse:
            {
            attr_resid = R_WEP_KEY_IN_USE;
            break;
            }

        case CWEPSecuritySettings::EWepAuthentication:
            {
            attr_resid = R_WEP_AUTHENTICATION;
            break;
            }

        case CWEPSecuritySettings::EWepKeyLength:
            {
            attr_resid = R_WEP_KEY_LENGTH;
            break;
            }

        case CWEPSecuritySettings::EWepKeyFormat:
            {
            attr_resid = R_WEP_KEY_FORMAT;
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
// CWEPSecuritySettingsDlg::ShowPopupTextSettingPageL
//----------------------------------------------------------
//
TBool CWEPSecuritySettingsDlg::ShowPopupTextSettingPageL()
    {
    TBool retval( EFalse );

    CWEPSecuritySettings::TWEPKeyFormat keyFormat = 
                                    iSecuritySettings->KeyFormat( iActiveTab );
    TInt expectedLength = iSecuritySettings->ExpectedLengthOfKeyData( 
                                iSecuritySettings->KeyLength( iActiveTab ) );

    if ( keyFormat == CWEPSecuritySettings::EAscii )
        {
        expectedLength /= KAsciiHexRatio; //Ascii key is half the length of Hex
        }

    HBufC16* bufKeyData = HBufC16::NewLC( expectedLength );
    TPtr16 ptrKeyData( bufKeyData->Des() );

    TBool showPage( ETrue );
    while ( showPage )
        {
        CWEPKeyDataTextSettingPage* dlg = 
            new( ELeave )CWEPKeyDataTextSettingPage( ptrKeyData, 
                                                     expectedLength,
                                                     keyFormat );

        if ( dlg->ExecuteLD( CAknSettingPage::EUpdateWhenAccepted ) )
            {
            HBufC8* buf8 = HBufC8::NewLC( bufKeyData->Des().Length() );
            buf8->Des().Copy( bufKeyData->Des() ); 

            TInt err = iSecuritySettings->VerifyKeyData( *buf8, expectedLength,
                                iSecuritySettings->KeyFormat( iActiveTab ) );
            if ( err == KErrNone )
                {
                if ( keyFormat == CWEPSecuritySettings::EAscii )
                    {
                    HBufC8* buf8Conv = 
                                HBufC8::NewLC( bufKeyData->Des().Length()
                                                            * KAsciiHexRatio );
                                        // Ascii key is half the length of Hex

                    iSecuritySettings->ConvertAsciiToHex( buf8->Des(), 
                                                          buf8Conv );
                    iSecuritySettings->SetKeyData( iActiveTab, 
                                                   buf8Conv->Des() );
                    CleanupStack::PopAndDestroy( buf8Conv ); // buf8Conv
                    }
                else
                    {
                    iSecuritySettings->SetKeyData( iActiveTab, buf8->Des() );
                    }

                retval = ETrue;
                showPage = EFalse;
                }
            else
                {
                HBufC* stringLabel;
                
                if ( err == KErrInvalidLength )
                    {
                    stringLabel = StringLoader::LoadL( R_INFO_WEP_KEY_TOO_SHORT,
                                                       expectedLength, 
                                                       iEikonEnv );
                    }
                else
                    {
                    stringLabel = StringLoader::LoadL( 
                                                R_INFO_WEP_KEY_ILLEGAL_CHARS,
                                                iEikonEnv );
                    }

                CleanupStack::PushL( stringLabel );

	            CAknInformationNote* dialog = new (ELeave)CAknInformationNote( 
                                                                        ETrue );
                CleanupStack::Pop( stringLabel );

                dialog->ExecuteLD( *stringLabel );

                delete stringLabel;   // stringLabel

                ptrKeyData.Zero();
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
// CWEPSecuritySettingsDlg::FillPopupSettingPageLC
// ---------------------------------------------------------
//
CDesCArrayFlat* CWEPSecuritySettingsDlg::FillPopupSettingPageLC( 
                                       CWEPSecuritySettings::TWepMember aData,
                                       TInt& aCurrvalue )
    {
    CDesCArrayFlat* items = new( ELeave)CDesCArrayFlat( 1 );
    CleanupStack::PushL( items );

    switch ( aData )
        {
        case CWEPSecuritySettings::EWepKeyInUse:
            {
            RBuf16 convert( iEikonEnv->AllocReadResourceL( 
                                                        R_WEP_KEY_NUMBER_1 ) );
            AknTextUtils::LanguageSpecificNumberConversion( convert );
            items->AppendL( convert );
            convert.Close();
            
            convert.Assign( iEikonEnv->AllocReadResourceL(
                                                        R_WEP_KEY_NUMBER_2 ) );
            AknTextUtils::LanguageSpecificNumberConversion( convert );
            items->AppendL( convert );
            convert.Close();
            
            convert.Assign( iEikonEnv->AllocReadResourceL(
                                                        R_WEP_KEY_NUMBER_3 ) );
            AknTextUtils::LanguageSpecificNumberConversion( convert );
            items->AppendL( convert );
            convert.Close();
            
            convert.Assign( iEikonEnv->AllocReadResourceL(
                                                        R_WEP_KEY_NUMBER_4 ) );
            AknTextUtils::LanguageSpecificNumberConversion( convert );
            items->AppendL( convert );
            convert.Close();

            aCurrvalue = iSecuritySettings->KeyInUse();
            break;
            }

        case CWEPSecuritySettings::EWepAuthentication:
            {
            items->AppendL( *iEikonEnv->AllocReadResourceLC( 
                                            R_WEP_AUTHENTICATION_OPEN ) );
            CleanupStack::PopAndDestroy();
            items->AppendL( *iEikonEnv->AllocReadResourceLC( 
                                            R_WEP_AUTHENTICATION_SHARED ) );
            CleanupStack::PopAndDestroy();

            aCurrvalue = iSecuritySettings->Authentication();
            break;
            }

        case CWEPSecuritySettings::EWepKeyLength:
            {
            items->AppendL( *iEikonEnv->AllocReadResourceLC( 
                                            R_WEP_KEY_LENGTH_64_BITS ) );
            CleanupStack::PopAndDestroy();
            items->AppendL( *iEikonEnv->AllocReadResourceLC( 
                                            R_WEP_KEY_LENGTH_128_BITS ) );
            CleanupStack::PopAndDestroy();

            if ( iSecuritySettings->WEP256Enabled() )
                {
                items->AppendL( *iEikonEnv->AllocReadResourceLC( 
                                            R_WEP_KEY_LENGTH_256_BITS ) );
                CleanupStack::PopAndDestroy();
                }

            aCurrvalue = iSecuritySettings->KeyLength( iActiveTab );
            break;
            }

        case CWEPSecuritySettings::EWepKeyFormat:
            {
            items->AppendL( *iEikonEnv->AllocReadResourceLC( 
                                            R_WEP_KEY_FORMAT_ASCII ) );
            CleanupStack::PopAndDestroy();
            items->AppendL( *iEikonEnv->AllocReadResourceLC( 
                                            R_WEP_KEY_FORMAT_HEX ) );
            CleanupStack::PopAndDestroy();

            aCurrvalue = iSecuritySettings->KeyFormat( iActiveTab );
            break;
            }

        default:
            {
            __ASSERT_DEBUG( EFalse, Panic ( EUnknownCase ) );
            break;
            }
        }
    return items;
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsDlg::UpdateFromPopupSettingPage
// ---------------------------------------------------------
//
TBool CWEPSecuritySettingsDlg::UpdateFromPopupSettingPage( 
                                        CWEPSecuritySettings::TWepMember aData,
                                        TInt aCurrvalue )
    {
    TBool retVal( EFalse );

    switch ( aData )
        {
        case CWEPSecuritySettings::EWepKeyInUse:
            {
            if ( iSecuritySettings->KeyInUse() != 
                             ( CWEPSecuritySettings::TWEPKeyInUse )aCurrvalue )
                {
                iSecuritySettings->SetKeyInUse( 
                            ( CWEPSecuritySettings::TWEPKeyInUse )aCurrvalue );
                retVal = ETrue;
                }
            break;
            }

        case CWEPSecuritySettings::EWepAuthentication:
            {
            if ( iSecuritySettings->Authentication() != 
                 ( CWEPSecuritySettings::TWEPAuthentication )aCurrvalue )
                {
                iSecuritySettings->SetAuthentication( 
                      ( CWEPSecuritySettings::TWEPAuthentication )aCurrvalue );
                retVal = ETrue;
                }
            break;
            }

        case CWEPSecuritySettings::EWepKeyLength:
            {
            if ( iSecuritySettings->KeyLength( iActiveTab ) != 
                 ( CWEPSecuritySettings::TWEPKeyLength )aCurrvalue )
                {
                iSecuritySettings->SetKeyLength( iActiveTab, 
                           ( CWEPSecuritySettings::TWEPKeyLength )aCurrvalue );
                retVal = ETrue;
                }
            break;
            }

        case CWEPSecuritySettings::EWepKeyFormat:
            {
            if ( iSecuritySettings->KeyFormat( iActiveTab ) != 
                 ( CWEPSecuritySettings::TWEPKeyFormat )aCurrvalue )
                {
                iSecuritySettings->SetKeyFormat( iActiveTab, 
                           ( CWEPSecuritySettings::TWEPKeyFormat )aCurrvalue );
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
// CWEPSecuritySettingsDlg::ChangeSettingsL
//----------------------------------------------------------
//
void CWEPSecuritySettingsDlg::ChangeSettingsL( TBool aQuick )
    {
    TInt itemIndex = ( Max( iList->CurrentItemIndex(), 0 ) );
    CWEPSecuritySettings::TWepMember* ptr = 
                  (iLevel ? iFieldsKeyConfiguration : iFieldsMain) + itemIndex;
    TInt* tptr = ( iLevel ? iTitlesKeyConfiguration : iTitlesMain ) + itemIndex;

    const TInt KShiftFromKeyLengthToKeyData = 2;
    switch ( *ptr  )
        {
        case CWEPSecuritySettings::EWepKeyInUse:
        case CWEPSecuritySettings::EWepKeyLength:
            { // Pop-up setting item
            if ( ShowPopupSettingPageL( *ptr ) )
                {
                UpdateListBoxItemL( *ptr, *tptr, itemIndex );
                *iEventStore |= CWEPSecuritySettings::EModified;
                if ( *ptr == CWEPSecuritySettings::EWepKeyLength )
                    {
                    ptr += KShiftFromKeyLengthToKeyData;
                    tptr += KShiftFromKeyLengthToKeyData;
                    iSecuritySettings->KeyData( iActiveTab )->Zero();
                    UpdateListBoxItemL( *ptr, *tptr, 
                                    itemIndex+KShiftFromKeyLengthToKeyData );
                    iList->SetCurrentItemIndexAndDraw( itemIndex+
                                                KShiftFromKeyLengthToKeyData );
                    }
                }
            break;
            }

        case CWEPSecuritySettings::EWepAuthentication:
        case CWEPSecuritySettings::EWepKeyFormat:
            { // Setting item with two available values
            TBool changed( ETrue );
            if ( aQuick )
                {
                InvertSettings( *ptr );
                }
            else
                {
                changed = ShowPopupSettingPageL( *ptr );
                }

            if ( changed )
                {
                UpdateListBoxItemL( *ptr, *tptr, itemIndex );
                if ( *ptr == CWEPSecuritySettings::EWepAuthentication )
                    {
                    *iEventStore |= CWEPSecuritySettings::EModified;
                    }
                }
            break;
            }

        case CWEPSecuritySettings::EWepKeyData:
            { // Text setting item
            if ( ShowPopupTextSettingPageL() )
                {
                UpdateListBoxItemL( *ptr, *tptr, itemIndex );
                *iEventStore |= CWEPSecuritySettings::EModified;
                }
            break;
            }

        case CWEPSecuritySettings::EWepKeyConfiguration:
            {
            iLevel = 1;

            iActiveTab = iSecuritySettings->KeyInUse();
            iTabGroup->SetActiveTabByIndex( iActiveTab );

            HandleListboxDataChangeL();
            itemIndex = 0;

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




//----------------------------------------------------------
// CWEPSecuritySettingsDlg::InvertSettings
//----------------------------------------------------------
//
void CWEPSecuritySettingsDlg::InvertSettings( CWEPSecuritySettings::TWepMember 
                                                                  aDataMember )
    {
    if ( aDataMember == CWEPSecuritySettings::EWepAuthentication )
        {
        if ( iSecuritySettings->Authentication() == 
                                              CWEPSecuritySettings::EAuthOpen )
            {
            iSecuritySettings->SetAuthentication( 
                                            CWEPSecuritySettings::EAuthShared );
            }
        else
            {
            iSecuritySettings->SetAuthentication( 
                                              CWEPSecuritySettings::EAuthOpen );
            }
        }
    else if ( aDataMember == CWEPSecuritySettings::EWepKeyFormat )
        {
        if ( iSecuritySettings->KeyFormat( iActiveTab ) == 
                                                 CWEPSecuritySettings::EAscii )
            {
            iSecuritySettings->SetKeyFormat( iActiveTab, 
                                          CWEPSecuritySettings::EHexadecimal );
            }
        else
            {
            iSecuritySettings->SetKeyFormat( iActiveTab, 
                                                 CWEPSecuritySettings::EAscii );
            }
        }
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsDlg::GetHelpContext
// ---------------------------------------------------------
//
void CWEPSecuritySettingsDlg::GetHelpContext( TCoeHelpContext& /* aContext */ ) const
    {
    // Avkon help dependencies removed, hence do nothing
    return;
    }


// -----------------------------------------------------------------------------
// CWEPSecuritySettingsDlg::TabChangedL( TInt aIndex )
// -----------------------------------------------------------------------------
// 
void CWEPSecuritySettingsDlg::TabChangedL( TInt aIndex )
    {
    iActiveTab = aIndex;
    HandleListboxDataChangeL();
    }


// End of File
