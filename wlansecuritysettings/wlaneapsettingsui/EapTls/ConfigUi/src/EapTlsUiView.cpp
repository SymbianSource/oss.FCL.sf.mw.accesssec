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
* Description: Implementation of EAP TLS UI settings dialog
*
*/

/*
* %version: 41 %
*/

// INCLUDE FILES
#include <eikdialg.h>
#include <AknDialog.h>
#include <aknlists.h>
#include "EapTlsUiView.h"
#include "EapTlsUi.hrh"
#include <eaptlsui.rsg>
#include <akntextsettingpage.h>
#include <aknsettingitemlist.h>
#include "EapTlsUiSettingArray.h"
#include <aknnavi.h>
#include <akntabgrp.h>
#include <aknnavide.h>
#include <aknnotewrappers.h> // TEMPORARY, for info message...
#include <aknradiobuttonsettingpage.h>
#include <EapTlsPeapUiConnection.h>
#include <EapTlsPeapUiDataConnection.h>
#include <EapTlsPeapUiCipherSuites.h>
#include <EapTlsPeapUiEapTypes.h>
#include <EapTlsPeapUiCertificates.h>
#include <AknIconArray.h>
#include <AknsUtils.h>

#include <featmgr.h>
#include <hlplch.h>
#include <csxhelp/cp.hlp.hrh>


// CONSTANTS
// UID of general settings app, in which help texts are included
const TUid KHelpUidPlugin = { 0x100058EC };

static const TInt KSuiteArrayGranularity = 4;
static const TInt KCertificateArrayGranularity = 5;
static const TInt KMaxLengthOfSuiteName = 255;

_LIT( KNameSeparator, " " );
_LIT( KEmptyString, "" );

/* This is the maximum length of a certificate's full name, includes
label, primary and secondary names */
const TUint32 KMaxFullCertLabelLength = KMaxCertLabelLength + 2 * 
                                    KMaxNameLength + 1; // 1 is for separator.

// MODULE DATA STRUCTURES
enum TPageIds
    {
    ESettingsPage = 0,
    ECipherSuitePage
    };

enum TSettingIds
    {
    EUserCertificateItem = 0,
    ECaCertificateItem,
    EUsernameInUseItem,
    EUsernameItem,
    ERealmInUseItem,
    ERealmItem
    };


// ============================ MEMBER FUNCTIONS ===============================

// -----------------------------------------------------------------------------
// CEapTlsUiDialog::CEapTlsUiDialog
// -----------------------------------------------------------------------------
//
CEapTlsUiDialog::CEapTlsUiDialog( CEapTlsPeapUiConnection* aConnection, 
								  TInt& aButtonId ) 
: CAknDialog(),
  iConnection( aConnection ),
  iDataConnection( 0 ), 
  iCipherSuites( 0 ), 
  iCertificates( 0 ),
  iUserCertificateListBox( 0 ), 
  iCaCertificateListBox( 0 ), 
  iCipherSuiteListBox( 0 ), 
  iSettingArray( 0 ), 
  iSettingListBox( 0 ), 
  iCipherSuitesViewArray( 0 ), 
  iPreviousText( 0 ), 
  iButtonId( &aButtonId ),
  iIsUIConstructionCompleted( EFalse )
    {
    }


// ---------------------------------------------------------
// CEapTlsUiDialog::ConstructAndRunLD
// ---------------------------------------------------------
//
TInt CEapTlsUiDialog::ConstructAndRunLD( TInt aResourceId )
    {
    CleanupStack::PushL( this );

    iSettingArray = CEapTlsSettingItemArray::NewL();

    User::LeaveIfError( iConnection->Connect() );
    
    // Basic data
    iDataConnection = iConnection->GetDataConnection();
    if ( iDataConnection == 0 )
        {
        User::Leave( KErrNoMemory );
        }
    User::LeaveIfError( iDataConnection->Open() );
    User::LeaveIfError( iDataConnection->GetData( &iUiData ) );
    
    // Cipher suites
    iCipherSuites = iConnection->GetCipherSuiteConnection();
    if ( iCipherSuites == 0 )
        {
        User::Leave( KErrNoMemory );
        }
    User::LeaveIfError( iCipherSuites->Open() );
    User::LeaveIfError( iCipherSuites->GetCipherSuites( &iUiCipherSuites ) );

    iCipherSuitesViewArray = new( ELeave ) CDesCArrayFlat( 
                                                    KSuiteArrayGranularity );

    FeatureManager::InitializeLibL();
    
    ConstructL( R_TLS_MENUBAR );
    
    // ExecuteLD will PushL( this ), so we have to Pop it...
    CleanupStack::Pop( this ); // this
    
    return CAknDialog::ExecuteLD( aResourceId );
    }
    

// -----------------------------------------------------------------------------
// CEapTlsUiDialog::OfferKeyEventL
// -----------------------------------------------------------------------------
//
TKeyResponse CEapTlsUiDialog::OfferKeyEventL( const TKeyEvent& aKeyEvent,
                                                    TEventCode aType )
    {
    TKeyResponse result( EKeyWasNotConsumed );
    
    TInt pageId = ActivePageId();
    if ( aType == EEventKey && pageId == KEAPTLSCIPHERPAGE )
        {
        TInt indexBefore = iCipherSuiteListBox->CurrentItemIndex();
        
        // Handle Enter key here, since it doesn't seem to convert into
        // the proper command id via the normal route
        // (maybe some Avkon support for Enter key is still missing in
        // S60 3.2 2008_wk22)
        if ( aKeyEvent.iCode == EKeyEnter )
            {
            if ( ( *iUiCipherSuites )[indexBefore].iIsEnabled )
                {
                OkToExitL( ETlsUiCmdDisable );
                }
            else
                {
                OkToExitL( ETlsUiCmdEnable );
                }
                
            result = EKeyWasConsumed;
            }
        else
            {        
            result = CAknDialog::OfferKeyEventL( aKeyEvent, aType );
            }
            
        TInt indexAfter = iCipherSuiteListBox->CurrentItemIndex();

        if ( indexBefore != indexAfter )
            {
            CEikButtonGroupContainer& cba = ButtonGroupContainer();
            if( ( *iUiCipherSuites )[ indexAfter ].iIsEnabled )
                {
                cba.SetCommandSetL( R_TLS_UI_SOFTKEYS_OPTIONS_BACK_DISABLE );
                }
            else
                {
                cba.SetCommandSetL( R_TLS_UI_SOFTKEYS_OPTIONS_BACK_ENABLE );
                }
            
            cba.DrawDeferred();
            }
        }
    else
        {
        result = CAknDialog::OfferKeyEventL( aKeyEvent, aType );
        }

    return result;
    }
    

// -----------------------------------------------------------------------------
// CEapTlsUiDialog::~CEapTlsUiDialog
// -----------------------------------------------------------------------------
//
CEapTlsUiDialog::~CEapTlsUiDialog()
    {
    if ( iSettingArray )
        {
        iSettingArray->Array()->ResetAndDestroy();
        }

    delete iSettingArray;
    iSettingListBox = 0;

    iDataConnection->Close();
    delete iDataConnection;

    iCipherSuites->Close();
    delete iCipherSuites;
    
    iCertificates->Close();
    delete iCertificates;
    
    iConnection->Close();
        
    iCipherSuitesViewArray->Reset();
    delete iCipherSuitesViewArray;
    
    delete iPreviousText;
    
    FeatureManager::UnInitializeLib();
    }


// ---------------------------------------------------------
// CEapTlsUiDialog::HandleListBoxEventL
// ---------------------------------------------------------
//
void CEapTlsUiDialog::HandleListBoxEventL( CEikListBox* aListBox,
                                           TListBoxEvent aEventType )
    {
    switch ( aEventType )
        {
        case EEventEnterKeyPressed:
        case EEventItemSingleClicked:
            {
            if ( aListBox == iSettingListBox )
                {
                OkToExitL( ETlsUiCmdChange );                 
                }
                
            else if ( aListBox == iCipherSuiteListBox )
                {
                TInt index = iCipherSuiteListBox->CurrentItemIndex();
                if( iUiCipherSuites->At( index ).iIsEnabled )
                    {
                    OkToExitL( ETlsUiCmdDisable );
                    }
                else
                    {
                    OkToExitL( ETlsUiCmdEnable );
                    }                 
                }
                
            else
                {
                // Do nothing; we should never end up here
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


// -----------------------------------------------------------------------------
// CEapTlsUiDialog::PreLayoutDynInitL
// -----------------------------------------------------------------------------
//
void CEapTlsUiDialog::PreLayoutDynInitL()
    {
    // Change title
    ChangeTitleL( ETrue );
    
    iSettingListBox = static_cast<CAknSettingStyleListBox*>( 
                                    ControlOrNull( ETlsSettingsListbox ) );
    iSettingListBox->SetComponentsToInheritVisibility( ETrue );

    iCipherSuiteListBox = static_cast<CAknSingleGraphicStyleListBox*>( 
                            ControlOrNull( ETlsSettingsCipherSuiteListbox ) );
    iCipherSuiteListBox->SetComponentsToInheritVisibility( ETrue );
        
      // Certificates
    iCertificates = iConnection->GetCertificateConnection( this );
    User::LeaveIfError( iCertificates->Open() );
    iCertificates->GetCertificates( &iUiUserCertificates, &iUiCACertificates );
    }


// -----------------------------------------------------------------------------
// CEapTlsUiDialog::CompleteReadCertificates
// -----------------------------------------------------------------------------
//
void CEapTlsUiDialog::CompleteReadCertificates( const TInt aResult )
    {
    if ( aResult == KErrNone ) // Certifiocates are received from core
        {
        TRAPD( err, CompleteUiConstructionL() );
        if ( err != KErrNone)
            {
            TRAP_IGNORE( TryExitL( KErrCancel ) );
            }
        }
    else
        {
        TRAP_IGNORE( TryExitL( KErrCancel ) );
        }
    }


// -----------------------------------------------------------------------------
// CEapTlsUiDialog::CompleteUiConstructionL
// -----------------------------------------------------------------------------
//
void CEapTlsUiDialog::CompleteUiConstructionL()
    {
    // Initialize setting page 
    iSettingListBox = static_cast<CAknSettingStyleListBox*>( 
                                        ControlOrNull( ETlsSettingsListbox ) );
    iSettingListBox->SetMopParent( this );
    iSettingListBox->CreateScrollBarFrameL( ETrue );
    iSettingListBox->ScrollBarFrame()->SetScrollBarVisibilityL( 
                                                CEikScrollBarFrame::EOff,
                                                CEikScrollBarFrame::EAuto );
    iSettingListBox->SetListBoxObserver( this );                                                
    DrawSettingsListL();

    // Initialize cipher suites page
    iCipherSuiteListBox = static_cast<CAknSingleGraphicStyleListBox*>( 
                            ControlOrNull( ETlsSettingsCipherSuiteListbox ) );
    iCipherSuiteListBox->CreateScrollBarFrameL( ETrue );
    iCipherSuiteListBox->ScrollBarFrame()->SetScrollBarVisibilityL( 
                                                CEikScrollBarFrame::EOff,
                                                CEikScrollBarFrame::EAuto );
    iCipherSuiteListBox->UpdateScrollBarsL();
    
    iCipherSuiteListBox->Model()->SetOwnershipType( ELbmDoesNotOwnItemArray );
    iCipherSuiteListBox->SetListBoxObserver( this );    

    //Following deletes internal array created from resources. 
    // To prevent memory leak.
    MDesCArray* internalArray = iCipherSuiteListBox->Model()->ItemTextArray();
    delete internalArray;
    
    SetIconsL();
    DrawCipherSuitesL();
    
    iIsUIConstructionCompleted = ETrue;
    }
    

// -----------------------------------------------------------------------------
// CEapTlsUiDialog::PostLayoutDynInitL
// -----------------------------------------------------------------------------
//
void CEapTlsUiDialog::PostLayoutDynInitL()
    {
    TUid naviPaneUid;
    naviPaneUid.iUid = EEikStatusPaneUidNavi;

    CEikStatusPane* statusPane = iEikonEnv->AppUiFactory()->StatusPane();
    CEikStatusPaneBase::TPaneCapabilities subPane = 
                                statusPane->PaneCapabilities( naviPaneUid );
    if ( subPane.IsPresent() && subPane.IsAppOwned() )
        {
        CAknNavigationControlContainer* naviPane = 
                                static_cast<CAknNavigationControlContainer*>(
                                        statusPane->ControlL( naviPaneUid ) );
        CAknNavigationDecorator* naviDecorator = naviPane->ResourceDecorator();
        if ( naviDecorator )
            {
            CAknTabGroup* tabGroup = static_cast<CAknTabGroup*>( 
                                        naviDecorator->DecoratedControl() );
            tabGroup->SetActiveTabById( 0 ); 
            tabGroup->SetTabFixedWidthL( KTabWidthWithOneTab );
            }
        }
    }


// -----------------------------------------------------------------------------
// CEapTlsUiDialog::ChangeTitleL
// -----------------------------------------------------------------------------
//
void CEapTlsUiDialog::ChangeTitleL( TBool aIsStarted )
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
                                                        R_TLS_SETTINGS_TITLE );
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
// CEapTlsUiDialog::OkToExitL
// -----------------------------------------------------------------------------
//
TBool CEapTlsUiDialog::OkToExitL( TInt aButtonId )
    {
    TBool ret( EFalse );
    switch ( aButtonId )
        {
        case EEikBidOk:
            {
            if( iIsUIConstructionCompleted )
                {
                TPageIds index = static_cast<TPageIds>( ActivePageIndex() );
                if ( index == ESettingsPage )
                    {
                    ShowSettingPageL( EFalse );
                    }
                }
            else
                {
                #if defined(_DEBUG) || defined(DEBUG)
				RDebug::Print(_L("CEapTlsUiDialog::OkToExitL - UI not ready - Ignoring key press.\n") );
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
            
        case ETlsUiCmdChange:
            {
            TPageIds index = static_cast<TPageIds>( ActivePageIndex() );
            if ( index == ESettingsPage )
                {
                if( iIsUIConstructionCompleted )
    				{
        			ShowSettingPageL( EFalse );
    				}
    			else
    			    {
    				#if defined(_DEBUG) || defined(DEBUG)
    				RDebug::Print(_L("CEapPeapUiDialog::ProcessCommandL - UI not ready - Ignoring key press.\n") );
    				#endif
    			    }
                }
            break;
            }
        case ETlsUiCmdEnable:
        case ETlsUiCmdDisable:
            {
            ProcessCommandL( aButtonId );
            ret = EFalse;
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
// CEapTlsUiDialog::DrawSettingsListL
// -----------------------------------------------------------------------------
//
void CEapTlsUiDialog::DrawSettingsListL()
    {  
    iSettingArray->Array()->ResetAndDestroy();
    TInt ordinal = 0;

    TInt activeUserCertificate = CheckActiveUserCertificate();
    TBuf<KMaxFullCertLabelLength> aActiveuserCertificateName = KEmptyString();
    if ( activeUserCertificate != KErrNotFound )
        {
		TBuf<KMaxFullCertLabelLength> text;
		GetFullCertLabel( 
                iUiUserCertificates->At( activeUserCertificate ).iCertEntry,
                text );
		aActiveuserCertificateName.Copy( text );		
        }
    else
        {
        TDesC* notDefinedText = iEikonEnv->AllocReadResourceLC( 
                                                        R_TLS_NOT_DEFINED );
        aActiveuserCertificateName.Copy( *notDefinedText );
        CleanupStack::PopAndDestroy( notDefinedText );
        }

    iSettingArray->AddTextItemL( aActiveuserCertificateName,
                                 ETlsSettingsUserCert,
                                 R_TLS_USER_CERT_SETTING,
                                 R_TLS_USERNAME_PAGE,
                                 NULL,
                                 ordinal++ );

    TInt activeCaCertificate = CheckActiveCaCertificate();
    TBuf<KMaxFullCertLabelLength> aActiveCaCertificateName = KEmptyString();
    if ( activeCaCertificate != KErrNotFound )
        {
		TBuf<KMaxFullCertLabelLength> text;
		GetFullCertLabel(
                    iUiCACertificates->At( activeCaCertificate ).iCertEntry, 
                    text );
		aActiveCaCertificateName.Copy( text );				
        }
    else
        {
        TDesC* notDefinedText = iEikonEnv->AllocReadResourceLC( 
                                                        R_TLS_NOT_DEFINED );
        aActiveCaCertificateName.Copy( *notDefinedText );
        CleanupStack::PopAndDestroy( notDefinedText );                
        }

    iSettingArray->AddTextItemL( aActiveCaCertificateName,
                                 ETlsSettingsCaCert,
                                 R_TLS_CA_CERT_SETTING,
                                 R_TLS_USERNAME_PAGE,
                                 NULL,
                                 ordinal++ );

    iSettingArray->AddBinarySettingItemL( R_TLS_DISPLAY_AUTOUSECONF_PAGE,
                                          R_TLS_USERNAME_INUSESTRING, 
                                          R_TLS_USERNAME_AUTOUSECONF_TEXTS,
                                          ordinal++,
                                          *iUiData->GetUseManualUsername() );
                                
    iSettingArray->AddTextItemL( iUiData->GetManualUsername(),
                                 ETlsTabSheetSettingsUsername,
                                 R_TLS_USERNAME_STRING,
                                 R_TLS_USERNAME_PAGE,
                                 NULL,
                                 ordinal++ );

    iSettingArray->AddBinarySettingItemL( R_TLS_DISPLAY_AUTOUSECONF_PAGE, 
                                          R_TLS_REALM_INUSESTRING, 
                                          R_TLS_REALM_AUTOUSECONF_TEXTS,
                                          ordinal++,
                                          *iUiData->GetUseManualRealm() );    

    iSettingArray->AddTextItemL( iUiData->GetManualRealm(),
                                 ETlsTabSheetSettingsRealm,
                                 R_TLS_REALM_STRING,
                                 R_TLS_REALM_PAGE,
                                 NULL,
                                 ordinal++ );

    iSettingArray->AddBinarySettingItemL( R_TLS_DISPLAY_AUTOUSECONF_PAGE,
                                          R_TLS_TLS_PRIVACY_STRING, 
                                          R_TLS_TLS_PRIVACY_AUTOUSECONF_TEXTS,
                                          ordinal++,
                                          *iUiData->GetTlsPrivacy() );
        
    iSettingListBox->Model()->SetItemTextArray( iSettingArray->Array() );
    iSettingListBox->Model()->SetOwnershipType( ELbmDoesNotOwnItemArray );
    iSettingArray->Array()->RecalculateVisibleIndicesL();
    iSettingListBox->HandleItemAdditionL();
    iSettingListBox->UpdateScrollBarsL();
    }


// -----------------------------------------------------------------------------
// CEapTlsUiDialog::DynInitMenuPaneL
// -----------------------------------------------------------------------------
//
void CEapTlsUiDialog::DynInitMenuPaneL( TInt aResourceId, 
                                        CEikMenuPane* aMenuPane )
    {
    CAknDialog::DynInitMenuPaneL( aResourceId, aMenuPane );

    if ( aMenuPane && aResourceId == R_TLS_MENU_PANE )
        {
        if ( !FeatureManager::FeatureSupported( KFeatureIdHelp ) )
            {
            aMenuPane->DeleteMenuItem( EAknCmdHelp );
            }

        TPageIds index = static_cast<TPageIds>( ActivePageIndex() );
        if ( index == ESettingsPage )
            {
            aMenuPane->SetItemDimmed( ETlsUiCmdEnable,  ETrue );
            aMenuPane->SetItemDimmed( ETlsUiCmdDisable, ETrue );
            }
        else if ( index == ECipherSuitePage )
            {
            aMenuPane->SetItemDimmed( ETlsUiCmdChange, ETrue );

            if ( iCipherSuitesViewArray->Count() > 0 )
                {
                TInt currIndex = iCipherSuiteListBox->CurrentItemIndex();
                TBool enabled = iUiCipherSuites->At( currIndex ).iIsEnabled;

                // Hide either "Enable" or "Disable", as appropriate.
                aMenuPane->SetItemDimmed( ETlsUiCmdEnable,  enabled );
                aMenuPane->SetItemDimmed( ETlsUiCmdDisable, !enabled );
                }
            else
                {
                aMenuPane->SetItemDimmed( ETlsUiCmdEnable,  ETrue );
                aMenuPane->SetItemDimmed( ETlsUiCmdDisable, ETrue );
                }
            }
        }
    }


// -----------------------------------------------------------------------------
// CEapTlsUiDialog::ProcessCommandL
// -----------------------------------------------------------------------------
//
void CEapTlsUiDialog::ProcessCommandL( TInt aCommand )
    {
    if ( MenuShowing() )
        {
        HideMenu();
        }

    TPageIds pageIndex = static_cast<TPageIds>( ActivePageIndex() );
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

        case ETlsUiCmdChange:
            {
            if ( pageIndex == ESettingsPage )
                {
                if( iIsUIConstructionCompleted )
    				{
        			ShowSettingPageL( ETrue );
    				}
    			else
    			    {
    				#if defined(_DEBUG) || defined(DEBUG)
    				RDebug::Print(_L("CEapTlsUiDialog::ProcessCommandL - UI not ready - Ignoring key press.\n") );
    				#endif						
    			    }
                }    
            break;
            }

        case ETlsUiCmdEnable:
            {
            if ( pageIndex == ECipherSuitePage )    // Safety check in tls.
                {
                TInt index = iCipherSuiteListBox->CurrentItemIndex();
                iUiCipherSuites->At( index ).iIsEnabled = ETrue;
                iCipherSuites->Update();
                DrawCipherSuitesL();
                CEikButtonGroupContainer& cba = ButtonGroupContainer();
                cba.SetCommandSetL( R_TLS_UI_SOFTKEYS_OPTIONS_BACK_DISABLE );
                cba.DrawDeferred();
                }
            break;
            }

        case ETlsUiCmdDisable:
            {
            if ( pageIndex == ECipherSuitePage )    // Safety check in tls.
                {
                TInt index = iCipherSuiteListBox->CurrentItemIndex();
                iUiCipherSuites->At( index ).iIsEnabled = EFalse;
                iCipherSuites->Update();                
                DrawCipherSuitesL();
                CEikButtonGroupContainer& cba = ButtonGroupContainer();
                cba.SetCommandSetL( R_TLS_UI_SOFTKEYS_OPTIONS_BACK_ENABLE );
                cba.DrawDeferred();
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
// CEapTlsUiDialog::PageChangedL
// -----------------------------------------------------------------------------
//
void CEapTlsUiDialog::PageChangedL( TInt aPageId )
    {
    if ( !iIsUIConstructionCompleted )
        {
        return;
        }
    
    if ( aPageId == KEAPTLSSETTINGSPAGE )
        {
        if (iSettingListBox->ScrollBarFrame())
            {
            iSettingListBox->ScrollBarFrame()->ComponentControl(0)->MakeVisible(ETrue);
            }
        if (iCipherSuiteListBox->ScrollBarFrame())
            {
            iCipherSuiteListBox->ScrollBarFrame()->ComponentControl(0)->MakeVisible(EFalse);
            }
        }

    else if ( aPageId == KEAPTLSCIPHERPAGE )
        {
        if (iSettingListBox->ScrollBarFrame())
            {
            iSettingListBox->ScrollBarFrame()->ComponentControl(0)->MakeVisible(EFalse);
            }
        if (iCipherSuiteListBox->ScrollBarFrame())
            {
            iCipherSuiteListBox->ScrollBarFrame()->ComponentControl(0)->MakeVisible(ETrue);
            }
        }
        
    CEikButtonGroupContainer& cba = ButtonGroupContainer();
    if( aPageId == KEAPTLSSETTINGSPAGE )
        {
        cba.SetCommandSetL( R_TLS_UI_SOFTKEYS_OPTIONS_BACK_EDIT );
        }
    else if( aPageId == KEAPTLSCIPHERPAGE )
        {
        TInt index = iCipherSuiteListBox->CurrentItemIndex();
        if( ( *iUiCipherSuites )[ index ].iIsEnabled )
            {
            cba.SetCommandSetL( R_TLS_UI_SOFTKEYS_OPTIONS_BACK_DISABLE );
            }
        else
            {
            cba.SetCommandSetL( R_TLS_UI_SOFTKEYS_OPTIONS_BACK_ENABLE );
            }
        }
    cba.DrawDeferred();
    }


// -----------------------------------------------------------------------------
// CEapTlsUiDialog::ShowSettingPageL
// -----------------------------------------------------------------------------
//
void CEapTlsUiDialog::ShowSettingPageL( TInt aCalledFromMenu ) 
    {
    TInt index = iSettingListBox->CurrentItemIndex();
    if ( index == EUserCertificateItem )
        {
        TInt activeUserCertificate = CheckActiveUserCertificate();
        CDesCArrayFlat* tempArray = new( ELeave )CDesCArrayFlat( 
                                                KCertificateArrayGranularity );
        CleanupStack::PushL( tempArray );
    
        TDesC* noneText = iEikonEnv->AllocReadResourceLC( 
                                                        R_TLS_NONE_SELECTION );
        tempArray->InsertL( 0, *noneText );
        CleanupStack::PopAndDestroy( noneText );
    
        for ( TInt i = 0; i < iUiUserCertificates->Count() ; i++ )
            {
            TEapTlsPeapUiCertificate certificate = 
                                                iUiUserCertificates->At( i );
            SCertEntry entry = certificate.iCertEntry;
			TBuf<KMaxFullCertLabelLength> text;
			GetFullCertLabel( entry, text);
			tempArray->InsertL( i+1, text );
            }

        TInt selected( 0 );    
        if ( activeUserCertificate == KErrNotFound )
            {
            selected = ShowRadioButtonSettingPageL( R_TLS_USER_CERT_SETTING, 
                                                    tempArray, 0 );
            }
        else 
            {
            selected = ShowRadioButtonSettingPageL( R_TLS_USER_CERT_SETTING, 
                                                    tempArray, 
                                                    activeUserCertificate+1 );
                                    //Plus 1 cause we added 'none' selection
            }

        CleanupStack::PopAndDestroy( tempArray );
        UserCertificateHouseKeeping( selected );    
        iCertificates->Update();
        DrawSettingsListL(); // List must be drawn again at this stage
        }
    else if ( index == ECaCertificateItem )
        {
        TInt activeCaCertificate = CheckActiveCaCertificate();

        CDesCArrayFlat* tempArray = new( ELeave )CDesCArrayFlat( 
                                                KCertificateArrayGranularity );
        CleanupStack::PushL( tempArray );

        TDesC* noneText = iEikonEnv->AllocReadResourceLC( 
                                                        R_TLS_NONE_SELECTION );
        tempArray->InsertL( 0, *noneText );
        CleanupStack::PopAndDestroy( noneText );

        for ( TInt i = 0; i < iUiCACertificates->Count(); i++ )
            {
            TEapTlsPeapUiCertificate certificate = iUiCACertificates->At( i );
            SCertEntry entry = certificate.iCertEntry;
            TBuf<KMaxFullCertLabelLength> text;
			GetFullCertLabel( entry, text );
			tempArray->InsertL( i+1, text );
            }

        TInt selected( 0 );
        if ( activeCaCertificate == KErrNotFound )
            {
            selected = ShowRadioButtonSettingPageL( R_TLS_CA_CERT_SETTING, 
                                                    tempArray, 0 );
            }
        else
            {
            selected = ShowRadioButtonSettingPageL( R_TLS_CA_CERT_SETTING, 
                                                    tempArray, 
                                                    activeCaCertificate+1 );
                                    //Plus 1 cause we added 'none' selection
            }

        CleanupStack::PopAndDestroy( tempArray );
        CaCertificateHouseKeeping( selected );
        iCertificates->Update();
        DrawSettingsListL(); // List must be drawn again at this stage
        }
    else
        {
        CAknSettingItem* item = iSettingArray->Array()->At( index );
        item->EditItemL( aCalledFromMenu );
        item->StoreL();
        }
    DrawNow();
    }


// -----------------------------------------------------------------------------
// CEapTlsUiDialog::ShowRadioButtonSettingPageL
// -----------------------------------------------------------------------------
//
TInt CEapTlsUiDialog::ShowRadioButtonSettingPageL( TInt aTitle, 
                                                   CDesCArrayFlat* aValues,
                                                   TInt aCurrentItem )
    {
    // title of the dialog
    HBufC* title = iCoeEnv->AllocReadResourceLC( aTitle );

    // We have everything to create dialog
    CAknRadioButtonSettingPage* dlg = new( ELeave )CAknRadioButtonSettingPage(
                                                R_RADIO_BUTTON_SETTING_PAGE,
                                                aCurrentItem, 
                                                aValues );
    CleanupStack::PushL( dlg );
    dlg->SetSettingTextL( *title ); 
    CleanupStack::Pop( dlg ); 
    dlg->ExecuteLD( CAknSettingPage::EUpdateWhenChanged );
    CleanupStack::PopAndDestroy( title ); 
    // index must be re-turned upside down, because options list is upside down
    return aCurrentItem;
    }
  
 
  
// -----------------------------------------------------------------------------
// CEapTlsUiDialog::DrawCipherSuitesL
// -----------------------------------------------------------------------------
//
void CEapTlsUiDialog::DrawCipherSuitesL()
    {
    iCipherSuitesViewArray->Reset();
    TInt listCount( 0 );
    TBuf<KMaxLengthOfSuiteName> temp;

    for ( TInt i = 0; i < iUiCipherSuites->Count() ; i++ )
        {
        temp.Zero();
        _LIT( KTab, "\t" );
        temp.Append( KTab );
        TEapTlsPeapUiCipherSuite suite = iUiCipherSuites->At( i );
        TUint32 suiteId = suite.iCipherSuite;

        switch ( suiteId )
            {
            case 0x0004:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_TLS_SUITE_RSARC4MD5 );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );
                break;
                }

            case 0x0005:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_TLS_SUITE_RSARC4SHA );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );
                break;
                }

            case 0x000a:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_TLS_SUITE_RSA3DESSHA );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );
                break;
                }

            case 0x0016:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_TLS_SUITE_DHERSA3DESSHA );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );            
                break;
                }

            case 0x0013:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_TLS_SUITE_DHEDSS3DESSHA );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );        
                break;
                }

            case 0x002F:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_TLS_SUITE_RSAAESSHA );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );                
                break;
                }

            case 0x0032:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_TLS_SUITE_DHERSAAESSHA );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );        
                break;
                }

            case 0x0033:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_TLS_SUITE_DHEDSSAESSHA );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );                     
                break;
                }

            default:
                {
                temp.Append( KEmptyString );                                    
                break;
                }

            }

        if (iUiCipherSuites->At( i ).iIsEnabled)
            {
            // Add mark icon to indicate that the suite is enabled
            _LIT( KTab0, "\t0" );
            temp.Append( KTab0 );    
            }

        iCipherSuitesViewArray->InsertL( listCount, temp );
        listCount++;                
        }

    iCipherSuiteListBox->Model()->SetItemTextArray( iCipherSuitesViewArray );
    iCipherSuiteListBox->HandleItemAdditionL();
    iCipherSuiteListBox->DrawDeferred();
    iCipherSuiteListBox->UpdateScrollBarsL();        
    }


// -----------------------------------------------------------------------------
// CEapTlsUiDialog::CheckActiveUserCertificate
// -----------------------------------------------------------------------------
//
TInt CEapTlsUiDialog::CheckActiveUserCertificate()
    {
    for ( TInt i = 0; i < iUiUserCertificates->Count(); i++ )
        {
        if ( iUiUserCertificates->At( i ).iIsEnabled )
            {
            return i;
            }
        }

    return KErrNotFound;
    }


// -----------------------------------------------------------------------------
// CEapTlsUiDialog::CheckActiveCaCertificate
// -----------------------------------------------------------------------------
//
TInt CEapTlsUiDialog::CheckActiveCaCertificate()
    {
    for ( TInt i = 0; i < iUiCACertificates->Count(); i++ )
        {
        if ( iUiCACertificates->At( i ).iIsEnabled )
            {
            return i;
            }
        }

    return KErrNotFound;
    }


// -----------------------------------------------------------------------------
// CEapTlsUiDialog::UserCertificateHouseKeeping
// -----------------------------------------------------------------------------
//
void CEapTlsUiDialog::UserCertificateHouseKeeping( TInt aSelected )
    {
    for ( TInt i = 0; i < iUiUserCertificates->Count(); i++ )
        {
        iUiUserCertificates->At( i ).iIsEnabled = EFalse;
        }

    if ( aSelected != 0 ) // Zero index is none
        {
        iUiUserCertificates->At( aSelected-1 ).iIsEnabled = ETrue;
        }
    }


// -----------------------------------------------------------------------------
// CEapTlsUiDialog::CaCertificateHouseKeeping
// -----------------------------------------------------------------------------
//
void CEapTlsUiDialog::CaCertificateHouseKeeping( TInt aSelected )
    {
    for ( TInt i = 0; i < iUiCACertificates->Count(); i++ )
        {
        iUiCACertificates->At( i ).iIsEnabled = EFalse;
        }

    if ( aSelected != 0 ) // Zero index is none
        {        
        iUiCACertificates->At( aSelected-1 ).iIsEnabled = ETrue;
        }
    }


// -----------------------------------------------------------------------------
// CEapTlsUiDialog::SetIconsL
// -----------------------------------------------------------------------------
//
void CEapTlsUiDialog::SetIconsL()
    {
    CArrayPtr< CGulIcon >* icons = new( ELeave ) CAknIconArray( 1 );
    CleanupStack::PushL( icons );

    MAknsSkinInstance* skinInstance = AknsUtils::SkinInstance();

/*    icons->AppendL( AknsUtils::CreateGulIconL( skinInstance, 
                                        KAknsIIDQgnIndiMarkedAdd,
                                        AknIconUtils::AvkonIconFileName(),
                                        EMbmAvkonQgn_indi_marked_add, 
                                        EMbmAvkonQgn_indi_marked_add_mask ) );
*/

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
    CleanupStack::Pop( icons ); // icons

    iCipherSuiteListBox->ItemDrawer()->ColumnData()->SetIconArray( icons );

    }


// -----------------------------------------------------------------------------
// CEapTlsUiDialog::GetHelpContext
// -----------------------------------------------------------------------------
//
void CEapTlsUiDialog::GetHelpContext( TCoeHelpContext& aContext ) const
    {
    aContext.iMajor = KHelpUidPlugin;
    TPageIds index = static_cast< TPageIds >( ActivePageIndex() );
    switch ( index )
        {
        case ECipherSuitePage:
            {
            aContext.iContext = KSET_HLP_WLAN_EAP_TLS_SUITES;
            break;
            }

        default:
            {
            aContext.iContext = KSET_HLP_WLAN_EAP_TLS_SETT;
            break;
            }
        }
    }



void CEapTlsUiDialog::GetFullCertLabel( const SCertEntry& aCert, 
                                        TDes& aFullLabel )
    {
    TInt length = 0;

	// For label.
    length += aCert.iLabel.Length();

	// For separator between label and primary name.    
    length += KNameSeparator.iTypeLength;    
    
    // For primary name.
    length += aCert.iPrimaryName.Length();

    if ( !( aCert.iLabel.Length() ) )
        {	
    	// For secondary name.
	    length += aCert.iSecondaryName.Length();
        }
    
    if( length > aFullLabel.MaxLength() )
        {
#if defined(_DEBUG) || defined(DEBUG)
		RDebug::Print(_L("CEapTlsUiDialog::GetFullCertLabel - ERROR! Length Mismatch in Certificate's full name\n") );
#endif
        }

    HBufC* label = NULL;
    TRAPD(err, label = HBufC::NewL( length ));
    if (err)
        {
#if defined(_DEBUG) || defined(DEBUG)
        RDebug::Print(_L("CEapTlsUiDialog::GetFullCertLabel - ERROR! LEAVE: HBufC::NewL\n") );
#endif
        return;
        }
    label->Des().Append( aCert.iLabel );

    label->Des().Append( KNameSeparator );
    label->Des().Append( aCert.iPrimaryName );

    if ( !( aCert.iLabel.Length() ) )
        {
    	// Secondary name, only if no label. Certificate manager does the same way.
	    label->Des().Append( aCert.iSecondaryName );
        }
            
	aFullLabel.Copy( label->Des().Left( aFullLabel.MaxLength() ) );   
    
    delete label;
    label = NULL;
    }


//  End of File
