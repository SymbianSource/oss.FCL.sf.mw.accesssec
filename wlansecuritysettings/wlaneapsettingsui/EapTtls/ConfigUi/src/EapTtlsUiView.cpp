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
* Description: Implementation of EAP TTLS UI settings dialog
*
*/

/*
* %version: 27.1.1.1.9 %
*/

// INCLUDE FILES
#include <eikdialg.h>
#include <AknDialog.h>
#include <aknlists.h>
#include "EapTtlsUiView.h"
#include "EapTtlsUi.hrh"
#include <eapttlsui.rsg>
#include <akntextsettingpage.h>
#include <aknsettingitemlist.h>
#include "EapTtlsUiSettingArray.h"
#include <aknnavi.h>
#include <akntabgrp.h>
#include <aknnavide.h>
#include <aknradiobuttonsettingpage.h>
#include <StringLoader.h>
#include <aknnotewrappers.h>
#include <EapTlsPeapUiCipherSuites.h>
#include <EapTlsPeapUiEapTypes.h>
#include <EapTlsPeapUiCertificates.h>
#include <EapType.h>
#include <EapTypeInfo.h> 
#include <AknIconArray.h>
#include <AknsUtils.h>

#include <featmgr.h>
#include <hlplch.h>
#include <csxhelp/cp.hlp.hrh>


// CONSTANTS
// UID of general settings app, in which help texts are included
const TUid KHelpUidPlugin = { 0x100058EC };

static const TInt KSettingArrayGranularity = 4;    
static const TInt KSuiteArrayGranularity = 5;
static const TInt KMaxLengthOfEapLine = 270;
static const TInt KCertificateArrayGranularity = 5;
static const TInt KMaxLengthOfSuiteName = 255;
static const TInt KEapTtlsId = 21;

_LIT( KNameSeparator, " " );
_LIT( KEmptyString, "" );
const TUint KFirstElement = 0;
const TUint KSecondElement = 1;
const TUint KMinEnabledCount = 1;

/* This is the maximum length of a certificate's full name, includes
label, primary and secondary names */
const TUint32 KMaxFullCertLabelLength = KMaxCertLabelLength + 2 * 
                                    KMaxNameLength + 1; // 1 is for separator.

// MODULE DATA STRUCTURES
enum TPageIds
    {
    ESettingsPage = 0,
    EEapTypePage,
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
// CEapTtlsUiDialog::CEapTtlsUiDialog
// -----------------------------------------------------------------------------
//
CEapTtlsUiDialog::CEapTtlsUiDialog( CEapTlsPeapUiConnection* aConnection,
                                    TIndexType aIndexType, TInt aIndex, 
								    TInt& aButtonId ) 
: CAknDialog(), 
  iConnection( aConnection ),
  iIndexType( aIndexType ), 
  iIndex( aIndex ), 
  iButtonId( &aButtonId ),
  iIsUIConstructionCompleted( EFalse ),
  iExiting( EFalse )
    {
    }


// ---------------------------------------------------------
// CEapTtlsUiDialog::ConstructAndRunLD
// ---------------------------------------------------------
//
TInt CEapTtlsUiDialog::ConstructAndRunLD( TInt aResourceId )
    {
    CleanupStack::PushL( this );

    iSettingArray = CEapTtlsSettingItemArray::NewL();

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
    //EAP types 
    iEapTypes = iConnection->GetEapTypeConnection();
    if ( iEapTypes == 0 )
        {
        User::Leave( KErrNoMemory );
        }
    User::LeaveIfError( iEapTypes->Open() );
    User::LeaveIfError( iEapTypes->GetEapTypes( &iUiEapTypes ) );
    if ( iUiEapTypes->Count() == 0 )
        {
        CreateEapTypeDataBaseL();
        }

    iEapTypeViewArray = new( ELeave ) CDesCArrayFlat( 
                                                    KSettingArrayGranularity );

    FeatureManager::InitializeLibL();

    ConstructL( R_TTLS_MENUBAR );
    
    // ExecuteLD will PushL( this ), so we have to Pop it...
    CleanupStack::Pop( this ); // this
    
    return CAknDialog::ExecuteLD( aResourceId );
    }


// -----------------------------------------------------------------------------
// CEapTtlsUiDialog::OfferKeyEventL
// -----------------------------------------------------------------------------
//
TKeyResponse CEapTtlsUiDialog::OfferKeyEventL( const TKeyEvent& aKeyEvent,
                                                     TEventCode aType )
    {
    TKeyResponse result( EKeyWasNotConsumed );
    
    // gently handle impatient users
	if ( !iIsUIConstructionCompleted )
        {
        return CAknDialog::OfferKeyEventL( aKeyEvent, aType );
        }
    
    TInt pageId = ActivePageId();
    if ( aType == EEventKey && pageId == KEAPTTLSCIPHERPAGE )
        {
        TInt indexBefore = iCipherSuiteListBox->CurrentItemIndex();
        
        if ( aKeyEvent.iCode == EKeyEnter )
            {
            if ( ( *iUiCipherSuites )[indexBefore].iIsEnabled )
                {
                OkToExitL( ETtlsUiCmdDisable );
                }
            else
                {
                OkToExitL( ETtlsUiCmdEnable );
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
                cba.SetCommandSetL( R_TTLS_UI_SOFTKEYS_OPTIONS_BACK_DISABLE );
                }
            else
                {
                cba.SetCommandSetL( R_TTLS_UI_SOFTKEYS_OPTIONS_BACK_ENABLE );
                }
            
            cba.DrawDeferred();
            }
        }
    else if ( aType == EEventKey && pageId == KEAPTTLSEAPPAGE )
        {
        TInt indexBefore = iEapTypesListBox->CurrentItemIndex();
        
        if ( aKeyEvent.iCode == EKeyEnter )
            {
            if ( ( *iUiEapTypes )[indexBefore].iIsEnabled )
                {
                OkToExitL( ETtlsUiCmdConfigure );
                }
            else
                {
                OkToExitL( ETtlsUiCmdEnable );
                }
                
            result = EKeyWasConsumed;
            }
        else
            {        
            result = CAknDialog::OfferKeyEventL( aKeyEvent, aType );
            }
            
        TInt indexAfter = iEapTypesListBox->CurrentItemIndex();

        if ( indexBefore != indexAfter )
            {
            CEikButtonGroupContainer& cba = ButtonGroupContainer();
            if( ( *iUiEapTypes )[indexAfter].iIsEnabled )
                {
                cba.SetCommandSetL( R_TTLS_UI_SOFTKEYS_OPTIONS_BACK_CONFIGURE );
                }
            else
                {
                cba.SetCommandSetL( R_TTLS_UI_SOFTKEYS_OPTIONS_BACK_ENABLE );
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
// CEapTtlsUiDialog::~CEapTtlsUiDialog
// -----------------------------------------------------------------------------
//
CEapTtlsUiDialog::~CEapTtlsUiDialog()
    {
     if ( iSettingArray )
        {
        iSettingArray->Array()->ResetAndDestroy();
        }

    delete iSettingArray;

    iSettingListBox = NULL;
    
    iDataConnection->Close();
    delete iDataConnection;

    iCipherSuitesViewArray->Reset();
    delete iCipherSuitesViewArray;    

    iEapTypeViewArray->Reset();
    delete iEapTypeViewArray;

	iCertificates->Close();
	delete iCertificates;

	iCipherSuites->Close();
	delete iCipherSuites;

	iEapTypes->Close();
	delete iEapTypes;

	iConnection->Close();
    
    delete iPreviousText;
    
    FeatureManager::UnInitializeLib();
    }
    
    
// ---------------------------------------------------------
// CEapTtlsUiDialog::HandleListBoxEventL
// ---------------------------------------------------------
//
void CEapTtlsUiDialog::HandleListBoxEventL( CEikListBox* aListBox,
                                            TListBoxEvent aEventType )
    {
    switch ( aEventType )
        {
        case EEventEnterKeyPressed:
        case EEventItemSingleClicked:
            {
            if ( aListBox == iSettingListBox )
                {
                OkToExitL( ETtlsUiCmdChange );                    
                }
                
            else if ( aListBox == iEapTypesListBox )
                {
                TInt index = iEapTypesListBox->CurrentItemIndex();
                if ( iUiEapTypes->At( index ).iIsEnabled )
                    {
                    ConfigureL(ETrue);   
                    }
                else
                    {
                    OkToExitL( ETtlsUiCmdEnable );
                    }                    
                }
                                     
            else if ( aListBox == iCipherSuiteListBox )
                {
                TInt index = iCipherSuiteListBox->CurrentItemIndex();
                if ( iUiCipherSuites->At( index ).iIsEnabled )
                    {
                    OkToExitL( ETtlsUiCmdDisable );
                    }
                else
                    {
                    OkToExitL( ETtlsUiCmdEnable );
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


// ---------------------------------------------------------
// CEapTtlsUiDialog::HandleDialogPageEventL
// ---------------------------------------------------------
//
void CEapTtlsUiDialog::HandleDialogPageEventL( TInt aEventID )
    {
     CAknDialog::HandleDialogPageEventL( aEventID );
         if( iExiting )
             {        
             // Exit requested. 
             TryExitL( EAknCmdExit );
             }   
     }


// ---------------------------------------------------------
// CEapTtlsUiDialog::ConfigureL
// ---------------------------------------------------------
//
void CEapTtlsUiDialog::ConfigureL( TBool aQuick )
    {
    RImplInfoPtrArray eapArray;
    eapArray.Reset();
    REComSession::ListImplementationsL( KEapTypeInterfaceUid,
            eapArray );
    TInt itemIndex = iEapTypesListBox->CurrentItemIndex(); 
    TInt eapIndex( 0 );
    for ( TInt i = 0; i < eapArray.Count(); ++i )
        {
        CImplementationInformation* tempInfo = eapArray[i];
        if ( iUiEapTypes->At( itemIndex ).iEapType == 
        tempInfo->DataType() )
            {
            eapIndex = i;
            break;            
            }
        }   

    CEapType* eapType;
    eapType = CEapType::NewL( eapArray[eapIndex]->DataType(), 
            iIndexType, iIndex );
    eapArray.ResetAndDestroy();
    eapType->SetTunnelingType( KEapTtlsId );
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


// -----------------------------------------------------------------------------
// CEapTtlsUiDialog::PreLayoutDynInitL
// -----------------------------------------------------------------------------
//
void CEapTtlsUiDialog::PreLayoutDynInitL()
    {
    // Change title
    ChangeTitleL( ETrue );
    
    iSettingListBox = static_cast<CAknSettingStyleListBox*>( 
                              ControlOrNull( ETtlsSettingsListbox ) );
    iSettingListBox->SetComponentsToInheritVisibility( ETrue );
    
    iEapTypesListBox = static_cast<CAknSingleNumberStyleListBox*>(
                              ControlOrNull( ETtlsSettingsEapTypeListbox ) );
    iEapTypesListBox->SetComponentsToInheritVisibility( ETrue );

    iCipherSuiteListBox = static_cast<CAknSingleNumberStyleListBox*>(
                               ControlOrNull( ETtlsSettingsCipherSuiteListbox ) );
    iCipherSuiteListBox->SetComponentsToInheritVisibility( ETrue );
    
    // Get certificates before building the UI. 
    // Will continue when certificates are received
    iCertificates = iConnection->GetCertificateConnection( this );
    User::LeaveIfError( iCertificates->Open() );
    iCertificates->GetCertificates( &iUiUserCertificates, &iUiCACertificates );
    }


// -----------------------------------------------------------------------------
// CEapTtlsUiDialog::CompleteReadCertificates
// -----------------------------------------------------------------------------
//
void CEapTtlsUiDialog::CompleteReadCertificates( const TInt aResult )
    {
    if ( aResult == KErrNone ) // Certifiocates are received from core
        {
        TRAPD( err, CompleteUiConstructionL() );
        if ( err != KErrNone )
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
// CEapTtlsUiDialog::CompleteUiConstructionL
// -----------------------------------------------------------------------------
//
void CEapTtlsUiDialog::CompleteUiConstructionL()
    {
    // Initialize setting page 
    iSettingListBox = static_cast<CAknSettingStyleListBox*>( 
                                    ControlOrNull( ETtlsSettingsListbox ) );
    iSettingListBox->SetMopParent( this );
    iSettingListBox->CreateScrollBarFrameL( ETrue );
    iSettingListBox->ScrollBarFrame()->SetScrollBarVisibilityL( 
                                                CEikScrollBarFrame::EOff,
                                                CEikScrollBarFrame::EAuto );
    iSettingListBox->SetListBoxObserver( this );                                                 
    DrawSettingsListL();

    // Initialize EAP types page
    iEapTypesListBox = static_cast<CAknSingleNumberStyleListBox*>( 
                                ControlOrNull( ETtlsSettingsEapTypeListbox ) );
    iEapTypesListBox->SetMopParent( this );
    iEapTypesListBox->CreateScrollBarFrameL( ETrue );
    iEapTypesListBox->ScrollBarFrame()->SetScrollBarVisibilityL( 
                                                CEikScrollBarFrame::EOff,
                                                CEikScrollBarFrame::EAuto );
    iEapTypesListBox->Model()->SetOwnershipType( ELbmDoesNotOwnItemArray );
    iEapTypesListBox->SetListBoxObserver( this );     
    
    // Following deletes internal array created from resources. 
    // To prevent memory leak.
    MDesCArray* internalArray1 = iEapTypesListBox->Model()->ItemTextArray();
    delete internalArray1;

    // Initialize cipher suites page
    iCipherSuiteListBox = static_cast<CAknSingleNumberStyleListBox*>( 
                            ControlOrNull( ETtlsSettingsCipherSuiteListbox ) );
    iCipherSuiteListBox->CreateScrollBarFrameL( ETrue );
    iCipherSuiteListBox->ScrollBarFrame()->SetScrollBarVisibilityL( 
                                                CEikScrollBarFrame::EOff,
                                                CEikScrollBarFrame::EAuto );
    iCipherSuiteListBox->UpdateScrollBarsL();
    iCipherSuiteListBox->Model()->SetOwnershipType( ELbmDoesNotOwnItemArray );
    iCipherSuiteListBox->SetListBoxObserver( this );   
        
    //Following deletes internal array created from resources. 
    // To prevent memory leak.
    MDesCArray* internalArray2 = iCipherSuiteListBox->Model()->ItemTextArray();
    delete internalArray2;

    SetEapIconsL();
    DrawEapListL( 0 );

    SetCipherIconsL();
    DrawCipherSuitesL();
    
    iIsUIConstructionCompleted = ETrue;
    }


// -----------------------------------------------------------------------------
// CEapTtlsUiDialog::PostLayoutDynInitL
// -----------------------------------------------------------------------------
//
void CEapTtlsUiDialog::PostLayoutDynInitL()
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
// CEapTtlsUiDialog::ChangeTitleL
// -----------------------------------------------------------------------------
//
void CEapTtlsUiDialog::ChangeTitleL( TBool aIsStarted )
    {
    TUid titlePaneUid;
    titlePaneUid.iUid = EEikStatusPaneUidTitle;

    CEikStatusPane* statusPane = iEikonEnv->AppUiFactory()->StatusPane();
    CEikStatusPaneBase::TPaneCapabilities subPane = 
                                statusPane->PaneCapabilities( titlePaneUid );
    
    if ( subPane.IsPresent()&&subPane.IsAppOwned() )
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
                                                    R_TTLS_SETTINGS_TITLE );
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
// CEapTtlsUiDialog::OkToExitL
// -----------------------------------------------------------------------------
//
TBool CEapTtlsUiDialog::OkToExitL( TInt aButtonId )
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
                else if ( index == EEapTypePage )
                    {
                    ProcessCommandL( ETtlsUiCmdConfigure );
                    }
                }
            else
                {
                #if defined(_DEBUG) || defined(DEBUG)
				RDebug::Print(_L("CEapTtlsUiDialog::OkToExitL - UI not ready - Ignoring key press.\n") );
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
            if( ( GetEnabledEapTypeCount() > KMinEnabledCount ) &&
                  ( IsPlainMschapv2Enabled() || IsPapEnabled() ) )
                {
                HBufC* stringLabel;

                if ( IsPlainMschapv2Enabled() )
                    {
                    stringLabel = StringLoader::LoadL(
                            R_TTLS_INFO_PLAIN_MSCHAP_CANNOT_ENABLE_ALONG,
                                                   iEikonEnv );
                    }
                else
                    {
                    stringLabel = StringLoader::LoadL(
                            R_TTLS_INFO_PAP_CANNOT_ENABLE_ALONG,
                                                   iEikonEnv );
                    }
                CleanupStack::PushL( stringLabel );
                CAknInformationNote* dialog = new ( ELeave )
                                            CAknInformationNote( ETrue );
                dialog->ExecuteLD( *stringLabel );
                CleanupStack::PopAndDestroy( stringLabel );
                
                // after showing the info note, EAP settings page
                // must be shown
                if( ActivePageId() == KEAPTTLSSETTINGSPAGE )
                    {
                    TKeyEvent keyRight = 
                        {
                            EKeyRightArrow,
                            EStdKeyRightArrow,
                            EModifierPureKeycode,
                            0
                        };
                    CAknDialog::OfferKeyEventL
                                            ( keyRight,
                                              EEventKey );
                    }
                if( ActivePageId() == KEAPTTLSCIPHERPAGE )
                    {
                    TKeyEvent keyLeft = 
                        {
                            EKeyLeftArrow,
                            EStdKeyLeftArrow,
                            EModifierPureKeycode,
                            0
                        };
                    CAknDialog::OfferKeyEventL
                                            ( keyLeft,
                                              EEventKey );
                    }

                iExiting = EFalse;    
                ret = EFalse;
                }
            else
                {
                if( iIsUIConstructionCompleted )
                    {
                    iDataConnection->Update();
                    ChangeTitleL( EFalse );
                    ret = ETrue;
                    }
                }
            break;
            }
            
        case ETtlsUiCmdChange:
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
            
        case ETtlsUiCmdConfigure:
        case ETtlsUiCmdEnable:
        case ETtlsUiCmdDisable:
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
// CEapTtlsUiDialog::DrawSettingsListL
// -----------------------------------------------------------------------------
//
void CEapTtlsUiDialog::DrawSettingsListL()
    {  
    iSettingArray->Array()->ResetAndDestroy();
    TInt ordinal = 0;
    TInt activeUserCertificate = CheckActiveUserCertificate();
    TBuf<KMaxFullCertLabelLength> aActiveuserCertificateName = KEmptyString();
    if ( activeUserCertificate != KErrNotFound )
        {
		TBuf<KMaxFullCertLabelLength> text;
		GetFullCertLabelL( 
                iUiUserCertificates->At( activeUserCertificate ).iCertEntry,
                text );
		aActiveuserCertificateName.Copy( text );		
        }
    else
        {
        TDesC* notDefinedText = iEikonEnv->AllocReadResourceLC( 
                                                        R_TTLS_NOT_DEFINED );
        aActiveuserCertificateName.Copy( *notDefinedText );
        CleanupStack::PopAndDestroy( notDefinedText );
        }

    iSettingArray->AddTextItemL( aActiveuserCertificateName,
                                 ETtlsSettingUserCert,
                                 R_TTLS_USER_CERT_STRING,
                                 R_TTLS_USERNAME_PAGE,
                                 NULL,
                                 ordinal++ );

    TInt activeCaCertificate = CheckActiveCaCertificate();
    TBuf<KMaxFullCertLabelLength> aActiveCaCertificateName = KEmptyString();
    if ( activeCaCertificate != KErrNotFound )
        {
		TBuf<KMaxFullCertLabelLength> text;
		GetFullCertLabelL(
                    iUiCACertificates->At( activeCaCertificate ).iCertEntry,
                    text );
		aActiveCaCertificateName.Copy( text );				
        }
    else
        {
        TDesC* notDefinedText = iEikonEnv->AllocReadResourceLC( 
                                                        R_TTLS_NOT_DEFINED );
        aActiveCaCertificateName.Copy( *notDefinedText );
        CleanupStack::PopAndDestroy( notDefinedText );                
        }

    iSettingArray->AddTextItemL( aActiveCaCertificateName,
                                 ETtlsSettingCaCert,
                                 R_TTLS_CA_CERT_STRING,
                                 R_TTLS_USERNAME_PAGE,
                                 NULL,
                                 ordinal++ );
      
    iSettingArray->AddBinarySettingItemL( R_TTLS_DISPLAY_AUTOUSECONF_PAGE, 
                                          R_TTLS_USERNAME_INUSESTRING, 
                                          R_TTLS_USERNAME_AUTOUSECONF_TEXTS,
                                          ordinal++,
                                          *iUiData->GetUseManualUsername() );

    iSettingArray->AddTextItemL( iUiData->GetManualUsername(),
                                 ETtlsTabSheetSettingsUsername,
                                 R_TTLS_USERNAME_STRING,
                                 R_TTLS_USERNAME_PAGE,
                                 NULL,
                                 ordinal++ );

    iSettingArray->AddBinarySettingItemL( R_TTLS_DISPLAY_AUTOUSECONF_PAGE,
                                          R_TTLS_REALM_INUSESTRING, 
                                          R_TTLS_REALM_AUTOUSECONF_TEXTS,
                                          ordinal++,
                                          *iUiData->GetUseManualRealm() );    

    iSettingArray->AddTextItemL( iUiData->GetManualRealm(),
                                 ETtlsTabSheetSettingsRealm,
                                 R_TTLS_REALM_STRING,
                                 R_TTLS_REALM_PAGE,
                                 NULL,
                                 ordinal++ );
    
    iSettingArray->AddBinarySettingItemL( R_TTLS_DISPLAY_AUTOUSECONF_PAGE,
                                          R_TTLS_TLS_PRIVACY_STRING, 
                                          R_TTLS_TLS_PRIVACY_AUTOUSECONF_TEXTS,
                                          ordinal++,
                                          *iUiData->GetTlsPrivacy() );
        
    iSettingListBox->Model()->SetItemTextArray( iSettingArray->Array() );    
    iSettingListBox->Model()->SetOwnershipType( ELbmDoesNotOwnItemArray );
    iSettingArray->Array()->RecalculateVisibleIndicesL();
    iSettingListBox->HandleItemAdditionL();
    iSettingListBox->UpdateScrollBarsL();  
    }


// -----------------------------------------------------------------------------
// CEapTtlsUiDialog::DynInitMenuPaneL
// -----------------------------------------------------------------------------
//
void CEapTtlsUiDialog::DynInitMenuPaneL( TInt aResourceId, 
                                         CEikMenuPane* aMenuPane )
    {
    CAknDialog::DynInitMenuPaneL( aResourceId, aMenuPane );

    if ( aMenuPane && aResourceId == R_TTLS_MENU_PANE )
        {
        if ( !FeatureManager::FeatureSupported( KFeatureIdHelp ) )
            {
            aMenuPane->DeleteMenuItem( EAknCmdHelp );
            }

        TPageIds index = static_cast<TPageIds>( ActivePageIndex() );
        if ( index == ESettingsPage )
            {
            aMenuPane->SetItemDimmed( ETtlsUiCmdEnable,    ETrue );
            aMenuPane->SetItemDimmed( ETtlsUiCmdDisable,   ETrue );
            aMenuPane->SetItemDimmed( ETtlsUiCmdConfigure, ETrue );
            aMenuPane->SetItemDimmed( ETtlsUiCmdMoveUp,    ETrue );
            aMenuPane->SetItemDimmed( ETtlsUiCmdMoveDown,  ETrue );
            }
        else if ( index == EEapTypePage )
            {
            aMenuPane->SetItemDimmed( ETtlsUiCmdChange, ETrue );

            if ( iEapTypeViewArray->Count() > 0 )
                {
                TInt currentIndex = iEapTypesListBox->CurrentItemIndex();
                TBool enabled = iUiEapTypes->At( currentIndex ).iIsEnabled;
                
                // Hide either "Enable" or "Disable", as appropriate.
                aMenuPane->SetItemDimmed( ETtlsUiCmdEnable,  enabled );
                aMenuPane->SetItemDimmed( ETtlsUiCmdDisable, !enabled );

                // Don't display "Configure" for disabled items
                aMenuPane->SetItemDimmed( ETtlsUiCmdConfigure, !enabled );

                // Don't display "Raise priority" nor "Lower priority" for 
                // disabled items
                aMenuPane->SetItemDimmed( ETtlsUiCmdMoveUp, !enabled );
                aMenuPane->SetItemDimmed( ETtlsUiCmdMoveDown, !enabled );

                if ( enabled )
                    {
                    if ( currentIndex == 0 )
                        {
                        // Can't go higher than top.
                        aMenuPane->SetItemDimmed( ETtlsUiCmdMoveUp, ETrue );
                        }
                    else if ( currentIndex == iEapTypeViewArray->Count()-1 ||
                         ( currentIndex < iEapTypeViewArray->Count()-1 && 
                         !iUiEapTypes->At( currentIndex + 1 ).iIsEnabled ) ) 
                        {
                        // Can't go lower than the last enabled item
                        aMenuPane->SetItemDimmed( ETtlsUiCmdMoveDown, ETrue );
                        }
                    }

                }
            else
                {
                aMenuPane->SetItemDimmed( ETtlsUiCmdEnable,    ETrue );
                aMenuPane->SetItemDimmed( ETtlsUiCmdDisable,   ETrue );
                aMenuPane->SetItemDimmed( ETtlsUiCmdConfigure, ETrue );
                aMenuPane->SetItemDimmed( ETtlsUiCmdMoveUp,    ETrue );
                aMenuPane->SetItemDimmed( ETtlsUiCmdMoveDown,  ETrue );
                aMenuPane->SetItemDimmed( ETtlsUiCmdChange,    ETrue );
                }
            }
        else if ( index == ECipherSuitePage )
            {
            aMenuPane->SetItemDimmed( ETtlsUiCmdConfigure, ETrue );
            aMenuPane->SetItemDimmed( ETtlsUiCmdMoveUp,    ETrue );
            aMenuPane->SetItemDimmed( ETtlsUiCmdMoveDown,  ETrue );
            aMenuPane->SetItemDimmed( ETtlsUiCmdChange,    ETrue );

            if ( iCipherSuitesViewArray->Count() > 0 )
                {
                TInt currIndex = iCipherSuiteListBox->CurrentItemIndex();
                TBool enabled = iUiCipherSuites->At( currIndex ).iIsEnabled;

                // Hide either "Enable" or "Disable", as appropriate.
                aMenuPane->SetItemDimmed( ETtlsUiCmdEnable,  enabled );
                aMenuPane->SetItemDimmed( ETtlsUiCmdDisable, !enabled );
                }
            else
                {
                aMenuPane->SetItemDimmed( ETtlsUiCmdEnable,  ETrue );
                aMenuPane->SetItemDimmed( ETtlsUiCmdDisable, ETrue );
                }
            }
        }
    }


// -----------------------------------------------------------------------------
// CEapTtlsUiDialog::ProcessCommandL
// -----------------------------------------------------------------------------
//
void CEapTtlsUiDialog::ProcessCommandL( TInt aCommand )
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

        case ETtlsUiCmdChange:
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
    				RDebug::Print(_L("CEapTtlsUiDialog::ProcessCommandL - UI not ready - Ignoring key press.\n") );
    				#endif						
    			    }
                }    
            break;
            }

        case ETtlsUiCmdMoveUp:
            {
            if ( pageIndex == EEapTypePage )
                {
                TInt cur = iEapTypesListBox->CurrentItemIndex();
                MoveEapTypeL( cur, cur - 1 );
                }
            break;
            }

        case ETtlsUiCmdMoveDown:
            {
            if ( pageIndex == EEapTypePage )
                {
                TInt cur = iEapTypesListBox->CurrentItemIndex();
                MoveEapTypeL( cur, cur + 1 );
                }
            break;
            }

        case ETtlsUiCmdEnable:
            {
            if ( pageIndex == ECipherSuitePage )
                {
                TInt index = iCipherSuiteListBox->CurrentItemIndex();
                iUiCipherSuites->At( index ).iIsEnabled = ETrue;
                iCipherSuites->Update();
                DrawCipherSuitesL();
                CEikButtonGroupContainer& cba = ButtonGroupContainer();
                cba.SetCommandSetL( R_TTLS_UI_SOFTKEYS_OPTIONS_BACK_DISABLE );
                cba.DrawDeferred();
                }
            else if ( pageIndex == EEapTypePage )
                {
                TInt cur = iEapTypesListBox->CurrentItemIndex();
                iUiEapTypes->At( cur ).iIsEnabled = ETrue;

                iEapTypes->Update();

                // enabling moves item to the top of the list
                MoveEapTypeL( cur, 0 );                

                // load the new CBA from resource
                CEikButtonGroupContainer& cba = ButtonGroupContainer();                
                cba.SetCommandSetL( R_TTLS_UI_SOFTKEYS_OPTIONS_BACK_CONFIGURE );
                cba.DrawDeferred();
                }                
            break;
            }

        case ETtlsUiCmdDisable:
            {
            if ( pageIndex == ECipherSuitePage )
                {
                TInt index = iCipherSuiteListBox->CurrentItemIndex();
                iUiCipherSuites->At( index ).iIsEnabled = EFalse;
                iCipherSuites->Update();
                DrawCipherSuitesL();    
                CEikButtonGroupContainer& cba = ButtonGroupContainer();
                cba.SetCommandSetL( R_TTLS_UI_SOFTKEYS_OPTIONS_BACK_ENABLE );
                cba.DrawDeferred();        
                }            
            else if ( pageIndex == EEapTypePage )
                {
                TInt itemIndex = iEapTypesListBox->CurrentItemIndex();

                if( GetEnabledEapTypeCount() > KMinEnabledCount )
                    {
                    // disabling moves item just after the last enabled one,
                    // so find that position
                    TInt next = itemIndex;
                    
                    while ( next < iUiEapTypes->Count() - 1 &&
                            iUiEapTypes->At( next ).iIsEnabled )
                        {
                        ++next;
                        }

                    if ( next > itemIndex && 
                         !iUiEapTypes->At( next ).iIsEnabled ) 
                        {
                        --next;
                        }


                    iUiEapTypes->At( itemIndex ).iIsEnabled = EFalse;

                    // move item if needed
                    MoveEapTypeL( itemIndex, next );
                    iEapTypes->Update();                

                    // Highlight follows movement.
                    //iEapTypesListBox->SetCurrentItemIndex( next );
                    
                    // load the new CBA from resource
                    CEikButtonGroupContainer& cba = ButtonGroupContainer();
                    cba.SetCommandSetL( 
                                     R_TTLS_UI_SOFTKEYS_OPTIONS_BACK_ENABLE );
                    cba.DrawDeferred();
                    }
                else
                    {
                    HBufC* stringLabel;
                    stringLabel = StringLoader::LoadL(
                                R_TTLS_INFO_CANNOT_DISABLE_ALL_EAP_PLUGINS,
                                                       iEikonEnv );
                    CleanupStack::PushL( stringLabel );
                    CAknInformationNote* dialog = new ( ELeave )
                                                CAknInformationNote( ETrue );
                    dialog->ExecuteLD( *stringLabel );
                    CleanupStack::PopAndDestroy( stringLabel );
                    }
                }
            break;
            }

        case ETtlsUiCmdConfigure:
            {
            if ( pageIndex == EEapTypePage )
                {
                ConfigureL(EFalse);
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
// CEapTtlsUiDialog::PageChangedL
// -----------------------------------------------------------------------------
//
void CEapTtlsUiDialog::PageChangedL( TInt aPageId )
    {
    if ( !iIsUIConstructionCompleted )
        {
        return;
        }

    if ( aPageId == KEAPTTLSSETTINGSPAGE )
        {
        if (iSettingListBox->ScrollBarFrame())
            {
            iSettingListBox->ScrollBarFrame()->ComponentControl(0)->MakeVisible(ETrue);
            }
        if (iEapTypesListBox->ScrollBarFrame())
            {
            iEapTypesListBox->ScrollBarFrame()->ComponentControl(0)->MakeVisible(EFalse);
            }
        if (iCipherSuiteListBox->ScrollBarFrame())
            {
            iCipherSuiteListBox->ScrollBarFrame()->ComponentControl(0)->MakeVisible(EFalse);
            }
        }
     else if ( aPageId == KEAPTTLSEAPPAGE )
        {
        if (iSettingListBox->ScrollBarFrame())
            {
            iSettingListBox->ScrollBarFrame()->ComponentControl(0)->MakeVisible(EFalse);
            }
        if (iEapTypesListBox->ScrollBarFrame())
            {
            iEapTypesListBox->ScrollBarFrame()->ComponentControl(0)->MakeVisible(ETrue);
            }
        if (iCipherSuiteListBox->ScrollBarFrame())
            {
            iCipherSuiteListBox->ScrollBarFrame()->ComponentControl(0)->MakeVisible(EFalse);
            }
        }
    else if ( aPageId == KEAPTTLSCIPHERPAGE )
        {
        if (iSettingListBox->ScrollBarFrame())
            {
            iSettingListBox->ScrollBarFrame()->ComponentControl(0)->MakeVisible(EFalse);
            }
        if (iEapTypesListBox->ScrollBarFrame())
            {
            iEapTypesListBox->ScrollBarFrame()->ComponentControl(0)->MakeVisible(EFalse);
            }
        if (iCipherSuiteListBox->ScrollBarFrame())
            {
            iCipherSuiteListBox->ScrollBarFrame()->ComponentControl(0)->MakeVisible(ETrue);
            }
        }
        
    CEikButtonGroupContainer& cba = ButtonGroupContainer();
    if( aPageId == KEAPTTLSSETTINGSPAGE )
        {
        cba.SetCommandSetL( R_TTLS_UI_SOFTKEYS_OPTIONS_BACK_EDIT );
        }
    else if( aPageId == KEAPTTLSEAPPAGE )
        {
        cba.SetCommandSetL( R_TTLS_UI_SOFTKEYS_OPTIONS_BACK_CONFIGURE );
        }
    else if( aPageId == KEAPTTLSCIPHERPAGE )
        {
        TInt index = iCipherSuiteListBox->CurrentItemIndex();
        if( ( *iUiCipherSuites )[ index ].iIsEnabled )
            {
            cba.SetCommandSetL( R_TTLS_UI_SOFTKEYS_OPTIONS_BACK_DISABLE );
            }
        else
            {
            cba.SetCommandSetL( R_TTLS_UI_SOFTKEYS_OPTIONS_BACK_ENABLE );
            }
        }
    cba.DrawDeferred();
    }
    

// -----------------------------------------------------------------------------
// CEapTtlsUiDialog::ShowSettingPageL
// -----------------------------------------------------------------------------
//
void CEapTtlsUiDialog::ShowSettingPageL( TInt aCalledFromMenu )
    {
    TInt index = iSettingListBox->CurrentItemIndex();
    if ( index == EUserCertificateItem )
        {
        TInt activeUserCertificate = CheckActiveUserCertificate();
        CDesCArrayFlat* tempArray = new( ELeave )CDesCArrayFlat( 
                                                KCertificateArrayGranularity );
        CleanupStack::PushL( tempArray );
    
        TDesC* noneText = iEikonEnv->AllocReadResourceLC( 
                                                    R_TTLS_NONE_SELECTION );
        tempArray->InsertL( 0, *noneText );
        CleanupStack::PopAndDestroy( noneText );
    
        for ( TInt i = 0; i < iUiUserCertificates->Count() ; i++ )
            {
            TEapTlsPeapUiCertificate certificate = 
                                                iUiUserCertificates->At( i );
            SCertEntry entry = certificate.iCertEntry;
			TBuf<KMaxFullCertLabelLength> text;
			GetFullCertLabelL( entry, text);
			tempArray->InsertL( i+1, text );
            }
        TInt selected( 0 );    
        if ( activeUserCertificate == KErrNotFound )
            {
            selected = ShowRadioButtonSettingPageL( R_TTLS_USER_CERT_STRING, 
                                                    tempArray, 0 );
            }
        else 
            {
            selected = ShowRadioButtonSettingPageL( R_TTLS_USER_CERT_STRING, 
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
                                                    R_TTLS_NONE_SELECTION );
        tempArray->InsertL( 0, *noneText );
        CleanupStack::PopAndDestroy( noneText );

        for ( TInt i = 0; i < iUiCACertificates->Count(); i++ )
            {
            TEapTlsPeapUiCertificate certificate = iUiCACertificates->At( i );
            SCertEntry entry = certificate.iCertEntry;
            TBuf<KMaxFullCertLabelLength> text;
			GetFullCertLabelL( entry, text );
			tempArray->InsertL( i+1, text );
            }

        TInt selected( 0 );
        if ( activeCaCertificate == KErrNotFound )
            {
            selected = ShowRadioButtonSettingPageL( R_TTLS_CA_CERT_STRING, 
                                                    tempArray, 0 );        
            }
        else
            {
            selected = ShowRadioButtonSettingPageL( R_TTLS_CA_CERT_STRING, 
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
// CEapPeapUiDialog::MoveEapTypeL
// -----------------------------------------------------------------------------
//
void CEapTtlsUiDialog::MoveEapTypeL( TInt aOldPos, TInt aNewPos )
    {
    TEapTlsPeapUiEapType originalUpper = iUiEapTypes->At( aOldPos );
    iUiEapTypes->Delete( aOldPos );
    iUiEapTypes->InsertL( aNewPos, originalUpper );
    iUiEapTypes->Compress();    // Might not be needed
    iEapTypes->Update();
    DrawEapListL( aNewPos );
    }
    
    
// -----------------------------------------------------------------------------
// CEapTtlsUiDialog::DrawEapListL
// -----------------------------------------------------------------------------
//
void CEapTtlsUiDialog::DrawEapListL( TInt aWantedIndex )
    {    
    iEapTypeViewArray->Reset();
    RImplInfoPtrArray eapArray;
    eapArray.Reset();

    REComSession::ListImplementationsL( KEapTypeInterfaceUid, eapArray );
    for ( TInt i = 0; i < iUiEapTypes->Count(); i++ )
        {
        TBuf<KMaxLengthOfEapLine> tempLine;
        
        if ( iUiEapTypes->At( i ).iIsEnabled )
            {
            _LIT( KNumTab, "%d\t" );
            tempLine.AppendFormat( KNumTab, i+1 );
            }
        else
            {
            _LIT( KTab, "\t" );
            tempLine.Append( KTab );
            }
        
        for ( TInt index = 0; index < eapArray.Count(); index++ )
            {
            if ( eapArray[index]->DataType() == iUiEapTypes->At( i ).iEapType )
                {
                tempLine.Append( eapArray[index]->DisplayName() );
                break;
                }
            }

        if ( iUiEapTypes->At( i ).iIsEnabled )
            {       // Add mark icon to indicate that the eap type is enabled
            _LIT( KTab0, "\t0" );
            tempLine.Append( KTab0 );
            }

        iEapTypeViewArray->InsertL( i, tempLine );
        }

    eapArray.ResetAndDestroy();
    iEapTypesListBox->Model()->SetItemTextArray( iEapTypeViewArray );
    iEapTypesListBox->HandleItemAdditionL();
    iEapTypesListBox->SetCurrentItemIndex( aWantedIndex );
    iEapTypesListBox->DrawDeferred();
    iEapTypesListBox->UpdateScrollBarsL();
    }


// -----------------------------------------------------------------------------
// CEapTtlsUiDialog::ShowRadioButtonSettingPageL
// -----------------------------------------------------------------------------
//
TInt CEapTtlsUiDialog::ShowRadioButtonSettingPageL( TInt aTitle, 
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
    CleanupStack::PopAndDestroy( title ); // title
    // index must be re-turned upside down, because options list is upside down
    return aCurrentItem;
    }


// -----------------------------------------------------------------------------
// CEapTtlsUiDialog::DrawCipherSuitesL
// -----------------------------------------------------------------------------
//
void CEapTtlsUiDialog::DrawCipherSuitesL()
    {
    iCipherSuitesViewArray->Reset();
    TInt listCount( 0 );
    TBuf<KMaxLengthOfSuiteName> temp;
    for ( TInt i = 0; i < iUiCipherSuites->Count(); i++ )
        {
        temp.Zero();
        _LIT( KTab, "\t" );
        temp.Append( KTab ); 

        TEapTlsPeapUiCipherSuite suite = iUiCipherSuites->At( i );
        TUint32 suiteId = suite.iCipherSuite;

        switch( suiteId )
            {
            case 0x0004:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_TTLS_SUITE_RSARC4MD5 );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );
                break;
                }

            case 0x0005:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_TTLS_SUITE_RSARC4SHA );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );
                break;
                }

            case 0x000a:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_TTLS_SUITE_RSA3DESSHA );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );
                break;
                }

            case 0x0016:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_TTLS_SUITE_DHERSA3DESSHA );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );            
                break;
                }

            case 0x0013:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_TTLS_SUITE_DHEDSS3DESSHA );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );        
                break;
                }

            case 0x002F:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_TTLS_SUITE_RSAAESSHA );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );                
                break;
                }

            case 0x0032:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_TTLS_SUITE_DHERSAAESSHA );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );        
                break;
                }

            case 0x0033:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_TTLS_SUITE_DHEDSSAESSHA );
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

        if ( iUiCipherSuites->At( i ).iIsEnabled )
            {       // Add mark icon to indicate that the suite is enabled
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
// CEapTtlsUiDialog::CheckActiveUserCertificate
// -----------------------------------------------------------------------------
//
TInt CEapTtlsUiDialog::CheckActiveUserCertificate()
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
// CEapTtlsUiDialog::CheckActiveCaCertificate
// -----------------------------------------------------------------------------
//
TInt CEapTtlsUiDialog::CheckActiveCaCertificate()
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
// CEapTtlsUiDialog::UserCertificateHouseKeeping
// -----------------------------------------------------------------------------
//
void CEapTtlsUiDialog::UserCertificateHouseKeeping( TInt aSelected )
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
// CEapTtlsUiDialog::CaCertificateHouseKeeping
// -----------------------------------------------------------------------------
//
void CEapTtlsUiDialog::CaCertificateHouseKeeping( TInt aSelected )
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
// CEapTtlsUiDialog::CreateEapTypeDataBaseL
// -----------------------------------------------------------------------------
//
void CEapTtlsUiDialog::CreateEapTypeDataBaseL()
    {
    RImplInfoPtrArray eapArray;
    eapArray.Reset();

    REComSession::ListImplementationsL( KEapTypeInterfaceUid, eapArray );
    TInt allowedInTtlsCount( 0 );
    for ( TInt i = 0; i < eapArray.Count(); i++ )
        {
        if ( !CEapType::IsDisallowedInsideTTLS(*eapArray[i]) )
            {
            CImplementationInformation* info = eapArray[i];
            TEapTlsPeapUiEapType tempEapType;
            tempEapType.iEapType = info->DataType();
            
            // BINARY RESOURCE DATA
            
            // [FE] [00 00 00] [TEapType_bigendian]
            // OR
            // [FE] [FF FF FF] [MSCHAPv2_bigendian]
            
            _LIT8( KExpEapFirstQuad, "\xFE\0\0\0" );
            TPtrC8 firstQuad( tempEapType.iEapType.Ptr(), 4 );
            // TUint32 dataType = BigEndian::Get32( tempEapType.iEapType.Ptr()+4 );
            TUint32 dataType = ( tempEapType.iEapType[4] << 24 ) |
                               ( tempEapType.iEapType[5] << 16 ) |
                               ( tempEapType.iEapType[6] << 8 ) |
                               tempEapType.iEapType[7];
            
    
            if ( !firstQuad.Compare( KExpEapFirstQuad ) && 
                 ( dataType == EAPSettings::EEapSim || 
                   dataType == EAPSettings::EEapAka ) )
                {
                tempEapType.iIsEnabled = ETrue;
                iUiEapTypes->InsertL( KFirstElement, tempEapType );
                }
            else
                {
                tempEapType.iIsEnabled = EFalse;
                iUiEapTypes->InsertL( allowedInTtlsCount, tempEapType );
                }

            allowedInTtlsCount++;
            }
        }

    __ASSERT_DEBUG( iUiEapTypes->Count() >= 2, User::Panic( _L("EAP-SIM/AKA missing"), 1) );
    
    // Check if EAP-SIM and EAP-AKA are in correct order
    
    // BINARY RESOURCE DATA
    const TDesC8& firstEap = iUiEapTypes->At( KFirstElement ).iEapType;
    const TDesC8& secondEap = iUiEapTypes->At( KSecondElement ).iEapType;
    
    TUint32 dataTypeFirst = ( firstEap[4] << 24 ) |
                            ( firstEap[5] << 16 ) |
                            ( firstEap[6] << 8 ) |
                            firstEap[7];
    TUint32 dataTypeSecond = ( secondEap[4] << 24 ) |
                             ( secondEap[5] << 16 ) |
                             ( secondEap[6] << 8 ) |
                             secondEap[7];

    // If not, switch them
    if ( dataTypeFirst == EAPSettings::EEapAka &&
        dataTypeSecond == EAPSettings::EEapSim )
        {
        TEapTlsPeapUiEapType tempEapType = iUiEapTypes->At( KFirstElement );
        iUiEapTypes->Delete( KFirstElement );
        iUiEapTypes->InsertL( KSecondElement, tempEapType );
        }
    
    iEapTypes->Update();
    eapArray.ResetAndDestroy();        
    }


// -----------------------------------------------------------------------------
// CEapTtlsUiDialog::SetCipherIconsL
// -----------------------------------------------------------------------------
//
void CEapTtlsUiDialog::SetCipherIconsL()
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
    CleanupStack::Pop( icons ); // icons
    
    iCipherSuiteListBox->ItemDrawer()->ColumnData()->SetIconArray( icons );
  
    }


// -----------------------------------------------------------------------------
// CEapTtlsUiDialog::SetEapIconsL
// -----------------------------------------------------------------------------
//
void CEapTtlsUiDialog::SetEapIconsL()
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
    CleanupStack::Pop( icons ); // icons

    iEapTypesListBox->ItemDrawer()->ColumnData()->SetIconArray( icons );
    }


// -----------------------------------------------------------------------------
// CEapTtlsUiDialog::GetEnabledEapTypeCount
// -----------------------------------------------------------------------------
//
TUint CEapTtlsUiDialog::GetEnabledEapTypeCount()
    {
    TUint itemCount( 0 );
    for( TInt i( 0 ); i < iUiEapTypes->Count(); ++i )
        {
        if( iUiEapTypes->At( i ).iIsEnabled )
            {
            ++itemCount;
            }
        }
    return itemCount;
    }


// -----------------------------------------------------------------------------
// CEapTtlsUiDialog::IsPlainMschapv2Enabled
// -----------------------------------------------------------------------------
//
TBool CEapTtlsUiDialog::IsPlainMschapv2Enabled()
    {
    TBool isEnabled( EFalse );
    for( TUint i( 0 ); i < iUiEapTypes->Count(); ++i )
        {
        // was: _LIT8( KPlainMsChapV2ExpandedId, "\xFE\xFF\xFF\xFF\0\0\0\x1A" );
        // workaround:
        _LIT8( KPlainMsChapV2ExpandedId, "\xFE\xFF\xFF\xFF\0\0\0\x63" );

        const TDesC8& currEap = iUiEapTypes->At( i ).iEapType;

        if ( !currEap.Compare( KPlainMsChapV2ExpandedId ) )
            {
            isEnabled = iUiEapTypes->At( i ).iIsEnabled;
            break;
            }

        }
    return isEnabled;
    }

// -----------------------------------------------------------------------------
// CEapTtlsUiDialog::IsPapEnabled
// -----------------------------------------------------------------------------
//
TBool CEapTtlsUiDialog::IsPapEnabled()
    {
    TBool isEnabled( EFalse );
    for( TUint i( 0 ); i < iUiEapTypes->Count(); ++i )
        {
        _LIT8( KPapExpandedId, "\xFE\xFF\xFF\xFF\0\0\0\x62" );
        const TDesC8& currEap = iUiEapTypes->At( i ).iEapType;
        if ( !currEap.Compare( KPapExpandedId ) )
            {
            isEnabled = iUiEapTypes->At( i ).iIsEnabled;
            break;
            }
        }
    return isEnabled;
    }
    

// -----------------------------------------------------------------------------
// CEapTtlsUiDialog::GetHelpContext
// -----------------------------------------------------------------------------
//
void CEapTtlsUiDialog::GetHelpContext( TCoeHelpContext& aContext ) const
    {
    aContext.iMajor = KHelpUidPlugin;
    TPageIds index = static_cast<TPageIds>( ActivePageIndex() );
    switch ( index )
        {
        case EEapTypePage:
            {
            aContext.iContext = KSET_HLP_WLAN_EAP_TTLS_TYPES;
            break;
            }

        case ECipherSuitePage:
            {
            aContext.iContext = KSET_HLP_WLAN_EAP_TTLS_SUITES;
            break;
            }

        default:
            {
            aContext.iContext = KSET_HLP_WLAN_EAP_TTLS_SETT;
            break;
            }
        }
    }


void CEapTtlsUiDialog::GetFullCertLabelL( const SCertEntry& aCert, 
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
		RDebug::Print(_L("CEapTtlsUiDialog::GetFullCertLabelL - ERROR! Length Mismatch in Certificate's full name\n") );
#endif
        }

    HBufC* label = HBufC::NewL( length );
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


// End of file
