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
* Description: Implementation of EAP PEAP UI settings dialog
*
*/

/*
* %version: 37.1.7 %
*/

// INCLUDE FILES
#include <eikdialg.h>
#include <AknDialog.h>
#include <aknlists.h>
#include "EapPeapUiView.h"
#include "EapPeapUi.hrh"
#include <EapPeapUi.rsg>
#include <akntextsettingpage.h>
#include <aknsettingitemlist.h>
#include "EapPeapUiSettingArray.h"
#include <aknnavi.h>
#include <akntabgrp.h>
#include <aknnavide.h>
#include <aknnotewrappers.h>
#include <aknradiobuttonsettingpage.h>
#include <StringLoader.h>
#include <EapTlsPeapUiConnection.h>
#include <EapTlsPeapUiDataConnection.h>
#include <EapTlsPeapUiTlsPeapData.h>
#include <EapTlsPeapUiCipherSuites.h>
#include <EapTlsPeapUiEapTypes.h>
#include <EapTlsPeapUiCertificates.h>
#include <EapType.h>
#include <EapTypeInfo.h> // For EAP type info query
#include <AknIconArray.h>
#include <AknsUtils.h>
#include <FeatMgr.h>
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
static const TInt KEapPeapId = 25;

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
    ESettingsPage=0,
    EEapTypePage,
    ECipherSuitePage
    };


enum TSettingIds
    {
    EUserCertificateItem=0,
    ECaCertificateItem,
    EUsernameInUseItem,
    EUsernameItem,
    ERealmInUseItem,
    ERealmItem
    };


// ============================ MEMBER FUNCTIONS ===============================

// -----------------------------------------------------------------------------
// CEapPeapUiDialog::CEapPeapUiDialog
// -----------------------------------------------------------------------------
//
CEapPeapUiDialog::CEapPeapUiDialog( CEapTlsPeapUiConnection* aConnection,
                                    TIndexType aIndexType, 
                                    TInt aIndex, 
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
// CEapPeapUiDialog::ConstructAndRunLD
// ---------------------------------------------------------
//
TInt CEapPeapUiDialog::ConstructAndRunLD( TInt aResourceId )
    {
    CleanupStack::PushL( this );

    iSettingArray = CEapPeapSettingItemArray::NewL();

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
    
    ConstructL( R_PEAP_MENUBAR );
    
    // ExecuteLD will PushL( this ), so we have to Pop it...
    CleanupStack::Pop( this ); // this
    
    return CAknDialog::ExecuteLD( aResourceId );
    }
    

// -----------------------------------------------------------------------------
// CEapPeapUiDialog::OfferKeyEventL
// -----------------------------------------------------------------------------
//
TKeyResponse CEapPeapUiDialog::OfferKeyEventL( const TKeyEvent& aKeyEvent,
                                                     TEventCode aType )
    {
    TKeyResponse result( EKeyWasNotConsumed );
    
    // gently handle impatient users
    if ( !iIsUIConstructionCompleted )
        {
        return CAknDialog::OfferKeyEventL( aKeyEvent, aType );
        }
        
    TInt pageId = ActivePageId();
    
    if ( aType == EEventKey && pageId == KEAPPEAPCIPHERPAGE )
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
                OkToExitL( EPeapUiCmdDisable );
                }
            else
                {
                OkToExitL( EPeapUiCmdEnable );
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
            if( ( *iUiCipherSuites )[indexAfter].iIsEnabled )
                {
                cba.SetCommandSetL( R_PEAP_UI_SOFTKEYS_OPTIONS_BACK_DISABLE );
                }
            else
                {
                cba.SetCommandSetL( R_PEAP_UI_SOFTKEYS_OPTIONS_BACK_ENABLE );
                }
            
            cba.DrawDeferred();
            }
        }
    else if ( aType == EEventKey && pageId == KEAPPEAPEAPPAGE )
        {
        TInt indexBefore = iEapTypesListBox->CurrentItemIndex();
        // Handle Enter key here, since it doesn't seem to convert into
        // the proper command id via the normal route
        // (maybe some Avkon support for Enter key is still missing in
        // S60 3.2 2008_wk22)
        if ( aKeyEvent.iCode == EKeyEnter )
            {
            if ( ( *iUiEapTypes )[indexBefore].iIsEnabled )
                {
                OkToExitL( EPeapUiCmdConfigure );
                }
            else
                {
                OkToExitL( EPeapUiCmdEnable );
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
                cba.SetCommandSetL( R_PEAP_UI_SOFTKEYS_OPTIONS_BACK_CONFIGURE );
                }
            else
                {
                cba.SetCommandSetL( R_PEAP_UI_SOFTKEYS_OPTIONS_BACK_ENABLE );
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
// CEapPeapUiDialog::~CEapPeapUiDialog
// -----------------------------------------------------------------------------
//
CEapPeapUiDialog::~CEapPeapUiDialog()
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
// CEapPeapUiDialog::HandleListBoxEventL
// ---------------------------------------------------------
//
void CEapPeapUiDialog::HandleListBoxEventL( CEikListBox* aListBox,
                                            TListBoxEvent aEventType )
    {
    switch ( aEventType )
        {
        case EEventEnterKeyPressed:
        case EEventItemSingleClicked:
            {
            if ( aListBox == iSettingListBox )
                {
                OkToExitL( EPeapUiCmdChange );                    
                }
                
            else if ( aListBox == iEapTypesListBox )
                {
                TInt index = iEapTypesListBox->CurrentItemIndex();
                if ( iUiEapTypes->At( index ).iIsEnabled )
                    {
                    ConfigureL( ETrue );    
                    }
                else
                    {
                    OkToExitL( EPeapUiCmdEnable );
                    }                    
                }
                                     
            else if ( aListBox == iCipherSuiteListBox )
                {
                TInt index = iCipherSuiteListBox->CurrentItemIndex();
                if ( iUiCipherSuites->At( index ).iIsEnabled )
                    {
                    OkToExitL( EPeapUiCmdDisable );
                    }
                else
                    {
                    OkToExitL( EPeapUiCmdEnable );
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
// CEapPeapUiDialog::HandleDialogPageEventL
// ---------------------------------------------------------
//
void CEapPeapUiDialog::HandleDialogPageEventL( TInt aEventID )
    {
     CAknDialog::HandleDialogPageEventL( aEventID );
         if( iExiting )
             {        
             // Exit requested. 
             TryExitL( EAknCmdExit );
             }   
     }


// ---------------------------------------------------------
// CEapPeapUiDialog::ConfigureL
// ---------------------------------------------------------
//
void CEapPeapUiDialog::ConfigureL( TBool aQuick )
    {
    RImplInfoPtrArray eapArray;
    eapArray.Reset();

    REComSession::ListImplementationsL( KEapTypeInterfaceUid, 
                                        eapArray );
    TInt itemIndex = iEapTypesListBox->CurrentItemIndex();    
    TInt eapIndex( 0 );
    for ( TInt i = 0; i < eapArray.Count(); i++ )
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
    eapType->SetTunnelingType( KEapPeapId );
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
// CEapPeapUiDialog::PreLayoutDynInitL
// -----------------------------------------------------------------------------
//
void CEapPeapUiDialog::PreLayoutDynInitL()
    {
    // Change title
    ChangeTitleL( ETrue );
    
    iSettingListBox = static_cast<CAknSettingStyleListBox*>( 
                                    ControlOrNull( EPeapSettingsListbox ) );
    iSettingListBox->SetComponentsToInheritVisibility( ETrue );

    iEapTypesListBox = static_cast<CAknSingleNumberStyleListBox*>(
                                ControlOrNull( EPeapSettingsEapTypeListbox ) );
    iEapTypesListBox->SetComponentsToInheritVisibility( ETrue );

    iCipherSuiteListBox = static_cast<CAknSingleNumberStyleListBox*>(
                            ControlOrNull( EPeapSettingsCipherSuiteListbox ) );
    iCipherSuiteListBox->SetComponentsToInheritVisibility( ETrue );
    
    // Get certificates before building the UI. 
    // Will continue when certificates are received
    iCertificates = iConnection->GetCertificateConnection( this );
    User::LeaveIfError( iCertificates->Open() );
    iCertificates->GetCertificates( &iUiUserCertificates, &iUiCACertificates );
    }


// -----------------------------------------------------------------------------
// CEapPeapUiDialog::CompleteReadCertificates
// -----------------------------------------------------------------------------
//
void CEapPeapUiDialog::CompleteReadCertificates( const TInt aResult )
    {
    if ( aResult == KErrNone ) // Certificates are received from core
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
// CEapPeapUiDialog::CompleteUiConstructionL
// -----------------------------------------------------------------------------
//
void CEapPeapUiDialog::CompleteUiConstructionL()
    {
    // Initialize setting page 
    iSettingListBox = static_cast<CAknSettingStyleListBox*>( 
                                    ControlOrNull( EPeapSettingsListbox ) );
    iSettingListBox->SetMopParent( this );
    iSettingListBox->CreateScrollBarFrameL( ETrue );
    iSettingListBox->ScrollBarFrame()->SetScrollBarVisibilityL( 
                                                CEikScrollBarFrame::EOff,
                                                CEikScrollBarFrame::EAuto );
    iSettingListBox->SetListBoxObserver( this );                                                                                                
    DrawSettingsListL();

    // Initialize EAP types page
    iEapTypesListBox = static_cast<CAknSingleNumberStyleListBox*>(
                                ControlOrNull( EPeapSettingsEapTypeListbox ) );
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
                            ControlOrNull( EPeapSettingsCipherSuiteListbox ) );
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
// CEapPeapUiDialog::PostLayoutDynInitL
// -----------------------------------------------------------------------------
//
void CEapPeapUiDialog::PostLayoutDynInitL()
    {
    TUid naviPaneUid;
    naviPaneUid.iUid = EEikStatusPaneUidNavi;

    CEikStatusPane* statusPane = iEikonEnv->AppUiFactory()->StatusPane();
    CEikStatusPaneBase::TPaneCapabilities subPane = 
                                statusPane->PaneCapabilities( naviPaneUid );
    if ( subPane.IsPresent()&&subPane.IsAppOwned() )
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
// CEapPeapUiDialog::ChangeTitleL
// -----------------------------------------------------------------------------
//
void CEapPeapUiDialog::ChangeTitleL( TBool aIsStarted )
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
                                                    R_PEAP_SETTINGS_TITLE );
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
// CEapPeapUiDialog::OkToExitL
// -----------------------------------------------------------------------------
//
TBool CEapPeapUiDialog::OkToExitL( TInt aButtonId )
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
                    ProcessCommandL( EPeapUiCmdConfigure );
                    }    
                }
            else
                {
                #if defined(_DEBUG) || defined(DEBUG)
				RDebug::Print(_L("CEapPeapUiDialog::OkToExitL - UI not ready - Ignoring key press.\n") );
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
        
        case EPeapUiCmdChange:
            {
            TInt pageId = ActivePageId();
            if ( pageId == KEAPPEAPSETTINGSPAGE )
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
        case EPeapUiCmdConfigure:
        case EPeapUiCmdEnable:
        case EPeapUiCmdDisable:
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
// CEapPeapUiDialog::DrawSettingsListL
// -----------------------------------------------------------------------------
//
void CEapPeapUiDialog::DrawSettingsListL()
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
                                                        R_PEAP_NOT_DEFINED );
        aActiveuserCertificateName.Copy( *notDefinedText );
        CleanupStack::PopAndDestroy( notDefinedText );
        }

    iSettingArray->AddTextItemL( aActiveuserCertificateName,
                                 EPeapSettingUserCert,
                                 R_PEAP_USER_CERT_STRING,
                                 R_PEAP_USERNAME_PAGE,
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
                                                        R_PEAP_NOT_DEFINED );
        aActiveCaCertificateName.Copy( *notDefinedText );
        CleanupStack::PopAndDestroy( notDefinedText );                
        }

    iSettingArray->AddTextItemL( aActiveCaCertificateName,
                                 EPeapSettingCaCert,
                                 R_PEAP_CA_CERT_STRING,
                                 R_PEAP_USERNAME_PAGE,
                                 NULL,
                                 ordinal++ );
      
    iSettingArray->AddBinarySettingItemL( R_PEAP_DISPLAY_AUTOUSECONF_PAGE,
                                          R_PEAP_USERNAME_INUSESTRING, 
                                          R_PEAP_USERNAME_AUTOUSECONF_TEXTS,
                                          ordinal++,
                                          *iUiData->GetUseManualUsername() );

    iSettingArray->AddTextItemL( iUiData->GetManualUsername(),
                                 EPeapTabSheetSettingsUsername,
                                 R_PEAP_USERNAME_STRING,
                                 R_PEAP_USERNAME_PAGE,
                                 NULL,
                                 ordinal++ );

    iSettingArray->AddBinarySettingItemL( R_PEAP_DISPLAY_AUTOUSECONF_PAGE,
                                          R_PEAP_REALM_INUSESTRING, 
                                          R_PEAP_REALM_AUTOUSECONF_TEXTS,
                                          ordinal++,
                                          *iUiData->GetUseManualRealm() );    

    iSettingArray->AddTextItemL( iUiData->GetManualRealm(),
                                 EPeapTabSheetSettingsRealm,
                                 R_PEAP_REALM_STRING,
                                 R_PEAP_REALM_PAGE,
                                 NULL,
                                 ordinal++ );
    
    iSettingArray->AddBinarySettingItemL( R_PEAP_DISPLAY_AUTOUSECONF_PAGE,
                                          R_PEAP_TLS_PRIVACY_STRING, 
                                          R_PEAP_TLS_PRIVACY_AUTOUSECONF_TEXTS,
                                          ordinal++,
                                          *iUiData->GetTlsPrivacy() );
    

    iSettingArray->AddBinarySettingItemL( R_PEAP_ALLOW_VERSION_0, 
                                          R_PEAP_ALLOW_PEAPV0, 
                                          R_PEAP_ALLOW_VERSION_TEXTS,
                                          ordinal++,
                                          *iUiData->GetAllowVersion0() );

    iSettingArray->AddBinarySettingItemL( R_PEAP_ALLOW_VERSION_1, 
                                          R_PEAP_ALLOW_PEAPV1, 
                                          R_PEAP_ALLOW_VERSION_TEXTS,
                                          ordinal++,
                                          *iUiData->GetAllowVersion1() );
                                
    iSettingArray->AddBinarySettingItemL( R_PEAP_ALLOW_VERSION_2,
                                          R_PEAP_ALLOW_PEAPV2, 
                                          R_PEAP_ALLOW_VERSION_TEXTS,
                                          ordinal++,
                                          *iUiData->GetAllowVersion2() );

    iSettingListBox->Model()->SetItemTextArray( iSettingArray->Array() );    
    iSettingListBox->Model()->SetOwnershipType( ELbmDoesNotOwnItemArray );
    iSettingArray->Array()->RecalculateVisibleIndicesL();
    iSettingListBox->HandleItemAdditionL();
    iSettingListBox->UpdateScrollBarsL();
    }


// -----------------------------------------------------------------------------
// CEapPeapUiDialog::DynInitMenuPaneL
// -----------------------------------------------------------------------------
//
void CEapPeapUiDialog::DynInitMenuPaneL( TInt aResourceId, 
                                         CEikMenuPane* aMenuPane )
    {
    CAknDialog::DynInitMenuPaneL( aResourceId, aMenuPane );

    if ( aMenuPane && aResourceId == R_PEAP_MENU_PANE )
        {
        if ( !FeatureManager::FeatureSupported( KFeatureIdHelp ) )
            {
            aMenuPane->DeleteMenuItem( EAknCmdHelp );
            }

        TPageIds index = static_cast<TPageIds>( ActivePageIndex() );
        if ( index == ESettingsPage )
            {
            aMenuPane->SetItemDimmed( EPeapUiCmdEnable,    ETrue );
            aMenuPane->SetItemDimmed( EPeapUiCmdDisable,   ETrue );
            aMenuPane->SetItemDimmed( EPeapUiCmdConfigure, ETrue );
            aMenuPane->SetItemDimmed( EPeapUiCmdMoveUp,    ETrue );
            aMenuPane->SetItemDimmed( EPeapUiCmdMoveDown,  ETrue );
            }
        else if ( index == EEapTypePage )
            {
            aMenuPane->SetItemDimmed( EPeapUiCmdChange, ETrue );

            if ( iEapTypeViewArray->Count() > 0 )
                {
                TInt currentIndex = iEapTypesListBox->CurrentItemIndex();
                TBool enabled = iUiEapTypes->At( currentIndex ).iIsEnabled;

                // Hide either "Enable" or "Disable", as appropriate.
                aMenuPane->SetItemDimmed( EPeapUiCmdEnable,  enabled );
                aMenuPane->SetItemDimmed( EPeapUiCmdDisable, !enabled );

                // Don't display "Configure" for disabled items
                aMenuPane->SetItemDimmed( EPeapUiCmdConfigure, !enabled );

                // Don't display "Raise priority" nor "Lower priority" for 
                // disabled items
                aMenuPane->SetItemDimmed( EPeapUiCmdMoveUp, !enabled );
                aMenuPane->SetItemDimmed( EPeapUiCmdMoveDown, !enabled );

                if ( enabled )
                    {
                    
                    if ( currentIndex == 0 )
                        {
                        // Can't go higher than top.
                        aMenuPane->SetItemDimmed( EPeapUiCmdMoveUp, ETrue );
                        }
                    
                    if ( currentIndex == iEapTypeViewArray->Count()-1 ||
                         ( currentIndex < iEapTypeViewArray->Count()-1 && 
                         !iUiEapTypes->At( currentIndex + 1 ).iIsEnabled ) ) 
                        {
                        // Can't go lower than the last enabled item
                        aMenuPane->SetItemDimmed( EPeapUiCmdMoveDown, ETrue );
                        }

                    }

                }
            else
                {
                aMenuPane->SetItemDimmed( EPeapUiCmdEnable,    ETrue );
                aMenuPane->SetItemDimmed( EPeapUiCmdDisable,   ETrue );
                aMenuPane->SetItemDimmed( EPeapUiCmdConfigure, ETrue );
                aMenuPane->SetItemDimmed( EPeapUiCmdMoveUp,    ETrue );
                aMenuPane->SetItemDimmed( EPeapUiCmdMoveDown,  ETrue );
                aMenuPane->SetItemDimmed( EPeapUiCmdChange,    ETrue );
                }
            }
        else if ( index == ECipherSuitePage )
            {
            aMenuPane->SetItemDimmed( EPeapUiCmdConfigure, ETrue );
            aMenuPane->SetItemDimmed( EPeapUiCmdMoveUp,    ETrue );
            aMenuPane->SetItemDimmed( EPeapUiCmdMoveDown,  ETrue );
            aMenuPane->SetItemDimmed( EPeapUiCmdChange,    ETrue );

            if ( iCipherSuitesViewArray->Count() > 0 )
                {
                TInt currIndex = iCipherSuiteListBox->CurrentItemIndex();
                TBool enabled = iUiCipherSuites->At( currIndex ).iIsEnabled;

                // Hide either "Enable" or "Disable", as appropriate.
                aMenuPane->SetItemDimmed( EPeapUiCmdEnable,  enabled );
                aMenuPane->SetItemDimmed( EPeapUiCmdDisable, !enabled );
                }
            else
                {
                aMenuPane->SetItemDimmed( EPeapUiCmdEnable,  ETrue );
                aMenuPane->SetItemDimmed( EPeapUiCmdDisable, ETrue );
                }
            }
        }
    }


// -----------------------------------------------------------------------------
// CEapPeapUiDialog::ProcessCommandL
// -----------------------------------------------------------------------------
//
void CEapPeapUiDialog::ProcessCommandL( TInt aCommand )
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

        case EPeapUiCmdChange:
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
    				RDebug::Print(_L("CEapPeapUiDialog::ProcessCommandL - UI not ready - Ignoring key press.\n") );
    				#endif
    			    }
                }
            break;
            }

        case EPeapUiCmdMoveUp:
            {
            if ( pageIndex == EEapTypePage )
                {
                TInt cur = iEapTypesListBox->CurrentItemIndex();
                MoveEapTypeL( cur, cur - 1 );
                }
            break;
            }

        case EPeapUiCmdMoveDown:
            {
            if ( pageIndex == EEapTypePage )
                {
                TInt cur = iEapTypesListBox->CurrentItemIndex();
                MoveEapTypeL( cur, cur + 1 );
                }
            break;
            }

        case EPeapUiCmdEnable:
            {
            if ( pageIndex == ECipherSuitePage )
                {
                TInt index = iCipherSuiteListBox->CurrentItemIndex();
                iUiCipherSuites->At( index ).iIsEnabled = ETrue;
                iCipherSuites->Update();
                DrawCipherSuitesL();
                CEikButtonGroupContainer& cba = ButtonGroupContainer();
                cba.SetCommandSetL( R_PEAP_UI_SOFTKEYS_OPTIONS_BACK_DISABLE );
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
                cba.SetCommandSetL( R_PEAP_UI_SOFTKEYS_OPTIONS_BACK_CONFIGURE );
                cba.DrawDeferred();
                }                
            break;
            }

        case EPeapUiCmdDisable:
            {
            if ( pageIndex == ECipherSuitePage )
                {
                TInt index = iCipherSuiteListBox->CurrentItemIndex();
                iUiCipherSuites->At( index ).iIsEnabled = EFalse;
                iCipherSuites->Update();
                DrawCipherSuitesL();
                CEikButtonGroupContainer& cba = ButtonGroupContainer();
                cba.SetCommandSetL( R_PEAP_UI_SOFTKEYS_OPTIONS_BACK_ENABLE );
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
                                     R_PEAP_UI_SOFTKEYS_OPTIONS_BACK_ENABLE );
                    
                    cba.DrawDeferred();
                    }
                else
                    {
                    HBufC* stringLabel;
                    stringLabel = StringLoader::LoadL(
                                R_PEAP_INFO_CANNOT_DISABLE_ALL_EAP_PLUGINS,
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
            
        case EPeapUiCmdConfigure:
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
// CEapPeapUiDialog::PageChangedL
// -----------------------------------------------------------------------------
//
void CEapPeapUiDialog::PageChangedL( TInt aPageId )
    {
    if ( !iIsUIConstructionCompleted )
        {
        return;
        }
        
    if ( aPageId == KEAPPEAPSETTINGSPAGE )
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
     else if ( aPageId == KEAPPEAPEAPPAGE )
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
    else if ( aPageId == KEAPPEAPCIPHERPAGE )
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
    if( aPageId == KEAPPEAPSETTINGSPAGE )
        {
        cba.SetCommandSetL( R_PEAP_UI_SOFTKEYS_OPTIONS_BACK_EDIT );
        }
    else if( aPageId == KEAPPEAPEAPPAGE )
        {
        TInt index = iEapTypesListBox->CurrentItemIndex();
        if ( ( *iUiEapTypes )[index].iIsEnabled )
            {
            cba.SetCommandSetL( R_PEAP_UI_SOFTKEYS_OPTIONS_BACK_CONFIGURE );    
            }
        else
            {
            cba.SetCommandSetL( R_PEAP_UI_SOFTKEYS_OPTIONS_BACK_ENABLE );
            }
        
        }
    else if( aPageId == KEAPPEAPCIPHERPAGE )
        {
        TInt index = iCipherSuiteListBox->CurrentItemIndex();
        if( ( *iUiCipherSuites )[ index ].iIsEnabled )
            {
            cba.SetCommandSetL( R_PEAP_UI_SOFTKEYS_OPTIONS_BACK_DISABLE );
            }
        else
            {
            cba.SetCommandSetL( R_PEAP_UI_SOFTKEYS_OPTIONS_BACK_ENABLE );
            }
        }
    cba.DrawDeferred();
    }


// -----------------------------------------------------------------------------
// CEapPeapUiDialog::ShowSettingPageL
// -----------------------------------------------------------------------------
//
void CEapPeapUiDialog::ShowSettingPageL( TInt aCalledFromMenu ) 
    {
    TInt index = iSettingListBox->CurrentItemIndex();
    if ( index == EUserCertificateItem )
        {
        TInt activeUserCertificate = CheckActiveUserCertificate();
        CDesCArrayFlat* tempArray = new( ELeave )CDesCArrayFlat( 
                                                KCertificateArrayGranularity );
        CleanupStack::PushL( tempArray );

        TDesC* noneText = iEikonEnv->AllocReadResourceLC( 
                                                    R_PEAP_NONE_SELECTION );
        tempArray->InsertL( 0, *noneText );
        CleanupStack::PopAndDestroy( noneText );

        for ( TInt i = 0; i < iUiUserCertificates->Count(); i++ )
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
            selected = ShowRadioButtonSettingPageL( R_PEAP_USER_CERT_STRING, 
                                                    tempArray, 0 );
            }
        else 
            {
            selected = ShowRadioButtonSettingPageL( R_PEAP_USER_CERT_STRING, 
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
        CleanupStack::PushL( tempArray);

        TDesC* noneText = iEikonEnv->AllocReadResourceLC( 
                                                    R_PEAP_NONE_SELECTION );
        tempArray->InsertL( 0, *noneText);
        CleanupStack::PopAndDestroy( noneText);

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
            selected = ShowRadioButtonSettingPageL( R_PEAP_CA_CERT_STRING, 
                                                    tempArray, 0 );
            }
        else
            {
            selected = ShowRadioButtonSettingPageL( R_PEAP_CA_CERT_STRING, 
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
void CEapPeapUiDialog::MoveEapTypeL( TInt aOldPos, TInt aNewPos )
    {
    TEapTlsPeapUiEapType originalUpper = iUiEapTypes->At( aOldPos );
    iUiEapTypes->Delete( aOldPos );
    iUiEapTypes->InsertL( aNewPos, originalUpper );
    iUiEapTypes->Compress();    // Might not be needed
    iEapTypes->Update();
    DrawEapListL( aNewPos );
    }
    
    
// -----------------------------------------------------------------------------
// CEapPeapUiDialog::DrawEapListL
// -----------------------------------------------------------------------------
//
void CEapPeapUiDialog::DrawEapListL( TInt aWantedIndex )
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
            TBuf8<100> egyik( eapArray[index]->DataType() );
            TBuf8<100> masik( iUiEapTypes->At( i ).iEapType );
            if ( eapArray[index]->DataType() == iUiEapTypes->At( i ).iEapType )
                {
                tempLine.Append( eapArray[ index ]->DisplayName() );
                break;
                }
            }
        if ( iUiEapTypes->At( i ).iIsEnabled )
            {   // Add mark icon to indicate that the eap type is enabled
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
// CEapPeapUiDialog::ShowRadioButtonSettingPageL
// -----------------------------------------------------------------------------
//
TInt CEapPeapUiDialog::ShowRadioButtonSettingPageL( TInt aTitle, 
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
// CEapPeapUiDialog::DrawCipherSuitesL
// -----------------------------------------------------------------------------
//
void CEapPeapUiDialog::DrawCipherSuitesL()
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
        switch ( suiteId )
            {
            case 0x0004:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_PEAP_SUITE_RSARC4MD5 );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );
                break;
                }

            case 0x0005:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_PEAP_SUITE_RSARC4SHA );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );
                break;
                }

            case 0x000a:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_PEAP_SUITE_RSA3DESSHA );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );
                break;
                }

            case 0x0016:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_PEAP_SUITE_DHERSA3DESSHA );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );            
                break;
                }

            case 0x0013:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_PEAP_SUITE_DHEDSS3DESSHA );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );        
                break;
                }

            case 0x002F:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_PEAP_SUITE_RSAAESSHA );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );                
                break;
                }

            case 0x0032:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_PEAP_SUITE_DHERSAAESSHA );
                temp.Append( *suite );
                CleanupStack::PopAndDestroy( suite );
                break;
                }

            case 0x0033:
                {
                HBufC* suite = iCoeEnv->AllocReadResourceLC( 
                                                R_PEAP_SUITE_DHEDSSAESSHA );
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
            {   // Add mark icon to indicate that the suite is enabled
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
// CEapPeapUiDialog::CheckActiveUserCertificate
// -----------------------------------------------------------------------------
//
TInt CEapPeapUiDialog::CheckActiveUserCertificate()
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
// CEapPeapUiDialog::CheckActiveCaCertificate
// -----------------------------------------------------------------------------
//
TInt CEapPeapUiDialog::CheckActiveCaCertificate()
    {
    for ( TInt i = 0; i<iUiCACertificates->Count(); i++ )
        {
        if ( iUiCACertificates->At( i ).iIsEnabled )
            {
            return i;
            }
        }

    return KErrNotFound;
    }


// -----------------------------------------------------------------------------
// CEapPeapUiDialog::UserCertificateHouseKeeping
// -----------------------------------------------------------------------------
//
void CEapPeapUiDialog::UserCertificateHouseKeeping( TInt aSelected )
    {
    for ( TInt i = 0; i < iUiUserCertificates->Count(); i++ )
        {
        iUiUserCertificates->At( i ).iIsEnabled = EFalse;
        }

    if ( aSelected != 0 )   // Zero index is none
        {
        iUiUserCertificates->At( aSelected-1 ).iIsEnabled = ETrue;
        } 
    }


// -----------------------------------------------------------------------------
// CEapPeapUiDialog::CaCertificateHouseKeeping
// -----------------------------------------------------------------------------
//
void CEapPeapUiDialog::CaCertificateHouseKeeping( TInt aSelected )
    {
    for ( TInt i = 0; i<iUiCACertificates->Count() ; i++ )
        {
        iUiCACertificates->At( i ).iIsEnabled = EFalse;
        }

    if ( aSelected != 0 )   // Zero index is none
        {        
        iUiCACertificates->At( aSelected-1 ).iIsEnabled = ETrue;
        }
    }


// -----------------------------------------------------------------------------
// CEapPeapUiDialog::CreateEapTypeDataBaseL
// -----------------------------------------------------------------------------
//
void CEapPeapUiDialog::CreateEapTypeDataBaseL()
    {
    RImplInfoPtrArray eapArray;
    eapArray.Reset();
    REComSession::ListImplementationsL( KEapTypeInterfaceUid, eapArray );
    TInt allowedInPeapCount( 0 );
    for ( TInt i = 0; i < eapArray.Count(); i++ )
        {
        if ( !CEapType::IsDisallowedInsidePEAP( *eapArray[i] ) )
            {
            CImplementationInformation* info = eapArray[i];
            TEapTlsPeapUiEapType tempEapType;
            tempEapType.iEapType = info->DataType();
            
            // MNOL-6RNHEX
            // Only EAP-SIM and EAP-AKA should be enabled, in that order

            // BINARY RESOURCE DATA
            
            // [FE] [00 00 00] [TEapType_bigendian]
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
                iUiEapTypes->InsertL( allowedInPeapCount, tempEapType );
                }

            allowedInPeapCount++;
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
// CEapPeapUiDialog::SetCipherIconsL
// -----------------------------------------------------------------------------
//
void CEapPeapUiDialog::SetCipherIconsL()
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
    CleanupStack::Pop( icons ); 

    iCipherSuiteListBox->ItemDrawer()->ColumnData()->SetIconArray( icons );
    }


// -----------------------------------------------------------------------------
// CEapPeapUiDialog::SetEapIconsL
// -----------------------------------------------------------------------------
//
void CEapPeapUiDialog::SetEapIconsL()
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
    CleanupStack::Pop( icons ); 

    iEapTypesListBox->ItemDrawer()->ColumnData()->SetIconArray( icons );
    }


// -----------------------------------------------------------------------------
// CEapPeapUiDialog::GetEnabledEapTypeCount
// -----------------------------------------------------------------------------
//
TUint CEapPeapUiDialog::GetEnabledEapTypeCount()
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
// CEapPeapUiDialog::GetHelpContext
// -----------------------------------------------------------------------------
//
void CEapPeapUiDialog::GetHelpContext(TCoeHelpContext& aContext) const
    {
    aContext.iMajor = KHelpUidPlugin;
    TPageIds index = static_cast< TPageIds >( ActivePageIndex() );
    switch ( index )
        {
        case EEapTypePage:
            {
            aContext.iContext = KSET_HLP_WLAN_EAP_PEAP_TYPES;
            break;
            }

        case ECipherSuitePage:
            {
            aContext.iContext = KSET_HLP_WLAN_EAP_PEAP_SUITES;
            break;
            }

        default:
            {
            aContext.iContext = KSET_HLP_WLAN_EAP_PEAP_SETT;
            break;
            }
        }
    }



void CEapPeapUiDialog::GetFullCertLabelL( const SCertEntry& aCert, 
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
		RDebug::Print(_L("CEapTtlsUiDialog::GetFullCertLabel - ERROR! Length Mismatch in Certificate's full name\n") );
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


//  End of File
