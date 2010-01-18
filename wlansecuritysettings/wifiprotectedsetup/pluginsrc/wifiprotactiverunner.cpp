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
* Description: Implements a state - machine like active object that controls Wi-Fi Protected Setup Process. 
*
*/

/*
* %version: tr1cfwln#28 %
*/

//SYSTEM INCLUDES
#include <wlanmgmtclient.h>
#include <wifiprotplugin.rsg>
#include <StringLoader.h>
#include <AknWaitDialog.h>
#include <cmpluginwlandef.h>
#include <commdb.h>
#include <WPASecuritySettingsUI.h>
#include <WEPSecuritySettingsUI.h>
#include <e32math.h>
#include <cmconnectionmethoddef.h>
#include <wlanerrorcodes.h>
#include <utf.h>
#include <AknIconArray.h>
#include <AknGlobalNote.h>
#include <AknSgcc.h>
#include <uikon/eiksrvui.h>
#include <AknsUtils.h>
#include <data_caging_path_literals.hrh>
#include <wifiprot.mbg>

#include <CoreApplicationUIsSDKCRKeys.h>
#include <e32std.h>
#include <ConnectionUiUtilities.h>

//USER INCLUDES
#include "wifiprotlogger.h"
#include "wifiprotactiverunner.h"
#include "wifiprotconfirmationnotedlg.h"
#include "wifiprotselectnetworkdlg.h"
#include "wifiprotenterpindlg.h"
#include "wifiprotinitiateeasysetupdlg.h"

#include "FeatMgr.h"

// valid Wep key lengths, to check wep key format
// (wep key format depends on key length)
const TInt KConnUiUtilsWepLengthASCII5 = 5;
const TInt KConnUiUtilsWepLengthASCII13 = 13;
const TInt KConnUiUtilsWepLengthASCII29 = 29;
const TInt KConnUiUtilsWepLengthHEX10 = 10;
const TInt KConnUiUtilsWepLengthHEX26 = 26;
const TInt KConnUiUtilsWepLengthHEX58 = 58; 
#ifdef __WINS__
const TInt KNumberOfEmulatedAvailableNetworks = 2; 
const TInt KIndexOfFirstEmulatedAvailableNetwork = 0;
const TInt KIndexOfSecondEmulatedAvailableNetwork = 1;
#endif

/**
* Management frame information element IDs.
* needed to determine coverage
*/
enum T802Dot11InformationElementID
    {
    E802Dot11SsidIE                 = 0,
    E802Dot11SupportedRatesIE       = 1,
    E802Doi11FhParameterSetIE       = 2,
    E802Dot11DsParameterSetIE       = 3,
    E802Dot11CfParameterSetIE       = 4,
    E802Dot11TimIE                  = 5,
    E802Dot11IbssParameterSetIE     = 6,
    E802Dot11CountryIE              = 7,
    E802Dot11HoppingPatternParamIE  = 8,
    E802Dot11HoppingPatternTableIE  = 9,
    E802Dot11RequestIE              = 10,

    E802Dot11ChallengeTextIE        = 16,
    // Reserved for challenge text extension 17 - 31
    E802Dot11ErpInformationIE       = 42,
    E802Dot11ExtendedRatesIE        = 50,
    E802Dot11AironetIE              = 133,
    E802Dot11ApIpAddressIE          = 149,
    E802Dot11RsnIE                  = 221
    };

const TInt KArrayGranularity = 10; 
const TInt KIconsGranularity = 4;

_LIT( KWiFiFileIcons, "z:wifiprot.mbm" );

_LIT8( KEapWsc, "\xFE\x00\x37\x2A\x00\x00\x00\x01");

_LIT( KWiFiPanic, "Wi-Fi Protected Setup");

using namespace CMManager;

// ================= MEMBER FUNCTIONS =======================
//
// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::NewL
// --------------------------------------------------------------------------
//
CWiFiProtActiveRunner* CWiFiProtActiveRunner::NewL(
        CWiFiProtDlgsPlugin* aParent, TInt aPriority )
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::NewL" );
    
    CWiFiProtActiveRunner* self =
         new(ELeave) CWiFiProtActiveRunner( aParent, aPriority );
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop(); // self
    
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::NewL" );
    
    return self;
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::~CWiFiProtActiveRunner
// --------------------------------------------------------------------------
//
CWiFiProtActiveRunner::~CWiFiProtActiveRunner()
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::~CWiFiProtActiveRunner" );

    // Close notifier
    iNotifier.Close();

    Cancel();
    
    // If the cancel has been initiated by the client, temp IAP cannot be deleted until
    // after the RNotifier Cancel() call has returned (deadlock between MPM and CMM).
    // Therefore, temp IAP cleanup must be done later.
    if ( !iClientCancelled )
        {
        TRAP_IGNORE( DeleteTempIapL() ); //we can't do much if delete fails
        }
    
    delete iWlanMgmtEngine;
    
    // if cancelled from client, wait note may still be visible
    if ( iWaitDlg )
        {
        CLOG_WRITE( "iWaitDlg->SetCallback( NULL );" );
        iWaitDlg->SetCallback( NULL );
        CLOG_WRITE( "iWaitDlg->ProcessFinishedL( );" );
        TRAP_IGNORE( iWaitDlg->ProcessFinishedL() );
        delete iWaitDlg;
        }
    
    if ( iPinDlg )
        {
        delete iPinDlg;
        }
    
    TBool cleanupCms = EFalse;
    if ( iReturn == EWiFiCancel )
        {
        cleanupCms = ETrue;
        }
        
    for ( TInt i = 0; i < iCmArray.Count();i++ )
        {
        // if we are setting up a connection, we save the settings into
        // easy wlan iap (connection method), which we shouldn't ever delete!
        if ( ( !iIsConnectionNeeded ) && cleanupCms )
            {
            //we can't do much if delete fails
            TRAP_IGNORE( iCmArray[i]->DeleteL() );
            }
        iCmArray[i]->Close();
        delete iCmArray[i];
        iCmArray[i] = NULL;
        }
        
    iCmArray.ResetAndDestroy();
    iAvailableNetworks.Close();
    delete iIapParametersArray;
    delete iScanInfo;
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::~CWiFiProtActiveRunner" );
    
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::StartProtectedSetupL
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::StartProtectedSetupAsyncL (
                                            const TWlanSsid& aSSid,
                                            RArray<TUint32>& aUids,
                                            RCmManagerExt& aCmManagerToUse )
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::StartProtectedSetupAsyncL" );
    
    iIsConnectionNeeded = EFalse;
    iUids = &aUids;
    iCmManagerExt = &aCmManagerToUse;    
    iSsid.Copy( aSSid );
    ShowInitialDialogL();
    
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::StartProtectedSetupAsyncL" );
    
    }
    
// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::StartProtectedSetupConnL
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::StartProtectedSetupConnL (
                                     const TWlanSsid& aSSid,
                                     TWlanProtectedSetupCredentialAttribute&
                                          aNetworkSettings,
                                     RCmManagerExt& aCmManagerToUse )
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::StartProtectedSetupConnL" );
    
    iIsConnectionNeeded = ETrue;
    iNetworkSettings = &aNetworkSettings;
    iCmManagerExt = &aCmManagerToUse;    
    iSsid.Copy( aSSid );
    ShowInitialDialogL();
    
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::StartProtectedSetupConnL" );
    
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::StartProtectedSetupL
// --------------------------------------------------------------------------
//
WiFiProt::TWiFiReturn CWiFiProtActiveRunner::StartProtectedSetupL (
                                            const TWlanSsid& aSSid,
                                            RArray<TUint32>& aUids,
                                            RCmManagerExt& aCmManagerToUse )
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::StartProtectedSetupL" );
    
    iSyncMode = ETrue;
    iIsConnectionNeeded = EFalse;
    iUids = &aUids;
    iCmManagerExt = &aCmManagerToUse;    
    iSsid.Copy( aSSid );
    ShowInitialDialogL();
    
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::StartProtectedSetupL" );
    
    return iReturn;
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::CancelByClient()
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::CancelByClient()
    {
    iClientCancelled = ETrue;
    Cancel();
    if ( iWaitDlg )
        {
        CLOG_WRITE( "Removing wait note( );" );
        iWaitDlg->SetCallback( NULL );
        
        TRAPD(err, iWaitDlg->ProcessFinishedL());
        if (err)
            {
            CLOG_WRITE( "LEAVE: iWaitDlg->ProcessFinishedL" );
            
            }
        delete iWaitDlg;
        iWaitDlg = NULL;
        }
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::ShowInitialDialogL()
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::ShowInitialDialogL()
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::ShowInitialDialogL" );
    
    if ( IsActive() == EFalse ) 
        {
        
        // Check if offline mode is on:
        iInOfflineMode = EFalse;
        if ( FeatureManager::FeatureSupported( KFeatureIdOfflineMode ) )
               {
               TInt connAllowed;
               CRepository* repository = CRepository::NewLC( 
                                                           KCRUidCoreApplicationUIs );
               repository->Get( KCoreAppUIsNetworkConnectionAllowed, connAllowed );
               CleanupStack::PopAndDestroy(repository);  // repository
               if ( connAllowed == 0 )
                   {
                   iInOfflineMode = ETrue;
                   }
               }

        if ( iInOfflineMode && iSyncMode )
            {
            // If in offline mode, query about offline mode first.
            iNextWiFiProtState = EWifiProtOfflineQuery;
            }
        else
            {
            // Else initiate easy setup.
            iNextWiFiProtState = EWiFiProtInitiateEasySetup;
            }
        
        iConfirmationDialog =
                     new ( ELeave ) CWiFiProtConfirmationNoteDlg( iStatus );
        iConfirmationDialog->ExecuteLD( R_WIFIPROT_CONFIGURE_AUTO_DIALOG );
        iORequest = EWiFiProtReqConfirmDialog;
        SetActive( );
        if ( iSyncMode )
            {
            CLOG_WRITE(  "CActiveSchedulerWait Started" );
            iWait.Start();
            CLOG_WRITE(  "CActiveSchedulerWait Returned" );
            }
                        
        }// do nothing if already active
        
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::ShowInitialDialogL" );
    
    }
    
// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::ShowInitiateEasySetupDialogL()
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::ShowInitiateEasySetupDialogL()
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::ShowInitiateEasySetupDialogL" );
    
    iDestroyInitDialogLater = EFalse;
    iNextWiFiProtState = EWiFiProtUsePinCode;
    //store it, but not own it
    iInitDialog = new ( ELeave ) CWiFiProtInitiateEasySetupDlg( iStatus ); 
    iInitDialog->PrepareLC( R_WIFIPROT_INITIATE_EASY_SETUP_DIALOG );
    _LIT( KLinkStartTag, "\n<AknMessageQuery Link>" );
    _LIT( KLinkEndTag, "</AknMessageQuery Link>" );

    HBufC *messageBase =
             StringLoader::LoadLC( R_QTN_NETW_CONSET_WPS_MSG_PBC );
    HBufC* linkString1 = StringLoader::LoadLC( 
                            R_QTN_NETW_CONSET_WPS_MSG_LINK_USE_PIN );

    TInt lenMsg = messageBase->Des().Length()+
                  linkString1->Des().Length()+
                  KLinkStartTag().Length()+
                  KLinkEndTag().Length();    
    
    HBufC* message = HBufC::NewLC( lenMsg );
    TPtr messagePtr = message->Des();

    messagePtr.Append( messageBase->Des() ); 

    messagePtr.Append( KLinkStartTag ); 
    messagePtr.Append( linkString1->Des() );
    messagePtr.Append( KLinkEndTag );    
    
    iInitDialog->SetMessageTextL( messagePtr );
    CleanupStack::PopAndDestroy( message );
    
    CleanupStack::PopAndDestroy( linkString1 );
    CleanupStack::PopAndDestroy( messageBase );    
    TCallBack callBackLink( CWiFiProtActiveRunner::UsePinCodeLinkSelectedL,
                                                                     this );

    iInitDialog->SetLink( callBackLink  );    
    iInitDialog->RunLD();
    iORequest = EWiFiProtReqInitDialog;
    SetActive( );
    
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::ShowInitiateEasySetupDialogL" );
    
    }
    
// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::ShowEnterPinOnStationDialogL()
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::ShowEnterPinOnStationDialogL()
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::ShowEnterPinOnStationDialogL" );
    
    iNextWiFiProtState = EWiFiProtStartingWaitDlg;
    TInt pin = 0;
    TTime t;
    t.HomeTime();
    TInt64 seed = t.Int64();
    do  {
         pin = Math::Rand( seed );
        }
        while ( pin <(10^(KMaxPINLength-2))
             || ( ((pin / 1000000) % 10) ) == 0 );
    //last digit is checksum, so we need 7 digits
    //and the first shouldn't be 0
    pin = pin % 10000000; 
    TInt checkSum = ComputeChecksum(pin);
    pin *= 10;
    pin += checkSum;
    _LIT(KPinFormat,"%d");
    iPIN.Format(KPinFormat, pin);
    
    CLOG_WRITE( "Enter pin code note" );
    
    HBufC* prompt =
     StringLoader::LoadLC( R_QTN_NETW_CONSET_WPS_INFO_ENTER_PIN_CODE, pin );
    CWiFiProtEnterPinDlg* pinDlg = new ( ELeave ) CWiFiProtEnterPinDlg( *this );
    
    CleanupStack::PushL(pinDlg);
    pinDlg->SetPromptL( *prompt );
    CleanupStack::Pop(pinDlg);

    CleanupStack::PopAndDestroy( prompt );
    iPinDlg = pinDlg;
    iPinDlg->ExecuteLD( R_WIFIPROT_ENTER_PIN_CODE_DIALOG );
    iPinQueryActive = ETrue;
    SetActive( );
    SetNextStateAndComplete( EWiFiProtConfiguring );
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::ShowEnterPinOnStationDialogL" );
    
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::ShowWaitingDialogL()
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::ShowWaitingDialogL()
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::ShowWaitingDialogL" );
    HBufC* text = StringLoader::LoadLC(
            R_QTN_NETW_CONSET_WAIT_WPS_CONFIGURING );
    iWaitDlg = new ( ELeave ) CAknWaitDialog(
                          ( REINTERPRET_CAST( CEikDialog**, &iWaitDlg )),
                            ETrue );
    iWaitDlg->SetTextL( *text );
    CleanupStack::PopAndDestroy( text );
    iWaitDlg->SetCallback( this );
    iWaitDlg->SetTone( CAknNoteDialog::EConfirmationTone );
    iWaitDlg->ExecuteLD( R_WIFIPROT_WAIT_NOTE  );
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::ShowWaitingDialogL" );
    }


// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::ShowWaitingDialogAndProceedL()
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::ShowWaitingDialogAndProceedL()
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::ShowWaitingDialogAndProceedL" );
    
    iStatus = KRequestPending; //should be set by service provider
    ShowWaitingDialogL();
    SetActive( );
    SetNextStateAndComplete( EWiFiProtConfiguring );
    
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::ShowWaitingDialogAndProceedL" );
    
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::ShowFinalNoteL()
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::ShowFinalNoteL()
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::ShowFinalNoteL" );
    
    const TInt KSettingsConfNone = 0;
    const TInt KSettingsConfOne = 1;
    const TInt KSettingsConfMulti = 2;
    const TInt KResourceIdInvalid = 0;
    
    HBufC* text = NULL;
    TInt resId = KResourceIdInvalid;
    CAknNoteDialog::TTone tone = CAknNoteDialog::ENoTone;
    TInt numberOfNetworksConfigured = 0;
    if ( iIsConnectionNeeded )
        {
        // we have one network configured if we are here
        numberOfNetworksConfigured = 1;
        }
    else
        {
        numberOfNetworksConfigured = iCmArray.Count();
        }
        
    
    //more than one = multiple
    if ( numberOfNetworksConfigured > KSettingsConfOne) 
        {
        numberOfNetworksConfigured = KSettingsConfMulti;
        }
    switch ( numberOfNetworksConfigured )
        {
        case KSettingsConfOne :
            {
            CLOG_WRITE( "Show one network configured note " );
            HBufC* name;
            if ( iIsConnectionNeeded )
                {
                // We have to convert the 8-bit SSID to 16-bit 
                HBufC* ssid16 = HBufC::NewLC( (*iIapParametersArray)
                    [iAvailableNetworks[
                            iSelectedNetworkIndex]].iSsid.Length()+1 );
                TPtr ssid16Ptr( ssid16->Des() );
                CnvUtfConverter::ConvertToUnicodeFromUtf8( ssid16Ptr,
                    (*iIapParametersArray)[iAvailableNetworks[
                                        iSelectedNetworkIndex]].iSsid );
                ssid16Ptr.ZeroTerminate();
                name = ssid16Ptr.AllocL();
                CleanupStack::PopAndDestroy( ssid16 );             
                }
            else
                {
                RCmConnectionMethodExt cm =
                     iCmManagerExt->ConnectionMethodL(
                                    iCmArray[0]->GetIntAttributeL( ECmId ) );
                CleanupClosePushL( cm );
                name =  cm.GetStringAttributeL( EWlanSSID );
                CleanupStack::PopAndDestroy( &cm );
                }
            CleanupStack::PushL( name );
            text = StringLoader::LoadL(
                 R_QTN_NETW_CONSET_CONF_WPS_ONE_NETWORK_CONFIGURED , *name);
            CleanupStack::PopAndDestroy( name );
            CleanupStack::PushL( text );
            resId = R_WIFIPROT_OK_NOTE;
            tone = CAknNoteDialog::EConfirmationTone;
            break;
            }
        case KSettingsConfMulti:
            {
            CLOG_WRITE( "Show multiple networks configured note " );
            text = StringLoader::LoadLC(
                 R_QTN_NETW_CONSET_CONF_WPS_MULTIPLE_NETWORKS_CONFIG );
            resId = R_WIFIPROT_OK_NOTE;
            tone = CAknNoteDialog::EConfirmationTone;
            break;
            }
        case KSettingsConfNone :
            {
            CLOG_WRITE( "Show no networks configured note " );
            text = StringLoader::LoadLC(
                 R_QTN_NETW_CONSET_CONF_WPS_NO_NETWORKS_CONFIGURED );
            resId = R_WIFIPROT_INFO_NOTE;
            break;
            }
        default:
            {
            //should not ever get here
            CLOG_WRITE( "Unhandled Final Note!!!" );
            User::Leave( KErrGeneral );
            break;            
            }
        }

    CAknNoteDialog* dlg = new (ELeave) CAknNoteDialog(
                             tone,
                             CAknNoteDialog::ELongTimeout );
    dlg->SetTextL( *text );
    CleanupStack::PopAndDestroy( text );   
    iStatus = KRequestPending; //should be set by service provider
    SetActive( );
    dlg->ExecuteLD( resId  ); 
    SetNextStateAndComplete( EWiFiProtFinished );
    
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::ShowFinalNoteL" );
    
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::DialogDismissedL
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::DialogDismissedL( TInt aButtonId )
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::DialogDismissedL" );
    
    //wait dialog cancelled
    if ( aButtonId == EAknSoftkeyCancel )
        {    
        CLOG_WRITE( "Cancel pressed!" );
        if (iWaitDlg)
            {
            iWaitDlgCancelled = ETrue;
            }
        iUserCancelled = ETrue;   
        CancelOngoingRequest();        
        }
    // iWaitDlg is destroyed, so we can null it
    iWaitDlg = NULL; 
 
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::DialogDismissedL" );
    
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::CreateTempIapL
// --------------------------------------------------------------------------
//
TUint32 CWiFiProtActiveRunner::CreateTempIapL( TUint32& aTempServId )
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::CreateTempIapL" );
    
    RCmConnectionMethodExt cm;
    cm = iCmManagerExt->CreateConnectionMethodL( KUidWlanBearerType );
    CleanupClosePushL(cm);

    // We have to convert the 8-bit SSID to 16-bit for CommsDat.
    HBufC* ssid16 = HBufC::NewLC( iSsid.Length() );
    TPtr ssid16Ptr( ssid16->Des() );
    CnvUtfConverter::ConvertToUnicodeFromUtf8( ssid16Ptr , iSsid ); 
    cm.SetStringAttributeL( EWlanSSID, *ssid16 ); 
    cm.SetStringAttributeL( ECmName, *ssid16 ); 
    CLOG_WRITEF( _L("SSid: ") );
    CLOG_WRITEF( *ssid16 );
    CleanupStack::PopAndDestroy( ssid16 ); 
    
    
    cm.SetIntAttributeL( EWlanSecurityMode, EWlanSecModeWpa2 );
    cm.UpdateL();
    
    aTempServId = cm.GetIntAttributeL( ECmIapServiceId );
    TInt32 iapID = cm.GetIntAttributeL( ECmId );
    
    CommsDat::CMDBSession* db =
       CommsDat::CMDBSession::NewL( CommsDat::CMDBSession::LatestVersion() );
    CleanupStack::PushL( db );
    CWPASecuritySettings* wpaSecSettings =
         CWPASecuritySettings::NewL( ESecurityModeWpa );
    CleanupStack::PushL( wpaSecSettings );      
    User::LeaveIfError( wpaSecSettings->SetWPAEnabledEAPPlugin( KEapWsc ) );
    CLOG_WRITEF( _L("Enabled EAP plugin set: EAP WSC"));
    if (iPIN != KNullDesC)
        { 
        User::LeaveIfError( wpaSecSettings->SetWPAPreSharedKey( iPIN ) );
        CLOG_WRITEF( _L("Pin set as WPA key: "));
        CLOG_WRITEF( iPIN );
        }    

    CLOG_WRITEF( _L("WPA settings save - ECmIapServiceId in aTempServId %d"), aTempServId );
    wpaSecSettings->SaveL( aTempServId , *db, ESavingBrandNewAP, 0 );
    CLOG_WRITEF( _L("WPA settings saved!"));
    CleanupStack::PopAndDestroy( wpaSecSettings );         
    db->Close();
    CleanupStack::PopAndDestroy( db ); 
    CleanupStack::PopAndDestroy( &cm ); 
    
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::CreateTempIapL" );
    
    return iapID;
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::RunProtectedSetup
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::RunProtectedSetup ( const TInt32 aIapId )
    {
    
    CLOG_ENTERFN( "CWiFiProtActiveRunner::RunProtectedSetup" );
    
    iNextWiFiProtState = EWiFiProtWlanMgmtEngineReturned;
    if ( iWlanMgmtEngine ) 
        {
        CLOG_WRITEF(_L(
         "We have a wlanmgmt engine, calling RunProtectedSetup with uid %d")
         , aIapId );
        iWlanMgmtEngine->RunProtectedSetup( iStatus, aIapId,
                                            *iIapParametersArray );
        iORequest = EWiFiProtReqWPS;
        SetActive( );
        }
    else
        {
        // we complete ourselves after creating these cms synchronously
        //just for wins testing
        //add 1 conneciton method;
#ifdef __WINS__
        CLOG_WRITE( "No wlanmgmt engine, simulating... " );
        TWlanProtectedSetupCredentialAttribute tmpCred;
        tmpCred.iOperatingMode = EWlanOperatingModeInfrastructure;
        tmpCred.iAuthenticationMode = EWlanAuthenticationModeOpen;
        tmpCred.iSecurityMode = EWlanIapSecurityModeAllowUnsecure;
        tmpCred.iSsid = _L8("Available Network");
       
        TRAP_IGNORE( iIapParametersArray->AppendL(tmpCred) );

        tmpCred.iOperatingMode = EWlanOperatingModeInfrastructure;
        tmpCred.iAuthenticationMode = EWlanAuthenticationModeOpen;
        tmpCred.iSecurityMode = EWlanIapSecurityModeAllowUnsecure;
        tmpCred.iSsid = _L8("Available Network 2");
        
        TRAP_IGNORE( iIapParametersArray->AppendL(tmpCred) );
        
        tmpCred.iOperatingMode = EWlanOperatingModeInfrastructure;
        tmpCred.iAuthenticationMode = EWlanAuthenticationModeOpen;
        tmpCred.iSecurityMode = EWlanIapSecurityModeAllowUnsecure;
        tmpCred.iSsid = _L8("Unavailable Network");
        
        TRAP_IGNORE( iIapParametersArray->AppendL(tmpCred) );
        
        iStatus = KRequestPending;
        SetActive( );
        SetNextStateAndComplete(EWiFiProtWlanMgmtEngineReturned );
#else
        //no engine in hardware, should not ever get here!
        User::Panic( KWiFiPanic , KErrNotFound );
#endif
        }
        
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::RunProtectedSetup" );
    
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::CWiFiProtActiveRunner
// --------------------------------------------------------------------------
//
CWiFiProtActiveRunner::CWiFiProtActiveRunner( 
                    CWiFiProtDlgsPlugin* aParent,  TInt aPriority ) 
                    : CActive( aPriority ),
                    iParent( aParent ),
                    iIsConnectionNeeded( EFalse ),
                    iWaitDlgCancelled( EFalse ),
                    iSsid( KNullDesC8 ),
                    iPIN( KNullDesC ),
                    iNextWiFiProtState( EWiFiProtAskConfigureAutomatically ),
                    iReturn( EWiFiCancel ),
                    iUsePin( EFalse ),
                    iError( KErrNone ),
                    iPinQueryActive( EFalse ),
                    iWaitNoteNeeded( EFalse ),
                    iInitDialog( NULL ),
                    iClientCancelled( EFalse )
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::CWiFiProtActiveRunner" );
    
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::CWiFiProtActiveRunner" );
    
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::ConstructL
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::ConstructL()
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::ConstructL" );   
    
    CActiveScheduler::Add( this );
#ifndef __WINS__
    iWlanMgmtEngine = CWlanMgmtClient::NewL();
    iScanInfo = CWlanScanInfo::NewL();
#endif // !__WINS__    
    iIapParametersArray = new (ELeave)
     CArrayFixSeg<TWlanProtectedSetupCredentialAttribute>
                                    ( KArrayGranularity );

    User::LeaveIfError(iNotifier.Connect()); // Connects to the extended notifier server
    
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::ConstructL" );
    
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::DoCancel
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::DoCancel()
    { 
    CLOG_ENTERFN( "CWiFiProtActiveRunner::DoCancel" );
    
    CancelOngoingRequest();
               
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::DoCancel" );
    
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::RunL
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::RunL()
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::RunL" );
    
    // reset the async request id
    iORequest = EWiFiProtReqNone;
    
    if ( iClientCancelled )
        {
        // no further actions needed here, message completion taken care of
        // in the notifier
        return;
        }
    
    CLOG_WRITEF(  _L(" iNextWiFiProtState: %d"), iNextWiFiProtState );
    if ( iNextWiFiProtState == EWiFiProtWlanMgmtEngineReturned ) 
        {
        iORequest = EWiFiProtReqNone;
        //if we have a dialog and configuration is finished,
        // store error code for destroying dialog         
        iError = iStatus.Int();
        CleanupTempIapL();
        }
    else if ( iNextWiFiProtState == EWiFiProtDestroyWaitNote )         
        {
        DestroyWaitDialog();
        }
    else
        {
        if ( iUserCancelled )        
            {
            iStatus = KErrCancel;
            }
            
        if ( iStatus.Int() == KErrNone ) //no error
            {
            HandleNoErrorL();
            } 
         // error or cancel           
         // try to handle error, if can't, just cancel 
         else if ( !HandleErrorL( iStatus.Int() ) )  
                {
                if ( (iStatus.Int() != KErrAbort) && 
                     (iNextWiFiProtState == EWifiProtOfflineQuery || iNextWiFiProtState == EWiFiProtInitiateEasySetup) )
                    {
                    // Use WPS to configure or connect in offline mode? -> No -> Continue the traditional way without WPS
                    iReturn = EWifiNoAuto;
                    }
                 else
                    {
                    iReturn = EWiFiCancel;
                    }
                
                if ( iSyncMode )
                    {
                    if ( iWait.IsStarted() )
                        {
                        iWait.AsyncStop();
                        }
                    }
                else
                    {
                    iParent->CompleteProcessL( iReturn );
                    }
                }
        }
        
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::RunL" );
    
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::SetNextStateAndComplete
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::SetNextStateAndComplete(
                                                 TWiFiProtStates aNextState,
                                                            TInt aError )
    { 
    CLOG_ENTERFN( "CWiFiProtActiveRunner::SetNextStateAndComplete" );
    
    iNextWiFiProtState = aNextState;
    CLOG_WRITEF(  _L(" aNextState: %d"), aNextState );
    TRequestStatus* pS = &iStatus;                
    User::RequestComplete( pS, aError ); 
    
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::SetNextStateAndComplete" );

    }
    
// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::ConfigureL()
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::ConfigureL()
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::ConfigureL" );
    iWaitNoteNeeded = ETrue;
    iTempIapId = CreateTempIapL( iTempServId );
    CLOG_WRITEF( _L("Temp Iap created! Id: %d"), iTempIapId );
    RunProtectedSetup( iTempServId );
    // do not complete self, waiting for engine or user cancel to complete us 
    
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::ConfigureL" );
    
    }        
    
// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::EvaluateResult
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::EvaluateResult()
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::EvaluateResult" );
    if (iError == KErrNone)
        {
        if ( iIsConnectionNeeded )
            {
            TRAPD(err, CheckNetworkAvailabilityL());
            if (err)
                {
                CLOG_WRITE(
                     "LEAVE: CheckNetworkAvailabilityL" );
                }
            }
        else
            {
            CLOG_WRITE(
                 "SetNextStateAndComplete( EWiFiProtSettingsConfNote );" );
            SetNextStateAndComplete( EWiFiProtSettingsConfNote );
            }
        }
    else
        { //now we complete with the error code as dialog is finished
        CLOG_WRITE( "SetNextStateAndComplete( EWiFiProtFinished, iError );" );
        SetNextStateAndComplete( EWiFiProtFinished , iError );
        }
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::EvaluateResult" );
    }
    
// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::DestroyWaitDialog
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::DestroyWaitDialog()
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::DestroyWaitDialog" );
    
    CLOG_WRITE( "SetActive();" );
    SetActive();    
    iStatus = KRequestPending; //should be set by service provider
    iWaitNoteNeeded = EFalse;
    if( !iWaitDlgCancelled )
        {
        // iWaitDlg possibly wasn't even shown...
        if ( iWaitDlg )
            {
            CLOG_WRITE( "iWaitDlg->SetCallback( NULL );" );
            iWaitDlg->SetCallback( NULL );
            CLOG_WRITE( "iWaitDlg->ProcessFinishedL( );" );
            
            TRAPD(err, iWaitDlg->ProcessFinishedL());
            if (err)
                {
                CLOG_WRITE( "LEAVE: iWaitDlg->ProcessFinishedL( );" );
                }
            
            CLOG_WRITE( "delete iWaitDlg;" );
            delete iWaitDlg;
            iWaitDlg = NULL;
            }
        if ( iPinQueryActive )   //waiting for PIN Query
            {
            CLOG_WRITE(
             "SetNextStateAndComplete( EWiFiProtWaitForPINQuery );" );
            // if pin query is still active, remove the cancel...
            if ( iPinQueryActive && iPinDlg)
                {
                iPinDlg->RemoveCancel();
                }            
            iNextWiFiProtState = EWiFiProtWaitForPINQuery;
            }
        else
            {
            EvaluateResult();
            }
        }
    else
        {
        CLOG_WRITE(
         "SetNextStateAndComplete( EWiFiProtFinished, KErrCancel );" );
        SetNextStateAndComplete( EWiFiProtFinished , KErrCancel );
        }
    
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::DestroyWaitDialog" );
    
    }
    
// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::ComputeChecksum
// --------------------------------------------------------------------------
//
TInt CWiFiProtActiveRunner::ComputeChecksum(TInt aPin)
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::ComputeChecksum" );
    
    TInt accum = 0;
    aPin *= 10;
    accum += 3 * ((aPin / 10000000) % 10);
    accum += 1 * ((aPin / 1000000) % 10);
    accum += 3 * ((aPin / 100000) % 10);
    accum += 1 * ((aPin / 10000) % 10);
    accum += 3 * ((aPin / 1000) % 10);
    accum += 1 * ((aPin / 100) % 10);
    accum += 3 * ((aPin / 10) % 10);
    TInt digit = (accum % 10);
        
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::ComputeChecksum" );
    
    return (10 - digit) % 10;
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::CreateAllIapsL
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::CreateAllIapsL()
    {
    CreateIapL(0);
    iStatus = KRequestPending; //should be set by service provider
    SetActive();   
    if ( iIapParametersArray->Count() )
        {
        //another cm, another round
        SetNextStateAndComplete( EWiFiProtCreateAllIaps ); 
        }
     else
        {
        //cm creation finished
        SetNextStateAndComplete( EWiFiProtDestroyWaitNote ); 
        }    
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::CreateIapL
// --------------------------------------------------------------------------
//
TUint32 CWiFiProtActiveRunner::CreateIapL( const TInt aIndex )
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::CreateIapL" );
    
    TInt32 iapID = 0;
    if ( iIapParametersArray->Count() )
        {
        RCmConnectionMethodExt cm;
        cm = iCmManagerExt->CreateConnectionMethodL( KUidWlanBearerType );
        CleanupClosePushL(cm);
        iapID = SetIapDataL( aIndex, cm );
        CleanupStack::Pop( &cm ); 
        
        RCmConnectionMethodExt* cmToAppend =
                 new (ELeave) RCmConnectionMethodExt(cm);
        CleanupStack::PushL(cmToAppend);
        iCmArray.Append( cmToAppend ); //ownership transferred
        CleanupStack::Pop( cmToAppend ); 
        CLOG_WRITEF( _L("Cm appended to array: ") );


        (*iIapParametersArray).Delete(aIndex);
        }
    
       
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::CreateIapL" );
    
    return iapID;
    }


// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::SetIapDataL
// --------------------------------------------------------------------------
//
TUint32 CWiFiProtActiveRunner::SetIapDataL( const TInt aIndex,
                                           RCmConnectionMethodExt& aCmToSet )
    {
            // We have to convert the 8-bit SSID to 16-bit for CommsDat.
        HBufC* ssid16 =
             HBufC::NewLC( ( *iIapParametersArray)[aIndex].iSsid.Length() );
        TPtr ssid16Ptr( ssid16->Des() );
        CnvUtfConverter::ConvertToUnicodeFromUtf8(
                 ssid16Ptr , (*iIapParametersArray)[aIndex].iSsid ); 
        
        aCmToSet.SetStringAttributeL( ECmName, *ssid16 );
        aCmToSet.SetStringAttributeL( EWlanSSID, *ssid16 );
        CLOG_WRITEF( _L("Parameters from wlan mgmt engine: ") );
        CLOG_WRITEF( _L("SSid: ") );
        CLOG_WRITEF( *ssid16 );
        CleanupStack::PopAndDestroy( ssid16 );

        TInt connMode = EAdhoc;
        switch ( (*iIapParametersArray)[aIndex].iOperatingMode )
            {
            case EWlanOperatingModeAdhoc:
                {
                CLOG_WRITEF( _L("Operating Mode: Adhoc") );
                break;
                }
            case EWlanOperatingModeInfrastructure:
                {
                CLOG_WRITEF( _L("Operating Mode: Infra") );
                connMode = EInfra;
                break;
                }
            default:
                {
                CLOG_WRITEF( _L("Operating Mode: Not Supported") );
                User::Leave( KErrNotSupported );            
                break;
                }
            }
        aCmToSet.SetIntAttributeL( EWlanConnectionMode, connMode );

        CMManager::TWlanSecMode secMode = EWlanSecModeOpen;
        switch( (*iIapParametersArray)[aIndex].iSecurityMode )
            {
            case EWlanIapSecurityModeAllowUnsecure:
                {
                CLOG_WRITEF( _L("Security Mode: Open") );
                secMode = EWlanSecModeOpen;
                break;
                }
            
            case EWlanIapSecurityModeWep:
                {
                CLOG_WRITEF( _L("Security Mode: Wep") );
                secMode = EWlanSecModeWep;
                break;
                }
            
            case EWlanIapSecurityMode802d1x:
                {
                CLOG_WRITEF( _L("Security Mode: 802_1x") );
                secMode = EWlanSecMode802_1x;
                break;
                }
                
            // EWlanIapSecurityModeWpa and 
            // EWlanIapSecurityModeWpa2Only are handled as wpa            
            case EWlanIapSecurityModeWpa: 
            case EWlanIapSecurityModeWpa2Only:
                {
                CLOG_WRITEF( _L("Security Mode: wpa") );
                secMode = EWlanSecModeWpa;
                break;
                }
            
            default:
                {
                User::Leave( KErrNotSupported );
                }
            }

        aCmToSet.SetIntAttributeL( EWlanSecurityMode, secMode );

        aCmToSet.UpdateL();
        TInt32 wlanServId = aCmToSet.GetIntAttributeL( ECmIapServiceId );
        TInt32 iapID = aCmToSet.GetIntAttributeL( ECmId );

        CommsDat::CMDBSession* db =
             CommsDat::CMDBSession::NewL(
                     CommsDat::CMDBSession::LatestVersion() );
        CleanupStack::PushL( db );

        switch( (*iIapParametersArray)[aIndex].iSecurityMode )
            {
            case EWlanIapSecurityModeWep:
                {
                SaveWepSecuritySettingsL(
                         ( *iIapParametersArray )[aIndex], wlanServId, *db );
                break;
                }
            // EWlanIapSecurityModeWpa and 
            // EWlanIapSecurityModeWpa2Only are handled as wpa                
            case EWlanIapSecurityModeWpa:
            case EWlanIapSecurityModeWpa2Only:        
                {
                CWPASecuritySettings* wpaSecSettings =
                     CWPASecuritySettings::NewL( ESecurityModeWpa );
                CleanupStack::PushL( wpaSecSettings );    
                if ((*iIapParametersArray)
                        [aIndex].iWpaPreSharedKey != KNullDesC8)
                    {
                    TBuf<KWlanWpaPskMaxLength> wpaBuf16;
                    wpaBuf16.Copy((*iIapParametersArray)
                        [aIndex].iWpaPreSharedKey);           
                    User::LeaveIfError(
                            wpaSecSettings->SetWPAPreSharedKey( wpaBuf16 ) );
                    CLOG_WRITEF( _L("wpa psk set: ") );
                    CLOG_WRITEF( wpaBuf16 );
                    
                    }
                
                TTypeOfSaving typeOfSaving = ESavingBrandNewAP;
                    
                if ( iapID == iCmManagerExt->EasyWlanIdL() )
                    {
                    typeOfSaving = ESavingEditedAP;
                    }
                    
                wpaSecSettings->SaveL( wlanServId, *db,
                                         typeOfSaving, 0 ) ;    
                
                CleanupStack::PopAndDestroy( wpaSecSettings );         
                break;
                }
            // EWlanIapSecurityMode802d1x and 
            // EWlanConnectionSecurityOpen - no key needs to be saved                
            case EWlanIapSecurityMode802d1x:
            case EWlanConnectionSecurityOpen:
            default:
                {
                break;
                }
            }

        db->Close();
        CleanupStack::PopAndDestroy( db ); 
    return iapID;
    }
    
// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::CleanupTempIapL()
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::CleanupTempIapL()
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::CleanupTempIapL" );
    
    //we don't need the temp iap anymore, delete it
    //shouldn't be any errors, because nobody else knows about our temp iap
    DeleteTempIapL();
    SetActive();    
    iStatus = KRequestPending; //should be set by service provider
    if ( iError == KErrNone )
        {
        if ( iIsConnectionNeeded )
            {
            StartWlanScan(); //scan wlan before we close the wait dialog
            }
         else
            {
            //start creating iaps
            SetNextStateAndComplete( EWiFiProtCreateAllIaps ); 
            }
        }
    else
       {
       //don't create iaps or scan wlan, we had an error!
       SetNextStateAndComplete( EWiFiProtDestroyWaitNote ); 
       }
    
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::CleanupTempIapL" );
    
    } 

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::DeleteTempIapL()
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::DeleteTempIapL()
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::DeleteTempIapL" );
    
    if ( iTempIapId )
        {
        const TInt KInvalidUid = 0;
        
        CLOG_WRITE( "Calling iCmManagerExt->ConnectionMethodL" );
        
        RCmConnectionMethodExt cm =
                             iCmManagerExt->ConnectionMethodL(iTempIapId);
        
        CLOG_WRITE( "Calling cm.DeleteL" );
        
        TRAPD(err, cm.DeleteL());
        CLOG_WRITEF( _L("Temp Iap deleted! Error code: %d"), err );
        cm.Close();
        iTempIapId = KInvalidUid;
        }
        
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::DeleteTempIapL" );
    
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::IsWepFormatHexL
// --------------------------------------------------------------------------
//
TBool CWiFiProtActiveRunner::IsWepFormatHexL( TInt aLength )
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::IsWepFormatHexL" );

    if ( ( aLength == KConnUiUtilsWepLengthASCII5 ) ||
        ( aLength == KConnUiUtilsWepLengthASCII13 ) ||
        ( aLength == KConnUiUtilsWepLengthASCII29 ) )
        {
        return EFalse;
        }
    else if ( ( aLength == KConnUiUtilsWepLengthHEX10 ) ||
        ( aLength == KConnUiUtilsWepLengthHEX26 ) ||
        ( aLength == KConnUiUtilsWepLengthHEX58 ) )
        {
        return ETrue;
        }
    else
        {
        User::Leave( KErrNotSupported );
        }

    CLOG_LEAVEFN( "CWiFiProtActiveRunner::IsWepFormatHexL" );
            
    return EFalse;
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::SaveWepSecuritySettingsL
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::SaveWepSecuritySettingsL(
                                 TWlanProtectedSetupCredentialAttribute
                                         aCredentialAttribute, 
                                 TUint32 aWlanServiceId,
                                 CommsDat::CMDBSession& aDb )
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::SaveWepSecuritySettingsL" );
    
    CWEPSecuritySettings* wepSecSettings = CWEPSecuritySettings::NewL( );
    CleanupStack::PushL( wepSecSettings );    
    TInt keyIndex = 0;
    // wep key 1
    SetWepKeyL( *wepSecSettings, aCredentialAttribute.iWepKey1, keyIndex );
    keyIndex++;
    // wep key 2
    SetWepKeyL( *wepSecSettings, aCredentialAttribute.iWepKey2, keyIndex );
    keyIndex++;
    // wep key 3
    SetWepKeyL( *wepSecSettings, aCredentialAttribute.iWepKey3, keyIndex );
    keyIndex++;
    // wep key 4
    SetWepKeyL( *wepSecSettings, aCredentialAttribute.iWepKey4, keyIndex );
       
    //should be the same enum       
    wepSecSettings->SetKeyInUse( (CWEPSecuritySettings::TWEPKeyInUse)
                                 aCredentialAttribute.iWepDefaultKey );
    CLOG_WRITEF( _L("Wep key in use %d:"),
             aCredentialAttribute.iWepDefaultKey );
                                 
    CWEPSecuritySettings::TWEPAuthentication auth =
             CWEPSecuritySettings::EAuthOpen;
                                    
    switch( aCredentialAttribute.iAuthenticationMode )
        {
        case EWlanAuthenticationModeOpen:
            {
            CLOG_WRITEF( _L("Authentication mode: open") );
            break;
            }
        case EWlanAuthenticationModeShared:
            {
            CLOG_WRITEF( _L("Authentication mode: shared") );
            auth = CWEPSecuritySettings::EAuthShared;
            break;
            }
        default:
            {
            break;
            }
        }
                    
    //should be the same enum                    
    wepSecSettings->SetAuthentication(
         (CWEPSecuritySettings::TWEPAuthentication) auth );
    wepSecSettings->SaveL( aWlanServiceId, aDb ) ;    
    CleanupStack::PopAndDestroy( wepSecSettings );         

    CLOG_LEAVEFN( "CWiFiProtActiveRunner::SaveWepSecuritySettingsL" );

    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::HandleErrorL()
// --------------------------------------------------------------------------
//
TBool CWiFiProtActiveRunner::HandleErrorL( TInt aErrorCode )
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::HandleErrorL" );
    
    CLOG_WRITEF( _L("Error code: %d"), aErrorCode );
    if (iWaitDlg) //close dialog first
        {
        TInt error = iStatus.Int();
        iStatus = KRequestPending; //should be set by service provider
        SetActive( );
        SetNextStateAndComplete( EWiFiProtDestroyWaitNote , error );    
        
        CLOG_LEAVEFN( "CWiFiProtActiveRunner::HandleErrorL" );    
        
        return ETrue;    
        }
    else
        {
        TWiFiProtStates nextState = EWiFiProtFinished;
        TInt textResId = 0;
        TInt status = KErrCancel;
        TBool ret = ETrue;
        switch (aErrorCode)
            {
            // Error codes are in the original order
            case KErrWlanProtectedSetupOOBInterfaceReadError:
            case KErrWlanProtectedSetupDecryptionCRCFailure:
            // the same handling here for this error code too
                {
                textResId = R_QTN_ERR_WLAN_SC_CONFIG_FAILED_TRY_AGAIN;  
                break;
                }
            case KErrWlanProtectedSetup5_0ChannelNotSupported:
            case KErrWlanProtectedSetup2_4ChannelNotSupported:
            // the same handling here for this error code too
                {
                textResId = R_QTN_ERR_WLAN_SC_CONFIG_FAILED;  
                break;
                }
            case KErrWlanSignalTooWeak:
                {
                textResId = R_QTN_ERR_WLAN_SIGNAL_TOO_WEAK;  
                break;
                }
            case KErrWlanProtectedSetupNetworkAuthFailure:
                {
                status = KErrNone;
                textResId = R_QTN_ERR_WLAN_SC_CONFIG_FAILED_TRY_AGAIN;
                if ( iUsePin )
                    {
                    // ...pin code dialog if pin code was used
                    nextState = EWiFiProtUsePinCode;
                    }
                else
                    {
                    // ... or initiate WPS dialog if push button was used
                    nextState = EWiFiProtInitiateEasySetup;
                    } 
                break;
                }
            case KErrWlanProtectedSetupNetworkAssociationFailure:
                {
                textResId = R_QTN_ERR_WLAN_NETWORK_NOT_FOUND;  
                break;
                }
            case KErrWlanProtectedSetupNoDHCPResponse:
            case KErrWlanProtectedSetupFailedDHCPConfig:
            // the same handling here for this error code too
            case KErrWlanProtectedSetupIPAddressConflict:
            // the same handling here for this error code too
            case KErrWlanProtectedSetupCouldNotConnectToRegistrar:
            // the same handling here for this error code too
                {
                textResId = R_QTN_ERR_WLAN_SC_CONFIG_FAILED;  
                break;
                }
            case KErrWlanProtectedSetupMultiplePBCSessionsDetected:
                {
                nextState = EWiFiProtInitiateEasySetup;
                status = KErrNone;
                textResId =
                 R_QTN_ERR_WLAN_SC_CONFIG_FAILED_MULTIPLE_PB_SESSIONS;  
                break;
                }
            case KErrWlanProtectedSetupRogueActivitySuspected:
                {
                nextState = EWiFiProtUsePinCode;
                iUsePin = ETrue;
                status = KErrNone;
                textResId =
                 R_QTN_ERR_WLAN_SC_CONFIG_FAILED_ROGUE_ACTIVITY;  
                break;
                }            
            case KErrWlanProtectedSetupDeviceBusy:
            case KErrWlanProtectedSetupSetupLocked:
            // the same handling here for this error code too
            case KErrWlanProtectedSetupMessageTimeout:
            // the same handling here for this error code too
                {
                textResId = R_QTN_ERR_WLAN_SC_CONFIG_FAILED_TRY_AGAIN;  
                break;
                }
            case KErrWlanProtectedSetupRegistrationSessionTimeout:
                {
                textResId = R_QTN_ERR_WLAN_SC_CONFIG_FAILED_TRY_AGAIN;  
                status = KErrNone;
                // Registration session timeout, return to ...
                if ( iUsePin )
                    {
                    // ...pin code dialog if pin code was used
                    nextState = EWiFiProtUsePinCode;
                    }
                else
                    {
                    // ... or initiate WPS dialog if push button was used
                    nextState = EWiFiProtInitiateEasySetup;
                    }
                break;
                }
            case KErrWlanProtectedSetupDevicePasswordAuthFailure:
                {
                status = KErrNone;
                textResId = R_QTN_ERR_WLAN_SC_CONFIG_FAILED_TRY_AGAIN;
                if ( iUsePin )
                    {
                    // ...pin code dialog if pin code was used
                    nextState = EWiFiProtUsePinCode;
                    }
                else
                    {
                    // ... or initiate WPS dialog if push button was used
                    nextState = EWiFiProtInitiateEasySetup;
                    } 
                break;
                }
            case KErrWlanProtectedSetupPINMethodNotSupported:
                {
                textResId =
                 R_QTN_ERR_WLAN_SC_CONFIG_FAILED_PIN_NOT_SUPPORTED;  
                break;
                }
            case KErrWlanProtectedSetupPBMethodNotSupported:
                {
                textResId =
                 R_QTN_ERR_WLAN_SC_CONFIG_FAILED_PB_NOT_SUPPORTED;  
                break;
                } 
            case KErrWlanConnAlreadyActive:
                {
                textResId = R_QTN_WLAN_INFO_CONNECTION_ALREADY_ACTIVE;  
                break;
                }
            default:
                {
                ret = EFalse;
                }
            }
        if (ret)    
            {
            HBufC* text = StringLoader::LoadLC( textResId );
            CLOG_WRITEF( *text );
            CAknNoteDialog* dlg = new (ELeave) CAknNoteDialog(
                                     CAknNoteDialog::EErrorTone,
                                     CAknNoteDialog::ELongTimeout );
            dlg->SetTextL( *text );
            CleanupStack::PopAndDestroy( text );   
            iStatus = KRequestPending; //should be set by service provider
            SetActive( );
            dlg->ExecuteLD( R_WIFIPROT_ERROR_NOTE  ); 
            SetNextStateAndComplete( nextState , status );
            }
            
        CLOG_LEAVEFN( "CWiFiProtActiveRunner::HandleErrorL" );    
        
        return ret;
        }
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::ShowOfflineQuery
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::ShowOfflineQuery()
    {
    iNextWiFiProtState = EWiFiProtInitiateEasySetup;

    iNotifier.StartNotifierAndGetResponse(iStatus,KUidCOfflineWlanNoteDlg, 
                                           KNullDesC8(), 
                                           iOfflineReply );
    SetActive();
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::HandleNoErrorL
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::HandleNoErrorL()
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::HandleNoErrorL" );
    
    switch (iNextWiFiProtState)
        {
        case EWifiProtOfflineQuery :
            {
            ShowOfflineQuery();
            break;
            }
        case EWiFiProtInitiateEasySetup :
            {
            ShowInitiateEasySetupDialogL();
            break;
            }
        case EWiFiProtUsePinCode :
            {
            if ( iUsePin )
                {
                // dismiss the link dialog now
                if ( iDestroyInitDialogLater )
                    {
                    iInitDialog->TryExitL( EAknSoftkeyView );
                    iDestroyInitDialogLater = EFalse;
                    }
                ShowEnterPinOnStationDialogL();
                }
            else
                {
                iStatus = KRequestPending;
                SetActive( );
                SetNextStateAndComplete( EWiFiProtStartingWaitDlg );
                }
            break;                
            }
        case EWiFiProtStartingWaitDlg :
            {
            ShowWaitingDialogAndProceedL( );
            break;
            }
        case EWiFiProtConfiguring :
            {
            ConfigureL();
            break;
            }
        case EWiFiProtCreateAllIaps :
            {
            CreateAllIapsL();
            break;
            }

        // when we are here, wlan scan is finished                    
        case EWiFiProtWlanScan :              
            {
            iORequest = EWiFiProtReqNone;
            iStatus = KRequestPending;
            SetActive( );
            SetNextStateAndComplete( EWiFiProtDestroyWaitNote );
            break;
            }
        case EWiFiProtSelectConnection :                   
            {
            SelectConnectionL();                   
            break;
            }
            
        case EWiFiProtSettingsConfNote  :
            {
            ShowFinalNoteL( );
            break;
            }
        case EWiFiProtFinished  :
            {
            iReturn = EWiFiOK;

            if ( iIsConnectionNeeded )
                {
                *iNetworkSettings = (*iIapParametersArray)[
                    iAvailableNetworks[iSelectedNetworkIndex] ];
                }
            else
                {
                // Copy the results into the output array
                for (TInt i = 0; i< iCmArray.Count();i++ )
                    {
                    CLOG_WRITEF( _L(
                  "Copy the results into the output array, i == %d"), i );
                    if ( iUids == NULL)
                        {
                        User::Panic( KWiFiPanic, KErrNotSupported );
                        }
                    iUids->Append( iCmArray[i]->GetIntAttributeL( ECmId ) );
                    }
                }
            
            if ( iSyncMode )
                {
                if (iWait.IsStarted() )
                    {
                    iWait.AsyncStop();
                    }
                }
            else
                {
                iParent->CompleteProcessL( iReturn );
                }
            break;
            }
        default:
            {
            //should not ever get here
            CLOG_WRITE( "Unhandled WiFiProtState!!!" );
            User::Leave( KErrGeneral );
            break;
            }
        }
    
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::HandleNoErrorL" );
    }
    
// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::PinQueryExitL
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::PinQueryExitL( TInt aResponse )
    {
    iPinQueryActive = EFalse;
    iPinDlg = NULL;
    if ( aResponse  == KErrNone )
        {
            
        if ( iWaitNoteNeeded )
            {
            ShowWaitingDialogL();
            }
        else
            {
            EvaluateResult(); //we were just waiting for PIN query to exit
            }
        }
    else
        {
        iUserCancelled = ETrue;
        CancelOngoingRequest();        
        }
    }

// --------------------------------------------------------------------------
// void CWiFiProtActiveRunner::DoUsePinCodeLinkSelectedL()
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::DoUsePinCodeLinkSelectedL()
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::DoUsePinCodeLinkSelectedL" );
    if ( !iDestroyInitDialogLater )
        {
        iUsePin = ETrue;
        TRequestStatus* pS = &iStatus;                
        User::RequestComplete( pS, KErrNone );
        iDestroyInitDialogLater = ETrue;
        }
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::DoUsePinCodeLinkSelectedL" );
    }
    
// --------------------------------------------------------------------------
// void CWiFiProtActiveRunner::StartWlanScan()
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::StartWlanScan()
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::StartWlanScan" );
    // this flag is needed to store the cancel because we cannot
    // cancel wlan scan itself
#ifdef __WINS__
    SetNextStateAndComplete( EWiFiProtWlanScan );
#else
    iORequest = EWiFiProtReqWlanScan;
    iNextWiFiProtState = EWiFiProtWlanScan;
    iWlanMgmtEngine->GetScanResults( iStatus, *iScanInfo );
#endif
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::StartWlanScan" );
    }
    
// --------------------------------------------------------------------------
// void CWiFiProtActiveRunner::CheckNetworkAvailabilityL()
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::CheckNetworkAvailabilityL()
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::CheckNetworkAvailabilityL" );
 
    iAvailableNetworks.Reset();
    TBool found = EFalse;
    for (TInt i = 0; i < iIapParametersArray->Count(); i++ )
        {  
        found = EFalse;
#ifdef __WINS__        
        for (TInt j = 0; j<KNumberOfEmulatedAvailableNetworks; j++)
#else
        for ( iScanInfo->First(); (!iScanInfo->IsDone())
                        && (!found); iScanInfo->Next() )
#endif        
            {
            TUint8 ieLen( 0 );
            const TUint8* ieData;
            TBuf8<KWlanMaxSsidLength> ssid8;
#ifdef __WINS__        
            TBuf8<KWlanMaxSsidLength> ssidData;
            ieData = ssidData.PtrZ();
            switch (j)
                {
                case KIndexOfFirstEmulatedAvailableNetwork:
                    {
                    ssidData = _L8("Available Network");
                    break;
                    }
                case KIndexOfSecondEmulatedAvailableNetwork:
                    {
                    ssidData = _L8("Available Network 2");
                    break;
                    }
                default:
                    {
                    User::Panic( KWiFiPanic , KErrNotFound );
                    break;
                    }
                }
            ieLen = ssidData.Length();     
            TInt ret = KErrNone;
#else
            TInt ret = iScanInfo->InformationElement( E802Dot11SsidIE, ieLen,
                                                     &ieData );
#endif        
            User::LeaveIfError( ret );
            if ( ieLen )
                {
                CLOG_WRITE( "Starting copying ssid" );  
                // get the ssid
                ssid8.Copy( ieData, ieLen );
                CLOG_WRITE( "SSID copied" );  
                if ( !(*iIapParametersArray)[i].iSsid.Compare( ssid8 ) )
                    {
                    iAvailableNetworks.Append(i);
                    found = ETrue;
                    }
                }
            }
        }
            
        if (iAvailableNetworks.Count() == 1)
            {
            // only one network available, go to confirmation note
            iSelectedNetworkIndex = 0;
            SetNextStateAndComplete( EWiFiProtSettingsConfNote );
            }
        else if (iAvailableNetworks.Count() > 1)
            {
            // more are available, select connection dialog
            SetNextStateAndComplete( EWiFiProtSelectConnection );
            }
        else
            {
            // no wlan networks found note
            ShowNoWlanNetworksNoteL();
            }

    CLOG_LEAVEFN( "CWiFiProtActiveRunner::CheckNetworkAvailabilityL" );
    }
    
// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::SelectConnection
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::SelectConnectionL( )
    {
    CDesCArrayFlat* items =
         new ( ELeave ) CDesCArrayFlat( KArrayGranularity );
    CleanupStack::PushL( items );
    
    _LIT( KListBoxItemFormat, "%d\t%s\t" );
    const TInt KListBoxItemFormatLength = 4;
    TBuf<KWlanMaxSsidLength+KListBoxItemFormatLength+1> buf;
    for (TInt i = 0; i < iAvailableNetworks.Count(); i++ )
        {
        // We have to convert the 8-bit SSID to 16-bit 
        HBufC* ssid16 = HBufC::NewLC( (*iIapParametersArray)
            [iAvailableNetworks[i]].iSsid.Length()+1 );
        TPtr ssid16Ptr( ssid16->Des() );
        CnvUtfConverter::ConvertToUnicodeFromUtf8( ssid16Ptr,
            (*iIapParametersArray)[iAvailableNetworks[i]].iSsid );
        ssid16Ptr.ZeroTerminate();
        buf.Format( KListBoxItemFormat,
             0/*we use only one icon*/, ssid16->Ptr() ); 
        CleanupStack::PopAndDestroy( ssid16 );        
        items->AppendL(buf);
        }
    CAknIconArray* icons = new( ELeave ) CAknIconArray( KIconsGranularity );
    CleanupStack::PushL( icons );
    //creating icon    
    TAknsItemID id;
    MAknsSkinInstance* skinInstance = AknsUtils::SkinInstance();
           
    TParse mbmFile;
    User::LeaveIfError( mbmFile.Set( KWiFiFileIcons, 
                        &KDC_BITMAP_DIR,
                        NULL ) );
    
    CGulIcon* icon = AknsUtils::CreateGulIconL( 
                        skinInstance, 
                        id,
                        mbmFile.FullName(), 
                        EMbmWifiprotQgn_prop_wlan_bearer, 
                        EMbmWifiprotQgn_prop_wlan_bearer_mask );
    ///                                
    
    CleanupStack::PushL(icon);
    icons->AppendL( icon );
    CleanupStack::Pop();  //icon array takes ownership
    // we are finished, don't create any iaps in connection mode!
    iNextWiFiProtState = EWiFiProtFinished;
    CWiFiProtSelectNetworkDlg* dlg =
         new ( ELeave ) CWiFiProtSelectNetworkDlg(iStatus ,
                                                  iSelectedNetworkIndex,
                                                  items, icons );
    CleanupStack::Pop( icons ); // list takes ownership
    CleanupStack::Pop( items );// list takes ownership
    dlg->PrepareAndRunLD(  );
    SetActive();
    }

// --------------------------------------------------------------------------
// void CWiFiProtActiveRunner::ShowNoWlanNetworksNoteL()
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::ShowNoWlanNetworksNoteL()
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::ShowNoWlanNetworksNoteL" );
    HBufC* stringLabel = StringLoader::LoadLC( 
                                         R_QTN_WLAN_INFO_NO_NETWORKS_FOUND );

    RAknUiServer* globalNote = CAknSgcClient::AknSrv();
    if ( globalNote->Handle() )
        {
        globalNote->ShowGlobalNoteL( *stringLabel, 
                                    EAknGlobalInformationNote );
        }
    CleanupStack::PopAndDestroy( stringLabel );
    SetNextStateAndComplete( EWiFiProtFinished );

    CLOG_LEAVEFN( "CWiFiProtActiveRunner::ShowNoWlanNetworksNoteL" );
    
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::CancelOngoingRequest
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::CancelOngoingRequest()
    {
    
    CLOG_ENTERFN( "CWiFiProtActiveRunner::CancelOngoingRequest" );
    
    switch ( iORequest )
        {
        case EWiFiProtReqConfirmDialog:
            {
            // Remove the showing dialog and cancel the request
            delete iConfirmationDialog;
            iConfirmationDialog = NULL;
            TRequestStatus* pS = &iStatus;                
            User::RequestComplete( pS, KErrCancel );
            break;
            }
        case EWiFiProtReqInitDialog:
            {
            // Remove the showing dialog and cancel the request
            delete iInitDialog;
            iInitDialog = NULL;
            TRequestStatus* pS = &iStatus;                
            User::RequestComplete( pS, KErrCancel );
            break;
            }       
        case EWiFiProtReqWPS :
            {
            if ( iPinQueryActive )
                {
                delete iPinDlg;
                iPinDlg = NULL;
                }           
            if ( iWlanMgmtEngine )
                {
                CLOG_WRITE( "Calling WPS cancel!" );
                iWlanMgmtEngine->CancelProtectedSetup();
                CLOG_WRITE( "WPS cancel called!" );
                }
            break;
            }
        case EWiFiProtReqWlanScan :
            {
            iWlanMgmtEngine->CancelGetScanResults();
            break;
            }    
        case EWiFiProtReqNone :
            {
            // it is possible, especially in emulator, that the pin dialog
            // is still visible at this point
            if ( iPinQueryActive )
                {
                delete iPinDlg;
                iPinDlg = NULL;
                TRequestStatus* pS = &iStatus;                
                User::RequestComplete( pS, KErrCancel );
                }
            // set CancelCalled flag to make RunL start shutdown next time
            iUserCancelled = ETrue;
            break;
            }
            
        default:
            {
            // should not ever get here
            }
        }
    
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::CancelOngoingRequest" );
    
    } 
    
// --------------------------------------------------------------------------
// CWiFiProtActiveRunner::SetWepKeyL
// --------------------------------------------------------------------------
//
void CWiFiProtActiveRunner::SetWepKeyL( CWEPSecuritySettings&
                                            aWepSecSettings,
                                        TWlanWepKey& aWepKey,
                                        TInt aKeyNumber )
    {
    if ( aWepKey != KNullDesC8)
        {
        TBool wepKeyInAsciiFormat = IsWepFormatHexL( aWepKey.Length() );
        TBuf<KWlanWepKeyMaxLength> wepBuf16;
        wepBuf16.Copy( aWepKey );           
        User::LeaveIfError(aWepSecSettings.SetKeyDataL( aKeyNumber, wepBuf16,
                                         wepKeyInAsciiFormat ) );
        CLOG_WRITEF( _L("Wep key: %d"), aKeyNumber );
        CLOG_WRITEF( wepBuf16 );
        }
    }
    
// --------------------------------------------------------------------------
// TInt CWiFiProtActiveRunner::UsePinCodeLinkSelectedL()
// --------------------------------------------------------------------------
//
TInt CWiFiProtActiveRunner::UsePinCodeLinkSelectedL( TAny* aObject )
    {
    CLOG_ENTERFN( "CWiFiProtActiveRunner::UsePinCodeLinkSelectedL" );
    CWiFiProtActiveRunner* myself =
                            static_cast<CWiFiProtActiveRunner*>( aObject );
    myself->DoUsePinCodeLinkSelectedL();
    CLOG_LEAVEFN( "CWiFiProtActiveRunner::UsePinCodeLinkSelectedL" );

    return 1;
    }    
// End of File  
