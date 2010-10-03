/*
* Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies). 
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of "Eclipse Public License v1.0"
* which accompanies this distribution, and is available
* at the URL "http://www.eclipse.org/legal/epl-v10.html".
*
* Initial Contributors:
* Nokia Corporation - initial contribution.
*
* Contributors:
*
* Description: 
*   EAP Authentication Notitier implementation
*
*/

/*
* %version: 24 %
*/

// System include files
#include <hb/hbcore/hbsymbianvariant.h>
#include <e32debug.h> 
#include <EapExpandedType.h> 
// User include files 
#include "eap_auth_notifier.h"
#include "eap_auth_observer.h"
#include "eap_auth_ui_strings.h"

// External function prototypes

// Local constants
const TInt KVariableLength = 30; 
const TInt KDlgTypeStrLength = 100; 
const TInt KMaxAuthMethodLength = 50;

_LIT( KUsername, "username");
_LIT( KAuthmethod, "authmethod");
_LIT( KPacservername, "pacservername");
_LIT( KPacfilename, "pacfilename");
_LIT( KEaptype, "eaptype");
_LIT( KMessage, "messagetxt");
_LIT( KFastprovwaitnote, "notificationtxt");
_LIT( KPwdcorrectness, "pwdcorrectind");

_LIT(KTypeunamepwddlg, "com.nokia.eap.usernamepassworddialog/1.0");
_LIT(KTypepwdquerydlg, "com.nokia.eap.passwordquerydialog/1.0");
_LIT(KTypequerydlg, "com.nokia.eap.querydialog/1.0"); 
_LIT(KTypeinstallpacquerydlg, "com.nokia.eap.fastinstallpacquerydialog/1.0");
_LIT(KTypepacstorepwquerydlg, "com.nokia.eap.fastpacstorepwquerydialog/1.0"); 
_LIT(KTypemasterkeyquerydlg, "com.nokia.eap.fastcreatemasterkeyquerydialog/1.0"); 
_LIT(KTypepacfilepwquerydlg, "com.nokia.eap.fastpacfilepwquerydialog/1.0"); 
_LIT(KTypeprovwaitnotedlg, "com.nokia.eap.fastprovwaitnotedialog/1.0"); 
_LIT(KTypepwdexpnotedlg,"com.nokia.eap.mschapv2passwordexpirednotedialog/1.0"); 
_LIT(KTypeoldpwddlg,"com.nokia.eap.mschapv2oldpassworddialog/1.0"); 
_LIT(KTypenewpwddlg,"com.nokia.eap.mschapv2newpassworddialog/1.0"); 
_LIT(KTypeshowprovnotsuccdlg,"com.nokia.eap.fastshowprovnotsuccessnotedialog/1.0"); 

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------
//
CEapAuthNotifier::CEapAuthNotifier( MNotificationCallback& aClient )
    :iClient(aClient),
     iDialog(NULL),
     iObserver(NULL),   
     iCompleted(EFalse),
     iCancelled(EFalse) 
    {
    RDebug::Print(_L("CEapAuthNotifier::CEapAuthNotifier DLL++") );
    
    }

// ---------------------------------------------------------------------------
// Destructor
// ---------------------------------------------------------------------------
//
CEapAuthNotifier::~CEapAuthNotifier()
    {
    RDebug::Print(_L("CEapAuthNotifier::~CEapAuthNotifier") );
    
    if ( iCancelled == EFalse )
        {
        iCompleted = ETrue;
        if ( iDialog )
            { 
            iDialog->Cancel();
            }
        }
    if ( iDialog )
        { 
        delete iDialog;
        }
    if ( iObserver )
        {
        delete iObserver;
        }
    }

// ---------------------------------------------------------------------------
// Two-phased constructor
// ---------------------------------------------------------------------------
//
EXPORT_C CEapAuthNotifier* CEapAuthNotifier::NewL( 
    MNotificationCallback& aClient )
    {
    RDebug::Print(_L("CEapAuthNotifier::NewL"));
    
    CEapAuthNotifier* self = 
        new ( ELeave ) CEapAuthNotifier( aClient );
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop( self );
    return self;
    }

// ---------------------------------------------------------------------------
// ConstructL for the Notifier
// ---------------------------------------------------------------------------
//
void CEapAuthNotifier::ConstructL()
    {
    RDebug::Print(_L("CEapAuthNotifier::ConstructL"));
    //Observer is needed in order to get the user inputs
    iObserver = CEapAuthObserver::NewL( this ); 
    iDialog = CHbDeviceDialogSymbian::NewL();    
    }

// ---------------------------------------------------------------------------
// Start the Notifier
// ---------------------------------------------------------------------------
//
EXPORT_C void CEapAuthNotifier::StartL( 
    EEapNotifierType aType,
    TEapDialogInfo* aEapInfo, 
    TEapExpandedType& aEapType )
    {
    TInt error;
    TBuf<KDlgTypeStrLength> EapNtfType;
    TBuf16<KMaxAuthMethodLength> authMethod;
               
    RDebug::Print(_L("CEapAuthNotifier::StartL: ENTERING"));
    
    iCancelled = EFalse;
    iCompleted = EFalse;
    iEapInfo = aEapInfo;
            
    //Method must be called before using the observer  
    iObserver->SetNotifierType(aType);
        
    //The variant map is needed to construct the dialog correctly,
    CHbSymbianVariantMap* map = CHbSymbianVariantMap::NewL();
    CleanupStack::PushL( map );
    
    if ( aType == EEapNotifierTypeLEapUsernamePasswordDialog )
        {
        authMethod.Copy(EapAuthUiStrings::Leap);
        SetUsernamePasswordDataL( aEapInfo, aEapType, map, authMethod );  
        EapNtfType.Copy(KTypeunamepwddlg);
        }   
    else if ( aType == EEapNotifierTypeGTCUsernamePasswordDialog )
        {
        authMethod.Copy(EapAuthUiStrings::EapGtc);
        SetUsernamePasswordDataL( aEapInfo, aEapType, map, authMethod );  
        EapNtfType.Copy(KTypeunamepwddlg);
        }   
    else if ( aType == EEapNotifierTypePapUsernamePasswordDialog )
        {
        authMethod.Copy(EapAuthUiStrings::Pap);
        SetUsernamePasswordDataL( aEapInfo, aEapType, map, authMethod );    
        EapNtfType.Copy(KTypeunamepwddlg);
        }   
    else if ( aType == EEapNotifierTypeEapMsChapV2UsernamePasswordDialog )
        {
        authMethod.Copy(EapAuthUiStrings::EapMschapv2);
        SetUsernamePasswordDataL( aEapInfo, aEapType, map, authMethod );   
        EapNtfType.Copy(KTypeunamepwddlg);
        }   
    else if ( aType == EEapNotifierTypeMsChapV2UsernamePasswordDialog )
        {
        authMethod.Copy(EapAuthUiStrings::Mschapv2);
        SetUsernamePasswordDataL( aEapInfo, aEapType, map, authMethod );  
        EapNtfType.Copy(KTypeunamepwddlg);
        }   
    else if ( aType == EEapNotifierTypeGtcChallengeDialog )
        {
        authMethod.Copy(EapAuthUiStrings::EapGtc);
        SetQueryDialogDataL( aEapInfo, map, authMethod );
        EapNtfType.Copy(KTypequerydlg);
        }    
    else if ( aType == EEapNotifierTypePapChallengeDialog )
        {
        authMethod.Copy(EapAuthUiStrings::Pap);
        SetQueryDialogDataL( aEapInfo, map, authMethod );
        EapNtfType.Copy(KTypequerydlg);
        }
    else if ( aType == EEapNotifierTypeGTCQueryDialog )
        {
        authMethod.Copy(EapAuthUiStrings::EapGtc);
        SetPasswordQueryDataL( aEapType, map, authMethod );
        EapNtfType.Copy(KTypepwdquerydlg); 
        }
    else if ( aType == EEapNotifierTypePapAuthQueryDialog )
        {
        authMethod.Copy(EapAuthUiStrings::Pap);
        SetPasswordQueryDataL( aEapType, map, authMethod );
        EapNtfType.Copy(KTypepwdquerydlg); 
        }
    else if ( aType == EEapNotifierTypeFastInstallPacQueryDialog ) 
        {
        SetFastInstallPacQueryDialogDataL( aEapInfo, map );
        EapNtfType.Copy(KTypeinstallpacquerydlg);
        }
    else if ( aType == EEapNotifierTypeFastPacStorePwQueryDialog ) 
        {
        EapNtfType.Copy(KTypepacstorepwquerydlg);
        }
    else if ( aType == EEapNotifierTypeFastCreateMasterkeyQueryDialog ) 
        {
        EapNtfType.Copy(KTypemasterkeyquerydlg);
        }
    else if ( aType == EEapNotifierTypeFastPacFilePwQueryDialog ) 
        {
        SetFastPacFileQueryPwDialogDataL( aEapInfo, map );
        EapNtfType.Copy(KTypepacfilepwquerydlg);
        }
    else if ( aType == EEapNotifierTypeFastStartAuthProvWaitNote )
        {
        SetFastProvWaitNoteDialogDataL( map, ETrue );
        EapNtfType.Copy(KTypeprovwaitnotedlg);
        }
    else if ( aType == EEapNotifierTypeFastStartUnauthProvWaitNote )
        {
        SetFastProvWaitNoteDialogDataL( map, EFalse );
        EapNtfType.Copy(KTypeprovwaitnotedlg);
        }   
    else if ( aType == EEapNotifierTypeMsChapV2PasswordExpiredNote )
        {
        EapNtfType.Copy(KTypepwdexpnotedlg);
        }
    else if ( aType == EEapNotifierTypeMsChapV2OldPasswordDialog )
        {
        EapNtfType.Copy(KTypeoldpwddlg);
        }
    else if ( aType == EEapNotifierTypeMsChapV2NewPasswordDialog )
        {
        EapNtfType.Copy(KTypenewpwddlg);
        }
    else if ( aType == EEapNotifierTypeFastShowProvNotSuccessNote )
        {
        EapNtfType.Copy(KTypeshowprovnotsuccdlg);
        }

    RDebug::Print(_L("CEapAuthNotifier::StartL: Load the Dialog NOW!"));
    
    //Show the dialog.
    error = iDialog->Show( EapNtfType, *map, iObserver );
    
    User::LeaveIfError( error );
    CleanupStack::PopAndDestroy( map ); 

    RDebug::Print(_L("CEapAuthNotifier::StartL: LEAVING") );
    }

// ---------------------------------------------------------------------------
// Set data for the EAP-FAST provisioning wait note Dialog(s)
// ---------------------------------------------------------------------------
//
void CEapAuthNotifier::SetFastProvWaitNoteDialogDataL(    
    CHbSymbianVariantMap* aMap,
    TBool aAuthProvWaitNote )
    {
    TInt error;  
    TBuf<KVariableLength> key(KFastprovwaitnote);
            
    CHbSymbianVariant *variant = NULL;
    
    RDebug::Print(_L("CEapAuthNotifier::SetFastProvWaitNoteDialogDataL: ENTERING"));    

    //Create the variant data information for the plugin
    variant =  
        CHbSymbianVariant::NewL (
        &aAuthProvWaitNote, CHbSymbianVariant::EBool );
    CleanupStack::PushL( variant );
    error = aMap->Add( key, variant);
    User::LeaveIfError( error );
    CleanupStack::Pop( variant ); // map's cleanup sequence handles variant.
    
    RDebug::Print(_L("CEapAuthNotifier::SetFastProvWaitNoteDialogDataL: LEAVING") );
    }

// ---------------------------------------------------------------------------
// Set data for the EAP-FAST PAC file query Dialog(s)
// ---------------------------------------------------------------------------
//
void CEapAuthNotifier::SetFastPacFileQueryPwDialogDataL( 
    TEapDialogInfo* aEapInfo,
    CHbSymbianVariantMap* aMap )
    {
    TInt error;  
    TBuf<KVariableLength> key(KPacfilename);
                
    CHbSymbianVariant *variant = NULL;
        
    RDebug::Print(_L("CEapAuthNotifier::SetFastPacFileQueryPwDialogDataL: ENTERING"));
        
    if( 0 < aEapInfo->iUidata.Length() )
       {
       RDebug::Print(_L("CEapAuthNotifier::SetFastPacFileQueryPwDialogDataL: Set PAC filename"));
       RDebug::Print(_L("CEapAuthNotifier::SetFastPacFileQueryPwDialogDataL: aEapInfo->iUidata = %S\n"), &aEapInfo->iUidata );
        
       // Create the variant data information for the plugin
       variant =  
           CHbSymbianVariant::NewL ( 
           &aEapInfo->iUidata, CHbSymbianVariant::EDes );
       CleanupStack::PushL( variant );
       error = aMap->Add( key, variant);
       User::LeaveIfError( error );
       CleanupStack::Pop( variant ); // map's cleanup sequence handles variant.
       }     
    RDebug::Print(_L("CEapAuthNotifier::SetFastPacFileQueryPwDialogDataL: LEAVING") );
    }

// ---------------------------------------------------------------------------
// Set data for the EAP-FAST Install PAC query Dialog(s)
// ---------------------------------------------------------------------------
//
void CEapAuthNotifier::SetFastInstallPacQueryDialogDataL( 
    TEapDialogInfo* aEapInfo,
    CHbSymbianVariantMap* aMap )
    {
    TInt error;  
    TBuf<KVariableLength> key(KPacservername);
            
    CHbSymbianVariant *variant = NULL;
    
    RDebug::Print(_L("CEapAuthNotifier::SetFastInstallPacQueryDialogData: ENTERING"));
    
    if( 0 < aEapInfo->iUidata.Length() )
        {
        RDebug::Print(_L("CEapAuthNotifier::SetFastInstallPacQueryDialogData: Set PAC Install server name"));
        RDebug::Print(_L("CEapAuthNotifier::SetFastInstallPacQueryDialogData: aEapInfo->iUidata = %S\n"), &aEapInfo->iUidata );
    
        // Create the variant data information for the plugin
        variant =  
            CHbSymbianVariant::NewL ( 
            &aEapInfo->iUidata, CHbSymbianVariant::EDes );
        CleanupStack::PushL( variant );
        error = aMap->Add( key, variant);
        User::LeaveIfError( error );
        CleanupStack::Pop( variant ); // map's cleanup sequence handles variant.
        }     
    RDebug::Print(_L("CEapAuthNotifier::SetFastInstallPacQueryDialogData: LEAVING") );
    }

// ---------------------------------------------------------------------------
// Set data for the Challenge Query Dialog(s)
// ---------------------------------------------------------------------------
//
void CEapAuthNotifier::SetQueryDialogDataL( 
    TEapDialogInfo* aEapInfo,
    CHbSymbianVariantMap* aMap,
    const TDesC& aAuthMethod )
    {
    TInt error;  
    TBuf<KVariableLength> key1(KAuthmethod);
    TBuf<KVariableLength> key2(KMessage);
        
    CHbSymbianVariant *variant = NULL;
    
    RDebug::Print(_L("CEapAuthNotifier::SetQueryDialogData: ENTERING"));
    
    RDebug::Print(_L("CEapAuthNotifier::SetQueryDialogData: Set Heading"));
    RDebug::Print(_L("CEapAuthNotifier::SetQueryDialogData: aAuthMethod = %S\n"), &aAuthMethod );
    
    // Create the variant data information for the plugin
    variant =  
        CHbSymbianVariant::NewL ( &aAuthMethod, CHbSymbianVariant::EDes );
    CleanupStack::PushL( variant );
    error = aMap->Add( key1, variant);
    User::LeaveIfError( error );
    CleanupStack::Pop( variant ); // map's cleanup sequence handles variant.
            
    if( 0 < aEapInfo->iUidata.Length() )
        {
        RDebug::Print(_L("CEapAuthNotifier::SetQueryDialogData: Set user input message"));
        RDebug::Print(_L("CEapAuthObserver::SetQueryDialogData: aEapInfo->iUidata = %S\n"), &aEapInfo->iUidata );
    
        // Create the variant data information for the plugin
        variant =  
            CHbSymbianVariant::NewL (
            &aEapInfo->iUidata, CHbSymbianVariant::EDes );
        CleanupStack::PushL( variant );
        error = aMap->Add( key2, variant);
        User::LeaveIfError( error );
        CleanupStack::Pop( variant ); // map's cleanup sequence handles variant.
        }     
    RDebug::Print(_L("CEapAuthNotifier::SetQueryDialogData: LEAVING") );
    }

// ---------------------------------------------------------------------------
// Set data for the Password Query Dialog(s)
// ---------------------------------------------------------------------------
//
void CEapAuthNotifier::SetPasswordQueryDataL( 
    TEapExpandedType& aEapType,
    CHbSymbianVariantMap* aMap,
    const TDesC& aAuthMethod )
    {
    TInt error;  
    TBuf<KVariableLength> key2(KAuthmethod);
    TBuf<KVariableLength> key3(KEaptype); 
    CHbSymbianVariant *variant = NULL;
    
    RDebug::Print(_L("CEapAuthNotifier::SetPasswordQueryData: ENTERING"));
    RDebug::Print(_L("CEapAuthNotifier::SetPasswordQueryData: aAuthMethod = %S\n"), &aAuthMethod );
    
    //Create the variant data information for the plugin
    //Set authentication method 
    variant =  
        CHbSymbianVariant::NewL ( &aAuthMethod, CHbSymbianVariant::EDes );
    CleanupStack::PushL( variant );
    error = aMap->Add( key2, variant);
    User::LeaveIfError( error );
    CleanupStack::Pop( variant ); // map's cleanup sequence handles variant.
    
    //Set EAP type
    variant =  
        CHbSymbianVariant::NewL(
        &aEapType.GetValue(), CHbSymbianVariant::EBinary );
    CleanupStack::PushL( variant );
    error = aMap->Add( key3, variant);
    User::LeaveIfError( error );
    CleanupStack::Pop( variant ); // map's cleanup sequence handles variant.    
    RDebug::Print(_L("CEapAuthNotifier::SetPasswordQueryData: LEAVING") );
    }

// ---------------------------------------------------------------------------
// Set data for the UsernamePassword Dialog(s)
// ---------------------------------------------------------------------------
//
void CEapAuthNotifier::SetUsernamePasswordDataL( 
    TEapDialogInfo* aEapInfo,
    TEapExpandedType& aEapType,
    CHbSymbianVariantMap* aMap,
    const TDesC& aAuthMethod )
    {
    TInt error;  
    TBuf<KVariableLength> key1(KUsername);
    TBuf<KVariableLength> key2(KAuthmethod);
    TBuf<KVariableLength> key3(KEaptype);
    CHbSymbianVariant *variant = NULL;
    
    RDebug::Print(_L("CEapAuthNotifier::SetUsernamePasswordData: ENTERING"));
    RDebug::Print(_L("CEapAuthNotifier::SetUsernamePasswordData: aAuthMethod = %S\n"), &aAuthMethod );
    
    //Create the variant data information for the plugin
    //Set authentication method 
    variant =  
        CHbSymbianVariant::NewL ( &aAuthMethod, CHbSymbianVariant::EDes );
    CleanupStack::PushL( variant );
    error = aMap->Add( key2, variant);
    User::LeaveIfError( error );
    CleanupStack::Pop( variant ); // map's cleanup sequence handles variant.
    
    //Set username
    if( 0 < aEapInfo->iUsername.Length() )
        {
        RDebug::Print(_L("CEapAuthNotifier::SetUsernamePasswordData: Set default UNAME"));
        RDebug::Print(_L("CEapAuthNotifier::SetUsernamePasswordData: iEapInfo->iUsername = %S\n"), &iEapInfo->iUsername );
    
        // Create the variant data information for the plugin
        variant =  
            CHbSymbianVariant::NewL ( 
            &aEapInfo->iUsername, CHbSymbianVariant::EDes );
        CleanupStack::PushL( variant );
        error = aMap->Add( key1, variant);
        User::LeaveIfError( error );
        CleanupStack::Pop( variant ); // map's cleanup sequence handles variant.
        }

    //Set EAP type
    variant =  
        CHbSymbianVariant::NewL( 
        &aEapType.GetValue(), CHbSymbianVariant::EBinary );
    CleanupStack::PushL( variant );
    error = aMap->Add( key3, variant);
    User::LeaveIfError( error );
    CleanupStack::Pop( variant ); // map's cleanup sequence handles variant.    
    RDebug::Print(_L("CEapAuthNotifier::SetUsernamePasswordData: LEAVING") );
    }

// ---------------------------------------------------------------------------
// Sets the selected user name and password of the presented dialog
// ---------------------------------------------------------------------------
//
void CEapAuthNotifier::SetSelectedUnameAndPwd ( TEapDialogInfo& aEapInfo )
    {
    RDebug::Print(_L("CEapAuthNotifier::SetSelectedUnameAndPwd"));
    
    iEapInfo->iIsIdentityQuery = aEapInfo.iIsIdentityQuery;
    if ( aEapInfo.iIsIdentityQuery ) 
        {
        iEapInfo->iUsername = aEapInfo.iUsername;
        RDebug::Print(_L("CEapAuthNotifier::SetSelectedUnameAndPwd: iEapInfo->iUsername = %S\n"), &iEapInfo->iUsername );
        }
    
    iEapInfo->iPasswordPromptEnabled = aEapInfo.iPasswordPromptEnabled;
    if ( aEapInfo.iPasswordPromptEnabled )
        {
        iEapInfo->iPassword = aEapInfo.iPassword;
        RDebug::Print(_L("CEapAuthNotifier::SetSelectedUnameAndPwd: iEapInfo->iPassword = %S\n"), &iEapInfo->iPassword );
        }    
    }

// ---------------------------------------------------------------------------
// Sets the selected password of the presented dialog
// ---------------------------------------------------------------------------
//
void CEapAuthNotifier::SetSelectedPassword ( TEapDialogInfo& aPasswordInfo )
    {
    RDebug::Print(_L("CEapAuthNotifier::SetSelectedPassword"));

    iEapInfo->iPassword = aPasswordInfo.iPassword;
    RDebug::Print(_L("CEapAuthNotifier::SetSelectedPassword: iEapInfo->iPassword = %S\n"), &iEapInfo->iPassword );    
    }

// ---------------------------------------------------------------------------
// Sets the selected Old password of the presented dialog
// ---------------------------------------------------------------------------
//
void CEapAuthNotifier::SetSelectedOldPassword ( TEapDialogInfo& aPasswordInfo )
    {
    RDebug::Print(_L("CEapAuthNotifier::SetSelectedOldPassword"));

    iEapInfo->iOldPassword = aPasswordInfo.iOldPassword;
    RDebug::Print(_L("CEapAuthNotifier::SetSelectedOldPassword: iEapInfo->iOldPassword = %S\n"), &iEapInfo->iOldPassword );    
    }
    
// ---------------------------------------------------------------------------
// Check if password match
// ---------------------------------------------------------------------------
//
TBool CEapAuthNotifier::CheckPasswordMatchingL ( TEapDialogInfo& aPasswordInfo )   
    {
    RDebug::Print(_L("CEapAuthNotifier::CheckPasswordMatchingL"));   
    
    TBool match(EFalse);
 
    TRAPD(err, match = iClient.IsMasterKeyAndPasswordMatchingL(aPasswordInfo.iPassword));     
    
    RDebug::Print(_L("CEapAuthNotifier::CheckPasswordMatchingL: trap returned err = %d\n"), err );    
    
    return match;
    } 

// ---------------------------------------------------------------------------
// Update device dialog parameters 
// ---------------------------------------------------------------------------
//
void CEapAuthNotifier::UpdateDialogL( TBool aIsPwdCorrect )
    {
    RDebug::Print(_L("CEapAuthNotifier::UpdateDialogL: ENTERING"));  
    
    TInt error;
        
    //The variant map is needed to update the dialog parameters
    CHbSymbianVariantMap* map = CHbSymbianVariantMap::NewL();
    CleanupStack::PushL( map );  
      
    TBuf<KVariableLength> key(KPwdcorrectness);
            
    CHbSymbianVariant *variant = NULL;
    
    //Create the variant data information for the plugin
    variant =  
        CHbSymbianVariant::NewL (
        &aIsPwdCorrect, CHbSymbianVariant::EBool );
    CleanupStack::PushL( variant );
    error = map->Add( key, variant);
    User::LeaveIfError( error );
    CleanupStack::Pop( variant ); // map's cleanup sequence handles variant.    
    
    //Update the dialog.
    error = iDialog->Update( *map );
    
    User::LeaveIfError( error );           
    CleanupStack::PopAndDestroy( map ); 

    RDebug::Print(_L("CEapAuthNotifier::UpdateDialogL: LEAVING") );    
        
    }
    
// ---------------------------------------------------------------------------
// The notifier is complete
// ---------------------------------------------------------------------------
//
void CEapAuthNotifier::CompleteL( TInt aStatus )
    {
    RDebug::Print(_L("CEapAuthNotifier::CompleteL"));
    
    if ( !iCompleted )
        {
        iClient.DlgComplete(aStatus);
        iCompleted = ETrue;
        }
    }

// ---------------------------------------------------------------------------
// Cancel() the notifier
// ---------------------------------------------------------------------------
//
EXPORT_C void CEapAuthNotifier::Cancel()
    {
    RDebug::Print(_L("CEapAuthNotifier::Cancel"));
    if ( !iCompleted )
        {
        iCancelled = ETrue;
        iDialog->Cancel();
        }
    }
