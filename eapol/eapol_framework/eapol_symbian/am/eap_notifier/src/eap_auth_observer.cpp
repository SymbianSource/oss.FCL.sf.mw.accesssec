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
* Description: Dialog observer implementation
*
*/

#include <hb/hbcore/hbsymbianvariant.h>
#include <e32debug.h>
#include "eap_auth_notifier.h"
#include "eap_auth_observer.h"


// ---------------------------------------------------------
// CEapAuthObserver* CEapAuthObserver::NewL
// ---------------------------------------------------------
//
CEapAuthObserver* CEapAuthObserver::NewL( 
    CEapAuthNotifier* aNotifier,
    CEapAuthNotifier::EEapNotifierType aType )
    {
    RDebug::Print(_L("CEapAuthObserver::NewL") );
    
    CEapAuthObserver* self = new ( ELeave ) CEapAuthObserver( aNotifier, aType );
    return self;
    }

// ---------------------------------------------------------
// CEapAuthObserver::CEapAuthObserver
// ---------------------------------------------------------
//
CEapAuthObserver::CEapAuthObserver( 
    CEapAuthNotifier* aNotifier,
    CEapAuthNotifier::EEapNotifierType aType ): 
    iNotifier( aNotifier ),
    iType(aType)
    {
    RDebug::Print(_L("CEapAuthObserver::CEapAuthObserver") );
    }

// ---------------------------------------------------------
// CEapAuthObserver::~CEapAuthObserver()
// ---------------------------------------------------------
//
CEapAuthObserver::~CEapAuthObserver()
    {
    RDebug::Print(_L("CEapAuthObserver::~CEapAuthObserver") );
    }

// ---------------------------------------------------------
// void CEapAuthObserver::DataReceived
// ---------------------------------------------------------
//
void CEapAuthObserver::DataReceived( CHbSymbianVariantMap& aData )
{
    RDebug::Print(_L("CEapAuthObserver::DataReceived") );
    
    if ( iType == CEapAuthNotifier::EEapNotifierTypeLEapUsernamePasswordDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeLEapUsernamePasswordDialog") );
        UsernamePasswordDlgDataReceived(aData);
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypeGTCUsernamePasswordDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeGTCUsernamePasswordDialog") );
        UsernamePasswordDlgDataReceived(aData);
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypePapUsernamePasswordDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypePapUsernamePasswordDialog") );
        UsernamePasswordDlgDataReceived(aData);
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypeEapMsChapV2UsernamePasswordDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeEapMsChapV2UsernamePasswordDialog") );
        UsernamePasswordDlgDataReceived(aData);
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypeMsChapV2UsernamePasswordDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeMsChapV2UsernamePasswordDialog") );
        UsernamePasswordDlgDataReceived(aData);
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypeGTCSecurIDPasscodeQueryUidDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeGTCSecurIDPasscodeQueryUidDialog") ); 
        PwdQueryDataReceived(aData);
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypePapChallengeReplyQueryDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypePapChallengeReplyQueryDialog") ); 
        PwdQueryDataReceived(aData);
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypeFastPacStorePwQueryDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeFastPacStorePwQueryDialog") ); 
        PwdQueryDataReceived(aData);
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypeFastCreateMasterkeyQueryDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeFastCreateMasterkeyQueryDialog") ); 
        PwdQueryDataReceived(aData);
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypeFastPacFilePwQueryDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeFastPacFilePwQueryDialog") ); 
        PwdQueryDataReceived(aData);
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypeMsChapV2OldPasswordDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeMsChapV2OldPasswordDialog") ); 
        OldPwdQueryDataReceived(aData);
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypeMsChapV2NewPasswordDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeMsChapV2NewPasswordDialog") ); 
        PwdQueryDataReceived(aData);
        }
    
    TInt status = KErrNone;
    
    TRAP_IGNORE( iNotifier->CompleteL( status ));
}

// ---------------------------------------------------------
// void CEapAuthObserver::UsernamePasswordDlgDataReceived
// ---------------------------------------------------------
//
void CEapAuthObserver::UsernamePasswordDlgDataReceived( CHbSymbianVariantMap& aData )
{
    RDebug::Print(_L("CEapAuthObserver::UsernamePasswordDlgDataReceived") ); 
    
    _LIT(KUsername, "username");
    _LIT(KPassword, "password");
    
    CEapAuthNotifier::TEapDialogInfo PasswordInfo;
    TDesC* Data = NULL;
       
    PasswordInfo.iIsIdentityQuery = EFalse; 
    PasswordInfo.iPasswordPromptEnabled = EFalse;
    
    const CHbSymbianVariant *my_variant = aData.Get(KUsername); 
    if ( my_variant != NULL )
        {
        ASSERT( my_variant->Type() == CHbSymbianVariant::EDes  );
    
        Data = reinterpret_cast<TDesC*>(my_variant->Data());       
        PasswordInfo.iUsername.Copy( Data->Ptr(), Data->Length() );
        PasswordInfo.iIsIdentityQuery = ETrue; 
        RDebug::Print(_L("CEapAuthObserver::DataReceived: PasswordInfo.iUsername = %S\n"), &PasswordInfo.iUsername );
        }
    my_variant = aData.Get(KPassword);
    if ( my_variant != NULL )
        {
        ASSERT( my_variant->Type() == CHbSymbianVariant::EDes  );
    
        Data = reinterpret_cast<TDesC*>(my_variant->Data());     
        PasswordInfo.iPassword.Copy( Data->Ptr(), Data->Length() );
        PasswordInfo.iPasswordPromptEnabled = ETrue;
        RDebug::Print(_L("CEapAuthObserver::DataReceived: PasswordInfo.iPassword = %S\n"), &PasswordInfo.iPassword );
        }
       
    iNotifier->SetSelectedUnameAndPwd( PasswordInfo );   
}

// ---------------------------------------------------------
// void CEapAuthObserver::OldPwdQueryDataReceived
// ---------------------------------------------------------
//
void CEapAuthObserver::OldPwdQueryDataReceived( CHbSymbianVariantMap& aData )
{
    RDebug::Print(_L("CEapAuthObserver::OldPwdQueryDataReceived") ); 
    
    _LIT(KPassword, "password");
    
    CEapAuthNotifier::TEapDialogInfo PasswordInfo;
    TDesC* Data = NULL;
          
    const CHbSymbianVariant *my_variant = aData.Get(KPassword); 
    if ( my_variant != NULL )
        {
        ASSERT( my_variant->Type() == CHbSymbianVariant::EDes  );
    
        Data = reinterpret_cast<TDesC*>(my_variant->Data());     
        PasswordInfo.iOldPassword.Copy( Data->Ptr(), Data->Length() );

        RDebug::Print(_L("CEapAuthObserver::OldPwdQueryDataReceived: PasswordInfo.iOldPassword = %S\n"), &PasswordInfo.iOldPassword );
        }
       
    iNotifier->SetSelectedOldPassword( PasswordInfo );   
}

// ---------------------------------------------------------
// void CEapAuthObserver::PwdQueryDataReceived
// ---------------------------------------------------------
//
void CEapAuthObserver::PwdQueryDataReceived( CHbSymbianVariantMap& aData )
{
    RDebug::Print(_L("CEapAuthObserver::PwdQueryDataReceived") ); 
    
    _LIT(KPassword, "password");
    
    CEapAuthNotifier::TEapDialogInfo PasswordInfo;
    TDesC* Data = NULL;
           
    const CHbSymbianVariant *my_variant = aData.Get(KPassword); 
    if ( my_variant != NULL )
        {
        ASSERT( my_variant->Type() == CHbSymbianVariant::EDes  );
    
        Data = reinterpret_cast<TDesC*>(my_variant->Data());     
        PasswordInfo.iPassword.Copy( Data->Ptr(), Data->Length() );

        RDebug::Print(_L("CEapAuthObserver::PwdQueryDataReceived: PasswordInfo.iPassword = %S\n"), &PasswordInfo.iPassword );
        }
       
    iNotifier->SetSelectedPassword( PasswordInfo );   
}

// ---------------------------------------------------------
// void CEapAuthObserver::DeviceDialogClosed
// ---------------------------------------------------------
//
void CEapAuthObserver::DeviceDialogClosed( TInt /*aCompletionCode*/ )
{
    // Dialog was closed, let's complete with that error code
    RDebug::Print(_L("CEapAuthObserver::DeviceDialogClosed"));
    
    TInt status = KErrCancel;
    
    if ( iType != CEapAuthNotifier::EEapNotifierTypeFastStartAuthProvWaitNote &&
         iType != CEapAuthNotifier::EEapNotifierTypeFastStartUnauthProvWaitNote )
        {
        TRAP_IGNORE( iNotifier->CompleteL( status ));
        }
}


