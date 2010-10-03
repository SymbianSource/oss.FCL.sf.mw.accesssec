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

/*
* %version: 12 %
*/

// System include files
#include <hb/hbcore/hbsymbianvariant.h>
#include <e32debug.h>

// User include files
#include "eap_auth_notifier.h"
#include "eap_auth_observer.h"

// External function prototypes

// Local constants

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

// ---------------------------------------------------------------------------
// Two-phased constructor.
// ---------------------------------------------------------------------------
//
CEapAuthObserver* CEapAuthObserver::NewL( 
    CEapAuthNotifier* aNotifier )
    {
    RDebug::Print(_L("CEapAuthObserver::NewL") );
    
    CEapAuthObserver* self = new ( ELeave ) CEapAuthObserver( aNotifier );
    return self;
    }

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------
//
CEapAuthObserver::CEapAuthObserver( 
    CEapAuthNotifier* aNotifier  ): 
    iNotifier( aNotifier )
    {
    RDebug::Print(_L("CEapAuthObserver::CEapAuthObserver") );
    }

// ---------------------------------------------------------------------------
// Destructor
// ---------------------------------------------------------------------------
//
CEapAuthObserver::~CEapAuthObserver()
    {
    RDebug::Print(_L("CEapAuthObserver::~CEapAuthObserver") );
    }

// ---------------------------------------------------------------------------
// Handles the setting of the notifier (dialog) type
// ---------------------------------------------------------------------------
//
void CEapAuthObserver::SetNotifierType( CEapAuthNotifier::EEapNotifierType aType )
    {
    RDebug::Print(_L("CEapAuthObserver::setNotifierType") );
    
    iType = aType;
    }

// Derived function:
// ---------------------------------------------------------------------------
// From class MHbDeviceDialogObserver.
// Handles the user input received from the dialog
// ---------------------------------------------------------------------------
//
void CEapAuthObserver::DataReceived( CHbSymbianVariantMap& aData )
{
    RDebug::Print(_L("CEapAuthObserver::DataReceived") );
        
    TInt status = KErrNone;    
    
    if ( iType == CEapAuthNotifier::EEapNotifierTypeLEapUsernamePasswordDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeLEapUsernamePasswordDialog") );
        UsernamePasswordDlgDataReceived(aData);
        TRAP_IGNORE( iNotifier->CompleteL( status ));
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypeGTCUsernamePasswordDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeGTCUsernamePasswordDialog") );
        UsernamePasswordDlgDataReceived(aData);
        TRAP_IGNORE( iNotifier->CompleteL( status ));
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypePapUsernamePasswordDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypePapUsernamePasswordDialog") );
        UsernamePasswordDlgDataReceived(aData);
        TRAP_IGNORE( iNotifier->CompleteL( status ));
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypeEapMsChapV2UsernamePasswordDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeEapMsChapV2UsernamePasswordDialog") );
        UsernamePasswordDlgDataReceived(aData);
        TRAP_IGNORE( iNotifier->CompleteL( status ));
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypeMsChapV2UsernamePasswordDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeMsChapV2UsernamePasswordDialog") );
        UsernamePasswordDlgDataReceived(aData);
        TRAP_IGNORE( iNotifier->CompleteL( status ));
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypeGTCQueryDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeGTCQueryDialog") ); 
        PwdQueryDataReceived(aData);
        TRAP_IGNORE( iNotifier->CompleteL( status ));
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypePapAuthQueryDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypePapAuthQueryDialog") ); 
        PwdQueryDataReceived(aData);
        TRAP_IGNORE( iNotifier->CompleteL( status ));
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypeFastPacStorePwQueryDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeFastPacStorePwQueryDialog") ); 
        PacStorePwdQueryDataReceived(aData);
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypeFastCreateMasterkeyQueryDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeFastCreateMasterkeyQueryDialog") ); 
        PwdQueryDataReceived(aData);
        TRAP_IGNORE( iNotifier->CompleteL( status ));
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypeFastPacFilePwQueryDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeFastPacFilePwQueryDialog") ); 
        PwdQueryDataReceived(aData);
        TRAP_IGNORE( iNotifier->CompleteL( status ));
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypeMsChapV2OldPasswordDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeMsChapV2OldPasswordDialog") ); 
        OldPwdQueryDataReceived(aData);
        TRAP_IGNORE( iNotifier->CompleteL( status ));
        }
    else if ( iType == CEapAuthNotifier::EEapNotifierTypeMsChapV2NewPasswordDialog )
        {
        RDebug::Print(_L("CEapAuthObserver::DataReceived: EEapNotifierTypeMsChapV2NewPasswordDialog") ); 
        PwdQueryDataReceived(aData);
        TRAP_IGNORE( iNotifier->CompleteL( status ));
        }
    
    
    
    //TRAP_IGNORE( iNotifier->CompleteL( status ));
}

// ---------------------------------------------------------------------------
// Handles the user name password input received from the dialog
// ---------------------------------------------------------------------------
//
void CEapAuthObserver::UsernamePasswordDlgDataReceived(
     CHbSymbianVariantMap& aData )
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

// ---------------------------------------------------------------------------
// Handles the old password query user input received from the dialog
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Handles the password query user input received from the dialog
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Handles the PAC Store password query user input received from the dialog
// ---------------------------------------------------------------------------
//
void CEapAuthObserver::PacStorePwdQueryDataReceived( CHbSymbianVariantMap& aData )
{
    RDebug::Print(_L("CEapAuthObserver::PacStorePwdQueryDataReceived") ); 
        
    TBool Match = EFalse;   
    TInt  status = KErrNone;    
    
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
             
     // Check if given password can be used to open the PAC store.
     Match = iNotifier->CheckPasswordMatchingL(PasswordInfo);

     if ( Match != EFalse )
        {
        RDebug::Print(_L("CEapAuthObserver::PacStorePwdQueryDataReceived: Match == TRUE") );     
        iNotifier->SetSelectedPassword( PasswordInfo );   
        //update(true); 
        TRAP_IGNORE( iNotifier->CompleteL( status ));    
        } 
     else
        {
        RDebug::Print(_L("CEapAuthObserver::PacStorePwdQueryDataReceived: Match == FALSE") );       
        //update(false);       
        }
     iNotifier->UpdateDialogL(Match);       
}

// Derived function:
// ---------------------------------------------------------------------------
// From class MHbDeviceDialogObserver.
// Handles the closing of the dialog
// ---------------------------------------------------------------------------
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


