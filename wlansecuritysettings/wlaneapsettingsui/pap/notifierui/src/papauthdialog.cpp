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
* Description: Implementation of authentication query dialog class of Pap Notifier
*
*/



// INCLUDE FILES
#include <papnotifdlgui.rsg>
#include "papnotifdlgplugin.h"
#include "papauthdialog.h"


// ============================ MEMBER FUNCTIONS ===============================

// -----------------------------------------------------------------------------
// CPapAuthDialog::CPapAuthDialog
// -----------------------------------------------------------------------------
//
CPapAuthDialog::CPapAuthDialog( CPapNotifDialogPlugin* aPlugin )
    : CAknMultiLineDataQueryDialog( ENoTone ), 
    iPlugin( aPlugin )
    {
    }


// -----------------------------------------------------------------------------
// CPapAuthDialog::NewL
// -----------------------------------------------------------------------------
//
CPapAuthDialog* CPapAuthDialog::NewL( TDes& aUsername, TDes& aPassword,
                                        CPapNotifDialogPlugin* aPlugin )
    {
    CPapAuthDialog* self = new( ELeave ) CPapAuthDialog( aPlugin );
    CleanupStack::PushL( self );
    if ( aUsername.Length() )
        {
        self->SetDataL( aUsername, aPassword );
        }

    CleanupStack::Pop( self );
    return self;
    }


// -----------------------------------------------------------------------------
// CPapAuthDialog::ConstructL
// -----------------------------------------------------------------------------
//
void CPapAuthDialog::ConstructL()
    {
    #if defined( _DEBUG ) || defined( DEBUG )
        RDebug::Print(_L("CPapAuthDialog::ConstructL") );
    #endif
    }


// -----------------------------------------------------------------------------
// CPapAuthDialog::~CPapAuthDialog
// -----------------------------------------------------------------------------
//
CPapAuthDialog::~CPapAuthDialog()
    {
    }


// -----------------------------------------------------------------------------
// CPapAuthDialog::OkToExitL
// -----------------------------------------------------------------------------
//
TBool CPapAuthDialog::OkToExitL( TInt aButtonId )
    {
    if ( CAknMultiLineDataQueryDialog::OkToExitL( aButtonId ) )
        {
        if ( aButtonId == EAknSoftkeyOk )
            {
            #if defined( _DEBUG ) || defined( DEBUG )
                RDebug::Print(_L("CPapAuthDialog::OkToExitL, softkey OK") );
            #endif
            
            // save the user entries to be sent back to eapol
            CAknMultilineQueryControl* firstControl = FirstControl();
            firstControl->GetText( iPlugin->Username() );

            CAknMultilineQueryControl* secondControl = SecondControl();
            secondControl->GetText( iPlugin->Password() );            
            
            iPlugin->SetAuthDlgDismissed();             
            iPlugin->CompleteL( KErrNone );
            return( ETrue );
            }
        else
            {
            #if defined( _DEBUG ) || defined( DEBUG )
                RDebug::Print(_L("CPapAuthDialog::OkToExitL, softkey Cancel") );
            #endif
            
            iPlugin->SetAuthDlgDismissed();
            iPlugin->CompleteL( KErrCancel );
            return( ETrue );
            }
        }

    return( EFalse );
    }


// -----------------------------------------------------------------------------
// CPapAuthDialog::HandleResourceChange
// -----------------------------------------------------------------------------
//
void CPapAuthDialog::HandleResourceChange( TInt aType )
    {
    CAknMultiLineDataQueryDialog::HandleResourceChange( aType );

    if ( aType == KAknsMessageSkinChange )
        {
        }
    }


// End of File
