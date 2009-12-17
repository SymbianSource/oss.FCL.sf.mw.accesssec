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
* Description: Implementation of PAP Challenge Message Display Dialog
*
*/


// INCLUDE FILES
#include "papnotifdlgplugin.h"
#include "papchallengemsgdialog.h"


// -----------------------------------------------------------------------------
// CPapChallengeMsgDialog::CPapChallengeMsgDialog
// -----------------------------------------------------------------------------
//
CPapChallengeMsgDialog::CPapChallengeMsgDialog( CPapNotifDialogPlugin* aPlugin )
: CAknMessageQueryDialog( ENoTone ), 
  iPlugin( aPlugin )
    {
    }


// -----------------------------------------------------------------------------
// CPapChallengeMsgDialog::~CPapChallengeMsgDialog
// -----------------------------------------------------------------------------
//
CPapChallengeMsgDialog::~CPapChallengeMsgDialog()
    {
    }


// -----------------------------------------------------------------------------
// CPapChallengeMsgDialog::NewL
// -----------------------------------------------------------------------------
//
CPapChallengeMsgDialog* CPapChallengeMsgDialog::NewL( const TDesC& aMessage, 
                                                    CPapNotifDialogPlugin* aPlugin )
    {
    CPapChallengeMsgDialog* self = new( ELeave ) CPapChallengeMsgDialog( aPlugin );

    CleanupStack::PushL( self );
    if ( aMessage.Length() )
        {
        self->SetMessageTextL( aMessage );
        }

    CleanupStack::Pop( self );
    return self;
    }


// -----------------------------------------------------------------------------
// CPapChallengeMsgDialog::OkToExitL
// -----------------------------------------------------------------------------
//
TBool CPapChallengeMsgDialog::OkToExitL( TInt aButtonId )
    {
    if ( CAknMessageQueryDialog::OkToExitL( aButtonId ) )
        {
        if ( aButtonId == EAknSoftkeyOk )
            {
            #if defined( _DEBUG ) || defined( DEBUG )
                RDebug::Print(_L("CPapChallengeMsgDialog::OkToExitL, softkey OK") );
            #endif
            iPlugin->SetChallengeMsgDismissed();
            iPlugin->CompleteL( KErrNone );
            }
        else
            {
            #if defined( _DEBUG ) || defined( DEBUG )
                RDebug::Print(_L("CPapChallengeMsgDialog::OkToExitL, softkey Cancel") );
            #endif
            // Some cancel.
            iPlugin->SetChallengeMsgDismissed();
            iPlugin->CompleteL( KErrCancel );
            }

        return( ETrue );
        }

    return( EFalse ); 
    }


// -----------------------------------------------------------------------------
// CPapChallengeMsgDialog::HandleResourceChange
// -----------------------------------------------------------------------------
//
void CPapChallengeMsgDialog::HandleResourceChange( TInt aType )
    {
    CAknMessageQueryDialog::HandleResourceChange( aType );
    if ( aType == KAknsMessageSkinChange )
        {
        }
    }


// End of File
