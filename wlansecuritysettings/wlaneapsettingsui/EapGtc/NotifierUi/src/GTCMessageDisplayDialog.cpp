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
* Description: Implementation of Gtc Message Display Dialog.
*
*/


// INCLUDE FILES
#include "GtcNotifDlgPlugin.h"
#include "GTCMessageDisplayDialog.h"


// -----------------------------------------------------------------------------
// CGTCMessageDisplayDialog::CGTCMessageDisplayDialog
// -----------------------------------------------------------------------------
//
CGTCMessageDisplayDialog::CGTCMessageDisplayDialog( CGtcDialogPlugin* aPlugin )
: CAknMessageQueryDialog( ENoTone ), 
  iPlugin( aPlugin )
    {
    }


// -----------------------------------------------------------------------------
// CGTCMessageDisplayDialog::~CGTCMessageDisplayDialog
// -----------------------------------------------------------------------------
//
CGTCMessageDisplayDialog::~CGTCMessageDisplayDialog()
    {
    }


// -----------------------------------------------------------------------------
// CGTCMessageDisplayDialog::NewL
// -----------------------------------------------------------------------------
//
CGTCMessageDisplayDialog* CGTCMessageDisplayDialog::NewL( const TDesC& aMessage, 
                                                    CGtcDialogPlugin* aPlugin )
    {
    CGTCMessageDisplayDialog* self = new( ELeave ) CGTCMessageDisplayDialog( 
                                                                    aPlugin );

    CleanupStack::PushL( self );
    if ( aMessage.Length() )
        {
        self->SetMessageTextL( aMessage );
        }

    CleanupStack::Pop( self );
    return self;
    }


// -----------------------------------------------------------------------------
// CGTCMessageDisplayDialog::OkToExitL
// -----------------------------------------------------------------------------
//
TBool CGTCMessageDisplayDialog::OkToExitL( TInt aButtonId )
    {
    if ( CAknMessageQueryDialog::OkToExitL( aButtonId ) )
        {
        if ( aButtonId == EAknSoftkeyOk )
            {
            iPlugin->CompleteMessageDisplayL( KErrNone );
            }
        else
            {
            // Some cancel.
            iPlugin->CompleteMessageDisplayL( KErrCancel );
            }

        return( ETrue );
        }

    return( EFalse ); 
    }


// -----------------------------------------------------------------------------
// CGTCMessageDisplayDialog::HandleResourceChange
// -----------------------------------------------------------------------------
//
void CGTCMessageDisplayDialog::HandleResourceChange( TInt aType )
    {
    CAknMessageQueryDialog::HandleResourceChange( aType );
    if ( aType == KAknsMessageSkinChange )
        {
        }
    }


// End of File
