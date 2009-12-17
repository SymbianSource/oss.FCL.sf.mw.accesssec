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
* Description: Implementation of PAP Challenge Reply Dialog
*
*/



// INCLUDE FILES
#include "papnotifdlgplugin.h"
#include "papchallengereplydialog.h"


// -----------------------------------------------------------------------------
// CPapChallengeReplyDialog::CPapChallengeReplyDialog
// -----------------------------------------------------------------------------
//
CPapChallengeReplyDialog::CPapChallengeReplyDialog( TDes& aResponse, 
                                                  CPapNotifDialogPlugin* aPlugin )
: CAknTextQueryDialog( aResponse ), 
  iPlugin( aPlugin )
    {    
    }


// -----------------------------------------------------------------------------
// CPapChallengeReplyDialog::~CPapChallengeReplyDialog
// -----------------------------------------------------------------------------
//
CPapChallengeReplyDialog::~CPapChallengeReplyDialog()
    {
    }


// -----------------------------------------------------------------------------
// CPapChallengeReplyDialog::NewL
// -----------------------------------------------------------------------------
//
CPapChallengeReplyDialog* CPapChallengeReplyDialog::NewL( TDes& aResponse, 
                                                    CPapNotifDialogPlugin* aPlugin )
    {
    CPapChallengeReplyDialog* self = new( ELeave ) CPapChallengeReplyDialog( 
                                                        aResponse, aPlugin );
    return self;
}


// -----------------------------------------------------------------------------
// CPapChallengeReplyDialog::OkToExitL
// -----------------------------------------------------------------------------
//
TBool CPapChallengeReplyDialog::OkToExitL( TInt aButtonId )
    {
    if ( CAknTextQueryDialog::OkToExitL( aButtonId ) )
       {
        if ( aButtonId==EAknSoftkeyOk )
            {
            iPlugin->SetChallengeReplyDismissed();
            iPlugin->CompleteL( KErrNone );
            }
        else
            {
            // Everything else is for cancel.
            iPlugin->SetChallengeReplyDismissed();
            iPlugin->CompleteL( KErrCancel );
            }

        return( ETrue );
        }

    return( EFalse ); 
    }


// -----------------------------------------------------------------------------
// CPapChallengeReplyDialog::HandleResourceChange
// -----------------------------------------------------------------------------
//
void CPapChallengeReplyDialog::HandleResourceChange( TInt aType )
    {
    CAknTextQueryDialog::HandleResourceChange( aType );
    if ( aType == KAknsMessageSkinChange )
        {
        }
    }


// End of File
