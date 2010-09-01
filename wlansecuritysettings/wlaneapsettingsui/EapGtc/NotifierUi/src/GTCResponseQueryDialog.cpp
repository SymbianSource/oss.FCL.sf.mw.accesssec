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
* Description: Implementation of Gtc Response Query Dialog.
*
*/

/*
* %version: tr1cfwln#11 %
*/

// INCLUDE FILES
#include "GtcNotifDlgPlugin.h"
#include "GTCResponseQueryDialog.h"


// -----------------------------------------------------------------------------
// CGTCResponseQueryDialog::CGTCResponseQueryDialog
// -----------------------------------------------------------------------------
//
CGTCResponseQueryDialog::CGTCResponseQueryDialog( TDes& aResponse, 
                                                  CGtcDialogPlugin* aPlugin )
: CAknTextQueryDialog( aResponse ), 
  iPlugin( aPlugin )
    {    
    }


// -----------------------------------------------------------------------------
// CGTCResponseQueryDialog::~CGTCResponseQueryDialog
// -----------------------------------------------------------------------------
//
CGTCResponseQueryDialog::~CGTCResponseQueryDialog()
    {
    }


// -----------------------------------------------------------------------------
// CGTCResponseQueryDialog::NewL
// -----------------------------------------------------------------------------
//
CGTCResponseQueryDialog* CGTCResponseQueryDialog::NewL( TDes& aResponse, 
                                                    CGtcDialogPlugin* aPlugin )
    {
    CGTCResponseQueryDialog* self = new( ELeave ) CGTCResponseQueryDialog( 
                                                        aResponse, aPlugin );
    return self;
}


// -----------------------------------------------------------------------------
// CGTCResponseQueryDialog::OkToExitL
// -----------------------------------------------------------------------------
//
TBool CGTCResponseQueryDialog::OkToExitL( TInt aButtonId )
    {
    if ( CAknTextQueryDialog::OkToExitL( aButtonId ) )
       {
        // This will be the case always since there is no "cancel" in this dialog.
        if ( aButtonId==EAknSoftkeyOk )
            {
            iPlugin->CompleteL( KErrNone );
            }
        else
            {
            // Everything else is for cancel.
            iPlugin->CompleteL( KErrCancel );
            }

        return( ETrue );
        }

    return( EFalse ); 
    }


// -----------------------------------------------------------------------------
// CGTCResponseQueryDialog::HandleResourceChange
// -----------------------------------------------------------------------------
//
void CGTCResponseQueryDialog::HandleResourceChange( TInt aType )
    {
    CAknTextQueryDialog::HandleResourceChange( aType );
    if ( aType == KAknsMessageSkinChange )
        {
        }
    }


// End of File
