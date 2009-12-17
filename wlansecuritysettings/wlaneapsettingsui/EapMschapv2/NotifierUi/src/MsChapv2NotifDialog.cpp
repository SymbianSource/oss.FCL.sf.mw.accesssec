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
* Description: Implementation of dialog class of MsChapv2NotifDlg
*
*/



// INCLUDE FILES
#include <MsChapv2NotifDlgUi.rsg>
#include "MsChapv2NotifDlgPlugin.h"
#include "MsChapv2NotifDialog.h"


// ============================ MEMBER FUNCTIONS ===============================

// -----------------------------------------------------------------------------
// CMsChapv2Dialog::CMsChapv2Dialog
// -----------------------------------------------------------------------------
//
CMsChapv2Dialog::CMsChapv2Dialog( CMsChapv2DialogPlugin* aPlugin, TBool aUsernameExists )
: CAknMultiLineDataQueryDialog( ENoTone ), 
  iPlugin( aPlugin ),
  iUsernameExists( aUsernameExists )
    {
    }


// -----------------------------------------------------------------------------
// CMsChapv2Dialog::NewL
// -----------------------------------------------------------------------------
//
CMsChapv2Dialog* CMsChapv2Dialog::NewL( TDes& aUsername, TDes& aPassword,
                                        CMsChapv2DialogPlugin* aPlugin )
    {
    CMsChapv2Dialog* self = new( ELeave ) CMsChapv2Dialog( aPlugin, aUsername.Length() > 0 );
    CleanupStack::PushL( self );
    if ( aUsername.Length() )
        {
        self->SetDataL( aUsername, aPassword );
        }

    CleanupStack::Pop( self );
    return self;
    }


// -----------------------------------------------------------------------------
// CMsChapv2Dialog::ConstructL
// -----------------------------------------------------------------------------
//
void CMsChapv2Dialog::ConstructL()
    {
    }


// -----------------------------------------------------------------------------
// CMsChapv2Dialog::~CMsChapv2Dialog
// -----------------------------------------------------------------------------
//
CMsChapv2Dialog::~CMsChapv2Dialog()
    {
    }


// -----------------------------------------------------------------------------
// CMsChapv2Dialog::OkToExitL
// -----------------------------------------------------------------------------
//
TBool CMsChapv2Dialog::OkToExitL( TInt aButtonId )
    {
    if ( CAknMultiLineDataQueryDialog::OkToExitL( aButtonId ) )
        {
        if ( aButtonId == EAknSoftkeyOk )
            {
            CAknMultilineQueryControl* firstControl = FirstControl();
            firstControl->GetText( iPlugin->GetUsername() );

            CAknMultilineQueryControl* secondControl = SecondControl();
            secondControl->GetText( iPlugin->GetPassword() );
        
            _LIT( KEmpty, "" );     // Empty string

            // Empty when we are not changing password
            iPlugin->SetOldPassword( KEmpty );
                  
            iPlugin->CompleteL( KErrNone );
            return( ETrue );
            }
        else
            {
            iPlugin->CompleteL( KErrCancel );
            return( ETrue );
            }
        }

    return( EFalse );
    }


// -----------------------------------------------------------------------------
// CMsChapv2Dialog::HandleResourceChange
// -----------------------------------------------------------------------------
//
void CMsChapv2Dialog::HandleResourceChange( TInt aType )
    {
    CAknMultiLineDataQueryDialog::HandleResourceChange( aType );

    if ( aType == KAknsMessageSkinChange )
        {
        }
    }


// End of File
