/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description: Implementation of GtcNotif dialog plugin.
*
*/

/*
* %version: 12.1.9 %
*/

// INCLUDE FILES
#include <coemain.h>
#include <eikenv.h>
#include <bautils.h>
#include <data_caging_path_literals.hrh>
#include <gtcnotifdlgui.rsg>
#include <e32base.h>
#include <StringLoader.h>

#include <e32property.h>            // For RProperty 
#include <UikonInternalPSKeys.h>    // For KPSUidUikon and KUikGlobalNotesAllowed.

#include "GtcNotifDlgPlugin.h"
#include "GTCResponseQueryDialog.h"
#include "GTCMessageDisplayDialog.h"


// CONSTANTS
static const TInt KMaxLengthOfGtcResponse = 256;

// Ratio between ascii and unicode character sizes
static const TUint KAsciiUnicodeRatio = 2;



// ================= OTHER EXPORTED FUNCTIONS ==============

// -----------------------------------------------------------------------------
// CreateNotifiersL
// -----------------------------------------------------------------------------
//
LOCAL_C void CreateNotifiersL( 
                          CArrayPtrFlat< MEikSrvNotifierBase2 >* aNotifiers )
    {
    MEikSrvNotifierBase2 *serNotify;

    serNotify = CGtcDialogPlugin::NewL();
    CleanupStack::PushL( serNotify );
    aNotifiers->AppendL( serNotify );
    CleanupStack::Pop( serNotify );
    }


// -----------------------------------------------------------------------------
// NotifierArray
// -----------------------------------------------------------------------------
//
EXPORT_C CArrayPtr< MEikSrvNotifierBase2 >* NotifierArray()
    {
    // NotifierArray() can't leave
    CArrayPtrFlat< MEikSrvNotifierBase2 >* array = 
            new CArrayPtrFlat< MEikSrvNotifierBase2 >( KPluginGranularity );

    if ( array )
        {
        TRAPD( err, CreateNotifiersL( array ) );
        
        if( err )
            {
            TInt count = array->Count();

            while( count-- )
                {
                ( *array )[ count ]->Release();
                }

            delete array;
            array = NULL;
            }
        }

    return( array );
    }


//////////////////////////////////////////////////////////////
// Gtc dialog plugin
/////////////////////////////////////////////////////////////

// -----------------------------------------------------------------------------
// CGtcDialogPlugin::CGtcDialogPlugin
// -----------------------------------------------------------------------------
//
CGtcDialogPlugin::CGtcDialogPlugin()
: iCancelled( EFalse ), 
  iGtcMessageCancelled( EFalse )
    {
    iManager = NULL;
    }


// -----------------------------------------------------------------------------
// CGtcDialogPlugin::~CGtcDialogPlugin
// -----------------------------------------------------------------------------
//
CGtcDialogPlugin::~CGtcDialogPlugin()
    {
    CCoeEnv::Static()->DeleteResourceFile( iResource );

    if ( !iGtcMessageCancelled )
        {
        delete iGTCMessageDisplayDlg;
        }

    if ( !iCancelled )
        {
        delete iGTCResponseQueryDlg;
        }
    }



// -----------------------------------------------------------------------------
// CGtcDialogPlugin::RegisterL
// -----------------------------------------------------------------------------
//
CGtcDialogPlugin::TNotifierInfo CGtcDialogPlugin::RegisterL()
    {
    iInfo.iUid      = KUidGtcDialog;
    iInfo.iPriority = ENotifierPriorityHigh;
    iInfo.iChannel  = KUidGtcDialog;
    return iInfo;
    }


// -----------------------------------------------------------------------------
// CGtcDialogPlugin::NewL
// -----------------------------------------------------------------------------
//
CGtcDialogPlugin* CGtcDialogPlugin::NewL()
    {
    CGtcDialogPlugin* self = new ( ELeave ) CGtcDialogPlugin();
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop( self );
    return self;
    }


// -----------------------------------------------------------------------------
// CGtcDialogPlugin::ConstructL
// -----------------------------------------------------------------------------
//
void CGtcDialogPlugin::ConstructL()
    {
    TFileName fileName;

    fileName.Append( KDriveZ );
    fileName.Append( KDC_RESOURCE_FILES_DIR );
    fileName.Append( KResourceFileName );

    BaflUtils::NearestLanguageFile( CCoeEnv::Static()->FsSession(), fileName );
    iResource = CCoeEnv::Static()->AddResourceFileL( fileName );
    }


// -----------------------------------------------------------------------------
// CGtcDialogPlugin::StartL
// -----------------------------------------------------------------------------
//
TPtrC8 CGtcDialogPlugin::StartL( const TDesC8& /*aBuffer*/ )
    {
    return KNullDesC8().Ptr();
    }


// -----------------------------------------------------------------------------
// CGtcDialogPlugin::StartL
// -----------------------------------------------------------------------------
//
void CGtcDialogPlugin::StartL( const TDesC8&  aBuffer, 
                               TInt aReplySlot, 
                               const RMessagePtr2& aMessage )
    {
    iCancelled = EFalse;
    iReplySlot = aReplySlot;
    iMessage   = aMessage;
     
    // This object gets constructed only once where as this gets called many 
    // times, if user is not answering the query. 
    // So initialize everything here itself.
    iGTCResponseQueryDlg = NULL;
    iGTCMessageDisplayDlg = NULL;
    iDataPtr = NULL;
    iDataPckgPtr = NULL;
    iGtcMessageCancelled = EFalse;

    // We are about to display the password prompt.
    // Since this part of the code can be executed during the bootup, check if
    // the UI has really started up to display notes/dialogs.
    TInt notesAllowed = 0;
    TInt error = RProperty::Get( KPSUidUikon, KUikGlobalNotesAllowed, 
                                 notesAllowed );

    // The above call can return error. Don't care the error. What we care is
    // if notesAllowed has turned to 1 from 0.
    if ( notesAllowed )
        {
        // Display EAP-GTC message if there's one...
        if ( aBuffer.Length() != 0 )
            {
            HBufC16* buffer = HBufC16::NewLC( aBuffer.Size() /
                                                        KAsciiUnicodeRatio );
            TPtr16 text = buffer->Des();
            text.Copy( reinterpret_cast<TUint16 *>( const_cast<TUint8 *> (
                                        aBuffer.Ptr() ) ), aBuffer.Size() /
                                                        KAsciiUnicodeRatio );

            iGTCMessageDisplayDlg = CGTCMessageDisplayDialog::NewL( text, 
                                                                    this );
            iGTCMessageDisplayDlg->ExecuteLD( R_MESSAGE_QUERY );

            // Do not set iGTCMessageDisplayDlg to NULL here, because then
            // a timeout cancel will cause a crash. Prevent double deletion
            // by checking iGtcMessageCancelled in the destructor.

            CleanupStack::PopAndDestroy( buffer );
            }
        else
            {
            // Show the data query directly since there is no message to display.
            CompleteMessageDisplayL( KErrNone );
            }
        }

    // In case if the notes are not allowed, this message gets completed when 
    // EAPOL time out occurs and a subsequent call to cancel from 
    // eap_am_type_securid_symbian_c::DoCancel().

    }


// -----------------------------------------------------------------------------
// CGtcDialogPlugin::UpdateL
// -----------------------------------------------------------------------------
//
TPtrC8 CGtcDialogPlugin::UpdateL( const TDesC8& /*aBuffer*/ )
    {
    return KNullDesC8().Ptr();
    }


// -----------------------------------------------------------------------------
// CGtcDialogPlugin::Cancel
// -----------------------------------------------------------------------------
//
void CGtcDialogPlugin::Cancel()
    {
    if ( !iCancelled )
        {
        iCancelled = ETrue;

        if ( !iMessage.IsNull() )
            {
            iMessage.Complete( KErrCancel );
            }

        if ( iGTCResponseQueryDlg )
            {
            delete iGTCResponseQueryDlg;
            iGTCResponseQueryDlg = NULL;
            }

        if ( !iGtcMessageCancelled && iGTCMessageDisplayDlg )
            {
            iGtcMessageCancelled = ETrue;
            delete iGTCMessageDisplayDlg;
            iGTCMessageDisplayDlg = NULL;
            }
        }

    if( iDataPtr ) 
        {
        delete iDataPtr;
        iDataPtr = NULL;
        }

    if( iDataPckgPtr ) 
        {
        delete iDataPckgPtr;
        iDataPckgPtr = NULL;
        }
    }


// -----------------------------------------------------------------------------
// CGtcDialogPlugin::CompleteL
// -----------------------------------------------------------------------------
//
void CGtcDialogPlugin::CompleteL( TInt aStatus )
    { 
    if ( aStatus == KErrNone  && !iMessage.IsNull() )
        {
        iMessage.WriteL( iReplySlot, *iDataPckgPtr);
        }

    iCancelled = ETrue;
    
    if ( !iMessage.IsNull() )
        {
        iMessage.Complete( aStatus );
        }

    if( iDataPtr ) 
        {
        delete iDataPtr;
        iDataPtr = NULL;
    }

    if( iDataPckgPtr ) 
        {
        delete iDataPckgPtr;
        iDataPckgPtr = NULL;
        }
    }


// -----------------------------------------------------------------------------
// CGtcDialogPlugin::Release
// -----------------------------------------------------------------------------
//
void CGtcDialogPlugin::Release()
    {
    delete this;
    }


// -----------------------------------------------------------------------------
// CGtcDialogPlugin::Info
// -----------------------------------------------------------------------------
//
CGtcDialogPlugin::TNotifierInfo CGtcDialogPlugin::Info() const
    {
    return iInfo;
    }


// -----------------------------------------------------------------------------
// CGtcDialogPlugin::CompleteMessageDisplayL
// -----------------------------------------------------------------------------
//
void CGtcDialogPlugin::CompleteMessageDisplayL( TInt aStatus )
    {
    iGtcMessageCancelled = ETrue;

    if ( aStatus == KErrNone )
        {
        // Now user has acknowledged the GTC message.
        // Show the response query to enter the password.

        iDataPtr = new( ELeave ) TEapGtcUsernamePasswordInfo;
        iDataPckgPtr = new( ELeave ) TPckg<TEapGtcUsernamePasswordInfo>( 
                                                                *iDataPtr );

        TBuf16<KMaxLengthOfGtcResponse> response;

        iGTCResponseQueryDlg = CGTCResponseQueryDialog::NewL( 
                                                iDataPtr->iPasscode, this );

        HBufC* text = StringLoader::LoadLC( R_GTC_RESPONSE );
        iGTCResponseQueryDlg->SetPromptL( *text );
        CleanupStack::PopAndDestroy( text );

        iGTCResponseQueryDlg->ExecuteLD( R_GTC_PASSWORD_QUERY);

        // Do not set iGTCResponseQueryDlg to NULL here, because then
        // a timeout cancel will cause a crash. Prevent double deletion
        // by checking iCancelled in the destructor.
        }
    else
        {
        // User probably cancelled the message, some how.
        // Can not continue to show the password query.
        if ( !iMessage.IsNull() )
            {
            iMessage.Complete( aStatus );
            }
        }
    }


// End of File
