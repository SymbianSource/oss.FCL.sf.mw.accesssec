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
* Description: Implementation of MsChapv2NotifDlg dialog plugin.
*
*/



// INCLUDE FILES
#include <coemain.h>
#include <eikenv.h>
#include <bautils.h>
#include <data_caging_path_literals.hrh>
#include <MsChapv2NotifDlgUi.rsg>

#include <e32property.h>		// For RProperty 
#include <UikonInternalPSKeys.h> // For KPSUidUikon and KUikGlobalNotesAllowed.

#include "MsChapv2NotifDlgPlugin.h"
#include "MsChapv2NotifDialog.h"



// ================= OTHER EXPORTED FUNCTIONS ==============

// -----------------------------------------------------------------------------
// CreateNotifiersL
// -----------------------------------------------------------------------------
//
LOCAL_C void CreateNotifiersL( 
                          CArrayPtrFlat< MEikSrvNotifierBase2 >* aNotifiers )
    {
    MEikSrvNotifierBase2 *serNotify;
    serNotify = CMsChapv2DialogPlugin::NewL();
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
// MsChapv2 dialog plugin
/////////////////////////////////////////////////////////////

// -----------------------------------------------------------------------------
// CMsChapv2DialogPlugin::CMsChapv2DialogPlugin
// -----------------------------------------------------------------------------
//
CMsChapv2DialogPlugin::CMsChapv2DialogPlugin()
: iCancelled( EFalse )
    {
    iManager = NULL;
    }


// -----------------------------------------------------------------------------
// CMsChapv2DialogPlugin::~CMsChapv2DialogPlugin
// -----------------------------------------------------------------------------
//
CMsChapv2DialogPlugin::~CMsChapv2DialogPlugin()
    {
    CCoeEnv::Static()->DeleteResourceFile( iResource );

    if ( !iCancelled )
        {
        delete iMSCHAPV2Dialog;
        }
    }



// -----------------------------------------------------------------------------
// CMsChapv2DialogPlugin::RegisterL
// -----------------------------------------------------------------------------
//
CMsChapv2DialogPlugin::TNotifierInfo CMsChapv2DialogPlugin::RegisterL()
    {
    iInfo.iUid      = KUidMsChapv2Dialog;
    iInfo.iPriority = ENotifierPriorityHigh;
    iInfo.iChannel  = KUidMsChapv2Dialog;
    return iInfo;
    }


// -----------------------------------------------------------------------------
// CMsChapv2DialogPlugin::NewL
// -----------------------------------------------------------------------------
//
CMsChapv2DialogPlugin* CMsChapv2DialogPlugin::NewL()
    {
    CMsChapv2DialogPlugin* self = new( ELeave ) CMsChapv2DialogPlugin();
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop( self );
    return self;
    }


// -----------------------------------------------------------------------------
// CMsChapv2DialogPlugin::ConstructL
// -----------------------------------------------------------------------------
//
void CMsChapv2DialogPlugin::ConstructL()
    {
    TFileName fileName;

    fileName.Append( KDriveZ );
    fileName.Append( KDC_RESOURCE_FILES_DIR );   
    fileName.Append( KResourceFileName );

    BaflUtils::NearestLanguageFile( CCoeEnv::Static()->FsSession(), fileName );
    iResource = CCoeEnv::Static()->AddResourceFileL( fileName );
    }


// -----------------------------------------------------------------------------
// CMsChapv2DialogPlugin::StartL
// -----------------------------------------------------------------------------
//
TPtrC8 CMsChapv2DialogPlugin::StartL( const TDesC8& /*aBuffer*/ )
    {
    return KNullDesC8().Ptr();
    }


// -----------------------------------------------------------------------------
// CMsChapv2DialogPlugin::StartL
// -----------------------------------------------------------------------------
//
void CMsChapv2DialogPlugin::StartL( const TDesC8& aBuffer, 
                                    TInt aReplySlot, 
                                    const RMessagePtr2& aMessage )
    {
    iCancelled = EFalse;
    iReplySlot = aReplySlot;
    iMessage   = aMessage;
     
    // This object gets constructed only once where as this gets called many 
    // times, if user is not answering the query. 
    // So initialize everything here itself.
    iMSCHAPV2Dialog = NULL;
    iDataPtr = NULL;
    iDataPckgPtr = NULL;
    
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
        iDataPtr = new( ELeave ) TEapMsChapv2UsernamePasswordInfo;
        iDataPtr->iIsIdentityQuery = ETrue;
        iDataPtr->iPasswordPromptEnabled = ETrue;    
        iDataPckgPtr = new( ELeave ) TPckg<TEapMsChapv2UsernamePasswordInfo>(
                                                                *iDataPtr );
        iDataPckgPtr->Copy(aBuffer);    
    
        iMSCHAPV2Dialog = CMsChapv2Dialog::NewL( iDataPtr->iUsername, 
                                                 iDataPtr->iPassword, this );
        iMSCHAPV2Dialog->ExecuteLD( R_MSCHAPV2NOTIF_USERNAME_PASSWORD_QUERY );
        }

    // In case if the notes are not allowed, this message gets completed when
    // EAPOL time out occurs and a subsequent call to cancel from 
    // eap_am_type_mschapv2_symbian_c::DoCancel().
    }

// -----------------------------------------------------------------------------
// CMsChapv2DialogPlugin::UpdateL
// -----------------------------------------------------------------------------
//
TPtrC8 CMsChapv2DialogPlugin::UpdateL( const TDesC8& /*aBuffer*/ )
    {
    return KNullDesC8().Ptr();
    }


// -----------------------------------------------------------------------------
// CMsChapv2DialogPlugin::Cancel
// -----------------------------------------------------------------------------
//
void CMsChapv2DialogPlugin::Cancel()
    {
    if ( !iCancelled )
        {
        iCancelled = ETrue;
        if ( !iMessage.IsNull() )
            {
            iMessage.Complete( KErrCancel );
            }

        if ( iMSCHAPV2Dialog )
            {
            delete iMSCHAPV2Dialog;
            iMSCHAPV2Dialog = NULL;
            }
        }

    if ( iDataPtr )
        {
        delete iDataPtr;
        iDataPtr = NULL;
        }

    if ( iDataPckgPtr )
        {
        delete iDataPckgPtr;
        iDataPckgPtr = NULL;
        }
    }


// -----------------------------------------------------------------------------
// CMsChapv2DialogPlugin::CompleteL
// -----------------------------------------------------------------------------
//
void CMsChapv2DialogPlugin::CompleteL( TInt aStatus )
    { 
    if ( aStatus == KErrNone && !iMessage.IsNull() )
        {
        iMessage.WriteL( iReplySlot, *iDataPckgPtr );
        }
    iCancelled = ETrue;
    if ( !iMessage.IsNull() )
        {
        iMessage.Complete( aStatus );
        }

    if ( iDataPtr ) 
        {
        delete iDataPtr;
        iDataPtr = NULL;		
        }

    if ( iDataPckgPtr )
        {
        delete iDataPckgPtr;
        iDataPckgPtr = NULL;
        }
    }


// -----------------------------------------------------------------------------
// CMsChapv2DialogPlugin::Release
// -----------------------------------------------------------------------------
//
void CMsChapv2DialogPlugin::Release()
    {
    delete this;
    }


// -----------------------------------------------------------------------------
// CMsChapv2DialogPlugin::Info
// -----------------------------------------------------------------------------
//
CMsChapv2DialogPlugin::TNotifierInfo CMsChapv2DialogPlugin::Info() const
    {
    return iInfo;
    }


// End of File
