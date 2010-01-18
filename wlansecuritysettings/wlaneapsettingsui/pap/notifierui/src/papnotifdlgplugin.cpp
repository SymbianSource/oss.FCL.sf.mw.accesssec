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
* Description: Implementation of PapNotifDlg dialog plugin.
*
*/

/*
* %version: 9 %
*/

// INCLUDE FILES
#include <coemain.h>
#include <eikenv.h>
#include <bautils.h>
#include <data_caging_path_literals.hrh>
#include <papnotifdlgui.rsg>

#include <e32property.h>		// For RProperty 
#include <UikonInternalPSKeys.h> // For KPSUidUikon and KUikGlobalNotesAllowed.

#include <EapTtlsPapNotifierStruct.h>
#include "papnotifdlgplugin.h"
#include "papauthdialog.h"
#include "papchallengemsgdialog.h"
#include "papchallengereplydialog.h"

// CONSTANTS
//static const TUint KUtf8UnicodeRatio = 2;

// ================= OTHER EXPORTED FUNCTIONS ==============

// -----------------------------------------------------------------------------
// CreateNotifiersL
// -----------------------------------------------------------------------------
//
LOCAL_C void CreateNotifiersL( CArrayPtrFlat< MEikSrvNotifierBase2 >* aNotifiers )
    {
    MEikSrvNotifierBase2 *serNotify;
    serNotify = CPapNotifDialogPlugin::NewL();
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
// PAP dialog plugin
/////////////////////////////////////////////////////////////

// -----------------------------------------------------------------------------
// CPapNotifDialogPlugin::CPapNotifDialogPlugin
// -----------------------------------------------------------------------------
//
CPapNotifDialogPlugin::CPapNotifDialogPlugin()
: iCancelled( EFalse ),
  iAuthDlgDismissed( EFalse ),
  iChallengeMsgDismissed( EFalse ),
  iChallengeReplyDismissed( EFalse )
    {
    iManager = NULL;
    }


// -----------------------------------------------------------------------------
// CPapNotifDialogPlugin::~CPapNotifDialogPlugin
// -----------------------------------------------------------------------------
//
CPapNotifDialogPlugin::~CPapNotifDialogPlugin()
    {
    CCoeEnv::Static()->DeleteResourceFile( iResource );

    if ( !iAuthDlgDismissed )
        {
        delete iPapAuthDialog;
        }

    if ( !iChallengeMsgDismissed )
        {
        delete iPapChallengeMsgDialog;
        }

    if ( !iChallengeReplyDismissed )
        {
        delete iPapChallengeReplyDialog;
        }

    }



// -----------------------------------------------------------------------------
// CPapNotifDialogPlugin::RegisterL
// -----------------------------------------------------------------------------
//
CPapNotifDialogPlugin::TNotifierInfo CPapNotifDialogPlugin::RegisterL()
    {
    iInfo.iUid      = KUidPapDialog;
    iInfo.iPriority = ENotifierPriorityHigh;
    iInfo.iChannel  = KUidPapDialog;
    return iInfo;
    }


// -----------------------------------------------------------------------------
// CPapNotifDialogPlugin::NewL
// -----------------------------------------------------------------------------
//
CPapNotifDialogPlugin* CPapNotifDialogPlugin::NewL()
    {
    CPapNotifDialogPlugin* self = new( ELeave ) CPapNotifDialogPlugin();
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop( self );
    return self;
    }


// -----------------------------------------------------------------------------
// CPapNotifDialogPlugin::ConstructL
// -----------------------------------------------------------------------------
//
void CPapNotifDialogPlugin::ConstructL()
    {
    #if defined( _DEBUG ) || defined( DEBUG )
        RDebug::Print(_L("CPapNotifDialogPlugin::ConstructL") );
    #endif
    
    TFileName fileName;

    fileName.Append( KDriveZ );
    fileName.Append( KDC_RESOURCE_FILES_DIR );   
    fileName.Append( KResourceFileName );

    BaflUtils::NearestLanguageFile( CCoeEnv::Static()->FsSession(), fileName );
    iResource = CCoeEnv::Static()->AddResourceFileL( fileName );
    }


// -----------------------------------------------------------------------------
// CPapNotifDialogPlugin::StartL
// -----------------------------------------------------------------------------
//
TPtrC8 CPapNotifDialogPlugin::StartL( const TDesC8& /*aBuffer*/ )
    {
    return KNullDesC8().Ptr();
    }


// -----------------------------------------------------------------------------
// CPapNotifDialogPlugin::StartL
// -----------------------------------------------------------------------------
//
void CPapNotifDialogPlugin::StartL( const TDesC8& aBuffer, 
                                    TInt aReplySlot, 
                                    const RMessagePtr2& aMessage )
    {
    #if defined( _DEBUG ) || defined( DEBUG )
        RDebug::Print(_L("CPapNotifDialogPlugin::StartL") );
    #endif
    
    iCancelled = EFalse;
    iReplySlot = aReplySlot;
    iMessage   = aMessage;
     
    // This object gets constructed only once but
    // can get called many times. 
    // So initialize everything here.
    iAuthDlgDismissed = EFalse;
    iChallengeMsgDismissed = EFalse;
    iChallengeReplyDismissed = EFalse;
    iPapAuthDialog = NULL;
    iPapChallengeMsgDialog = NULL;
    iPapChallengeReplyDialog = NULL;
    iDataPtr = NULL;
    iDataPckgPtr = NULL;
    
    // We are about to display the password prompt.
    // Since this part of the code can be executed during the bootup, check if 
    // the UI has really started up to display notes/dialogs.
    TInt notesAllowed = 0;
    TInt error = RProperty::Get( KPSUidUikon, KUikGlobalNotesAllowed, 
                                 notesAllowed );

    // The above call can return error. Ignore the error. What we care is 
    // if notesAllowed has turned to 1 from 0.
    if ( notesAllowed )
        {    
        iDataPtr = new( ELeave ) TPapUiNotifierInfo; 
        iDataPckgPtr = new( ELeave ) TPckg<TPapUiNotifierInfo>( *iDataPtr );
        iDataPckgPtr->Copy( aBuffer );
        
        #if defined( _DEBUG ) || defined( DEBUG )
            RDebug::Print(_L("CPapNotifDialogPlugin::StartL, state = %d"), iDataPtr->iState );
        #endif
        
        switch ( iDataPtr->iState )
            {
            case TPapUiNotifierInfo::EPapUiNotifierAuthQueryDialog:
                {
                iPapAuthDialog = CPapAuthDialog::NewL(
                                        iDataPtr->iUsrPwdInfo.iUserName, 
                                        iDataPtr->iUsrPwdInfo.iPassword,
                                        this );
                                        
                #if defined( _DEBUG ) || defined( DEBUG )                                        
                    RDebug::Print(_L("CPapNotifDialogPlugin::StartL, executing auth dialog") );
                #endif
                                                    
                iPapAuthDialog->ExecuteLD( R_PAPNOTIF_USERNAME_PASSWORD_QUERY );
                
                #if defined( _DEBUG ) || defined( DEBUG )
                    RDebug::Print(_L("CPapNotifDialogPlugin::StartL, auth dialog executed") );
                #endif
                
                break;
                }
                
            case TPapUiNotifierInfo::EPapUiNotifierPapChallengeSize:
                {
                iChallengeSize = iDataPtr->iSrvChallengeSize;
                break;
                }

            case TPapUiNotifierInfo::EPapUiNotifierPapChallengeMsgDialog:
                {
                #if defined( _DEBUG ) || defined( DEBUG )
                    RDebug::Print(_L("CPapNotifDialogPlugin::StartL, chal msg dialog start") );
                #endif
    
                HBufC16* challengetext = HBufC16::NewLC( KMaxPapChallengeLength );
                TPtr16 text = challengetext->Des();                
                text.Copy( iDataPtr->iPapChallenge ); 

                #if defined( _DEBUG ) || defined( DEBUG )
                    RDebug::Print(_L("CPapNotifDialogPlugin::StartL, create chal msg dialog") );
                #endif
    
                iPapChallengeMsgDialog = CPapChallengeMsgDialog::NewL( text,
                    this );
                #if defined( _DEBUG ) || defined( DEBUG )
                    RDebug::Print(_L("CPapNotifDialogPlugin::StartL, executing chal msg dialog") );
                #endif
                    
                iPapChallengeMsgDialog->ExecuteLD( R_PAP_CHALLENGE_MESSAGE_QUERY );
                #if defined( _DEBUG ) || defined( DEBUG )
                    RDebug::Print(_L("CPapNotifDialogPlugin::StartL, chal msg dialog executed") );
                #endif

                CleanupStack::PopAndDestroy( challengetext );
                
                break;
                }

            case TPapUiNotifierInfo::EPapUiNotifierPapChallengeReplyQueryDialog:
                {
                // construct and show the challenge reply dialog,
                // save the reply in the password field                       
                iPapChallengeReplyDialog = CPapChallengeReplyDialog::NewL(
                    iDataPtr->iUsrPwdInfo.iPassword, this );
                iPapChallengeReplyDialog->ExecuteLD( R_PAP_CHALLENGE_REPLY_QUERY);
    
                break;
                }

            default:
                {
                break;
                }
                                
            }
    
        } 

    // In case if the notes are not allowed, this message gets completed when
    // EAPOL time out occurs and a subsequent call to cancel
    }

// -----------------------------------------------------------------------------
// CPapNotifDialogPlugin::UpdateL
// -----------------------------------------------------------------------------
//
TPtrC8 CPapNotifDialogPlugin::UpdateL( const TDesC8& /*aBuffer*/ )
    {
    return KNullDesC8().Ptr();
    }


// -----------------------------------------------------------------------------
// CPapNotifDialogPlugin::Cancel
// -----------------------------------------------------------------------------
//
void CPapNotifDialogPlugin::Cancel()
    {
    #if defined( _DEBUG ) || defined( DEBUG )
        RDebug::Print(_L("CPapNotifDialogPlugin::Cancel") );
    #endif
    
    if ( !iCancelled )
        {
        iCancelled = ETrue;
        
        if ( !iMessage.IsNull() )
            {
            iMessage.Complete( KErrCancel );
            }

        if ( !iAuthDlgDismissed && iPapAuthDialog )
            {
            iAuthDlgDismissed = ETrue;
            delete iPapAuthDialog;
            iPapAuthDialog = NULL;
            }
            
        if ( !iChallengeMsgDismissed && iPapChallengeMsgDialog )
            {
            iChallengeMsgDismissed = ETrue;
            delete iPapChallengeMsgDialog;
            iPapChallengeMsgDialog = NULL;
            }
            
        if ( !iChallengeReplyDismissed && iPapChallengeReplyDialog )
            {
            iChallengeReplyDismissed = ETrue;
            delete iPapChallengeReplyDialog;
            iPapChallengeReplyDialog = NULL;
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
// CPapNotifDialogPlugin::CompleteL
// -----------------------------------------------------------------------------
//
void CPapNotifDialogPlugin::CompleteL( TInt aStatus )
    {
    #if defined( _DEBUG ) || defined( DEBUG )
        RDebug::Print(_L("CPapNotifDialogPlugin::CompleteL") );
    #endif
    
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
// CPapNotifDialogPlugin::Release
// -----------------------------------------------------------------------------
//
void CPapNotifDialogPlugin::Release()
    {
    delete this;
    }


// -----------------------------------------------------------------------------
// CPapNotifDialogPlugin::Info
// -----------------------------------------------------------------------------
//
CPapNotifDialogPlugin::TNotifierInfo CPapNotifDialogPlugin::Info() const
    {
    return iInfo;
    }
    
// -----------------------------------------------------------------------------
// CPapNotifDialogPlugin::Username
// -----------------------------------------------------------------------------
//
TDes& CPapNotifDialogPlugin::Username()
    {
    return ( iDataPtr->iUsrPwdInfo.iUserName ) ;
    }

// -----------------------------------------------------------------------------
// CPapNotifDialogPlugin::Password
// -----------------------------------------------------------------------------
//
TDes& CPapNotifDialogPlugin::Password()
    {
    return ( iDataPtr->iUsrPwdInfo.iPassword ) ;
    }

// -----------------------------------------------------------------------------
// CPapNotifDialogPlugin::SetAuthDlgDismissed
// -----------------------------------------------------------------------------
//
void CPapNotifDialogPlugin::SetAuthDlgDismissed()
    {
    iAuthDlgDismissed = ETrue;
    }

// -----------------------------------------------------------------------------
// CPapNotifDialogPlugin::SetChallengeMsgDismissed
// -----------------------------------------------------------------------------
//
void CPapNotifDialogPlugin::SetChallengeMsgDismissed()
    {
    iChallengeMsgDismissed = ETrue;
    }

// -----------------------------------------------------------------------------
// CPapNotifDialogPlugin::SetChallengeReplyDismissed
// -----------------------------------------------------------------------------
//
void CPapNotifDialogPlugin::SetChallengeReplyDismissed()
    {
    iChallengeReplyDismissed = ETrue;
    }



// End of File
