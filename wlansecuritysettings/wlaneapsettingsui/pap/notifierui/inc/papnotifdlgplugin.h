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
* Description: Declaration of PAP Notif Dialog Plugin
*
*/



#ifndef __PAPNOTIFDLGPLUGIN_H__
#define __PAPNOTIFDLGPLUGIN_H__


// INCLUDES
#include <eikdialg.h>
#include <e32std.h>
#include <e32base.h>
#include <cdblen.h>
#include <eiknotapi.h>
#include <AknForm.h>
#include <AknQueryDialog.h>
#include <aknPopup.h>
#include <EapTtlsPapNotifierStruct.h>


// CONSTANTS

// UIDs for dialogs

// ID of PAP username & password dialog
const TUid KUidPapDialog   = { 0x200159A9 };  

// Channel used for screen 
const TUid KScreenOutputChannel = { 0x00000123 };  

// Number of dialogs in this plugin
const TInt KPluginGranularity   = 1;

// ROM folder
_LIT( KDriveZ, "z:" );

// RSC file name.
_LIT( KResourceFileName, "papnotifdlgui.rsc" );


// GLOBAL FUNCTIONS

/**
* Array of connection dialog plugins.
* @return A CArray of MEikSrvNotifierBase2 based classes.
*/
IMPORT_C CArrayPtr< MEikSrvNotifierBase2 >* NotifierArray();


// CLASS DECLARATION

class CPapAuthDialog;
class CPapChallengeMsgDialog;
class CPapChallengeReplyDialog;

/**
 * PAP notifier dialog plugin class
 */
class CPapNotifDialogPlugin : public CBase,
                              public MEikSrvNotifierBase2
    {
    public:
        static CPapNotifDialogPlugin* NewL();

        ~CPapNotifDialogPlugin();

        TNotifierInfo RegisterL();
        TNotifierInfo Info() const;

        TPtrC8 StartL( const TDesC8& aBuffer );
        void StartL( const TDesC8& aBuffer, TInt aReplySlot,
                     const RMessagePtr2& aMessage );

        TPtrC8 UpdateL( const TDesC8& aBuffer );
        void Cancel();
        void CompleteL( TInt aStatus );
        void Release();
        
    public: // new
        
        TDes& Username();
        TDes& Password();

        void SetAuthDlgDismissed();
        void SetChallengeMsgDismissed();
        void SetChallengeReplyDismissed();

    protected:
        CPapNotifDialogPlugin();

        void ConstructL();

    protected:
        TNotifierInfo iInfo;        // Notifier info
        RMessagePtr2 iMessage;      // Message
        TInt iReplySlot;            // Reply slot
        TBool iCancelled;           // ETrue if dialog cancelled

    private:
    
        TInt iResource;             // Resource
        
        TPapUiNotifierInfo* iDataPtr;
        TPckg<TPapUiNotifierInfo>* iDataPckgPtr;        
            
        CPapAuthDialog* iPapAuthDialog;
        CPapChallengeMsgDialog* iPapChallengeMsgDialog;
        CPapChallengeReplyDialog*iPapChallengeReplyDialog;

        TUint iChallengeSize;

        TBool iAuthDlgDismissed;
        TBool iChallengeMsgDismissed;
        TBool iChallengeReplyDismissed;		

    };


#endif  // __PAPNOTIFDLGPLUGIN_H__

// End of File
