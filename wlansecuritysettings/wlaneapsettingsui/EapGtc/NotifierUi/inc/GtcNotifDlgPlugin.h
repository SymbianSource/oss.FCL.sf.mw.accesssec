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
* Description: Declaration of GtcNotifDlg Dialog Plugins
*
*/

/*
* %version: 11.1.7 %
*/

#ifndef __GTCNOTIFDLGPLUGIN_H__
#define __GTCNOTIFDLGPLUGIN_H__


// INCLUDES
#include <eikdialg.h>
#include <e32std.h>
#include <e32base.h>
#include <cdblen.h>
#include <eiknotapi.h>
#include <AknForm.h>
#include <AknQueryDialog.h>
#include <AknGlobalMsgQuery.h>
#include <aknPopup.h>


// CONSTANTS

// UIDs for dialogs

// ID of GTC username & password dialog
const TUid KUidGtcDialog        = { 0x101f8e7f };

// Channel used for screen   
const TUid KScreenOutputChannel = { 0x00000123 };

// Number of dialogs in this plugin
const TInt KPluginGranularity   = 1;

// ROM folder
_LIT( KDriveZ, "z:" );

// RSC file name.
_LIT( KResourceFileName, "GtcNotifDlgUi.rsc" );


// GLOBAL FUNCTIONS
//

/**
* Array of connection dialog plugins.
* @return A CArray of MEikSrvNotifierBase2 based classes.
*/
IMPORT_C CArrayPtr< MEikSrvNotifierBase2 >* NotifierArray();


// CLASS DECLARATION

class CGTCResponseQueryDialog;
class CGTCMessageDisplayDialog;


struct TEapGtcUsernamePasswordInfo
    {
    TBool iIsFirstQuery;
    TBuf16<128> iIdentity;
    TBuf16<256> iPasscode;
    TPassword iPincode;
    };


/**
 * Gtc dialog plugin class
 */
class CGtcDialogPlugin : public CBase,
                         public MEikSrvNotifierBase2
    {
    public:
        static CGtcDialogPlugin* NewL();

        ~CGtcDialogPlugin();

        TNotifierInfo RegisterL();
        TNotifierInfo Info() const;

        TPtrC8 StartL( const TDesC8& aBuffer );
        void StartL( const TDesC8& aBuffer, TInt aReplySlot,
                     const RMessagePtr2& aMessage );

        TPtrC8 UpdateL( const TDesC8& aBuffer );
        void Cancel();
        void CompleteL( TInt aStatus );
        void Release();
        void CompleteMessageDisplayL( TInt aStatus );

    protected:
        CGtcDialogPlugin();

        void ConstructL();
        
    protected:
        TNotifierInfo iInfo;        // Notifier info
        RMessagePtr2 iMessage;      // Message
        TInt iReplySlot;            // Reply slot
        TBool iCancelled;           // ETrue if dialog cancelled. For Query dialog.	    
        TBool iGtcMessageCancelled; // ETrue if message dialog is cancelled.

    private:
        CGTCResponseQueryDialog* iGTCResponseQueryDlg;
        CGTCMessageDisplayDialog* iGTCMessageDisplayDlg;

        TEapGtcUsernamePasswordInfo* iDataPtr;
        TPckg<TEapGtcUsernamePasswordInfo>* iDataPckgPtr;
        TInt iResource;             // Resource
    };


#endif  // __GTCNOTIFDLGPLUGIN_H__

// End of File
