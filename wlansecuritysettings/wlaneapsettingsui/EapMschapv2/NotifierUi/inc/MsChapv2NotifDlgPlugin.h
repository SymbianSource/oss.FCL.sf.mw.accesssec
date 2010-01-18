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
* Description: Declaration of MsChapv2Notif Dialog Plugins
*
*/

/*
* %version: 11.1.7 %
*/

#ifndef __MSCHAPV2NOTIFDLGPLUGIN_H__
#define __MSCHAPV2NOTIFDLGPLUGIN_H__


// INCLUDES
#include <eikdialg.h>
#include <e32std.h>
#include <e32base.h>
#include <cdblen.h>
#include <eiknotapi.h>
#include <AknForm.h>
#include <AknQueryDialog.h>
#include <aknPopup.h>


// CONSTANTS

// UIDs for dialogs

// ID of MsChapv2 username & password dialog
const TUid KUidMsChapv2Dialog   = { 0x101f8e69 };  

// Channel used for screen 
const TUid KScreenOutputChannel = { 0x00000123 };  

// Number of dialogs in this plugin
const TInt KPluginGranularity   = 1;

// ROM folder
_LIT( KDriveZ, "z:" );

// RSC file name.
_LIT( KResourceFileName, "MsChapv2NotifDlgUi.rsc" );


// GLOBAL FUNCTIONS

/**
* Array of connection dialog plugins.
* @return A CArray of MEikSrvNotifierBase2 based classes.
*/
IMPORT_C CArrayPtr< MEikSrvNotifierBase2 >* NotifierArray();


// CLASS DECLARATION

struct TEapMsChapv2UsernamePasswordInfo
    {
    TBool iIsIdentityQuery;
    TBool iPasswordPromptEnabled;
    TBuf16<256> iUsername;
    TBuf16<256> iPassword;
    TBuf16<256> iOldPassword;
    };

class CMsChapv2Dialog;

/**
 * MsChapv2 dialog plugin class
 */
class CMsChapv2DialogPlugin : public CBase,
                              public MEikSrvNotifierBase2
    {
    public:
        static CMsChapv2DialogPlugin* NewL();

        ~CMsChapv2DialogPlugin();

        TNotifierInfo RegisterL();
        TNotifierInfo Info() const;

        TPtrC8 StartL( const TDesC8& aBuffer );
        void StartL( const TDesC8& aBuffer, TInt aReplySlot,
                     const RMessagePtr2& aMessage );

        TPtrC8 UpdateL( const TDesC8& aBuffer );
        void Cancel();
        void CompleteL( TInt aStatus );
        void Release();

        inline TDes& GetUsername();
        inline TDes& GetPassword();
        inline void SetOldPassword( const TDesC& aOldPwd );

    protected:
        CMsChapv2DialogPlugin();

        void ConstructL();

    protected:
        TNotifierInfo iInfo;        // Notifier info
        RMessagePtr2 iMessage;      // Message
        TInt iReplySlot;            // Reply slot
        TBool iCancelled;           // ETrue if dialog cancelled

    private:
		CMsChapv2Dialog* iMSCHAPV2Dialog;
        TEapMsChapv2UsernamePasswordInfo* iDataPtr;
        TPckg<TEapMsChapv2UsernamePasswordInfo>* iDataPckgPtr;
        TInt iResource;             // Resource
    };

// Include inline functions
#include "MsChapv2NotifDlgPlugin.inl"


#endif  // __MSCHAPV2NOTIFDLGPLUGIN_H__

// End of File
