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
* Description: Declaration of PAP Challenge Message Display Dialog
*
*/



#ifndef __PAPCHALLENGEMSGDIALOG_H__
#define __PAPCHALLENGEMSGDIALOG_H__

// INCLUDES
#include <aknmessagequerydialog.h>


class CPapChallengeMsgDialog : public CAknMessageQueryDialog
    {
    public:
        static CPapChallengeMsgDialog* NewL( const TDesC& aMessage, 
                                               CPapNotifDialogPlugin* aPlugin );
        ~CPapChallengeMsgDialog();
  
    private:
        CPapChallengeMsgDialog( CPapNotifDialogPlugin* aPlugin );

        virtual TBool OkToExitL( TInt aButtonId );
        void HandleResourceChange( TInt aType );
        
    private:
        CPapNotifDialogPlugin* iPlugin;     // Pointer to the notifier plugin
    };

#endif  // __PAPCHALLENGEMSGDIALOG_H__
