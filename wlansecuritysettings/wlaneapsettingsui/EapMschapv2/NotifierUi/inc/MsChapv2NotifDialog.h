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
* Description: Declaration of dialog class of MsChapv2NotifDialog.
*
*/

/*
* %version: 15 %
*/

#ifndef __MSCHAPV2DIALOG_H__
#define __MSCHAPV2DIALOG_H__

// INCLUDES
#include <eikdialg.h>
#include <badesca.h>
#include <e32cons.h>
#include <AknForm.h>
#include <AknQueryDialog.h>
#include "MsChapv2NotifDlgPlugin.h"


// CLASS DECLARATION

/**
*/
class CMsChapv2Dialog : public CAknMultiLineDataQueryDialog
    {
    protected:
        CMsChapv2Dialog( CMsChapv2DialogPlugin* aPlugin, 
                         TBool aUsernameExists );
        void ConstructL();

    public:
        static CMsChapv2Dialog* NewL( TDes& aUsername, TDes& aPassword, 
                                      CMsChapv2DialogPlugin*  aPlugin );
        ~CMsChapv2Dialog();

    private:
        virtual TBool OkToExitL( TInt aButtonId );
        void HandleResourceChange( TInt aType );
        
    private:
        CMsChapv2DialogPlugin* iPlugin;     // Pointer to the notifier plugin
        TBool iUsernameExists;
    };

#endif  // __MSCHAPV2DIALOG_H__

// End of File
