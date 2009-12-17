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
* Description: Declaration of authentication query dialog class of PapNotifDialog.
*
*/



#ifndef __PAPAUTHDIALOG_H__
#define __PAPAUTHDIALOG_H__

// INCLUDES
#include <eikdialg.h>
#include <badesca.h>
#include <e32cons.h>
#include <AknForm.h>
#include <AknQueryDialog.h>
#include "papnotifdlgplugin.h"


// CLASS DECLARATION

/**
*/
class CPapAuthDialog : public CAknMultiLineDataQueryDialog
    {
    protected:
        CPapAuthDialog( CPapNotifDialogPlugin* aPlugin );
        void ConstructL();

    public:
        static CPapAuthDialog* NewL( TDes& aUsername, TDes& aPassword, 
                                      CPapNotifDialogPlugin* aPlugin );
        ~CPapAuthDialog();

    private:
        virtual TBool OkToExitL( TInt aButtonId );
        void HandleResourceChange( TInt aType );
        
    private:
        CPapNotifDialogPlugin* iPlugin;     // Pointer to the notifier plugin

    };

#endif  // __PAPAUTHDIALOG_H__

// End of File
