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
* Description: Declaration of Gtc Response Query Dialog
*
*/

/*
* %version: tr1cfwln#11 %
*/

#ifndef __GTCRESPONSEQUERYDIALOG_H__
#define __GTCRESPONSEQUERYDIALOG_H__

// INCLUDES
#include <AknQueryDialog.h>


class CGTCResponseQueryDialog : public CAknTextQueryDialog
    {
    public:
        static CGTCResponseQueryDialog* NewL( TDes& aResponse, 
                                              CGtcDialogPlugin* aPlugin );
        ~CGTCResponseQueryDialog();
  
    private:
        CGTCResponseQueryDialog( TDes& aResponse, CGtcDialogPlugin* aPlugin );

        virtual TBool OkToExitL( TInt aButtonId );
        void HandleResourceChange( TInt aType );
        
    private:
        CGtcDialogPlugin* iPlugin;     // Pointer to the notifier plugin
    };


#endif  // __GTCMESSAGEDISPLAYDIALOG_H__

// End of File
