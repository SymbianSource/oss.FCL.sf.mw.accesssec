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
* Description: Header file of EAP SIM settings UI
*
*/

/*
* %version: 11 %
*/

#ifndef _EAPSIMUI_H_
#define _EAPSIMUI_H_

// INCLUDES
#include <EapSimUiConnection.h>
#include <coecntrl.h>


// CLASS DECLARATION

/**
*  Main UI class definition
*/
class CEapSimUi : public CCoeControl
    {
    public: 
        ~CEapSimUi();
        static CEapSimUi* NewL( CEapSimUiConnection* aConnection );    
        TInt InvokeUiL();

    protected:
        CEapSimUi( CEapSimUiConnection* aConnection );
        void ConstructL();        

    private:
        CEapSimUiConnection* iConnection;
    };


#endif  // _EAPSIMUI_H_

//  End of File
