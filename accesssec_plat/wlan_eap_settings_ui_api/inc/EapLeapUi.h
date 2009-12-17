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
* Description: Header file of EAP LEAP UI
*
*/



#ifndef _EAPLEAPUI_H_
#define _EAPLEAPUI_H_

// INCLUDES
#include <EapLeapUiConnection.h>
#include <coecntrl.h>


// CLASS DECLARATION

/**
*  Main UI class definition
*/
class CEapLeapUi : public CCoeControl
    {
    public: 
        ~CEapLeapUi();
        static CEapLeapUi* NewL( CEapLeapUiConnection* aConnection );    
        TInt InvokeUiL();

    protected:
        CEapLeapUi( CEapLeapUiConnection* aConnection );
        void ConstructL();        

    private:
        CEapLeapUiConnection* iConnection;
    };


#endif //_EAPLEAPUI_H_

//  End of File
