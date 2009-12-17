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
* Description: Header file of PAP Config UI
*
*/



#ifndef _PAPUI_H_
#define _PAPUI_H_

// INCLUDES
#include <EapTlsPeapUiConnection.h>
#include <coecntrl.h>


// CLASS DECLARATION

/**
*  Main UI class definition
*/
class CPapUi : public CCoeControl
    {
    public: 
        ~CPapUi();
        static CPapUi* NewL( CEapTlsPeapUiConnection* aConnection );
        TInt InvokeUiL();

    protected:
        CPapUi( CEapTlsPeapUiConnection* aConnection );
        void ConstructL();        

    private:
        CEapTlsPeapUiConnection* iConnection;
    };


#endif // _PAPUI_H_

//  End of File
