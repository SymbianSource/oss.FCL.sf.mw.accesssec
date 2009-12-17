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
* Description: Header file of EAP FAST settings UI
*
*/



#ifndef _EAPFASTUI_H_
#define _EAPFASTUI_H_

// INCLUDES
#include "EapTlsPeapUiConnection.h"
#include <coecntrl.h>


// CLASS DECLARATION

/**
*  Main UI class definition
*/
class CEapFastUi : public CCoeControl
    {
    public: 
        ~CEapFastUi();
        static CEapFastUi* NewL( CEapTlsPeapUiConnection* aConnection, 
                                 TIndexType aIndexType, 
                                 TInt aIndex );
        TInt InvokeUiL();

    protected:
        CEapFastUi( CEapTlsPeapUiConnection* aConnection, 
                    TIndexType aIndexType, 
                    TInt aIndex );
        void ConstructL();        

    private:
        CEapTlsPeapUiConnection* iConnection;
        TIndexType iIndexType; 
        TInt iIndex;        
    };


#endif // _EAPFASTUI_H_

//  End of File
