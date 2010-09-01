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
* Description: Header file of EAP PEAP settings UI
*
*/

/*
* %version: 11 %
*/

#ifndef _EAPPEAPUI_H_
#define _EAPPEAPUI_H_

// INCLUDES
#include "EapTlsPeapUiConnection.h"
#include <coecntrl.h>


// CLASS DECLARATION

/**
*  Main UI class definition
*/
class CEapPeapUi : public CCoeControl
    {
    public: 
        ~CEapPeapUi();
        static CEapPeapUi* NewL( CEapTlsPeapUiConnection* aConnection, 
                                 TIndexType aIndexType, 
                                 TInt aIndex );
        TInt InvokeUiL();

    protected:
        CEapPeapUi( CEapTlsPeapUiConnection* aConnection, 
                    TIndexType aIndexType, 
                    TInt aIndex );
        void ConstructL();        

    private:
        CEapTlsPeapUiConnection* iConnection;
        TIndexType iIndexType; 
        TInt iIndex;        
    };


#endif // _EAPPEAPUI_H_

//  End of File
