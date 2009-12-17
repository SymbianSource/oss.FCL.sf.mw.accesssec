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
* Description: Header file of EAP TTLS settings UI
*
*/



#ifndef _EAPTTLSUI_H_
#define _EAPTTLSUI_H_

// INCLUDES
#include "EapTlsPeapUiConnection.h"
#include <coecntrl.h>


// CLASS DECLARATION

/**
*/
class CEapTtlsUi : public CCoeControl
    {
    public: 
        ~CEapTtlsUi();
        static CEapTtlsUi* NewL( CEapTlsPeapUiConnection* aConnection, 
                                 TIndexType aIndexType, 
                                 TInt aIndex );
        TInt InvokeUiL();

    protected:
        CEapTtlsUi( CEapTlsPeapUiConnection* aConnection, 
                    TIndexType aIndexType, 
                    TInt aIndex );
        void ConstructL();        

    private:
        CEapTlsPeapUiConnection* iConnection;
        TIndexType iIndexType; 
        TInt iIndex;
    };


#endif // _EAPTTLSUI_H_

//  End of File
