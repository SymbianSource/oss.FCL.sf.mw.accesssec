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
* Description: Header file of EAP TLS settings UI
*
*/

/*
* %version: 11 %
*/

#ifndef _EAPTLSUI_H_
#define _EAPTLSUI_H_

// INCLUDES
#include <coecntrl.h>
#include "EapTlsPeapUiConnection.h"


// CLASS DECLARATION

/**
*  Main UI class definition
*/
class CEapTlsUi : public CCoeControl
    {
    public: 
        ~CEapTlsUi();
        static CEapTlsUi* NewL( CEapTlsPeapUiConnection* aConnection );    
        TInt InvokeUiL();

    protected:
        CEapTlsUi( CEapTlsPeapUiConnection* aConnection );
        void ConstructL();        

    private:
        CEapTlsPeapUiConnection* iConnection;
    };


#endif //_EAPTLSUI_H_

//  End of File
