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
* Description: Header file of EAP GTC settings UI
*
*/

/*
* %version: 11 %
*/

#ifndef _EAPGTCUI_H_
#define _EAPGTCUI_H_

// INCLUDES
#include <EapGtcUiConnection.h>
#include <coecntrl.h>


// CLASS DECLARATION

/**
*  Main UI class definition
*/
class CEapGtcUi : public CCoeControl
    {
    public: 
        /**
        * Destructor.
        */
        ~CEapGtcUi();

        /**
        * Two-phased constructor.
        */
        static CEapGtcUi* NewL( CEapGtcUiConnection* aConnection );

        TInt InvokeUiL();

    protected:
        /**
        * C++ default constructor.
        */
        CEapGtcUi( CEapGtcUiConnection* aConnection );

        void ConstructL();

    private:
        CEapGtcUiConnection* iConnection;
    };


#endif // _EAPGTCUI_H_

//  End of File