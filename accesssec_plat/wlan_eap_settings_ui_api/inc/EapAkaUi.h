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
* Description: Header file of EAP AKA settings UI
*
*/

/*
* %version: 11 %
*/

#ifndef _EAPAKAUI_H_
#define _EAPAKAUI_H_

// INCLUDES
#include <EapAkaUiConnection.h> 
#include <coecntrl.h>


// CLASS DECLARATION

/**
*  Main UI class definition
*/
class CEapAkaUi : public CCoeControl
    {
    public: 
        /**
        * Destructor.
        */
        ~CEapAkaUi();

        /**
        * Two-phased constructor.
        */
        static CEapAkaUi* NewL( CEapAkaUiConnection* aConnection );

        TInt InvokeUiL();

    protected:
        CEapAkaUi( CEapAkaUiConnection* aConnection );

        void ConstructL();

    private:
        CEapAkaUiConnection* iConnection;
    };


#endif // _EAPAKAUI_H_

//  End of File

