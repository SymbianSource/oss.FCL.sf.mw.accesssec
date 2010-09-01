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
* Description: Header file of EAP MsChapv2 UI
*
*/

/*
* %version: 11 %
*/

#ifndef _EAPMSCHAPV2UI_H_
#define _EAPMSCHAPV2UI_H_

// INCLUDES
#include <EapMsChapV2UiConnection.h>
#include <coecntrl.h>


// CLASS DECLARATION

/**
*  Main UI class definition
*/
class CEapMsChapV2Ui : public CCoeControl
    {
    public: 
        ~CEapMsChapV2Ui();
        static CEapMsChapV2Ui* NewL( CEapMsChapV2UiConnection* aConnection );
        TInt InvokeUiL();

    protected:
        CEapMsChapV2Ui( CEapMsChapV2UiConnection* aConnection );
        void ConstructL();        

    private:
        CEapMsChapV2UiConnection* iConnection;
    };


#endif // _EAPMSCHAPV2UI_H_

//  End of File
