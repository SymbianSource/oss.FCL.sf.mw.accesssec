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
* Description: Header file of EAP GTC UI settings array
*
*/

/*
* %version: 11 %
*/

#ifndef _EAPGTCUISETTINGARRAY_H_
#define _EAPGTCUISETTINGARRAY_H_

// INCLUDES
#include <aknsettingitemlist.h>
#include "EapGtcUi.hrh"


// CLASS DECLARATION

/**
*/
class CEapGtcSettingItemArray : public CBase
    {
    public:
        static CEapGtcSettingItemArray* NewL();

        virtual ~CEapGtcSettingItemArray();

        CAknSettingItem* Item( TEapGtcUiSettingPageIds aItem );

        CAknSettingItemArray* Array();

        void StoreSettingsL();

        void AddTextItemL( TDes& aBuffer, 
                            TInt aId, 
                            TInt aTitleResource, 
                            TInt aSettingPageResource, 
                            TInt aAssociatedResource, 
                            TInt aOrdinal);

    protected:
        CEapGtcSettingItemArray();

        void ConstructL();

    private:
        CAknSettingItemArray* iArray;
    };

#endif  // _EAPGTCUISETTINGARRAY_H_

//  End of File