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
* Description: Header file of EAP AKA UI settings array
*
*/

/*
* %version: 12 %
*/

#ifndef _EAPAKAUISETTINGARRAY_H_
#define _EAPAKAUISETTINGARRAY_H_

// INCLUDES
#include <aknsettingitemlist.h>
#include "EapAkaUi.hrh"


// CLASS DECLARATION

/**
*/
class CEapAkaSettingItemArray : public CBase
    {
    public:
        static CEapAkaSettingItemArray* NewL();

        virtual ~CEapAkaSettingItemArray();

        CAknSettingItem* Item(TEapAkaUiSettingPageIds aItem);

        CAknSettingItemArray* Array();

        void StoreSettingsL();

        void AddTextItemL( TDes& aBuffer,
                            TInt aId, 
                            TInt aTitleResource, 
                            TInt aSettingPageResource, 
                            TInt aAssociatedResource, 
                            TInt aOrdinal);

        void AddBinarySettingItemL( TInt aSettingPageResourceId,
                                    TInt aTitleResourceId,
                                    TInt aAssociatedResourceId,
                                    TInt aOrdinal,
                                    TBool& aModifiedValue);

    protected:
        CEapAkaSettingItemArray();
        void ConstructL();

    private:
        CAknSettingItemArray* iArray;
    };

#endif  // _EAPAKAUISETTINGARRAY_H_

//  End of File