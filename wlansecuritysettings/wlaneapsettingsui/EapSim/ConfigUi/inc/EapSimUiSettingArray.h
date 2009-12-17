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
* Description: Header file of EAP SIM UI settings array
*
*/



#ifndef _EAPSIMUISETTINGARRAY_H_
#define _EAPSIMUISETTINGARRAY_H_

// INCLUDES
#include <aknsettingitemlist.h>
#include "EapSimUi.hrh"


// CLASS DECLARATION

/**
*/
class CEapSimSettingItemArray : public CBase
    {
    public:
        static CEapSimSettingItemArray* NewL();
        virtual ~CEapSimSettingItemArray();
        CAknSettingItem* Item( TEapSimUiSettingPageIds aItem );
        CAknSettingItemArray* Array();
        void StoreSettingsL();
        void AddTextItemL( TDes& aBuffer, TInt aId, TInt aTitleResource,
                           TInt aSettingPageResource, TInt aAssociatedResource,
                           TInt aOrdinal );

        void AddPasswordItemL( TDes& aPassword, TInt aId, TInt aTitleResource,
                               TInt aSettingPageResource, 
                               TInt aAssociatedResource, TInt aOrdinal );

        void AddBinarySettingItemL( TInt aSettingPageResourceId, 
                                    TInt aTitleResourceId,
                                    TInt aAssociatedResourceId,
                                    TInt aOrdinal,
                                    TBool& aModifiedValue );

    protected:
        CEapSimSettingItemArray();
        void ConstructL();

    private:
        CAknSettingItemArray* iArray;
    };

#endif  // _EAPSIMUISETTINGARRAY_H_

//  End of File
