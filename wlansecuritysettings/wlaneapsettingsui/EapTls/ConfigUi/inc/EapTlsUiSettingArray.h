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
* Description: Header file of EAP TLS UI settings array
*
*/

/*
* %version: 11 %
*/

#ifndef _EAPTLSUISETTINGARRAY_H_
#define _EAPTLSUISETTINGARRAY_H_

// INCLUDES
#include <aknsettingitemlist.h>
#include "EapTlsUi.hrh"


// CLASS DECLARATION

/**
*/
class CEapTlsSettingItemArray : public CBase
    {
    public:
        static CEapTlsSettingItemArray* NewL();
        virtual ~CEapTlsSettingItemArray();
        CAknSettingItem* Item( TEapTlsUiSettingPageIds aItem );
        CAknSettingItemArray* Array();
        void StoreSettingsL();
        void AddTextItemL( TDes& aBuffer, TInt aId, TInt aTitleResource, 
                           TInt aSettingPageResource, TInt aAssociatedResource,
                           TInt aOrdinal);

        void AddBinarySettingItemL( TInt aSettingPageResourceId,
                                    TInt aTitleResourceId,
                                    TInt aAssociatedResourceId,
                                    TInt aOrdinal,
                                    TBool& aModifiedValue);

    protected:
        CEapTlsSettingItemArray();
        void ConstructL();

    private:
        CAknSettingItemArray* iArray;
    };

#endif  // _EAPTLSUISETTINGARRAY_H_

//  End of File
