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
* Description: Header file of PAP UI settings array
*
*/



#ifndef _PAPUISETTINGARRAY_H_
#define _PAPUISETTINGARRAY_H_

// INCLUDES
#include <aknsettingitemlist.h>
#include "papui.hrh"


// CLASS DECLARATION

/**
*/
class CPapSettingItemArray : public CBase
    {
    public:
        static CPapSettingItemArray* NewL();
        virtual ~CPapSettingItemArray();
        CAknSettingItem* Item( TPapSettingItemId aItem );
        CAknSettingItemArray* Array();
        void StoreSettingsL();
        void AddTextItemL( TDes& aBuffer, 
                           TInt aId, 
                           TInt aTitleResource, 
                           TInt aSettingPageResource, 
                           TInt aAssociatedResource, 
                           TInt aOrdinal );
        void AddBinarySettingItemL( TInt aSettingPageResourceId,
                                    TInt aTitleResourceId,
                                    TInt aAssociatedResourceId,
                                    TInt aOrdinal,
                                    TBool& aModifiedValue );
        void AddPasswordItemL( TDes& aPassword, 
                               TInt aId, 
                               TInt aTitleResource, 
                               TInt aSettingPageResource, 
                               TInt aAssociatedResource, 
                               TInt aOrdinal );
        void PwItemCancelled( TBool aIsCancelled );                       
        TBool IsPwItemCancelled();
                                    

    protected:
        CPapSettingItemArray();
        void ConstructL();
 

    private:
        CEikonEnv* iEnv;
        CAknSettingItemArray* iArray;
        TBool iPwItemCancelled;
    };

#endif  // _PAPUISETTINGARRAY_H_

//  End of File
