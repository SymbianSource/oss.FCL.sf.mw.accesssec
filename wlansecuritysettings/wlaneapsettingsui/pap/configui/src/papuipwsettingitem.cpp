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
* Description: Implementation of PAP UI password setting item
*
*/

/*
* %version: 5 %
*/

// INCLUDE FILES
#include "papuipwsettingitem.h"
#include "papuisettingarray.h"
#include <aknsettingitemlist.h>


// ============================ MEMBER FUNCTIONS ===============================

// -----------------------------------------------------------------------------
// CPapUiPwSettingItem::CPapUiPwSettingItem
// -----------------------------------------------------------------------------
//
CPapUiPwSettingItem::CPapUiPwSettingItem( TInt aIdentifier,
            enum TAknPasswordSettingItemMode aMode,
            TDes &aPassword,
            CPapSettingItemArray* aParent )
    : CAknPasswordSettingItem( aIdentifier, aMode, aPassword ),
      iParent ( aParent )
    {    
    }

 

// -----------------------------------------------------------------------------
// CPapUiPwSettingItem::~CPapUiPwSettingItem
// -----------------------------------------------------------------------------
//
CPapUiPwSettingItem::~CPapUiPwSettingItem()
    {
    }


// ---------------------------------------------------------
// CPapUiPwSettingItem::HandleSettingPageEventL
// ---------------------------------------------------------
//
void CPapUiPwSettingItem::HandleSettingPageEventL(
    CAknSettingPage * /*aSettingPage*/, TAknSettingPageEvent aEventType )
    {
    #if defined(_DEBUG) || defined(DEBUG)
    RDebug::Print(_L("CPapUiPwSettingItem::HandleSettingPageEventL, event = %d"),
        aEventType );
    #endif

    switch ( aEventType )
        {
        case EEventSettingCancelled:
            {
            iParent->PwItemCancelled( ETrue );
            break;
            }
        
        case EEventSettingChanged:             
        case EEventSettingOked:
            {
            iParent->PwItemCancelled( EFalse );            
            break;
            }

        default:
            {
            break;
            };
        };
    }
    
// ---------------------------------------------------------
// CPapUiPwSettingItem::DeletePasswordL
// ---------------------------------------------------------
//
void CPapUiPwSettingItem::DeletePasswordL()
    {
    TPtr ptr = InternalTextPtr();
    ptr.Copy( KNullDesC );
    StoreL();
    }

//  End of File
