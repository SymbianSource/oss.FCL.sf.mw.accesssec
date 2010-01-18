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
* Description: Implementation of EAP GTC UI settings array
*
*/

/*
* %version: 11 %
*/

// INCLUDE FILES
#include "EapGtcUiSettingArray.h"
#include "EapGtcUi.hrh"
#include <aknsettingitemlist.h>
#include <akntextsettingpage.h>


// ============================ MEMBER FUNCTIONS ===============================

// -----------------------------------------------------------------------------
// CEapGtcSettingItemArray::CEapGtcSettingItemArray
// -----------------------------------------------------------------------------
//
CEapGtcSettingItemArray::CEapGtcSettingItemArray()
    {
    }


// -----------------------------------------------------------------------------
// CEapGtcSettingItemArray::NewL
// -----------------------------------------------------------------------------
//
CEapGtcSettingItemArray* CEapGtcSettingItemArray::NewL() 
    {
    CEapGtcSettingItemArray* self = new (ELeave) CEapGtcSettingItemArray();
    CleanupStack::PushL(self);
    self->ConstructL();
    CleanupStack::Pop( self ); 
    return self;
    }


// -----------------------------------------------------------------------------
// CEapGtcSettingItemArray::~CEapGtcSettingItemArray
// -----------------------------------------------------------------------------
//
CEapGtcSettingItemArray::~CEapGtcSettingItemArray()
    {
    if( iArray ) 
        {
        // ResetAndDestroy()
        iArray->ResetAndDestroy();
        }    
    delete iArray;   
    iArray = NULL;
    }


// -----------------------------------------------------------------------------
// CEapGtcSettingItemArray::Item
// -----------------------------------------------------------------------------
//
CAknSettingItem* CEapGtcSettingItemArray::Item( TEapGtcUiSettingPageIds aId )
    {
    for( TInt i = 0; i < iArray->Count(); i++ )
        {
        if( iArray->At( i )->Identifier() == aId )
            {
            return iArray->At( i );
            }
        }

    __ASSERT_DEBUG( EFalse, User::Invariant() );
    return NULL;
    }


// -----------------------------------------------------------------------------
// CEapGtcSettingItemArray::Array
// -----------------------------------------------------------------------------
//
CAknSettingItemArray* CEapGtcSettingItemArray::Array() 
    {
    return iArray;
    }


// -----------------------------------------------------------------------------
// CEapGtcSettingItemArray::StoreSettingsL
// -----------------------------------------------------------------------------
//
void CEapGtcSettingItemArray::StoreSettingsL()
    {
    // Do what SettingItemList::StoreSettings would do. 
    for( TInt i(0); i < iArray->Count(); ++i )
        {
        iArray->At(i)->StoreL();
       }
    }


// -----------------------------------------------------------------------------
// CEapGtcSettingItemArray::ConstructL
// -----------------------------------------------------------------------------
//
void CEapGtcSettingItemArray::ConstructL() 
    {
    iArray = new ( ELeave ) CAknSettingItemArray( 2, EFalse, 0 );
    }


// -----------------------------------------------------------------------------
// CEapGtcSettingItemArray::AddTextItemL
// -----------------------------------------------------------------------------
//
void CEapGtcSettingItemArray::AddTextItemL( TDes& aBuffer, 
                                            TInt aId, 
                                            TInt aTitleResource, 
                                            TInt aSettingPageResource,
                                            TInt aAssociatedResource, 
                                            TInt aOrdinal)
    {
    // Create new setting item
    CAknTextSettingItem* settingItem = new ( ELeave ) CAknTextSettingItem( aId,
                                                                    aBuffer );
    CleanupStack::PushL( settingItem );
    settingItem->SetEmptyItemTextL( KNullDesC );
    settingItem->SetSettingPageFlags( 
                                    CAknTextSettingPage::EZeroLengthAllowed );

    // Construct setting item with parametrized values
    HBufC* itemTitle = CEikonEnv::Static()->AllocReadResourceLC( 
                                                            aTitleResource );
    settingItem->ConstructL( EFalse, aOrdinal, *itemTitle, NULL, 
                             aSettingPageResource, EAknCtPopupSettingList,
                             NULL, aAssociatedResource );
    
    // Append item to settingitem-array
    iArray->InsertL( aOrdinal, settingItem );
    
    CleanupStack::PopAndDestroy( itemTitle );

    // Items are destroyed in destructor when resetting array
    CleanupStack::Pop( settingItem ); 
    }


//  End of File
