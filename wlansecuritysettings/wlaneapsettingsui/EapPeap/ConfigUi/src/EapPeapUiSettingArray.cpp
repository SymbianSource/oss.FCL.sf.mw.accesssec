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
* Description: Implementation of EAP PEAP UI settings array
*
*/



// INCLUDE FILES
#include "EapPeapUiSettingArray.h"
#include "EapPeapUi.hrh"
#include <aknsettingitemlist.h>
#include <akntextsettingpage.h>


// ============================ MEMBER FUNCTIONS ===============================

// -----------------------------------------------------------------------------
// CEapPeapSettingItemArray::CEapPeapSettingItemArray
// -----------------------------------------------------------------------------
//
CEapPeapSettingItemArray::CEapPeapSettingItemArray()
    {
    }


// -----------------------------------------------------------------------------
// CEapPeapSettingItemArray::NewL
// -----------------------------------------------------------------------------
//
CEapPeapSettingItemArray* CEapPeapSettingItemArray::NewL() 
    {
    CEapPeapSettingItemArray* self = new( ELeave ) CEapPeapSettingItemArray();
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop( self ); // self
    return self;
    }


// -----------------------------------------------------------------------------
// CEapPeapSettingItemArray::~CEapPeapSettingItemArray
// -----------------------------------------------------------------------------
//
CEapPeapSettingItemArray::~CEapPeapSettingItemArray()
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
// CEapPeapSettingItemArray::Item
// -----------------------------------------------------------------------------
//
CAknSettingItem* CEapPeapSettingItemArray::Item( TEapPeapUiSettingPageIds aId )
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
// CEapPeapSettingItemArray::Array
// -----------------------------------------------------------------------------
//
CAknSettingItemArray* CEapPeapSettingItemArray::Array() 
    {
    return iArray;
    }


// -----------------------------------------------------------------------------
// CEapPeapSettingItemArray::StoreSettingsL
// -----------------------------------------------------------------------------
//
void CEapPeapSettingItemArray::StoreSettingsL()
    {
    // Do what SettingItemList::StoreSettings would do. 
    for( TInt i( 0 ); i < iArray->Count(); ++i ) 
        {
        iArray->At( i )->StoreL();
        }
    }


// -----------------------------------------------------------------------------
// CEapPeapSettingItemArray::ConstructL
// -----------------------------------------------------------------------------
//
void CEapPeapSettingItemArray::ConstructL() 
    {
    iArray = new( ELeave ) CAknSettingItemArray( 2, EFalse, 0 );
    }


// -----------------------------------------------------------------------------
// CEapPeapSettingItemArray::AddTextItemL
// -----------------------------------------------------------------------------
//
void CEapPeapSettingItemArray::AddTextItemL( TDes& aBuffer, 
                                             TInt aId, 
                                             TInt aTitleResource, 
                                             TInt aSettingPageResource, 
                                             TInt aAssociatedResource, 
                                             TInt aOrdinal)
    {
    // Create new setting item
    CAknTextSettingItem* settingItem = 
                            new( ELeave ) CAknTextSettingItem( aId, aBuffer );
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


// -----------------------------------------------------------------------------
// CEapPeapSettingItemArray::AddBinarySettingItemL
// -----------------------------------------------------------------------------
//
void CEapPeapSettingItemArray::AddBinarySettingItemL( 
                                                TInt aSettingPageResourceId,
                                                TInt aTitleResourceId, 
                                                TInt aAssociatedResourceId,
                                                TInt aOrdinal, 
                                                TBool& aModifiedValue )
    {
    CAknSettingItem* settingItem = new ( ELeave ) 
    CAknBinaryPopupSettingItem( 0, aModifiedValue );
    CleanupStack::PushL( settingItem );

    HBufC* itemTitle = CEikonEnv::Static()->AllocReadResourceLC( 
                                                            aTitleResourceId );
    settingItem->ConstructL( EFalse, aOrdinal, *itemTitle, NULL, 
                             aSettingPageResourceId, EAknCtPopupSettingList, 
                             NULL, aAssociatedResourceId );
    iArray->AppendL( settingItem );

    CleanupStack::PopAndDestroy( itemTitle );
    CleanupStack::Pop( settingItem );
    }


//  End of File
