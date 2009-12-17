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
* Description: Implementation of EAP AKA UI settings array
*
*/



// INCLUDE FILES
#include "EapAkaUiSettingArray.h"
#include "EapAkaUi.hrh"
#include <aknsettingitemlist.h>
#include <akntextsettingpage.h>


// ============================ MEMBER FUNCTIONS ===============================

// -----------------------------------------------------------------------------
// CEapAkaSettingItemArray::CEapAkaSettingItemArray
// -----------------------------------------------------------------------------
//
CEapAkaSettingItemArray::CEapAkaSettingItemArray()
    {
    }


// -----------------------------------------------------------------------------
// CEapAkaSettingItemArray::NewL
// -----------------------------------------------------------------------------
//
CEapAkaSettingItemArray* CEapAkaSettingItemArray::NewL() 
    {
    CEapAkaSettingItemArray* self = new( ELeave ) CEapAkaSettingItemArray();
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop( self ); 
    return self;
    }


// -----------------------------------------------------------------------------
// CEapAkaSettingItemArray::~CEapAkaSettingItemArray
// -----------------------------------------------------------------------------
//
CEapAkaSettingItemArray::~CEapAkaSettingItemArray()
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
// CEapAkaSettingItemArray::Item
// -----------------------------------------------------------------------------
//
CAknSettingItem* CEapAkaSettingItemArray::Item( TEapAkaUiSettingPageIds aId )
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
// CEapAkaSettingItemArray::Array
// -----------------------------------------------------------------------------
//
CAknSettingItemArray* CEapAkaSettingItemArray::Array() 
    {
    return iArray;
    }


// -----------------------------------------------------------------------------
// CEapAkaSettingItemArray::StoreSettingsL
// -----------------------------------------------------------------------------
//
void CEapAkaSettingItemArray::StoreSettingsL()
    {
    // Do what SettingItemList::StoreSettings would do. 
    for( TInt i( 0 ); i < iArray->Count(); ++i ) 
        {
        iArray->At( i )->StoreL();
        }
    }


// -----------------------------------------------------------------------------
// CEapAkaSettingItemArray::ConstructL
// -----------------------------------------------------------------------------
//
void CEapAkaSettingItemArray::ConstructL() 
    {
    iArray = new( ELeave ) CAknSettingItemArray( 2, EFalse, 0 );
    }


// -----------------------------------------------------------------------------
// CEapAkaSettingItemArray::AddTextItemL
// -----------------------------------------------------------------------------
//
void CEapAkaSettingItemArray::AddTextItemL( TDes& aBuffer, 
                                          TInt aId, 
                                          TInt aTitleResource, 
                                          TInt aSettingPageResource, 
                                          TInt aAssociatedResource, 
                                          TInt aOrdinal )
    {
    // Create new setting item
    CAknTextSettingItem* settingItem = new( ELeave ) CAknTextSettingItem( aId,
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


// -----------------------------------------------------------------------------
// CEapAkaSettingItemArray::AddBinarySettingItemL
// -----------------------------------------------------------------------------
//
void CEapAkaSettingItemArray::AddBinarySettingItemL( 
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
