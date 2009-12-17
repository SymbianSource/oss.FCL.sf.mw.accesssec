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
* Description: Implementation of EAP SIM UI settings array
*
*/



// INCLUDE FILES
#include "EapSimUiSettingArray.h"

#include "EapSimUi.hrh"

#include <aknsettingitemlist.h>
#include <akntextsettingpage.h>



// ============================ MEMBER FUNCTIONS ===============================

// -----------------------------------------------------------------------------
// CEapSimSettingItemArray::CEapSimSettingItemArray
// -----------------------------------------------------------------------------
//
CEapSimSettingItemArray::CEapSimSettingItemArray()
    {
    }


// -----------------------------------------------------------------------------
// CEapSimSettingItemArray::NewL
// -----------------------------------------------------------------------------
//
CEapSimSettingItemArray* CEapSimSettingItemArray::NewL() 
    {
    CEapSimSettingItemArray* self = new ( ELeave ) CEapSimSettingItemArray();
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop( self ); 
    return self;
    }


// -----------------------------------------------------------------------------
// CEapSimSettingItemArray::ConstructL
// -----------------------------------------------------------------------------
//
void CEapSimSettingItemArray::ConstructL() 
    {
    iArray = new ( ELeave ) CAknSettingItemArray( 2, EFalse, 0 );
    }


// -----------------------------------------------------------------------------
// CEapSimSettingItemArray::~CEapSimSettingItemArray
// -----------------------------------------------------------------------------
//
CEapSimSettingItemArray::~CEapSimSettingItemArray()
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
// CEapSimSettingItemArray::Item
// -----------------------------------------------------------------------------
//
CAknSettingItem* CEapSimSettingItemArray::Item( TEapSimUiSettingPageIds aId )
    {
    for( TInt i = 0; i < iArray->Count(); i++)
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
// CEapSimSettingItemArray::Array
// -----------------------------------------------------------------------------
//
CAknSettingItemArray* CEapSimSettingItemArray::Array() 
    {
    return iArray;
    }


// -----------------------------------------------------------------------------
// CEapSimSettingItemArray::StoreSettingsL
// -----------------------------------------------------------------------------
//
void CEapSimSettingItemArray::StoreSettingsL()
    {
    // Do what SettingItemList::StoreSettings would do. 
    for( TInt i( 0 ); i < iArray->Count(); ++i) 
        {
        iArray->At( i )->StoreL();
        }
    }


// -----------------------------------------------------------------------------
// CEapSimSettingItemArray::AddTextItemL
// -----------------------------------------------------------------------------
//
void CEapSimSettingItemArray::AddTextItemL( TDes& aBuffer, 
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
// CEapSimSettingItemArray::AddBinarySettingItemL
// -----------------------------------------------------------------------------
//
void CEapSimSettingItemArray::AddBinarySettingItemL( 
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
