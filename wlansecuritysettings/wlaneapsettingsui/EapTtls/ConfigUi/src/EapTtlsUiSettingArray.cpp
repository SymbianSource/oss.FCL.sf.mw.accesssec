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
* Description: Implementation of EAP TTLS UI settings array
*
*/



// INCLUDE FILES
#include "EapTtlsUiSettingArray.h"
#include "EapTtlsUi.hrh"
#include <aknsettingitemlist.h>
#include <akntextsettingpage.h>


// ============================ MEMBER FUNCTIONS ===============================

// -----------------------------------------------------------------------------
// CEapTtlsSettingItemArray::CEapTtlsSettingItemArray
// -----------------------------------------------------------------------------
//
CEapTtlsSettingItemArray::CEapTtlsSettingItemArray()
    {
    }


// -----------------------------------------------------------------------------
// CEapTtlsSettingItemArray::NewL
// -----------------------------------------------------------------------------
//
CEapTtlsSettingItemArray* CEapTtlsSettingItemArray::NewL() 
    {
    CEapTtlsSettingItemArray* self = new( ELeave ) CEapTtlsSettingItemArray();
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop( self ); // self
    return self;
    }


// -----------------------------------------------------------------------------
// CEapTtlsSettingItemArray::ConstructL
// -----------------------------------------------------------------------------
//
void CEapTtlsSettingItemArray::ConstructL() 
    {
    iArray = new( ELeave ) CAknSettingItemArray( 2, EFalse, 0 );
    }


// -----------------------------------------------------------------------------
// CEapTtlsSettingItemArray::~CEapTtlsSettingItemArray
// -----------------------------------------------------------------------------
//
CEapTtlsSettingItemArray::~CEapTtlsSettingItemArray()
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
// CEapTtlsSettingItemArray::Item
// -----------------------------------------------------------------------------
//
CAknSettingItem* CEapTtlsSettingItemArray::Item( TEapTtlsUiSettingPageIds aId )
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
// CEapTtlsSettingItemArray::Array
// -----------------------------------------------------------------------------
//
CAknSettingItemArray* CEapTtlsSettingItemArray::Array() 
    {
    return iArray;
    }


// -----------------------------------------------------------------------------
// CEapTtlsSettingItemArray::StoreSettingsL
// -----------------------------------------------------------------------------
//
void CEapTtlsSettingItemArray::StoreSettingsL()
    {
    // Do what SettingItemList::StoreSettings would do. 
    for( TInt i( 0 ); i < iArray->Count(); ++i ) 
        {
        iArray->At( i )->StoreL();
        }
    }


// -----------------------------------------------------------------------------
// CEapTtlsSettingItemArray::AddTextItemL
// -----------------------------------------------------------------------------
//
void CEapTtlsSettingItemArray::AddTextItemL( TDes& aBuffer, 
                                             TInt aId, 
                                             TInt aTitleResource, 
                                             TInt aSettingPageResource,
                                             TInt aAssociatedResource, 
                                             TInt aOrdinal )
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


// -----------------------------------------------------------------------------
// CEapTtlsSettingItemArray::AddBinarySettingItemL
// -----------------------------------------------------------------------------
//
void CEapTtlsSettingItemArray::AddBinarySettingItemL( 
                                                 TInt aSettingPageResourceId,
                                                 TInt aTitleResourceId, 
                                                 TInt aAssociatedResourceId,
                                                 TInt aOrdinal, 
                                                 TBool& aModifiedValue )
    {
    CAknSettingItem* settingItem = new( ELeave ) 
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
