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
* Description: Implementation of EAP MsChapv2 UI settings array
*
*/



// INCLUDE FILES
#include "EapMschapv2UiSettingArray.h"
#include "EapMschapv2Ui.hrh"
#include <aknsettingitemlist.h>
#include <akntextsettingpage.h>

// CONSTANTS

// String representing an empty password field on the UI
_LIT( KEmptyPassword, "****" );


// ============================ MEMBER FUNCTIONS ===============================

// -----------------------------------------------------------------------------
// CEapMsChapV2SettingItemArray::CEapMsChapV2SettingItemArray
// -----------------------------------------------------------------------------
//
CEapMsChapV2SettingItemArray::CEapMsChapV2SettingItemArray()
    {
    }


// -----------------------------------------------------------------------------
// CEapMsChapV2SettingItemArray::NewL
// -----------------------------------------------------------------------------
//
CEapMsChapV2SettingItemArray* CEapMsChapV2SettingItemArray::NewL() 
    {
    CEapMsChapV2SettingItemArray* self = 
                                new( ELeave ) CEapMsChapV2SettingItemArray();
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop( self ); 
    return self;
    }


// -----------------------------------------------------------------------------
// CEapMsChapV2SettingItemArray::ConstructL
// -----------------------------------------------------------------------------
//
void CEapMsChapV2SettingItemArray::ConstructL() 
    {
    iArray = new( ELeave ) CAknSettingItemArray( 2, EFalse, 0 );
    }


// -----------------------------------------------------------------------------
// CEapMsChapV2SettingItemArray::~CEapMsChapV2SettingItemArray
// -----------------------------------------------------------------------------
//
CEapMsChapV2SettingItemArray::~CEapMsChapV2SettingItemArray()
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
// CEapMsChapV2SettingItemArray::Item
// -----------------------------------------------------------------------------
//
CAknSettingItem* CEapMsChapV2SettingItemArray::Item( 
                                                TEapMschapv2SettingItemId aId )
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
// CEapMsChapV2SettingItemArray::Array
// -----------------------------------------------------------------------------
//
CAknSettingItemArray* CEapMsChapV2SettingItemArray::Array()
    {
    return iArray;
    }


// -----------------------------------------------------------------------------
// CEapMsChapV2SettingItemArray::StoreSettingsL
// -----------------------------------------------------------------------------
//
void CEapMsChapV2SettingItemArray::StoreSettingsL()
    {
    // Do what SettingItemList::StoreSettings would do. 
    for( TInt i( 0 ); i < iArray->Count(); ++i )
        {
        iArray->At( i )->StoreL();
        }
    }


// -----------------------------------------------------------------------------
// CEapMsChapV2SettingItemArray::AddTextItemL
// -----------------------------------------------------------------------------
//
void CEapMsChapV2SettingItemArray::AddTextItemL( TDes& aBuffer, 
                                                 TInt aId, 
                                                 TInt aTitleResource, 
                                                 TInt aSettingPageResource,
                                                 TInt aAssociatedResource, 
                                                 TInt aOrdinal)
    {
    // Create new setting item
    CAknSettingItem* settingItem = 
                            new( ELeave ) CAknTextSettingItem( aId,  aBuffer );
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
// CEapMsChapV2SettingItemArray::AddPasswordItemL
// -----------------------------------------------------------------------------
//
void CEapMsChapV2SettingItemArray::AddPasswordItemL( TDes& aPassword, 
                                                     TInt aId, 
                                                     TInt aTitleResource, 
                                                     TInt aSettingPageResource,
                                                     TInt aAssociatedResource, 
                                                     TInt aOrdinal)
    {
    // Create new setting item
    CAknSettingItem* settingItem = new ( ELeave ) CAknPasswordSettingItem( aId,
                                            CAknPasswordSettingItem::EAlpha,
                                            aPassword );
    CleanupStack::PushL( settingItem );
    settingItem->SetEmptyItemTextL( KEmptyPassword );
    
    // Construct setting item with parametrized values
    HBufC* itemTitle = CEikonEnv::Static()->AllocReadResourceLC( 
                                                            aTitleResource );
   
    settingItem->ConstructL( EFalse, aOrdinal, *itemTitle, NULL, 
                             aSettingPageResource, EAknCtPopupSettingList, 
                             NULL, aAssociatedResource );
    
    // Append item to settingitem-array
    iArray->InsertL( aOrdinal, settingItem );
    
    CleanupStack::PopAndDestroy( itemTitle );
    CleanupStack::Pop( settingItem );
    }     


// -----------------------------------------------------------------------------
// CEapMsChapV2SettingItemArray::AddBinarySettingItemL
// -----------------------------------------------------------------------------
//
void CEapMsChapV2SettingItemArray::AddBinarySettingItemL( 
                                                TInt aSettingPageResourceId,
                                                TInt aTitleResourceId, 
                                                TInt aAssociatedResourceId,
                                                TInt aOrdinal, 
                                                TBool& aModifiedValue )
    {
    CAknSettingItem* settingItem = 
                new( ELeave ) CAknBinaryPopupSettingItem( 0, aModifiedValue );
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
