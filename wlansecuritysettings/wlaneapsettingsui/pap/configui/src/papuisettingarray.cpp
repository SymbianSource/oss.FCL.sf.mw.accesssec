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
* Description: Implementation of PAP UI settings array
*
*/



// INCLUDE FILES
#include "papuisettingarray.h"
#include "papui.hrh"
#include "papuipwsettingitem.h"
#include <papui.rsg>
#include <aknsettingitemlist.h>
#include <akntextsettingpage.h>

// CONSTANTS
_LIT( KEmptyPassword, "****" );


// ============================ MEMBER FUNCTIONS ===============================

// -----------------------------------------------------------------------------
// CPapSettingItemArray::CPapSettingItemArray
// -----------------------------------------------------------------------------
//
CPapSettingItemArray::CPapSettingItemArray()
    {
    iEnv = CEikonEnv::Static();
    }


// -----------------------------------------------------------------------------
// CPapSettingItemArray::NewL
// -----------------------------------------------------------------------------
//
CPapSettingItemArray* CPapSettingItemArray::NewL() 
    {
    CPapSettingItemArray* self = new( ELeave ) CPapSettingItemArray();
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop( self ); // self
    return self;
    }


// -----------------------------------------------------------------------------
// CPapSettingItemArray::ConstructL
// -----------------------------------------------------------------------------
//
void CPapSettingItemArray::ConstructL() 
    {
    iArray = new( ELeave ) CAknSettingItemArray( 2, EFalse, 0 );
    }


// -----------------------------------------------------------------------------
// CPapSettingItemArray::~CPapSettingItemArray
// -----------------------------------------------------------------------------
//
CPapSettingItemArray::~CPapSettingItemArray()
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
// CPapSettingItemArray::Item
// -----------------------------------------------------------------------------
//
CAknSettingItem* CPapSettingItemArray::Item( TPapSettingItemId aId )
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
// CEapFastSettingItemArray::Array
// -----------------------------------------------------------------------------
//
CAknSettingItemArray* CPapSettingItemArray::Array() 
    {
    return iArray;
    }


// -----------------------------------------------------------------------------
// CPapSettingItemArray::StoreSettingsL
// -----------------------------------------------------------------------------
//
void CPapSettingItemArray::StoreSettingsL()
    {
    // Do what SettingItemList::StoreSettings would do. 
    for( TInt i( 0 ); i < iArray->Count(); ++i ) 
        {
        iArray->At( i )->StoreL();
        }
    }


// -----------------------------------------------------------------------------
// CPapSettingItemArray::AddTextItemL
// -----------------------------------------------------------------------------
//
void CPapSettingItemArray::AddTextItemL( TDes& aBuffer, 
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
    
    HBufC* usernameNotDefinedText = iEnv->AllocReadResourceLC(
        R_PAP_USERNAME_NOT_DEFINED );
    settingItem->SetEmptyItemTextL( *usernameNotDefinedText );
    CleanupStack::PopAndDestroy( usernameNotDefinedText );

    settingItem->SetSettingPageFlags(
        CAknTextSettingPage::EZeroLengthNotOffered );

    // Construct setting item with parametrized values
    HBufC* itemTitle = iEnv->AllocReadResourceLC( aTitleResource );
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
// CPapSettingItemArray::AddBinarySettingItemL
// -----------------------------------------------------------------------------
//
void CPapSettingItemArray::AddBinarySettingItemL( 
                                                TInt aSettingPageResourceId,
                                                TInt aTitleResourceId, 
                                                TInt aAssociatedResourceId,
                                                TInt aOrdinal, 
                                                TBool& aModifiedValue )
    {
    CAknSettingItem* settingItem = new ( ELeave ) 
        CAknBinaryPopupSettingItem( 0, aModifiedValue );
    CleanupStack::PushL( settingItem );

    HBufC* itemTitle = iEnv->AllocReadResourceLC( aTitleResourceId );
    settingItem->ConstructL( EFalse, aOrdinal, *itemTitle, NULL, 
                             aSettingPageResourceId, EAknCtPopupSettingList, 
                             NULL, aAssociatedResourceId );
    iArray->AppendL( settingItem );

    CleanupStack::PopAndDestroy( itemTitle );
    CleanupStack::Pop( settingItem );
    }
    
// -----------------------------------------------------------------------------
// CPapSettingItemArray::AddPasswordItemL
// -----------------------------------------------------------------------------
//
void CPapSettingItemArray::AddPasswordItemL( TDes& aPassword, 
                               TInt aId, 
                               TInt aTitleResource, 
                               TInt aSettingPageResource, 
                               TInt aAssociatedResource, 
                               TInt aOrdinal )
    {
    // Create new setting item    
    CPapUiPwSettingItem* settingItem = new( ELeave ) CPapUiPwSettingItem( aId,
                                            CAknPasswordSettingItem::EAlpha,
                                            aPassword, this ); 
    CleanupStack::PushL( settingItem );
    settingItem->SetEmptyItemTextL( KEmptyPassword );
    
    settingItem->SetSettingPageFlags( 
                                    CAknTextSettingPage::EZeroLengthAllowed );
    
    // Construct setting item with parametrized values
    HBufC* itemTitle = iEnv->AllocReadResourceLC( aTitleResource );
   

    settingItem->ConstructL( EFalse, aOrdinal, *itemTitle, NULL, 
                             aSettingPageResource, EAknCtPopupSettingList, 
                             NULL, aAssociatedResource );
    
    // Append item to settingitem-array
    iArray->InsertL( aOrdinal, settingItem );
    
    CleanupStack::PopAndDestroy( itemTitle );
    CleanupStack::Pop( settingItem );
    }

// -----------------------------------------------------------------------------
// CPapSettingItemArray::PwItemCancelled
// -----------------------------------------------------------------------------
//    
void CPapSettingItemArray::PwItemCancelled( TBool aIsCancelled )                       
    {
    iPwItemCancelled = aIsCancelled;
    }

// -----------------------------------------------------------------------------
// CPapSettingItemArray::IsPwItemCancelled
// -----------------------------------------------------------------------------
//
TBool CPapSettingItemArray::IsPwItemCancelled()
    {
    return iPwItemCancelled;
    }
 
//  End of File
