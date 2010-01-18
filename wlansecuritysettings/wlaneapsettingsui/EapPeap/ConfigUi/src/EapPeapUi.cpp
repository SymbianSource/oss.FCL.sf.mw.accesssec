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
* Description: Implementation of EAP PEAP UI class
*
*/

/*
* %version: 14 %
*/

// INCLUDE FILES
#include "EapPeapUi.h"
#include "EapTlsPeapUiConnection.h"
#include "EapPeapUiView.h"
#include <EapPeapUi.rsg>
#include <bautils.h>
#include <coemain.h>
#include <aknnotewrappers.h>
#include <data_caging_path_literals.hrh>


// CONSTANTS
_LIT( KDriveZ, "z:" );                               // ROM folder
_LIT( KResourceFileName, "eappeapui.rsc" );


// CLASS DECLARATION
class TResourceFileCleanupItem
    {
    public:
        CCoeEnv* iCoeEnv;
        TInt iResourceFileOffset;
    }; 


// ============================= LOCAL FUNCTIONS ===============================

// -----------------------------------------------------------------------------
// CleanupResourceFile
// -----------------------------------------------------------------------------
//
static void CleanupResourceFile( TAny* aObject )
    {
    TResourceFileCleanupItem* item = 
                        REINTERPRET_CAST( TResourceFileCleanupItem*, aObject );
    item->iCoeEnv->DeleteResourceFile( item->iResourceFileOffset );
    delete item;
    }


// ============================ MEMBER FUNCTIONS ===============================

// -----------------------------------------------------------------------------
// CEapPeapUi::CEapPeapUi
// -----------------------------------------------------------------------------
//
CEapPeapUi::CEapPeapUi( CEapTlsPeapUiConnection* aConnection, 
                        TIndexType aIndexType, 
                        TInt aIndex ) 
: iConnection( aConnection ), 
  iIndexType( aIndexType ), 
  iIndex( aIndex ) 
    {
    }


// -----------------------------------------------------------------------------
// CEapPeapUi::NewL
// -----------------------------------------------------------------------------
//
CEapPeapUi* CEapPeapUi::NewL( CEapTlsPeapUiConnection* aConnection, 
                              TIndexType aIndexType, 
                              TInt aIndex )
    {
    CEapPeapUi* self = 
                new( ELeave ) CEapPeapUi( aConnection, aIndexType, aIndex );
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop( self );    
    return self;
    }


// -----------------------------------------------------------------------------
// CEapPeapUi::ConstructL
// -----------------------------------------------------------------------------
//
void CEapPeapUi::ConstructL()
    {
    }


// -----------------------------------------------------------------------------
// CEapPeapUi::~CEapPeapUi
// -----------------------------------------------------------------------------
//
CEapPeapUi::~CEapPeapUi()
    {
    }


// -----------------------------------------------------------------------------
// CEapPeapUi::InvokeUiL
// -----------------------------------------------------------------------------
//
TInt CEapPeapUi::InvokeUiL()
    {
    TFileName fileName;

    fileName.Append( KDriveZ );
    fileName.Append( KDC_RESOURCE_FILES_DIR );
    fileName.Append( KResourceFileName );

    CCoeEnv* coeEnv = CCoeEnv::Static();
    BaflUtils::NearestLanguageFile( coeEnv->FsSession(), fileName );

    TResourceFileCleanupItem* item = new( ELeave ) TResourceFileCleanupItem;

    item->iCoeEnv = coeEnv;
    CleanupStack::PushL( TCleanupItem( CleanupResourceFile, item ) );
    item->iResourceFileOffset = coeEnv->AddResourceFileL( fileName );

    TInt buttonId;
    CEapPeapUiDialog* settingsDlg = new( ELeave ) CEapPeapUiDialog( 
                                iConnection, iIndexType, iIndex, buttonId );
    settingsDlg->ConstructAndRunLD( R_PEAP_SETTING_DIALOG );

    CleanupStack::PopAndDestroy();  // For resource file

    return buttonId;
    }


//  End of File
