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
* Description: Implementation of EAP TTLS UI class
*
*/

/*
* %version: 14 %
*/

// INCLUDE FILES
#include "EapTtlsUi.h"
#include "EapTtlsUiView.h"
#include <EapTtlsUi.rsg>
#include <bautils.h>
#include <coemain.h>
#include <aknnotewrappers.h>
#include <data_caging_path_literals.hrh>


// CONSTANTS
_LIT( KDriveZ, "z:" );                               // ROM folder
_LIT( KResourceFileName, "eapttlsui.rsc" );


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
// CEapTtlsUi::CEapTtlsUi
// -----------------------------------------------------------------------------
//
CEapTtlsUi::CEapTtlsUi( CEapTlsPeapUiConnection* aConnection, 
                        TIndexType aIndexType, 
                        TInt aIndex ) 
: iConnection( aConnection ), 
  iIndexType( aIndexType ), 
  iIndex( aIndex )
    {
    }


// -----------------------------------------------------------------------------
// CEapTtlsUi::NewL
// -----------------------------------------------------------------------------
//
CEapTtlsUi* CEapTtlsUi::NewL( CEapTlsPeapUiConnection* aConnection, 
                              TIndexType aIndexType, 
                              TInt aIndex ) 
    {
    CEapTtlsUi* self = new( ELeave ) CEapTtlsUi( aConnection, aIndexType, 
                                                 aIndex );
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop( self );    
    return self;
    }


// -----------------------------------------------------------------------------
// CEapTtlsUi::ConstructL
// -----------------------------------------------------------------------------
//
void CEapTtlsUi::ConstructL()
    {
    }


// -----------------------------------------------------------------------------
// CEapTtlsUi::~CEapTtlsUi
// -----------------------------------------------------------------------------
//
CEapTtlsUi::~CEapTtlsUi()
    {
    }


// -----------------------------------------------------------------------------
// CEapTtlsUi::InvokeUiL
// -----------------------------------------------------------------------------
//
TInt CEapTtlsUi::InvokeUiL()
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
    CEapTtlsUiDialog* settingsDlg = new( ELeave ) CEapTtlsUiDialog( 
                                iConnection, iIndexType, iIndex, buttonId );
    settingsDlg->ConstructAndRunLD( R_TTLS_SETTING_DIALOG );

    CleanupStack::PopAndDestroy();  // For resource file
    
    return buttonId;
    }


//  End of File
