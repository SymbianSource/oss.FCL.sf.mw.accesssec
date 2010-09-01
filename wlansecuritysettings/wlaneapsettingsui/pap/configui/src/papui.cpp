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
* Description: Implementation of PAP UI class
*
*/

/*
* %version: 8 %
*/

// INCLUDE FILES
#include <papui.h>
#include <EapTlsPeapUiConnection.h>
#include "papuiview.h"
#include <papui.rsg>
#include <bautils.h>
#include <coemain.h>
#include <data_caging_path_literals.hrh>


// CONSTANTS
_LIT( KDriveZ, "z:" );                               // ROM folder
_LIT( KResourceFileName, "papui.rsc" );


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
// CPapUi::CPapUi
// -----------------------------------------------------------------------------
//
CPapUi::CPapUi( CEapTlsPeapUiConnection* aConnection ) 
: iConnection( aConnection )
    {
    }


// -----------------------------------------------------------------------------
// CPapUi::NewL
// -----------------------------------------------------------------------------
//
CPapUi* CPapUi::NewL( CEapTlsPeapUiConnection* aConnection )
    {
    CPapUi* self = new( ELeave ) CPapUi( aConnection );
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop( self );    
    return self;
    }


// -----------------------------------------------------------------------------
// CPapUi::ConstructL
// -----------------------------------------------------------------------------
//
void CPapUi::ConstructL()
    {
    }


// -----------------------------------------------------------------------------
// CPapUi::~CPapUi
// -----------------------------------------------------------------------------
//
CPapUi::~CPapUi()
    {
    }


// -----------------------------------------------------------------------------
// CPapUi::InvokeUiL
// -----------------------------------------------------------------------------
//
TInt CPapUi::InvokeUiL()
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
    CPapUiDialog* settingsDlg = new( ELeave ) CPapUiDialog(
        iConnection, buttonId );
        
    settingsDlg->ConstructAndRunLD( R_PAP_SETTING_DIALOG );

    CleanupStack::PopAndDestroy();  // Resource file
    
    return buttonId;
    }


//  End of File
