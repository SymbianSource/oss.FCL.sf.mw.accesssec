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
* Description: Implementation of EAP AKA UI class
*
*/



// INCLUDE FILES
#include "EapAkaUi.h"
#include "EapAkaUiView.h"
#include <EapAkaUi.rsg>
#include <bautils.h>
#include <coemain.h>
#include <aknnotewrappers.h>
#include <data_caging_path_literals.hrh>


// CONSTANTS
_LIT( KDriveZ, "z:" );                               // ROM folder
_LIT( KResourceFileName, "eapAkaui.rsc" );


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
// CEapAkaUi::CEapAkaUi
// -----------------------------------------------------------------------------
//
CEapAkaUi::CEapAkaUi( CEapAkaUiConnection* aConnection ) 
: iConnection( aConnection )
    {
    }


// -----------------------------------------------------------------------------
// CEapAkaUi::NewL
// -----------------------------------------------------------------------------
//
CEapAkaUi* CEapAkaUi::NewL( CEapAkaUiConnection* aConnection )
    {
    CEapAkaUi* self = new ( ELeave ) CEapAkaUi( aConnection );
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop( self );
    return self;
    }


// -----------------------------------------------------------------------------
// CEapAkaUi::ConstructL()
// -----------------------------------------------------------------------------
//
void CEapAkaUi::ConstructL()
    {
    }


// -----------------------------------------------------------------------------
// CEapAkaUi::~CEapAkaUi
// -----------------------------------------------------------------------------
//
CEapAkaUi::~CEapAkaUi()
    {
    }


// -----------------------------------------------------------------------------
// CEapAkaUi::InvokeUiL
// -----------------------------------------------------------------------------
//
TInt CEapAkaUi::InvokeUiL()
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
    CEapAkaUiDialog* settingsDlg = new( ELeave ) CEapAkaUiDialog( iConnection, 
                                                                  buttonId );
    settingsDlg->ConstructAndRunLD( R_AKA_SETTING_DIALOG );

    CleanupStack::PopAndDestroy();  // For resource file

    return buttonId;
    }


//  End of File
