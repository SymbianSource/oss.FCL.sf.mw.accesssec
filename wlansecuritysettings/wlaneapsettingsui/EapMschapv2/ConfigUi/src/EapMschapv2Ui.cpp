/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description: Implementation of EAP MsChapv2 UI class
*
*/

/*
* %version: 16 %
*/

// INCLUDE FILES
#include "EapMschapv2Ui.h"
#include <EapMsChapV2UiConnection.h>
#include "EapMschapv2UiView.h"
#include <eapmschapv2ui.rsg>
#include <bautils.h>
#include <coemain.h>
#include <aknnotewrappers.h>
#include <data_caging_path_literals.hrh>


// CONSTANTS
_LIT( KDriveZ, "z:" );                               // ROM folder
_LIT( KResourceFileName, "eapmschapv2ui.rsc" );


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
// CEapMsChapV2Ui::CEapMsChapV2Ui
// -----------------------------------------------------------------------------
//
CEapMsChapV2Ui::CEapMsChapV2Ui( CEapMsChapV2UiConnection* aConnection ) 
: iConnection( aConnection )
    {
    }


// -----------------------------------------------------------------------------
// CEapMsChapV2Ui::NewL
// -----------------------------------------------------------------------------
//
CEapMsChapV2Ui* CEapMsChapV2Ui::NewL( CEapMsChapV2UiConnection* aConnection )
    {
    CEapMsChapV2Ui* self = new ( ELeave ) CEapMsChapV2Ui( aConnection );
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop( self );    
    return self;
    }


// -----------------------------------------------------------------------------
// CEapMsChapV2Ui::ConstructL
// -----------------------------------------------------------------------------
//
void CEapMsChapV2Ui::ConstructL()
    {
    }


// -----------------------------------------------------------------------------
// CEapMsChapV2Ui::~CEapMsChapV2Ui
// -----------------------------------------------------------------------------
//
CEapMsChapV2Ui::~CEapMsChapV2Ui()
    {
    }


// -----------------------------------------------------------------------------
// CEapMsChapV2Ui::InvokeUiL
// -----------------------------------------------------------------------------
//
TInt CEapMsChapV2Ui::InvokeUiL()
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
    CEapMsChapV2UiDialog* settingsDlg = new( ELeave ) CEapMsChapV2UiDialog(
                                                    iConnection, buttonId );
    settingsDlg->ConstructAndRunLD( R_MSCHAPV2_SETTING_DIALOG );

    CleanupStack::PopAndDestroy();  // For resource file

    return buttonId;
    }

//  End of File
