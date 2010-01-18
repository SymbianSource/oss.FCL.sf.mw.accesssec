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
* Description: Implementation of class CWEPSecuritySettingsUiImpl. 
*
*/

/*
* %version: tr1cfwln#10 %
*/

// INCLUDE FILES
#include <bautils.h>
#include <WEPSecuritySettingsUI.h>

#include <data_caging_path_literals.hrh>

#include "WEPSecuritySettingsUiImpl.h"
#include "WEPSecuritySettingsDlg.h"


// CONSTANTS
_LIT( KDriveZ, "z:" );                                      // ROM folder
_LIT( KResourceFileName, "WEPSecuritySettingsUI.rsc" );     // RSC file name.


// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWEPSecuritySettingsUiImpl::NewL
// ---------------------------------------------------------
//
CWEPSecuritySettingsUiImpl* CWEPSecuritySettingsUiImpl::NewL( 
                                                        CEikonEnv& aEikEnv )
    {
    CWEPSecuritySettingsUiImpl* uiImpl = 
                        new( ELeave ) CWEPSecuritySettingsUiImpl( aEikEnv );
    CleanupStack::PushL( uiImpl );
    uiImpl->ConstructL();
    CleanupStack::Pop( uiImpl ); // uiImpl
    return uiImpl;
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsUiImpl::CWEPSecuritySettingsUiImpl
// ---------------------------------------------------------
//
CWEPSecuritySettingsUiImpl::CWEPSecuritySettingsUiImpl( CEikonEnv& aEikEnv )
: iEventStore( ENone ), 
  iEikEnv( &aEikEnv )
    {
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsUiImpl::~CWEPSecuritySettingsUiImpl
// ---------------------------------------------------------
//
CWEPSecuritySettingsUiImpl::~CWEPSecuritySettingsUiImpl()
    {
    if ( iResOffset )
        {
        iEikEnv->DeleteResourceFile( iResOffset );
        }
    }



// ---------------------------------------------------------
// CWEPSecuritySettingsUiImpl::ConstructL
// ---------------------------------------------------------
//
void CWEPSecuritySettingsUiImpl::ConstructL()
    {
    TFileName fileName;

    fileName.Append( KDriveZ );
    fileName.Append( KDC_RESOURCE_FILES_DIR );
    fileName.Append( KResourceFileName );

    BaflUtils::NearestLanguageFile( iEikEnv->FsSession(), fileName );
    iResOffset = iEikEnv->AddResourceFileL( fileName );
    }



// ---------------------------------------------------------
// CWEPSecuritySettingsUiImpl::EditL
// ---------------------------------------------------------
//
TInt CWEPSecuritySettingsUiImpl::EditL( CWEPSecuritySettingsImpl& aSettings,
                                        const TDesC& aTitle )
    {
    iEventStore = ENone;

    CWEPSecuritySettingsDlg* secSettDlg = 
                                CWEPSecuritySettingsDlg::NewL( iEventStore );
    secSettDlg->ConstructAndRunLD( &aSettings, aTitle );

    return iEventStore;
    }


// End of File
