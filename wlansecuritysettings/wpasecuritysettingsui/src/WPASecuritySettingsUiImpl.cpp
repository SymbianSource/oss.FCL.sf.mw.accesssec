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
* Description: Implementation of class CWPASecuritySettingsUiImpl. 
*
*/

/*
* %version: tr1cfwln#11 %
*/

// INCLUDE FILES
#include "WPASecuritySettingsUiImpl.h"
#include "WPASecuritySettingsDlg.h"
#include "WPASecuritySettingsImpl.h"

#include <bautils.h>
#include <WPASecuritySettingsUI.h>

#include <data_caging_path_literals.hrh>


// CONSTANTS
_LIT( KDriveZ, "z:" );                                    // ROM folder
_LIT( KResourceFileName, "WPASecuritySettingsUI.rsc" );   // RSC file name.


// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWPASecuritySettingsUiImpl::NewL
// ---------------------------------------------------------
//
CWPASecuritySettingsUiImpl* CWPASecuritySettingsUiImpl::NewL( 
                                                        CEikonEnv& aEikEnv )
    {
    CWPASecuritySettingsUiImpl* uiImpl = 
                        new( ELeave ) CWPASecuritySettingsUiImpl( aEikEnv );
    CleanupStack::PushL( uiImpl );
    uiImpl->ConstructL();
    CleanupStack::Pop( uiImpl ); // uiImpl
    return uiImpl;
    }


// ---------------------------------------------------------
// CWPASecuritySettingsUiImpl::CWPASecuritySettingsUiImpl
// ---------------------------------------------------------
//
CWPASecuritySettingsUiImpl::CWPASecuritySettingsUiImpl( CEikonEnv& aEikEnv )
: iEventStore( ENone ), 
  iEikEnv( &aEikEnv )
    {
    }


// ---------------------------------------------------------
// CWPASecuritySettingsUiImpl::~CWPASecuritySettingsUiImpl
// ---------------------------------------------------------
//
CWPASecuritySettingsUiImpl::~CWPASecuritySettingsUiImpl()
    {
    if ( iResOffset )
        {
        iEikEnv->DeleteResourceFile( iResOffset );
        }
    }



// ---------------------------------------------------------
// CWPASecuritySettingsUiImpl::ConstructL
// ---------------------------------------------------------
//
void CWPASecuritySettingsUiImpl::ConstructL()
    {
    TFileName fileName;

    fileName.Append( KDriveZ );
    fileName.Append( KDC_RESOURCE_FILES_DIR );
    fileName.Append( KResourceFileName );

    BaflUtils::NearestLanguageFile( iEikEnv->FsSession(), fileName );
    iResOffset = iEikEnv->AddResourceFileL( fileName );
    }



// ---------------------------------------------------------
// CWPASecuritySettingsUiImpl::EditL
// ---------------------------------------------------------
//
TInt CWPASecuritySettingsUiImpl::EditL( CWPASecuritySettingsImpl& aSettings,
                                        const TDesC& aTitle )
    {
    iEventStore = ENone;

    CWPASecuritySettingsDlg* secSettDlg = 
                        CWPASecuritySettingsDlg::NewL( iEventStore, 
                                                       aSettings.IapId(), 
                                                       aSettings.Plugin() );
    secSettDlg->ConstructAndRunLD( &aSettings, aTitle );

    return iEventStore;
    }


// End of File
