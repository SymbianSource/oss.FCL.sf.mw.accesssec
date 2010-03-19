/*
* ============================================================================
*  Name     : wapisecuritysettingsuiimpl
*  Part of  : WAPI Security Settings UI
*
*  Description:
*      Implementation of class CWAPISecuritySettingsUiImpl.
*  Version: %version:  4 %
*
*  Copyright (C) 2008 Nokia Corporation.
*  This material, including documentation and any related 
*  computer programs, is protected by copyright controlled by 
*  Nokia Corporation. All rights are reserved. Copying, 
*  including reproducing, storing,  adapting or translating, any 
*  or all of this material requires the prior written consent of 
*  Nokia Corporation. This material also contains confidential 
*  information which may not be disclosed to others without the 
*  prior written consent of Nokia Corporation.
*
* ============================================================================
*/

// INCLUDE FILES
#include <bautils.h>
#include <wapisecuritysettingsui.h>

#include <data_caging_path_literals.hrh>

#include "wapisecuritysettingsuiimpl.h"
#include "wapisecuritysettingsimpl.h"
#include "wapisecuritysettingsdlg.h"


// CONSTANTS
_LIT( KDriveZ, "z:" );                                      // ROM folder
_LIT( KResourceFileName, "wapisecuritysettingsui.rsc" );     // RSC file name.


// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWAPISecuritySettingsUiImpl::NewL
// ---------------------------------------------------------
//
CWAPISecuritySettingsUiImpl* CWAPISecuritySettingsUiImpl::NewL( 
                                                        CEikonEnv& aEikEnv )
    {
    CWAPISecuritySettingsUiImpl* uiImpl = 
                        new( ELeave ) CWAPISecuritySettingsUiImpl( aEikEnv );
    CleanupStack::PushL( uiImpl );
    uiImpl->ConstructL();
    CleanupStack::Pop( uiImpl );
    return uiImpl;
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsUiImpl::CWAPISecuritySettingsUiImpl
// ---------------------------------------------------------
//
CWAPISecuritySettingsUiImpl::CWAPISecuritySettingsUiImpl( CEikonEnv& aEikEnv )
: iEventStore( ENone ), 
  iEikEnv( &aEikEnv )
    {
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsUiImpl::~CWAPISecuritySettingsUiImpl
// ---------------------------------------------------------
//
CWAPISecuritySettingsUiImpl::~CWAPISecuritySettingsUiImpl()
    {
    if ( iResOffset )
        {
        iEikEnv->DeleteResourceFile( iResOffset );
        }
    }



// ---------------------------------------------------------
// CWAPISecuritySettingsUiImpl::ConstructL
// ---------------------------------------------------------
//
void CWAPISecuritySettingsUiImpl::ConstructL()
    {
    TFileName fileName;

    fileName.Append( KDriveZ );
    fileName.Append( KDC_RESOURCE_FILES_DIR );
    fileName.Append( KResourceFileName );

    BaflUtils::NearestLanguageFile( iEikEnv->FsSession(), fileName );
    iResOffset = iEikEnv->AddResourceFileL( fileName );
    }



// ---------------------------------------------------------
// CWAPISecuritySettingsUiImpl::EditL
// ---------------------------------------------------------
//
TInt CWAPISecuritySettingsUiImpl::EditL( CWAPISecuritySettingsImpl& aSettings,
                                        const TDesC& aTitle )
    {
    iEventStore = ENone;
    
    aSettings.LoadCertificatesL();
    
    CWAPISecuritySettingsDlg* secSettDlg = 
                                CWAPISecuritySettingsDlg::NewL( iEventStore );
    
    
    secSettDlg->ConstructAndRunLD( &aSettings, aTitle );

    return iEventStore;
    }


// End of File
