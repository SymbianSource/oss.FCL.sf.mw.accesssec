/*
* ============================================================================
*  Name     : wapisecuritysettingsui.cpp
*  Part of  : WAPI Security Settings UI
*
*  Description:
*      Implementation of class CWAPISecuritySettingsUi.
*
*  Version: %version:  3 %
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
#include <wapisecuritysettingsui.h>

#include "wapisecuritysettingsuiimpl.h"



// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWAPISecuritySettingsUi::NewLC
// ---------------------------------------------------------
//
EXPORT_C CWAPISecuritySettingsUi* CWAPISecuritySettingsUi::NewL( 
                                                        CEikonEnv& aEikEnv )
    {
    CWAPISecuritySettingsUi* secSett = new( ELeave ) CWAPISecuritySettingsUi();
    CleanupStack::PushL( secSett );
    secSett->iImpl = CWAPISecuritySettingsUiImpl::NewL( aEikEnv );
    CleanupStack::Pop( secSett );
    return secSett;
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsUi::~CWAPISecuritySettingsUi
// ---------------------------------------------------------
//
EXPORT_C CWAPISecuritySettingsUi::~CWAPISecuritySettingsUi()
    {
    delete iImpl;
    }

// End of File
