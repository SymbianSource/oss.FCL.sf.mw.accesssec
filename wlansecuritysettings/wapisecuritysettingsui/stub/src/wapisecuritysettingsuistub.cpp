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
* Description: Stub implementation of class CWAPISecuritySettingsUi.  
*
*/

/*
* %version: 5 %
*/

// INCLUDE FILES
#include <e32base.h>
#include <wapisecuritysettingsui.h>



// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWAPISecuritySettingsUi::NewL
// ---------------------------------------------------------
//
EXPORT_C CWAPISecuritySettingsUi* CWAPISecuritySettingsUi::NewL( 
                                                        CEikonEnv& /* aEikEnv */)
    {
    User::Leave(KErrNotSupported); 
    return NULL;
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsUi::~CWAPISecuritySettingsUi
// ---------------------------------------------------------
//
EXPORT_C CWAPISecuritySettingsUi::~CWAPISecuritySettingsUi()
    {
    }

// End of File
