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
* Description: Stub implementation of class CWPASecuritySettingsUi for 
*              non-WLAN products to support linking 
*
*/

/*
* %version: 2 %
*/

// INCLUDE FILES
#include <WPASecuritySettingsUI.h>



// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWPASecuritySettingsUi::NewLC
// ---------------------------------------------------------
//
EXPORT_C CWPASecuritySettingsUi* CWPASecuritySettingsUi::NewL( 
                                                        CEikonEnv& /*aEikEnv*/ )
    {
    User::Leave(KErrNotSupported);
    return NULL;
    }



// ---------------------------------------------------------
// CWPASecuritySettingsUi::~CWPASecuritySettingsUi
// ---------------------------------------------------------
//
EXPORT_C CWPASecuritySettingsUi::~CWPASecuritySettingsUi()
    {
    }



// ---------------------------------------------------------
// CWPASecuritySettingsUi::Cvt()
// ---------------------------------------------------------
//
EXPORT_C TInt CWPASecuritySettingsUi::Cvt()
    {
    return KErrNotSupported;
    }
// End of File
