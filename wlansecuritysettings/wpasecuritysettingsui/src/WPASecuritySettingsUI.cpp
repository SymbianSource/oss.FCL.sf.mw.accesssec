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
* Description: Implementation of class CWPASecuritySettingsUi.  
*
*/

/*
* %version: tr1cfwln#10 %
*/

// INCLUDE FILES
#include "WPASecuritySettingsUiImpl.h"

#include <WPASecuritySettingsUI.h>



// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWPASecuritySettingsUi::NewLC
// ---------------------------------------------------------
//
EXPORT_C CWPASecuritySettingsUi* CWPASecuritySettingsUi::NewL( 
                                                        CEikonEnv& aEikEnv )
    {
    CWPASecuritySettingsUi* secSett = new( ELeave )CWPASecuritySettingsUi;
    CleanupStack::PushL( secSett );
    secSett->iImpl = CWPASecuritySettingsUiImpl::NewL( aEikEnv );
    CleanupStack::Pop( secSett ); // secSett
    return secSett;
    }



// ---------------------------------------------------------
// CWPASecuritySettingsUi::~CWPASecuritySettingsUi
// ---------------------------------------------------------
//
EXPORT_C CWPASecuritySettingsUi::~CWPASecuritySettingsUi()
    {
    delete iImpl;
    }



// ---------------------------------------------------------
// CWPASecuritySettingsUi::Cvt()
// ---------------------------------------------------------
//
EXPORT_C TInt CWPASecuritySettingsUi::Cvt()
    {
    return KErrNone;
    }


// End of File
