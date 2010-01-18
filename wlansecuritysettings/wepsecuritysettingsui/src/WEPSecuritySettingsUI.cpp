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
* Description: Implementation of class CWEPSecuritySettingsUi.  
*
*/

/*
* %version: tr1cfwln#10 %
*/

// INCLUDE FILES
#include <WEPSecuritySettingsUI.h>

#include "WEPSecuritySettingsUiImpl.h"



// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWEPSecuritySettingsUi::NewLC
// ---------------------------------------------------------
//
EXPORT_C CWEPSecuritySettingsUi* CWEPSecuritySettingsUi::NewL( 
                                                        CEikonEnv& aEikEnv )
    {
    CWEPSecuritySettingsUi* secSett = new( ELeave ) CWEPSecuritySettingsUi();
    CleanupStack::PushL( secSett );
    secSett->iImpl = CWEPSecuritySettingsUiImpl::NewL( aEikEnv );
    CleanupStack::Pop( secSett ); // secSett
    return secSett;
    }



// ---------------------------------------------------------
// CWEPSecuritySettingsUi::~CWEPSecuritySettingsUi
// ---------------------------------------------------------
//
EXPORT_C CWEPSecuritySettingsUi::~CWEPSecuritySettingsUi()
    {
    delete iImpl;
    }



// ---------------------------------------------------------
// CWEPSecuritySettingsUi::Cvt()
// ---------------------------------------------------------
//
EXPORT_C TInt CWEPSecuritySettingsUi::Cvt()
    {
    return KErrNone;
    }


// End of File
