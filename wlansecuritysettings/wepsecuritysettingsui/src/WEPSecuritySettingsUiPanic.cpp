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
* Description: Implementation of panic function.     
*
*/

/*
* %version: tr1cfwln#8 %
*/

// INCLUDE FILES

#include <e32std.h>

#include "WEPSecuritySettingsUiPanic.h"


// ================= LOCAL FUNCTIONS =======================

// ---------------------------------------------------------
// Panic()
// ---------------------------------------------------------
//
void Panic( TWepSecuritySettingsPanicCodes aPanic )
    {
    _LIT( kWepSet, "WEPSecuritySettingsUi" );
    User::Panic( kWepSet, aPanic );
    }


// End of File
