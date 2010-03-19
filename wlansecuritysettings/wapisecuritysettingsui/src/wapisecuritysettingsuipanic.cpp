/*
* ============================================================================
*  Name     : wapisecuritysettingsuipanic.cpp 
*  Part of  : WAPI Security Settings UI
*
*  Description:
*      Implementation of panic function.   
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

#include <e32std.h>

#include "wapisecuritysettingsuipanic.h"


// ================= LOCAL FUNCTIONS =======================

// ---------------------------------------------------------
// Panic()
// ---------------------------------------------------------
//
void Panic( TWapiSecuritySettingsPanicCodes aPanic )
    {
    _LIT( KWapiSet, "wapisecuritysettingsui" );
    User::Panic( KWapiSet, aPanic );
    }


// End of File
