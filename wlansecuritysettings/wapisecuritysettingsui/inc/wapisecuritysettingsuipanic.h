/*
* ============================================================================
*  Name     : wapisecuritysettingsuipanic.h 
*  Part of  : WAPI Security Settings UI
*
*  Description:
*      Panic function and codes.   
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

#ifndef WAPISECURITYSETTINGSUIPANIC_H
#define WAPISECURITYSETTINGSUIPANIC_H

// TYPES

/**
* Panic reasons for WAPI Security Settings UI.
*/
enum TWapiSecuritySettingsPanicCodes
    {
    EUnknownCase
    };


// FUNCTION DECLARATIONS

/**
* Panic the thread.
* @param aReason Reason for the panic.
*/
void Panic( TWapiSecuritySettingsPanicCodes aPanic );

#endif
