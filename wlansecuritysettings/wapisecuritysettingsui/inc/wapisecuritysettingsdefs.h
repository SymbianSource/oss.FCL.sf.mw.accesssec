/*
* ============================================================================
*  Name     : wapisecuritysettingsdefs.h
*  Part of  : WAPI Security Settings UI
*
*  Description:
*     Definitions needed by WAPI security settings UI.
*  Version: %version:  7 %
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

#include "wapisecuritysettingsui.hrh"

#ifndef WAPISECURITYSETTINGSDEFS_H
#define WAPISECURITYSETTINGSDEFS_H

// CONSTANTS

//Index for None certificate

LOCAL_D const TInt KCertNone = 0;

// Invalid id
LOCAL_D const TUint32 KUidNone = 0;

// Authentication mode
enum TWapiAuth
    {
    EWapiAuthCert,
    EWapiAuthPSK
    };

// UID of application containing help texts (General Settings).
//LOCAL_D const TUid KWAPISecuritySettingsUiHelpMajor = { 0x100058EC };
LOCAL_D const TUid KWAPISecuritySettingsUiHelpMajor = { 0x10009D8D };


#endif  // WAPISECURITYSETTINGSDEFS_H

