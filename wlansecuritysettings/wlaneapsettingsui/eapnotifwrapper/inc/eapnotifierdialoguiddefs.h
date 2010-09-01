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
* Description: Declaration of the UIDs used by Connection Dialogs
*
*/

/*
* %version: tr1cfwln#8 %
*/

#ifndef __EAPNOTIFIERDIALOGUIDDEFS_H__
#define __EAPNOTIFIERDIALOGUIDDEFS_H__

// INCLUDES
#include <e32std.h>


// CONSTANTS

// UIDs for EAP notifier plugins

// ID of EAP-GTC dialog
const TUid KUidGtcDialog        = { 0x101f8e7f };

// ID of EAP-MSCHAPv2 dialog
const TUid KUidMsChapv2Dialog   = { 0x101f8e69 };

// ID of PAP dialog
const TUid KUidPapDialog = { 0x200159A9 };

#ifdef FF_WLAN_EXTENSIONS
// ID of EAP-LEAP dialog
const TUid KUidLeapDialog       = { 0x101f8ea9 };  
#endif

#endif  // __EAPNOTIFIERDIALOGUIDDEFS_H__ 

// End of File
