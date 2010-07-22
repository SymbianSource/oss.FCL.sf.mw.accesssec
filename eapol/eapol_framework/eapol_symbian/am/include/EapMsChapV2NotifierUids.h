/*
* Copyright (c) 2001-2006 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  EAP and WLAN authentication protocols.
*
*/

/*
* %version: %
*/

//
//	Copyright (c) Nokia Corporation 2002. All rights reserved.
//
// EapMsChapV2NotifierUids.h

/** 
	List of Uids for available connection notifiers
*/

#ifndef EAPMSCHAPV2NOTIFIERUIDS_H
#define EAPMSCHAPV2NOTIFIERUIDS_H

#include "EapolUID.h"

const TUid KEapMsChapV2NotifierDllUid = {EAP_MSCHAPV2_NOTIFIERS_DLL_UID};
const TUid KEapMsChapV2UsernamePasswordUid = {EAP_MSCHAPV2_USERNAME_PASSWORD_NOTIFIER_UID};
const TUid KEapMsChapV2ChangePasswordUid = {EAP_MSCHAPV2_CHANGE_PASSWORD_NOTIFIER_UID};

#endif
