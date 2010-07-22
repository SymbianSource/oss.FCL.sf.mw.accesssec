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

/** 
	List of Uids for available connection notifiers
*/

#ifndef EAPSECURIDNOTIFIERUIDS_H
#define EAPSECURIDNOTIFIERUIDS_H

#include "EapolUID.h"

const TUid KEapSecurIDDllUid = {EAP_SECURID_NOTIFIERS_DLL_UID};

const TUid KEapSecurIDIdentityQueryUid = {EAP_SECURID_IDENTITY_NOTIFIER_UID};
const TUid KEapSecurIDPasscodeQueryUid = {EAP_SECURID_PASSCODE_NOTIFIER_UID};
const TUid KEapSecurIDPincodeQueryUid = {EAP_SECURID_PINCODE_NOTIFIER_UID};

const TUid KEapGtcIdentityQueryUid = {EAP_GTC_IDENTITY_NOTIFIER_UID};
const TUid KEapGtcUserInputQueryUid = {EAP_GTC_USER_INPUT_NOTIFIER_UID};

#endif // EAPSECURIDNOTIFIERUIDS_H

// End of File
