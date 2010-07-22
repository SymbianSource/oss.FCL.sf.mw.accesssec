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

#if !defined(_EAPAKADBDEFAULTS_H_)
#define _EAPAKADBDEFAULTS_H_

#include "EapPluginDbDefaults.h"

// LOCAL CONSTANTS
const TUint default_EAP_AKA_use_manual_realm = EEapDbFalse;

const TUint default_EAP_AKA_use_manual_username = EEapDbFalse;

const TUint default_EAP_AKA_use_pseudonym_identity = EEapDbTrue; // Default is use pseudonym identity.

const TUint KMaxPseudonymIdLengthInDB = 1020; 	// This is the max possible length of an EAP packet.
const TUint KMaxReauthIdLengthInDB = 1020; 		// pseudonym id or reauth id can't be more than that.

const TUint KMaxIMSILengthInDB = 15;

const TUint KMaxXKeyLengthInDB = 20;
const TUint KMaxK_autLengthInDB = 16;
const TUint KMaxK_encrLengthInDB = 16;

#endif // _EAPAKADBDEFAULTS_H_

// End of file
