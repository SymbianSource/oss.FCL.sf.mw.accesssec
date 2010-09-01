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
* %version: 18 %
*/

#if !defined(_EAPSIMDBDEFAULTS_H_)
#define _EAPSIMDBDEFAULTS_H_

enum TGSMSIMUsePseudonymId 
{
	EGSMSIMUsePseudonymIdNo,		// False. Don't use pseudonym id.
	EGSMSIMUsePseudonymIdYes,		// True. Use pseudonym id.
	EGSMSIMUsePseudonymIdNotValid 	// This indicates that the value is not configured.
};

enum TGSMSIMUseManualRealm 
{
	EGSMSIMUseManualRealmNo,		// False. Don't use Manual Realm.
	EGSMSIMUseManualRealmYes,		// True. Use Manual Realm.
};

enum TGSMSIMUseManualUsername 
{
	EGSMSIMUseManualUsernameNo,		// False. Don't use Manual Username.
	EGSMSIMUseManualUsernameYes,		// True. Use Manual Username.
};

// LOCAL CONSTANTS
const TInt default_EAP_GSMSIM_use_manual_realm = EGSMSIMUseManualRealmNo;
_LIT(default_EAP_GSMSIM_manual_realm, "");

const TInt default_EAP_GSMSIM_use_manual_username = EGSMSIMUseManualUsernameNo;
_LIT(default_EAP_GSMSIM_manual_username, "");

const TInt default_EAP_GSMSIM_use_pseudonym_identity = EGSMSIMUsePseudonymIdYes; // Default is, use pseudonym identity.

const TInt64 default_MaxSessionTime = 0; // 0 means read from configuration file.
const TInt64 default_FullAuthTime = 0;

const TUint KMaxPseudonymIdLengthInDB = 1020; // This is the max possible length of an EAP packet.
const TUint KMaxReauthIdLengthInDB = 1020; //  Hope pseudonym id or reauth id can't be more than that.

const TUint KMaxManualUsernameLengthInDB = 255;
const TUint KMaxManualRealmLengthInDB = 255;

const TUint KMaxIMSILengthInDB = 15;

const TUint KMaxXKeyLengthInDB = 20;
const TUint KMaxK_autLengthInDB = 16;
const TUint KMaxK_encrLengthInDB = 16;

#endif // _EAPSIMDBDEFAULTS_H_

// End of file
