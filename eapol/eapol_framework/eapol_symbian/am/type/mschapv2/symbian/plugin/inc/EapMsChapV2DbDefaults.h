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




#ifndef _EAPMSCHAPV2DBDEFAULTS_H_
#define _EAPMSCHAPV2DBDEFAULTS_H_

enum TMSCHAPV2PasswordPrompt
{
	EMSCHAPV2PasswordPromptOff,		// False. Don't show password prompt.
	EMSCHAPV2PasswordPromptOn,		// True. Show password prompt.
};

// LOCAL CONSTANTS

const TUint default_EAP_MSCHAPV2_password_prompt = EMSCHAPV2PasswordPromptOff;

_LIT(default_EAP_MSCHAPV2_username, "");
_LIT(default_EAP_MSCHAPV2_password, "");

const TInt64 default_MaxSessionTime = 0; // 0 means read from configuration file.
const TInt64 default_FullAuthTime = 0;

const TUint KMaxUsernameLengthInDB = 255;
const TUint KMaxPasswordLengthInDB = 255;

#endif // _EAPMSCHAPV2DBDEFAULTS_H_
