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
* %version: 7 %
*/

#if !defined(_EAPPLUGINDBDEFAULTS_H_)
#define _EAPPLUGINDBDEFAULTS_H_

enum TEapDbBoolean 
{
	EEapDbFalse,
	EEapDbTrue,
	EEapDbNotValid, // This indicates that the value is not configured.
};

// LOCAL CONSTANTS

_LIT(KEapSecureUIDFormat, "SECURE[102072e9]"); // For the security policy.

const TUint default_EAP_password_prompt = EEapDbTrue;

_LIT(default_EAP_identity, "");
_LIT(default_EAP_username, "");
_LIT(default_EAP_realm, "");
_LIT(default_EAP_password, "");

_LIT(KNullPasswordData, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");

const TInt64 default_MaxSessionTime = 0; // 0 means read from configuration file.
const TInt64 default_FullAuthTime = 0;

const TUint KMaxIdentityLengthInDB = 255;
const TUint KMaxUsernameLengthInDB = 255;
const TUint KMaxRealmLengthInDB    = 255;
const TUint KMaxPasswordLengthInDB = 255;

#if !defined(USE_EAP_FILECONFIG)
	const TInt default_EAP_TRACE_disable_traces = 0;
	const TInt default_EAP_TRACE_enable_function_traces = 0;
	const TInt default_EAP_TRACE_only_trace_messages = 0;
	const TInt default_EAP_TRACE_only_test_vectors = 0;
	const TInt default_EAP_CORE_session_timeout = 120000; // ms = 120 seconds = 2 minutes.
	const TInt default_EAP_ERROR_TEST_enable_random_errors = 0;
	const TInt default_EAP_ERROR_TEST_send_original_packet_first = 0;
	const TInt default_EAP_ERROR_TEST_generate_multiple_error_packets = 2;
	const TInt default_EAP_ERROR_TEST_manipulate_ethernet_header = 0;
	const TInt default_EAP_ERROR_TEST_error_probability = 8000000;
	const TInt default_EAP_test_default_type = 18; // EAP-SIM
	const TInt default_EAP_CORE_retransmission_counter = 0;
#endif //#if !defined(USE_EAP_FILECONFIG)

#endif // _EAPPLUGINDBDEFAULTS_H_


// End of file
