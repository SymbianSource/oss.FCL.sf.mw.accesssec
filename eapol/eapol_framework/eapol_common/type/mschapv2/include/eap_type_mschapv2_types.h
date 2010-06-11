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

#ifndef _MSCHAPV2_TYPES_H_
#define _MSCHAPV2_TYPES_H_

#include "eap_configuration_field.h"

const u32_t EAP_MSCHAPV2_USERNAME_MAX_SIZE = 512; // 256 unicode-chars
const u32_t EAP_MSCHAPV2_PASSWORD_MAX_SIZE = 512; // 256 unicode-chars

const u32_t EAP_MSCHAPV2_AUTHENTICATOR_RESPONSE_SIZE = 42;
const u32_t EAP_MSCHAPV2_CHALLENGE_HASH_SIZE = 8;
const u32_t EAP_MSCHAPV2_NT_RESPONSE_SIZE = 24;
const u32_t EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE = 16;
const u32_t EAP_MSCHAPV2_PEER_CHALLENGE_SIZE = 16;
const u32_t EAP_MSCHAPV2_IDENT_SIZE = 1;
const u32_t EAP_MSCHAPV2_FLAGS_SIZE = 1;
const u32_t EAP_MSCHAPV2_OPCODE_SIZE = 1;
const u32_t EAP_MSCHAPV2_CHANGE_PASSWORD_FLAGS_SIZE = 2;
const u32_t EAP_MSCHAPV2_RESERVED_RESPONSE_SIZE = 8;
const u32_t EAP_MSCHAPV2_MD4_DIGEST_SIZE = 16;
const u32_t EAP_MSCHAPV2_SHA1_DIGEST_SIZE = 20;
const u32_t EAP_MSCHAPV2_DES_KEY_SIZE = 8;
const u32_t EAP_MSCHAPV2_DES_BLOCK_SIZE = 8;

const u32_t EAP_MSCHAPV2_RESPONSE_MESSAGE_SIZE
	= EAP_MSCHAPV2_IDENT_SIZE
	+ EAP_MSCHAPV2_FLAGS_SIZE
	+ EAP_MSCHAPV2_PEER_CHALLENGE_SIZE
	+ EAP_MSCHAPV2_RESERVED_RESPONSE_SIZE
	+ EAP_MSCHAPV2_NT_RESPONSE_SIZE;

const u32_t EAP_MSCHAPV2_PEER_CHALLENGE_OFFSET
	= EAP_MSCHAPV2_IDENT_SIZE
	+ EAP_MSCHAPV2_FLAGS_SIZE;

const u32_t EAP_MSCHAPV2_NT_RESPONSE_OFFSET
	= EAP_MSCHAPV2_PEER_CHALLENGE_OFFSET
	+ EAP_MSCHAPV2_PEER_CHALLENGE_SIZE
	+ EAP_MSCHAPV2_RESERVED_RESPONSE_SIZE;


const u32_t EAP_MSCHAPV2_MASTER_KEY_SIZE = 16;

const u32_t EAP_MSCHAPV2_SUCCESS_REQUEST_MESSAGE_MIN_LENGTH = 42;// "S=<40>"
const u32_t EAP_MSCHAPV2_FAILURE_MIN_SIZE = 48;
const u32_t EAP_MSCHAPV2_FAILURE_REQUEST_SIZE = 67; // "E=eeeeeeeeee R=r C=cccccccccccccccccccccccccccccccc V=vvvvvvvvvv M="
const u32_t EAP_MSCHAPV2_CHANGE_PASSWORD_ENCRYPTED_PASSWORD_SIZE = 516;
const u32_t EAP_MSCHAPV2_CHANGE_PASSWORD_ENCRYPTED_HASH_SIZE = 16;
const u32_t EAP_MSCHAPV2_HEADER_SIZE = 4; // OpCode, MS-CHAPv2-ID and MS-Length


const u8_t EAP_MSCHAPV2_MESSAGE_PREFIX[] = " M=";
const u32_t EAP_MSCHAPV2_MESSAGE_PREFIX_SIZE = 3;

const u8_t EAP_MSCHAPV2_IMPLICIT_CHALLENGE_HANDLE_KEY[] = "eap_type_mschapv2_c implicit challenge";

const u8_t EAP_MSCHAPV2_ZERO_CHALLENGE[]
	= { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, };

typedef struct
{
	u8_t password[EAP_MSCHAPV2_PASSWORD_MAX_SIZE]; // 256 unicode-chars
	u32_t password_length;
} pw_block_s;

enum eap_type_mschapv2_stored_e
{
	eap_type_mschapv2_stored_none,
	eap_type_mschapv2_stored_username,
	eap_type_mschapv2_stored_password,
	eap_type_mschapv2_implicit_challenge,
	eap_type_mschapv2_stored_password_expired_flag,
};


const u32_t TRACE_FLAGS_MSCHAPV2_ERROR = eap_am_tools_c::eap_trace_mask_error;

/**
 *  This is boolean configuration option.
 *  True value of this flag causes client return random
 *  identity on EAP-Response/Identity.
 *  False value causes client return real identity
 *  (IMSI, pseudonym or re-authentication identity)
 *  in EAP-Response/Identity.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_MSCHAPV2_wait_eap_success_packet,
	"EAP_MSCHAPV2_wait_eap_success_packet",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_MSCHAPV2_password_prompt,
	"EAP_MSCHAPV2_password_prompt",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_MSCHAPV2_username,
	"EAP_MSCHAPV2_username",
	eap_configure_type_hex_data,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_MSCHAPV2_password,
	"EAP_MSCHAPV2_password",
	eap_configure_type_hex_data,
	true);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_MSCHAPV2_use_implicit_challenge,
	"EAP_MSCHAPV2_use_implicit_challenge",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_MSCHAPV2_use_EAP_FAST_challenge,
	"EAP_MSCHAPV2_use_EAP_FAST_challenge",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_MSCHAPV2_client_EAP_FAST_challenge,
	"EAP_MSCHAPV2_client_EAP_FAST_challenge",
	eap_configure_type_hex_data,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_MSCHAPV2_server_EAP_FAST_challenge,
	"EAP_MSCHAPV2_server_EAP_FAST_challenge",
	eap_configure_type_hex_data,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_MSCHAPV2_use_EAP_FAST_full_key,
	"EAP_MSCHAPV2_use_EAP_FAST_full_key",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_MSCHAPV2_use_eap_expanded_type,
	"EAP_MSCHAPV2_use_eap_expanded_type",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_MSCHAPV2_do_password_expiration_tests,
	"EAP_MSCHAPV2_do_password_expiration_tests",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_MSCHAPV2_do_wrong_password_tests,
	"EAP_MSCHAPV2_do_wrong_password_tests",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_MSCHAPV2_do_asyncronous_completition,
	"EAP_MSCHAPV2_do_asyncronous_completition",
	eap_configure_type_boolean,
	false);

/**
 *  This u32_t configuration value specifies the maximum session validity time in seconds.
 *  Default value is 12 hours in seconds, which is 43200 seconds.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_MSCHAPv2_max_session_validity_time,
	"EAP_MSCHAPv2_max_session_validity_time",
	eap_configure_type_u32_t,
	false);

/** @} */ // End of group MSCHAPV2_config_options.

//--------------------------------------------------

/// Macro traces payload type and data.
#define EAP_MSCHAPV2_TRACE_PAYLOAD(prefix, payload) \
	{ \
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, (EAPL("%s (0x%08x): current payload 0x%04x=%s, data length 0x%04x.\n"), \
			prefix, payload, payload->get_current_payload(), payload->get_payload_AT_string(), payload->get_data_length())); \
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, (EAPL("payload"), \
			payload, \
			payload->get_payload_length())); \
	}

//--------------------------------------------------


#endif //#if !defined(_MSCHAPV2_TYPES_H_)
