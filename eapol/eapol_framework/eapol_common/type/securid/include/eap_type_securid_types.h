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

#ifndef SECURID_TYPES_H
#define SECURID_TYPES_H

#include "eap_configuration_field.h"


const u32_t TRACE_FLAGS_SECURID_ERROR = eap_am_tools_c::eap_trace_mask_error;


enum eap_type_gtc_stored_e
{
	eap_type_gtc_stored_none,
	eap_type_gtc_stored_identity,
};


EAP_CONFIGURATION_FIELD(
	cf_str_EAP_SECURID_identity,
	"EAP_SECURID_identity",
	eap_configure_type_hex_data,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_SECURID_passcode,
	"EAP_SECURID_passcode",
	eap_configure_type_hex_data,
	true);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GTC_identity,
	"EAP_GTC_identity",
	eap_configure_type_hex_data,
	false);


EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GTC_passcode,
	"EAP_GTC_passcode",
	eap_configure_type_hex_data,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GTC_passcode_prompt,
	"EAP_SECURID_passcode_prompt",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_SECURID_use_eap_expanded_type,
	"EAP_SECURID_use_eap_expanded_type",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GTC_use_eap_expanded_type,
	"EAP_GTC_use_eap_expanded_type",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GTC_use_EAP_FAST_response,
	"EAP_GTC_use_EAP_FAST_response",
	eap_configure_type_boolean,
	false);

/**
 *  This u32_t configuration value specifies the maximum session validity time in seconds.
 *  Default value is 12 hours in seconds, which is 43200 seconds.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GTC_max_session_validity_time,
	"EAP_GTC_max_session_validity_time",
	eap_configure_type_u32_t,
	false);


const u8_t EAP_FAST_EAP_GTC_RESPONSE_PREFIX[] = "RESPONSE=";
const u32_t EAP_FAST_EAP_GTC_RESPONSE_PREFIX_LENGTH = sizeof(EAP_FAST_EAP_GTC_RESPONSE_PREFIX)-1ul;

const u8_t EAP_FAST_EAP_GTC_RESPONSE_SEPARATOR[] = { 0x00 };
const u32_t EAP_FAST_EAP_GTC_RESPONSE_SEPARATOR_LENGTH = sizeof(EAP_FAST_EAP_GTC_RESPONSE_SEPARATOR);

/** @} */ // End of group SECURID_config_options.

//--------------------------------------------------

/// Macro traces payload type and data.
#define EAP_SECURID_TRACE_PAYLOAD(prefix, payload) \
	{ \
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT | TRACE_TEST_VECTORS, (EAPL("%s (0x%08x): current payload 0x%04x=%s, data length 0x%04x.\n"), \
			prefix, payload, payload->get_current_payload(), payload->get_payload_AT_string(), payload->get_data_length())); \
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT | TRACE_TEST_VECTORS, (EAPL("payload"), \
			payload, \
			payload->get_payload_length())); \
	}

//--------------------------------------------------

#endif //SECURID_TYPES_H

//--------------------------------------------------


// End.
