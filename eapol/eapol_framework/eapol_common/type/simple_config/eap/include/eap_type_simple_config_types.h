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

#if !defined(_EAP_TYPE_SIMPLE_CONFIG_TYPES_H_)
#define _EAP_TYPE_SIMPLE_CONFIG_TYPES_H_

#include "eap_buffer.h"
#include "eap_type_all_types.h"
#include "simple_config_types.h"
#include "eap_configuration_field.h"

/** @file eap_type_simple_config_types.h 
 *  @brief This file defines the constants of the SIMPLE_CONFIG EAP type.
 */

/**
 * This is the internal state of the SIMPLE_CONFIG EAP type.
 */
enum eap_type_simple_config_state_variable_e
{
	eap_type_simple_config_state_waiting_for_identity_request                          , ///< Client state waiting_for_identity_request
	eap_type_simple_config_state_pending_identity_query                                , ///< Client state pending_identity_query
	eap_type_simple_config_state_waiting_for_simple_config_start                                 , ///< Client state waiting_for_eap_start
	eap_type_simple_config_state_process_simple_config_start                                     , ///< Client state process_simple_config_start
	eap_type_simple_config_state_waiting_for_request                                   , ///< Client state waiting_for_request

	eap_type_simple_config_state_waiting_for_identity_response                         , ///< Server state waiting_for_identity_response
	eap_type_simple_config_state_waiting_for_response                                  , ///< Server state waiting_for_response

	eap_type_simple_config_state_process_simple_config_message                                   , ///< Client or server state process_simple_config_message

	eap_type_simple_config_state_success                                               , ///< State state_success
	eap_type_simple_config_state_failure                                               , ///< State state_failure

	eap_type_simple_config_state_last_value                                            , ///< Keep this enum the last one.
};


enum eap_type_simple_config_reassembly_state_e
{
	eap_type_simple_config_reassembly_state_none,
	eap_type_simple_config_reassembly_state_wait_first_message,
	eap_type_simple_config_reassembly_state_wait_last_fragment,
	eap_type_simple_config_reassembly_state_message_reassembled,
};


/**
 * This is the type of the SIMPLE_CONFIG authentication.
 */
enum eap_simple_config_authentication_type_e
{
	SIMPLE_CONFIG_AUTHENTICATION_TYPE_NONE,
	SIMPLE_CONFIG_AUTHENTICATION_TYPE_SIMPLE_CONFIG,
};

enum eap_type_simple_config_stored_e
{
	eap_type_simple_config_stored_none,
	eap_type_simple_config_stored_session_id,
	eap_type_simple_config_stored_master_secret,
	eap_type_simple_config_stored_used_cipher_suite,
	eap_type_simple_config_stored_count_of_session_resumes,
	eap_type_simple_config_stored_test_every_cipher_suite_counter,
};

/**
 * This is the size of the local send buffer.
 */
const u32_t EAP_SIMPLE_CONFIG_LOCAL_PACKET_BUFFER_LENGTH = EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH;

/**
 * This is the at character used in NAI.
 */
const u8_t EAP_SIMPLE_CONFIG_AT_CHARACTER = '@';


/**
 * This is the identity of Enrollee.
 */
const u8_t EAP_SIMPLE_CONFIG_ENROLLEE_IDENTITY[] = "WFA-SimpleConfig-Enrollee-1-0";

/**
 * This is the length of identity of Enrollee.
 */
const u32_t EAP_SIMPLE_CONFIG_ENROLLEE_IDENTITY_LENGTH = sizeof(EAP_SIMPLE_CONFIG_ENROLLEE_IDENTITY)-1;


/**
 * This is the maximum size of the EAP-SIMPLE_CONFIG message.
 * This value limits the maximum size of the received EAP-SIMPLE_CONFIG message.
 */
const u32_t EAP_SIMPLE_CONFIG_MAX_MESSAGE_LENGTH = 65536ul;


/**
 *  @defgroup EAP_SIMPLE_CONFIG_config_options Configuration options of EAP-SIMPLE_CONFIG.
 *  The following configuration options are read through abs_eap_base_type_c::read_configure() function.
 *  @{
 */

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_SIMPLE_CONFIG_use_manual_username,
	"EAP_SIMPLE_CONFIG_use_manual_username",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_SIMPLE_CONFIG_manual_username,
	"EAP_SIMPLE_CONFIG_manual_username",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_SIMPLE_CONFIG_use_manual_realm,
	"EAP_SIMPLE_CONFIG_use_manual_realm",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_SIMPLE_CONFIG_manual_realm,
	"EAP_SIMPLE_CONFIG_manual_realm",
	eap_configure_type_string,
	false);

/**
 *  This is boolean configuration option.
 *  True value means on EAP-type SIMPLE_CONFIG must check identifier of EAP-Response/Identity message.
 *  False value means on EAP-type SIMPLE_CONFIG does not check identifier of EAP-Response/Identity message.
 *  This is not possible in cases where identifier of the EAP-Request/Identity is generated by other network entities.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_SIMPLE_CONFIG_check_identifier_of_eap_identity_response,
	"EAP_SIMPLE_CONFIG_check_identifier_of_eap_identity_response",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  This flag activates NAI realm check. Default value is false.
 *  When active NAI realm muts be the same as realm given by EAP_SIMPLE_CONFIG_manual_realm option.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_SIMPLE_CONFIG_check_nai_realm,
	"EAP_SIMPLE_CONFIG_check_nai_realm",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  This is for testing.
 *  True value means on test version of EAP-type SIMPLE_CONFIG is used.
 *  Test version tries to make as many authentications as it is possible.
 *  False value means on real version of EAP-type SIMPLE_CONFIG is used.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_SIMPLE_CONFIG_test_version,
	"EAP_SIMPLE_CONFIG_test_version",
	eap_configure_type_boolean,
	false);


/**
 *  This u32_t configuration option is the timeout in milli seconds after
 *  the erroneus message is processed.
 *  Default value is 15000 ms = 15 seconds.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_SIMPLE_CONFIG_error_message_received_timeout,
	"SIMPLE_CONFIG_error_message_received_timeout",
	eap_configure_type_u32_t,
	false);

/**
 *  This hex data configuration option is the device password.
 *  Default value is empty. This must be configured in adaptation module.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_SIMPLE_CONFIG_device_password,
	"EAP_SIMPLE_CONFIG_device_password",
	eap_configure_type_hex_data,
	true);


/**
 *  This hex data configuration option is the server device password.
 *  Default value is empty. This is optional value for testing purposes.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_SIMPLE_CONFIG_server_device_password,
	"EAP_SIMPLE_CONFIG_server_device_password",
	eap_configure_type_hex_data,
	true);


/**
 *  This hex data configuration option is the new password on the Enrollee.
 *  Default value is empty. This is optional.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_SIMPLE_CONFIG_new_password,
	"SIMPLE_CONFIG_new_password",
	eap_configure_type_hex_data,
	true);


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
	cf_str_EAP_SIMPLE_CONFIG_use_random_identity_on_eap_identity_response,
	"EAP_SIMPLE_CONFIG_use_random_identity_on_eap_identity_response",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * This is used in simulator testing.
 * True value means queries to AM are completed asyncronous.
 * False value means queries to AM are completed syncronous.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_SIMPLE_CONFIG_do_asyncronous_completions,
	"EAP_SIMPLE_CONFIG_do_asyncronous_completions",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * This is used in simulator testing.
 * True value means queries to AM are randomly completed asyncronous.
 * False value means queries to AM are randomly completed syncronous.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_SIMPLE_CONFIG_do_asyncronous_completions_randomly,
	"EAP_SIMPLE_CONFIG_do_asyncronous_completions_randomly",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * This is used in simulator testing.
 * True value means queries to AM are randomly failed.
 * False value means queries to AM are randomly failed.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_SIMPLE_CONFIG_fail_registration_randomly,
	"EAP_SIMPLE_CONFIG_fail_registration_randomly",
	eap_configure_type_boolean,
	false);

/**
 * This is u32_t configuration option.
 * This is used in simulator testing.
 * Value is the maximum completion time (ms) when completitions are
 * completed randomly.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_SIMPLE_CONFIG_max_simple_config_completion_time,
	"EAP_SIMPLE_CONFIG_max_simple_config_completion_time",
	eap_configure_type_u32_t,
	false);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

/**
 *  This hex data configuration option is the Network Key on the Enrollee.
 *  Default value is empty. This is optional.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_SIMPLE_CONFIG_network_key,
	"SIMPLE_CONFIG_network_key",
	eap_configure_type_hex_data,
	true);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

/**
 *  This hex data configuration option is the Authentication Type on the Enrollee.
 *  Default value is empty. This is optional.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_SIMPLE_CONFIG_authentication_type,
	"SIMPLE_CONFIG_authentication_type",
	eap_configure_type_string,
	true);

EAP_CONFIGURATION_FIELD(
	cf_str_SIMPLE_CONFIG_authentication_type_None,
	"None",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_SIMPLE_CONFIG_authentication_type_Open,
	"Open",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_SIMPLE_CONFIG_authentication_type_WPAPSK,
	"WPAPSK",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_SIMPLE_CONFIG_authentication_type_Shared,
	"Shared",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_SIMPLE_CONFIG_authentication_type_WPA,
	"WPA",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_SIMPLE_CONFIG_authentication_type_WPA2,
	"WPA2",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_SIMPLE_CONFIG_authentication_type_WPA2PSK,
	"WPA2PSK",
	eap_configure_type_string,
	false);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

/** @} */ // End of group EAP_SIMPLE_CONFIG_config_options.

//--------------------------------------------------


#endif //#if !defined(_EAP_TYPE_SIMPLE_CONFIG_TYPES_H_)

//--------------------------------------------------



// End.
