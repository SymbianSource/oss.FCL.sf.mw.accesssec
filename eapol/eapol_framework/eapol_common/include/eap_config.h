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

#if !defined(_EAP_CONFIG_H_)
#define _EAP_CONFIG_H_

#include "eap_configuration_field.h"


enum eap_type_default_constants_e
{
	eap_type_default_credential_timeout = 43200000, ///< Default timeout of EAP credentials is 12 hours = 43200000 milli seconds.
};

//--------------------------------------------------------------------------------------------------

/**
 *  @defgroup Common_EAP_config_options Common configuration options of EAP.
 *  The following configuration options are read through abs_eap_base_type_c::read_configure() function.
 *  @{
 */



EAP_CONFIGURATION_FIELD(
	cf_str_EAP_access_point_name,
	"EAP_access_point_name",
	eap_configure_type_section,
	false);


/**
 *  This u32_t or hex data configuration option selects the default EAP type.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_default_type_hex_data,
	"EAP_default_type",
	eap_configure_type_hex_data,
	false);
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_default_type_u32_t,
	"EAP_default_type",
	eap_configure_type_u32_t,
	false);

/**
 *  This string configuration option sets the additional routing realms 
 *  to the NAI of EAP Identity-Response of the outer EAP method. The format of 
 *  the string must be "realm1!realm2!realm3" in which realm1 is the first 
 *  location in the route. The NAI becomes "realm2!realm3!homerealm!username@realm1".
 *  See RFC4242 for more info. Default value is an empty string.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_outer_identity_routing,
	"EAP_outer_identity_routing",
	eap_configure_type_string,
	false);

/**
 *  This string configuration option sets the additional NAI decoration 
 *  to the NAI of EAP Identity-Response of the outer EAP method. The given 
 *  string (e.g. "{decoration}") is placed as such in front of the username. 
 *  The NAI becomes "{decoration}username@realm". See RFC4242 for more info. 
 *  Default value is an empty string.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_outer_identity_decoration,
	"EAP_outer_identity_decoration",
	eap_configure_type_string,
	false);

/**
 *  This u32_t or hex data configuration option selects the default EAP type of EAP-server.
 *  Reason for this is we could test EAP-Core in a case where
 *  EAP-client and EAP-server have different default EAP-types.
 *  If this is not defined EAP-server uses EAP_default_type option.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_server_default_type_hex_data,
	"EAP_server_default_type",
	eap_configure_type_hex_data,
	false);
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_server_default_type_u32_t,
	"EAP_server_default_type",
	eap_configure_type_u32_t,
	false);

/**
 *  This boolean configuration option enables EAP-Nak message handling immediately with true value.
 *  False value means EAP-Nak is prosessed after a timeout.
 *  Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_CORE_process_EAP_Nak_immediately,
	"EAP_CORE_process_EAP_Nak_immediately",
	eap_configure_type_boolean,
	false);

/**
 *  This boolean configuration option disables EAP traces with true value.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TRACE_disable_traces,
	"EAP_TRACE_disable_traces",
	eap_configure_type_boolean,
	false);

/**
 *  This boolean configuration option enables EAP function traces with true value.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TRACE_enable_function_traces,
	"EAP_TRACE_enable_function_traces",
	eap_configure_type_boolean,
	false);

/**
 *  This boolean configuration option enables EAP timer traces with true value.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TRACE_enable_timer_traces,
	"EAP_TRACE_enable_timer_traces",
	eap_configure_type_boolean,
	false);

/**
 *  This boolean configuration option enables EAP timer queue traces with true value.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TRACE_enable_timer_queue_traces,
	"EAP_TRACE_enable_timer_queue_traces",
	eap_configure_type_boolean,
	false);


/**
 *  This boolean configuration option enables EAP OK return traces with true value.
 *  There will be a lot of traces.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TRACE_enable_ok_return_traces,
	"EAP_TRACE_enable_ok_return_traces",
	eap_configure_type_boolean,
	false);

/**
 *  This boolean configuration option enables EAP message data traces with true value.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TRACE_enable_message_data_traces,
	"EAP_TRACE_enable_message_data_traces",
	eap_configure_type_boolean,
	false);

/**
 *  This boolean configuration option enables EAP core map traces with true value.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TRACE_enable_core_map_traces,
	"EAP_TRACE_enable_core_map_traces",
	eap_configure_type_boolean,
	false);

/**
 *  This boolean configuration option enables test vector traces.
 *  True value means only test vector traces of each EAP-type are traced.
 *  False value does not change traces.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TRACE_only_test_vectors,
	"EAP_TRACE_only_test_vectors",
	eap_configure_type_boolean,
	false);

/**
 *  This boolean configuration option enables test vector traces of SHA1.
 *  True value means SHA1 test vector traces are traced.
 *  False value does not change traces.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TRACE_crypto_test_vectors_sha1,
	"EAP_TRACE_crypto_test_vectors_sha1",
	eap_configure_type_boolean,
	false);

/**
 *  This boolean configuration option enables test vector traces of RC4.
 *  True value means RC4 test vector traces are traced.
 *  False value does not change traces.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TRACE_crypto_test_vectors_rc4,
	"EAP_TRACE_crypto_test_vectors_rc4",
	eap_configure_type_boolean,
	false);

/**
 *  This boolean configuration option enables test vector traces of MD4.
 *  True value means MD4 test vector traces are traced.
 *  False value does not change traces.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TRACE_crypto_test_vectors_md4,
	"EAP_TRACE_crypto_test_vectors_md4",
	eap_configure_type_boolean,
	false);

/**
 *  This boolean configuration option enables test vector traces of test random generator.
 *  True value means test random generator test vector traces are traced.
 *  Note this activates EAP_TRACE_crypto_test_vectors_sha1 traces too.
 *  False value does not change traces.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TRACE_crypto_test_vectors_test_random,
	"EAP_TRACE_crypto_test_vectors_test_random",
	eap_configure_type_boolean,
	false);

/**
 *  This boolean configuration option enables only message traces with true value.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TRACE_only_trace_messages,
	"EAP_TRACE_only_trace_messages",
	eap_configure_type_boolean,
	false);

/**
 * This boolean configuration option with true value enables only
 * always active traces and error traces.
 * set_trace_mask(eap_trace_mask_always|eap_trace_mask_error).
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TRACE_activate_only_trace_masks_always_and_error,
	"EAP_TRACE_activate_only_trace_masks_always_and_error",
	eap_configure_type_boolean,
	false);

/**
 *  This boolean configuration option with true value enables activation of traces
 *  when error occurs.
 *  Look at the set_activate_trace_on_error() and eap_status_return()
 *  functions. NOTE the always active traces are only left active.
 *  That means set_activate_trace_on_error() function calls
 *  set_trace_mask(eap_trace_mask_always).
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TRACE_activate_trace_on_error,
	"EAP_TRACE_activate_trace_on_error",
	eap_configure_type_boolean,
	false);


#if defined(USE_EAP_ERROR_TESTS)

/**
 *  This variable is true (1) or false (0).
 *  True value means simulator EAP AM randomly drop send packets.
 *  False value means simulator EAP AM does not drop send packets.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_ERROR_TEST_randomly_drop_packets,
	"EAP_ERROR_TEST_randomly_drop_packets",
	eap_configure_type_boolean,
	false);

/**
 *  This u32_t configuration option selects probability of packet drop.
 *  Probability is EAP_ERROR_TEST_randomly_drop_packets_probability/(2^32).
 *  for example 8000000/(2^32) is about 0.00186.
 *  Value (2^32)=4294967295 gives probability 1, eg. every packet is dropped.
 *  Default value is 0, which means no packets are dropped.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_ERROR_TEST_randomly_drop_packets_probability,
	"EAP_ERROR_TEST_randomly_drop_packets_probability",
	eap_configure_type_u32_t,
	false);

/**
 *  This variable is true (1) or false (0).
 *  True value means simulator EAP AM activates random errors to send packets.
 *  False value means simulator EAP AM disables random errors to send packets.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_ERROR_TEST_enable_random_errors,
	"EAP_ERROR_TEST_enable_random_errors",
	eap_configure_type_boolean,
	false);

/**
 *  This boolean configuration option value true selects the original EAP-packet
 *  is sent first when EAP-packet randon error generation is enabled.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_ERROR_TEST_send_original_packet_first,
	"EAP_ERROR_TEST_send_original_packet_first",
	eap_configure_type_boolean,
	false);

/**
 *  This u32_t configuration option selects how many additional error packet are generated.
 *  Default value is 0, which means one error packet.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_ERROR_TEST_generate_multiple_error_packets,
	"EAP_ERROR_TEST_generate_multiple_error_packets",
	eap_configure_type_u32_t,
	false);

/**
 *  This boolean configuration option enables random error generation to ethernet packet with true value.
 *  True value means simulator EAP AM manipulates ethernet header with random errors.
 *  False value means simulator EAP AM does not manipulate ethernet header with random errors.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_ERROR_TEST_manipulate_ethernet_header,
	"EAP_ERROR_TEST_manipulate_ethernet_header",
	eap_configure_type_boolean,
	false);

/**
 *  This boolean configuration option enables random error generation to EAPOL packet with true value.
 *  True value means simulator EAP AM manipulates EAPOL header with random errors.
 *  False value means simulator EAP AM does not manipulate EAPOL header with random errors.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_ERROR_TEST_manipulate_eapol_header,
	"EAP_ERROR_TEST_manipulate_eapol_header",
	eap_configure_type_boolean,
	false);

/**
 *  This boolean configuration option enables random error generation only to EAPOL-Key packets with true value.
 *  True value means simulator EAP AM manipulates only EAPOL-Key packets with random errors.
 *  False value means simulator EAP AM does manipulate other packets too with random errors.
 *  This option works only when EAP_ERROR_TEST_enable_random_errors is true.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_ERROR_TEST_manipulate_only_eapol_key_messages,
	"EAP_ERROR_TEST_manipulate_only_eapol_key_messages",
	eap_configure_type_boolean,
	false);

/**
 * This variable is true (1) or false (0).
 * This boolean configuration option enables random error generation only to tunneled PEAP packets with true value.
 * True value means tls_application_eap_core_c manipulates only PEAP tunneled packets with random errors.
 * False value means simulator EAP AM does manipulate other packets too with random errors.
 * This option works only when EAP_ERROR_TEST_enable_random_errors is true.
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_ERROR_TEST_manipulate_only_tunneled_messages,
	"EAP_ERROR_TEST_manipulate_only_tunneled_messages",
	eap_configure_type_boolean,
	false);

/**
 *  This u32_t configuration option selects probability of errors generated.
 *  Probability is EAP_ERROR_TEST_error_probability/(2^32).
 *  for example 8000000/(2^32) is about 0.00186.
 *  Value (2^32)=4294967295 gives probability 1, eg. error is generated to every byte.
 *  Default value is 0, which means no errors.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_ERROR_TEST_error_probability,
	"EAP_ERROR_TEST_error_probability",
	eap_configure_type_u32_t,
	false);

#endif //#if defined(USE_EAP_ERROR_TESTS)


/**
 *  This string configuration option selects file and path name of trace log file.
 *  Default value is /tmp/eap_core.log.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TRACE_output_file_name,
	"EAP_TRACE_output_file_name",
	eap_configure_type_string,
	false);

/**
 *  This u32_t configuration option sets the maximum size of trace log file in bytes.
 *  Note this is not absolute value. New file is generated when size of trace log file
 *  exceeds this limitation.
 *  Default value is 100000000 bytes.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TRACE_max_trace_file_size,
	"EAP_TRACE_max_trace_file_size",
	eap_configure_type_u32_t,
	false);

/**
 *  This boolean configuration option value true activates random generator for test use.
 *  It does generate predictive pseudorandom data.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TEST_RANDOM_use_test_random_generator,
	"EAP_TEST_RANDOM_use_test_random_generator",
	eap_configure_type_boolean,
	false);

/**
 *  This boolean configuration option value true activates re-seeding of test random generator.
 *  It does generate unpredictive pseudorandom test data. Note this is just for testing.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TEST_RANDOM_use_test_random_reseeding,
	"EAP_TEST_RANDOM_use_test_random_reseeding",
	eap_configure_type_boolean,
	false);

/**
 *  This hex data configuration option value seed random generator for test use.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TEST_RANDOM_seed,
	"EAP_TEST_RANDOM_seed",
	eap_configure_type_hex_data,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_TEST_preshared_key,
	"EAPOL_TEST_preshared_key",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_TEST_override_wpa_psk,
	"EAPOL_TEST_override_wpa_psk",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_TEST_test_reassociation,
	"EAPOL_TEST_test_reassociation",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_TEST_test_reassociation_randomly,
	"EAPOL_TEST_test_reassociation_randomly",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_TEST_MTU,
	"EAPOL_TEST_MTU",
	eap_configure_type_u32_t,
	false);


EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_TEST_use_pmkid_in_ie,
	"EAPOL_TEST_use_pmkid_in_ie",
	eap_configure_type_boolean,
	false);


/**
 *  This hex data configuration option value client MAC address for test use.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_client_MAC_address,
	"EAP_client_MAC_address",
	eap_configure_type_hex_data,
	false);

/**
 *  This hex data configuration option value client MAC address for test use.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_server_MAC_address,
	"EAP_server_MAC_address",
	eap_configure_type_hex_data,
	false);


/**
 * This hex data or u32array configuration option value is list of EAP-types client accepts.
 * Values are hex data or u32array of EAP Expanded Type.
 * This is used in simulator testing.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_client_types_hex_data,
	"EAP_client_types",
	eap_configure_type_hex_data,
	false);
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_client_types_u32array,
	"EAP_client_types",
	eap_configure_type_u32array,
	false);

/**
 * This hex data or u32array configuration option value is list of EAP-types server accepts.
 * Values in the array are type of u32_t.
 * This is used in simulator testing.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_server_types_hex_data,
	"EAP_server_types",
	eap_configure_type_hex_data,
	false);
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_server_types_u32array,
	"EAP_server_types",
	eap_configure_type_u32array,
	false);

/**
 *  This u32_t configuration option selects maximum count of sent EAPOL-Start messages.
 *  Default value is EAPOL_CORE_MAX_EAPOL_START_SENDINGS.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_CORE_starts_max_count,
	"EAPOL_CORE_starts_max_count",
	eap_configure_type_u32_t,
	false);

/**
 *  This u32_t configuration option selects timeout between sent EAPOL-Start messages.
 *  Default value is EAPOL_CORE_TIMER_SEND_START_AGAIN_TIMEOUT.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_CORE_send_start_interval,
	"EAPOL_CORE_send_start_interval",
	eap_configure_type_u32_t,
	false);

/**
 *  This boolean configuration option enables test to skip start of 4-Way Handshake in server.
 *  This is for testing purposes.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_CORE_skip_start_4_way_handshake,
	"EAPOL_CORE_skip_start_4_way_handshake",
	eap_configure_type_boolean,
	false);

/**
 *  This u32_t configuration option set the timer resolution.
 *  Default value is EAP_TIMER_RESOLUTION.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TIMER_resolution,
	"EAP_TIMER_resolution",
	eap_configure_type_u32_t,
	false);

/**
 *  This boolean configuration option enables EAP milli second timer with true value.
 *  Note the AM must support this feature.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TIMER_use_eap_millisecond_timer,
	"EAP_TIMER_use_eap_millisecond_timer",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option. True value activates session re-use in eap_session_core_c.
 *  It optimises stack load by re-using the existing stack.
 *  False value creates always a new stack.
 *  Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_SESSION_use_reset_session,
	"EAP_SESSION_use_reset_session",
	eap_configure_type_boolean,
	false);

/**
 * This u32_t configuration option set the timeout value after the EAP-session is removed.
 * Default value is EAP_CORE_REMOVE_SESSION_TIMEOUT.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_CORE_remove_session_timeout,
	"EAP_CORE_remove_session_timeout",
	eap_configure_type_u32_t,
	false);

/**
 *  This is boolean configuration option. True value activates use of expanded EAP type field of 64-bits in length.
 *  False value forces to use the normal 8-bit EAP type field.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_CORE_use_eap_expanded_type,
	"EAP_CORE_use_eap_expanded_type",
	eap_configure_type_boolean,
	false);


#if defined(USE_EAP_MEMORY_FUNCTIONS) && defined(USE_EAP_MEMORY_FUNCTIONS_FAILURES)

/**
 * This u32_t configuration option sets the probability of memory failure.
 * Note you must define USE_EAP_MEMORY_FUNCTIONS and USE_EAP_MEMORY_FUNCTIONS_FAILURES
 * compiler flags in order to use this feature.
 * Probability is EAP_CORE_memory_alloc_failures_probability/(2^32).
 * for example 8000000/(2^32) is about 0.00186.
 * Value (2^32)=4294967295 gives probability 1, eg. every memory allocation fails.
 * Default value is 0, this means disabled.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_CORE_memory_alloc_failures_probability,
	"EAP_CORE_memory_alloc_failures_probability",
	eap_configure_type_u32_t,
	false);

/**
 * This u32_t configuration option sets the skip count of memory allocations before failures are generated.
 * Note you must define USE_EAP_MEMORY_FUNCTIONS and USE_EAP_MEMORY_FUNCTIONS_FAILURES
 * compiler flags in order to use this feature.
 * Default value is 0.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_CORE_memory_alloc_failures_skip_count,
	"EAP_CORE_memory_alloc_failures_skip_count",
	eap_configure_type_u32_t,
	false);

#endif //#if defined(USE_EAP_MEMORY_FUNCTIONS) && defined(USE_EAP_MEMORY_FUNCTIONS_FAILURES)


/**
 *  This boolean configuration option enables asyncronous test for EAPOL messages with true value.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_TEST_use_message_asyncronous_test,
	"EAPOL_TEST_use_message_asyncronous_test",
	eap_configure_type_boolean,
	false);


#if defined(USE_EAP_CONFIGURATION_TO_SKIP_USER_INTERACTIONS)
	/**
	 *  This boolean configuration option skips user interactions in selected test cases with true value.
	 *  Default value is false, then user interactions are enabled as normally.
	 */
	EAP_CONFIGURATION_FIELD(
		cf_str_EAP_skip_user_interactions_for_testing_purposes,
		"EAP_skip_user_interactions_for_testing_purposes",
		eap_configure_type_boolean,
		false);
#endif //#if defined(USE_EAP_CONFIGURATION_TO_SKIP_USER_INTERACTIONS)


/**
 *  This special configuration option reads all defines configuration options.
 *  Data is in message format. Please see eap_tlv_message_data_c.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_read_all_configurations,
	"EAP_read_all_configurations",
	eap_configure_type_all_configurations,
	false);


const u8_t EAP_WPS_CONFIGURATION_MEMORY_STORE_KEY[] = "eap_am_type_protected_setup shared key";

enum eap_type_protected_setup_stored_e
{
	eap_type_protected_setup_stored_none,
	eap_type_protected_setup_stored_preshared_key,
	eap_type_protected_setup_stored_ssid,
};


/** @} */ // End of group Common_EAP_config_options.

//--------------------------------------------------------------------------------------------------

/**
 *  @defgroup Common_EAP_RAS_config_options Common EAP RAS configuration options.
 *  The following configuration options are read through abs_eap_base_type_c::read_configure() function.
 *  @{
 */

/**
 *  This is boolean configuration option.
 *  True value means windows RAS AM sends Windows user name in EAP-Response/Identity.
 *  False value means windows RAS AM sends <GSMSIM identity>@realm in EAP-Response/Identity.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_RAS_use_windows_username,
	"EAP_RAS_use_windows_username",
	eap_configure_type_boolean,
	false);

/**
 *  This string configuration option is used in testing. It is the windows RAS username.
 *  This is used only when EAP_RAS_use_windows_username option is true.
 *  Default value is empty string.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_RAS_windows_username,
	"EAP_RAS_windows_username",
	eap_configure_type_string,
	false);

/**
 *  This is boolean configuration option.
 *  True value means windows RAS AM prompt user when authentication starts.
 *  False value means windows RAS AM does not prompt user.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_RAS_enable_prompt,
	"EAP_RAS_enable_prompt",
	eap_configure_type_boolean,
	false);

/**
 *  This string configuration option stores the latest IMSI used.
 *  Default value is empty string.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_RAS_latest_imsi,
	"EAP_RAS_latest_imsi",
	eap_configure_type_string,
	false);

/**
 *  This string configuration option stores the latest SSID used.
 *  Default value is empty string.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_RAS_latest_ssid,
	"EAP_RAS_latest_ssid",
	eap_configure_type_string,
	false);

/**
 *  This is u32_t configuration option.
 *  Value is limiter for authentication prompt.
 *  Maximum time without prompting for authentication if the SSID hasn't changed.
 *  Default value is 0, which means no limitation.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_RAS_prompt_threshold,
	"EAP_RAS_prompt_threshold",
	eap_configure_type_u32_t,
	false);

/**
 *  This is u32_t configuration option.
 *  Value is time stamp of last authentication.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_RAS_timestamp,
	"EAP_RAS_timestamp",
	eap_configure_type_u32_t,
	false);

/** @} */ // End of group Common_EAP_RAS_config_options.

//--------------------------------------------------------------------------------------------------


#endif //#if !defined(_EAP_CONFIG_H_)

//--------------------------------------------------



// End.
