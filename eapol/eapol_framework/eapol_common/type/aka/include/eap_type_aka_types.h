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
* %version: 22.1.2 %
*/

#if !defined(_AKA_TYPES_H_)
#define _AKA_TYPES_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TYPE_AKA_TYPES_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_AKA_TYPES_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_TYPES_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_AKA_TYPES_H 
	#define EAP_FUNC_EXPORT_EAP_TYPE_AKA_TYPES_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_AKA_TYPES_H 
#elif defined(EAP_EXPORT_EAP_TYPE_AKA_TYPES_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_AKA_TYPES_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_TYPES_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_AKA_TYPES_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_AKA_TYPES_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_AKA_TYPES_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_AKA_TYPES_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_TYPES_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_AKA_TYPES_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_AKA_TYPES_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_AKA_TYPES_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_type_aka_header.h"
#include "eap_type_all_types.h"
#include "eap_configuration_field.h"

/** @file eap_type_aka_types.h 
 *  @brief This file defines the constants of the AKA EAP type.
 */

/**
 * This is the internal state of the AKA EAP type.
 */
enum eap_type_aka_state_variable_e
{
	eap_type_aka_state_none                                                         , ///< State state_none

	eap_type_aka_state_waiting_for_identity_request                                 , ///< Client state waiting_for_identity_request
	eap_type_aka_state_pending_identity_query                                       , ///< Client state pending_identity_query
	eap_type_aka_state_waiting_for_aka_identity_request                             , ///< Client state imsi_waiting_for_aka_identity_request
	eap_type_aka_state_imsi_waiting_for_aka_identity_request                        , ///< Client state imsi_waiting_for_aka_identity_request
	eap_type_aka_state_pseydonym_waiting_for_aka_identity_request                   , ///< Client state pseydonym_waiting_for_aka_identity_request
	eap_type_aka_state_analyse_aka_identity_request                                 , ///< Client state analyse_aka_identity_request
	eap_type_aka_state_waiting_for_challenge_request                                , ///< Client state waiting_for_challenge_request
	eap_type_aka_state_analyses_challenge_request                                   , ///< Client state analyses_challenge_request
	eap_type_aka_state_pending_kc_sres_query                                        , ///< Client state pending_kc_sres_query
	eap_type_aka_state_waiting_for_notification_request_success                     , ///< Client state waiting_for_notification_request_success
	eap_type_aka_state_waiting_for_success                                          , ///< Client state waiting_for_success
	eap_type_aka_state_waiting_for_reauth_request                                   , ///< Client state waiting_for_reauth_request
	eap_type_aka_state_analyses_reauthentication_request                            , ///< Client state analyses_reauthentication_request

	eap_type_aka_state_pending_pseudonym_decode_query                               , ///< Server state pending_pseudonym_decode_query
	eap_type_aka_state_waiting_for_identity_response                                , ///< Server state waiting_for_identity_response
	eap_type_aka_state_waiting_for_aka_identity_response_with_at_permanent_identity , ///< Server state waiting_for_aka_identity_response_with_at_permanen_identity
	eap_type_aka_state_waiting_for_aka_identity_response_with_at_full_auth_identity , ///< Server state waiting_for_aka_identity_response_with_at_identity
	eap_type_aka_state_waiting_for_aka_identity_response_with_at_any_identity       , ///< Server state waiting_for_aka_identity_response_with_at_identity
	eap_type_aka_state_waiting_for_aka_identity_response                            , ///< Server state waiting_for_aka_identity_response
	eap_type_aka_state_pending_re_syncronization_query                              , ///< Server state pending_re_syncronization_query
	eap_type_aka_state_waiting_for_challenge_response                               , ///< Server state waiting_for_challenge_response
	eap_type_aka_state_pending_authentication_vector_query                          , ///< Server state pending_authentication_vector_query
	eap_type_aka_state_analyses_challenge_response                                  , ///< Server state analyses_challenge_response
	eap_type_aka_state_analyses_aka_identity_response                               , ///< Server state analyses_aka_identity_response
	eap_type_aka_state_waiting_for_notification_response_failure                    , ///< Server state waiting_for_notification_response, authentication failed
	eap_type_aka_state_waiting_for_notification_response_success                    , ///< Server state waiting_for_notification_response, authentication success
	eap_type_aka_state_waiting_for_reauth_response                                  , ///< Server state waiting_for_reauth_response
	eap_type_aka_state_analyses_reauthentication_response                           , ///< Server state analyses_reauthentication_response

	eap_type_aka_state_success                                                      , ///< State state_success
	eap_type_aka_state_failure                                                      , ///< State state_failure

	eap_type_aka_state_last_value                                                     ///< Keep this enum the last one.
};


/**
 * This is the required completion after a asyncronous call.
 */
enum eap_type_aka_complete_e
{
	eap_type_aka_complete_none, ///< No completion required
	eap_type_aka_complete_aka_identity_request, ///< AKA start request must be completed
	eap_type_aka_complete_query_eap_identity, ///< AKA EAP-identity query must be completed
	eap_type_aka_complete_handle_imsi_from_username,
	eap_type_aka_complete_handle_aka_identity_response_message_completion,
};


/**
 * This is the status of the authentication_vector.
 */
enum eap_aka_authentication_vector_status_e
{
	eap_aka_authentication_vector_status_ok                                               =    0,
	eap_aka_authentication_vector_status_no_roaming_agreement                             = 1024, ///< No roaming agreement.
	eap_aka_authentication_vector_status_users_calls_are_barred                           = 1026, ///< User's calls are barred.
	eap_aka_authentication_vector_status_user_has_not_subscribed_to_the_requested_service = 1031, ///< User has not subrcibed to the requested service.
};


enum eap_aka_notification_codes_e
{
   eap_aka_notification_no_F_no_P_general_failure                                  =      0, ///< General failure. (implies failure, used after successful authentication)
   eap_aka_notification_no_F_P_set_general_failure                                 =  16384, ///< General failure. (implies failure, used before authentication)
   eap_aka_notification_F_set_no_P_user_authenticated                              =  32768, ///< User has been successfully authenticated. (does not imply failure, used after successful authentication). The usage of this code is discussed in Section 4.4.2.
   eap_aka_notification_no_F_no_P_users_calls_are_barred                           =   1026, ///< User has been temporarily denied access to the requested service. (Implies failure, used after successful authentication)
   eap_aka_notification_no_F_no_P_user_has_not_subscribed_to_the_requested_service =   1031, ///< User has not subscribed to the requested service (implies failure, used after successful authentication)
   eap_aka_notification_none                                                       = 0xffff, ///< No code.
};


enum aka_notification_code_bits_e
{
	aka_notification_code_bit_f = 0x8000,
	aka_notification_code_bit_p = 0x4000,
	aka_notification_code_value = 0x3FFF,
};


/** See eap_aka_authentication_vector_status_e. */
const u8_t EAP_AKA_NOTIFICATION_NO_ROAMING_AGREEMENT[]
	= "1024 Visited network does not have a roaming agreement with user's home operator";
/** See eap_aka_authentication_vector_status_e. */
const u8_t EAP_AKA_NOTIFICATION_USERS_CALLS_ARE_BARRED[]
	= "1026 User's calls are barred";
/** See eap_aka_authentication_vector_status_e. */
const u8_t EAP_AKA_NOTIFICATION_USER_HAS_NOT_SUBSCRIBED_TO_THE_REQUESTED_SERVICE[]
	= "1031 User has not subscribed to the requested service";

/**
 * This is the type of the AKA identity.
 */
enum eap_type_aka_identity_type
{
	AKA_IDENTITY_TYPE_NONE,
	AKA_IDENTITY_TYPE_IMSI_ID,
	AKA_IDENTITY_TYPE_PSEUDONYM_ID,
	AKA_IDENTITY_TYPE_RE_AUTH_ID,
};

enum eap_aka_authentication_type_e
{
	AKA_AUTHENTICATION_TYPE_NONE,
	AKA_AUTHENTICATION_TYPE_FULL_AUTH,
	AKA_AUTHENTICATION_TYPE_REAUTHENTICATION,
};

const u8_t AKA_IMSI_PREFIX_CHARACTER[] = "0";

const u32_t TRACE_FLAGS_AKA_ERROR = eap_am_tools_c::eap_trace_mask_error;

const u8_t AKA_AT_CHARACTER[] = "@";

const u8_t AKA_OWLAN_ORG_PREFIX_STRING[] = "wlan";
const u32_t AKA_OWLAN_ORG_PREFIX_STRING_LENGTH = sizeof(AKA_OWLAN_ORG_PREFIX_STRING)-1ul;

const u8_t AKA_UMA_PREFIX_STRING[] = "uma";
const u32_t AKA_UMA_PREFIX_STRING_LENGTH = sizeof(AKA_UMA_PREFIX_STRING)-1ul;

const u8_t AKA_OWLAN_MNC_STRING[] = "mnc";
const u32_t AKA_OWLAN_MNC_STRING_LENGTH = sizeof(AKA_OWLAN_MNC_STRING)-1ul;

const u8_t AKA_OWLAN_DOT_STRING[] = ".";
const u32_t AKA_OWLAN_DOT_STRING_LENGTH = sizeof(AKA_OWLAN_DOT_STRING)-1ul;

const u8_t AKA_OWLAN_MCC_STRING[] = "mcc";
const u32_t AKA_OWLAN_MCC_STRING_LENGTH = sizeof(AKA_OWLAN_MCC_STRING)-1ul;

const u8_t AKA_OWLAN_ORG_STRING[] = "3gppnetwork.org";
const u32_t AKA_OWLAN_ORG_STRING_LENGTH = sizeof(AKA_OWLAN_ORG_STRING)-1ul;


enum eap_type_aka_constants_e
{
	EAP_TYPE_AKA_NONCE_MT_SIZE = 16ul, ///< bytes = 128 bits
	EAP_TYPE_AKA_MAC_SIZE = 16ul, ///< bytes = 128 bits
	EAP_TYPE_AKA_KEYMAT_SIZE = 20ul, ///< bytes = 160 bits
	EAP_TYPE_AKA_MASTER_SESSION_KEY_SIZE = 4u*32ul, ///< bytes
	EAP_TYPE_AKA_MAX_NAI_LENGTH = 255ul, ///< bytes
	EAP_TYPE_AKA_MAX_USER_NAI_LENGTH = 255ul, ///< bytes
	EAP_TYPE_AKA_DEFAULT_MINIMUM_RAND_COUNT = 2ul, ///< count
	EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH = 512ul, ///< This is the size of the local send buffer.
	EAP_TYPE_AKA_PADDING_MODULUS = 4ul, ///< Padding length is always mudulus of 4.
	EAP_TYPE_AKA_PADDING_MAX_VALUE = 12ul, ///< Maximum padding length is 12 bytes.
	EAP_TYPE_AKA_MINIMUM_RAND_LENGTH = 16ul,
	EAP_TYPE_AKA_MINIMUM_AUTN_LENGTH = 16ul,
	EAP_TYPE_AKA_AUTS_LENGTH = 14ul,
	EAP_TYPE_AKA_CK_LENGTH = 16ul,
	EAP_TYPE_AKA_IK_LENGTH = 16ul,
	EAP_TYPE_AKA_MINIMUM_RES_LENGTH = 4ul,
	EAP_TYPE_AKA_MAXIMUM_CHECKCODE_LENGTH = 20ul,
	EAP_TYPE_AKA_INITIAL_REAUTH_COUNTER = 1ul,
	EAP_TYPE_AKA_DEFAULT_MNC_LENGTH_3_BYTES = 3ul,
	EAP_TYPE_AKA_MNC_LENGTH_2_BYTES = 2ul,
	EAP_TYPE_AKA_MNC_OFFSET = 3ul,
	EAP_TYPE_AKA_MCC_LENGTH = 3ul,
	EAP_TYPE_AKA_MCC_OFFSET = 0ul,
	EAP_TYPE_AKA_MINIMUM_IMSI_LENGTH = EAP_TYPE_AKA_MCC_LENGTH+EAP_TYPE_AKA_MNC_LENGTH_2_BYTES+1,
};

enum eap_type_aka_timer_id_e
{
	EAP_TYPE_AKA_TIMER_DELAY_FAILURE_MESSAGE_SENT_ID,
	EAP_TYPE_AKA_TIMER_DELAY_NOTIFICATION_MESSAGE_ID,
};

enum eap_type_aka_timer_timeout_value_e
{
	EAP_TYPE_AKA_TIMER_TIMEOUT_VALUE_DELAY_FAILURE_MESSAGE_SENT = 0ul, ///< This is the default value. Zero means error message is handled immediately.
};

enum eap_type_aka_stored_e
{
	eap_type_aka_stored_none,
	eap_type_aka_stored_reauth_xkey,
	eap_type_aka_stored_reauth_k_aut,
	eap_type_aka_stored_reauth_k_encr,
	eap_type_aka_stored_pseudonym_identity,
	eap_type_aka_stored_reauth_identity,
	eap_type_aka_stored_pseudonym_key,
	eap_type_aka_stored_pseudonym_mac_key,
	eap_type_aka_stored_prev_pseudonym_key,
	eap_type_aka_stored_prev_pseudonym_mac_key,
	eap_type_aka_stored_pseudonym_key_index,
	eap_type_aka_stored_pseudonym_key_use_count,
	eap_type_aka_stored_pseudonym_use_count,
	eap_type_aka_stored_reauth_use_count,
	eap_type_aka_stored_saved_reauth_counter,
	eap_type_aka_stored_sqn,
};


/**
 *  @defgroup AKA_config_options Configuration options of AKA.
 *  The following configuration options are read through abs_eap_base_type_c::read_configure() function.
 *  @{
 */

/**
 *  This u32_t configuration option is timeout in milli seconds before erroneous message is processed.
 *  This is useful in protocol testing or if some delay is needed in final application.
 *  Default value is 0.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_failure_message_delay_time,
	"EAP_AKA_failure_message_delay_time",
	eap_configure_type_u32_t,
	false);

/**
 *  This boolean configuration option specifies whether the username should
 *  be generated automatically. 
 *  Default value is 0. That will cause use of automatic username. If this is 1
 *  then cf_str_EAP_AKA_manual_username is used as the username.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_use_manual_username,
	"EAP_AKA_use_manual_username",
	eap_configure_type_boolean,
	false);

/**
 *  This string configuration option is the username part of EAP-type AKA identity.
 *  Default value is empty string. That will cause use of automatic username.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_manual_username,
	"EAP_AKA_manual_username",
	eap_configure_type_string,
	false);

/**
 *  This boolean configuration option specifies whether the realm should
 *  be generated automatically. 
 *  Default value is 0. That will cause use of automatic realm. If this is 1
 *  then cf_str_EAP_AKA_manual_realm is used as the realm.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_use_manual_realm,
	"EAP_AKA_use_manual_realm",
	eap_configure_type_boolean,
	false);

/**
 *  This string configuration option is the realm part of EAP-type AKA identity.
 *  Default value is empty string. That will cause use of automatic realm.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_manual_realm,
	"EAP_AKA_manual_realm",
	eap_configure_type_string,
	false);

/**
 *  This is boolean configuration option.
 *  True value means on successfull authentication EAP-type AKA waits the EAP-Success message.
 *  False value means on successfull authentication EAP-type AKA does NOT wait the EAP-Success message.
 *  NOTE: True value is needed in Windows RAS.
 *  Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_wait_eap_success_packet,
	"EAP_AKA_wait_eap_success_packet",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  True value means on EAP-type AKA must check identifier of EAP-Response/Identity message.
 *  False value means on EAP-type AKA does not check identifier of EAP-Response/Identity message.
 *  This is not possible in cases where identifier of the EAP-Request/Identity is generated by other network entities.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_check_identifier_of_eap_identity_response,
	"EAP_AKA_check_identifier_of_eap_identity_response",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  This flag activates NAI realm check. Default value is false.
 *  When active NAI realm muts be the same as realm given by EAP_AKA_manual_realm option.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_check_nai_realm,
	"EAP_AKA_check_nai_realm",
	eap_configure_type_boolean,
	false);

/**
 *  This is for testing.
 *  This string configuration option is the full path name of the nonce_mt file.
 *  Default value is empty string.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_nonce_mt_file,
	"EAP_AKA_nonce_mt_file",
	eap_configure_type_string,
	false);

/**
 *  This is for testing.
 *  This string configuration option is the full path name of the triplet file.
 *  Default value is empty string.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_authentication_vector_file,
	"EAP_AKA_authentication_vector_file",
	eap_configure_type_string,
	false);

/**
 *  This is for testing.
 *  This string configuration option is the full path name of the pseudonym file.
 *  Default value is empty string.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_pseudonym_file,
	"EAP_AKA_pseudonym_file",
	eap_configure_type_string,
	false);

/**
 *  This is for testing.
 *  This string configuration option is the full path name of the reauthentication file.
 *  Default value is empty string.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_reauthentication_file,
	"EAP_AKA_reauthentication_file",
	eap_configure_type_string,
	false);

/**
 *  This is for testing.
 *  This string configuration option is the full path name of the encryption IV file.
 *  Default value is empty string.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_encryption_iv_file,
	"EAP_AKA_encryption_iv_file",
	eap_configure_type_string,
	false);

/**
 *  This is boolean configuration option.
 *  True value means client of EAP-type AKA responds to every re-transmitted EAP-AKA request packets.
 *  False value means client of EAP-type AKA does not respond to any re-transmitted EAP-AKA request packets,
 *  instead the EAP layer does re-transmit the response.
 *  The default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_client_responds_retransmitted_packets,
	"EAP_AKA_client_responds_retransmitted_packets",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  This is for testing.
 *  True value means test version of EAP-type AKA is used.
 *  Test version tries to make as many authentications as it is possible.
 *  False value means on real version of EAP-type AKA is used.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_test_version,
	"EAP_AKA_test_version",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  This is for testing.
 *  True value means server refuses EAP-identity randomly.
 *  False value means does not refuse EAP-identity randomly.
 *  NOTE EAP_AKA_test_version option must be true also.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_randomly_refuse_eap_identity,
	"EAP_AKA_randomly_refuse_eap_identity",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  True value means on test of re-authentication counter of EAP-type AKA will fail always.
 *  NOTE EAP_AKA_test_version option must be true also.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_fail_re_authentication_counter_check,
	"EAP_AKA_fail_re_authentication_counter_check",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  True value of this flag allows server accept the EAP-Response/Identity message.
 *  False value does not allow server accept the EAP-Response/Identity message.
 *  Instead server queries identity in EAP-Request/AKA/Start with AT_ANY_ID_REQ attribute.
 *  Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_accept_eap_identity_response,
	"EAP_AKA_accept_eap_identity_response",
	eap_configure_type_boolean,
	false);

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
	cf_str_EAP_AKA_use_random_identity_on_eap_identity_response,
	"EAP_AKA_use_random_identity_on_eap_identity_response",
	eap_configure_type_boolean,
	false);

/**
 * This is string configuration option.
 * This option selects the AKA algorithm used in akaulation.
 * Possible values are "nokia_test_network_xor" or "tls_prf_with_shared_secret".
 * The default value is nokia_test_network_xor.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_simulator_aka_algorithm,
	"EAP_AKA_simulator_aka_algorithm",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_simulator_aka_algorithm_config_value_nokia_test_network_xor,
	"nokia_test_network_xor",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_simulator_aka_algorithm_config_value_tls_prf_with_shared_secret,
	"tls_prf_with_shared_secret",
	eap_configure_type_string,
	false);

/**
 * This is hex data configuration option.
 * This Ki is used in software-AKA (SW-AKA) implementation of MILENAGE algorithm.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_simulator_aka_k,
	"EAP_AKA_simulator_aka_k",
	eap_configure_type_hex_data,
	false);

/**
 * This is hex data configuration option.
 * This OP is used in software-AKA (SW-AKA) implementation of MILENAGE algorithm.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_simulator_aka_op,
	"EAP_AKA_simulator_aka_op",
	eap_configure_type_hex_data,
	false);

/**
 * This is 16-bit hex data configuration option.
 * This AMF is used in software-AKA (SW-AKA) implementation of MILENAGE algorithm.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_simulator_aka_amf,
	"EAP_AKA_simulator_aka_amf",
	eap_configure_type_hex_data,
	false);

/**
 * This is boolean configuration option.
 * This flag tells whether the random synchronization errors
 * of MILENAGE algorithm must be done (true) or not (false).
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_simulator_aka_do_random_synchronization_errors,
	"EAP_AKA_simulator_aka_do_random_synchronization_errors",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * This flag tells whether the pseudonym identity could be used (true) or not (false).
 * Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_use_pseudonym_identity,
	"EAP_AKA_use_pseudonym_identity",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * This flag tells whether the re-authentication identity could be used (true) or not (false).
 * Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_use_reauthentication_identity,
	"EAP_AKA_use_reauthentication_identity",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * This is used in simulator testing.
 * True value means queries to AM are completed asyncronous.
 * False value means queries to AM are completed syncronous.
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_do_asyncronous_completions,
	"EAP_AKA_do_asyncronous_completions",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * This is used in simulator testing.
 * True value means authentication_vector queries to AM are failed randomly.
 * False value means authentication_vector queries to AM are not failed.
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_fail_AKA_authentication_vector_query_randomly,
	"EAP_AKA_fail_AKA_authentication_vector_query_randomly",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * This is used in simulator testing.
 * True value means queries to AM are randomly completed asyncronous.
 * False value means queries to AM are randomly completed syncronous.
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_do_asyncronous_completions_randomly,
	"EAP_AKA_do_asyncronous_completions_randomly",
	eap_configure_type_boolean,
	false);


/**
 * This is boolean configuration option.
 * This is used in simulator testing.
 * True value means EAP-AKA server fails randomly successfull authentication.
 * False value means EAP-AKA server does NOT fail randomly successfull authentication.
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_randomly_fail_successfull_authentication,
	"EAP_AKA_randomly_fail_successfull_authentication",
	eap_configure_type_boolean,
	false);


/**
 * This is boolean configuration option.
 * This is used in simulator testing.
 * True value means EAP-AKA client and server allows result indications.
 * False value means EAP-AKA client and server does NOT allow result indications.
 * Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_allow_use_result_indication,
	"EAP_AKA_allow_use_result_indication",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option. True value activates use of expanded EAP type field of 64-bits in length.
 *  False value forces to use the normal 8-bit EAP type field.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_use_eap_expanded_type,
	"EAP_AKA_use_eap_expanded_type",
	eap_configure_type_boolean,
	false);


/**
 * This is boolean configuration option.
 * This is used in simulator testing.
 * True value means EAP-AKA server allows result indications.
 * False value means EAP-AKA server does NOT allow result indications.
 * NOTE this option over rides cf_str_EAP_AKA_allow_use_result_indication
 * in server.
 * Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_server_allow_use_result_indication,
	"EAP_AKA_server_allow_use_result_indication",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * This flag tells whether the UMA profile is used (true) or not (false).
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_UMA_profile,
	"EAP_AKA_UMA_profile",
	eap_configure_type_boolean,
	false);

/**
 * This is string configuration option.
 * The string is the prefix of automatic realm in the UMA profile.
 * Note also the EAP_AKA_UMA_profile must be true before
 * this option is used.
 * Default value is empty.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_UMA_realm_prefix,
	"EAP_AKA_UMA_realm_prefix",
	eap_configure_type_string,
	false);

/**
 *  This u32_t array configuration option is includes those MCCs that uses 2 digit MNC.
 *  Default value is empty array.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_2_digit_mnc_map_of_mcc_of_imsi_array,
	"EAP_AKA_GSMSIM_2_digit_mnc_map_of_mcc_of_imsi_array",
	eap_configure_type_u32array,
	false);

/**
 * This is boolean configuration option.
 * This is used in simulator testing.
 * True value means EAP-AKA server randomly skip pseudonym and fast-reauth identity generation.
 * False value means EAP-AKA server does generate those identities.
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_server_randomly_skip_identity_generation,
	"EAP_AKA_server_randomly_skip_identity_generation",
	eap_configure_type_boolean,
	false);

/**
 *  This u32_t configuration value specifies the maximum session validity time in seconds.
 *  Default value is 12 hours in seconds, which is 43200 seconds.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_AKA_max_session_validity_time,
	"EAP_AKA_max_session_validity_time",
	eap_configure_type_u32_t,
	false);

/** @} */ // End of group AKA_config_options.

//--------------------------------------------------

/// Macro traces payload type and data.
#define EAP_AKA_TRACE_PAYLOAD(prefix, payload) \
	{ \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("%s (0x%08x): current payload 0x%04x=%s, data length 0x%04x.\n"), \
			prefix, (payload)->get_header_buffer((payload)->get_payload_length()), (payload)->get_current_payload(), \
			(payload)->get_payload_AT_string(), (payload)->get_data_length())); \
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, (EAPL("payload"), \
			(payload)->get_header_buffer((payload)->get_payload_length()), \
			(payload)->get_payload_length())); \
	}

//--------------------------------------------------


/// These are the stored attributes for message authentication calculations.
class EAP_CLASS_VISIBILITY_EAP_TYPE_AKA_TYPES_H eap_type_aka_MAC_attributes_c
{
private:
	//--------------------------------------------------

	u8_t * m_MAC;                       ///< This is the pointer to MAC.
	u32_t m_MAC_size;                   ///< This is the size of the MAC.
	u8_t *m_data;                       ///< This is the pointer to the authenticated data. 
	u32_t m_data_length;                ///< This the length of the authenticated data.

	//--------------------------------------------------
public:
	//--------------------------------------------------

	virtual ~eap_type_aka_MAC_attributes_c();

	eap_type_aka_MAC_attributes_c();

	eap_type_aka_MAC_attributes_c(
		u8_t * MAC,
		u32_t MAC_size,
		u8_t * const EAP_data,
		u32_t EAP_data_length);

	void init(
		u8_t * MAC,
		u32_t MAC_size,
		u8_t * const EAP_data,
		u32_t EAP_data_length);

	u8_t * get_MAC() const;

	void set_MAC(u8_t * MAC);

	u32_t get_MAC_size() const;

	eap_type_aka_MAC_attributes_c * copy() const;

	u8_t * get_data() const;

	u32_t get_data_length();

	void set_data(u8_t * const data);

	//--------------------------------------------------
};


#endif //#if !defined(_AKA_TYPES_H_)

//--------------------------------------------------



// End.
