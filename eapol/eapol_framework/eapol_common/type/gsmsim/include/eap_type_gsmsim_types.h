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

#if !defined(_GSMSIM_TYPES_H_)
#define _GSMSIM_TYPES_H_

#include "eap_type_all_types.h"
#include "eap_configuration_field.h"

/** @file eap_type_gsmsim_types.h 
 *  @brief This file defines the constants of the GSMSIM EAP type.
 */

const u32_t GSMSIM_FIRST_SEQUENCE = 1u;
const u32_t GSMSIM_PAYLOAD_LENGTH_ALIGN = 4u;
const u32_t GSMSIM_PAYLOAD_ZERO_DATA_LENGTH = 0u;
const u8_t GSMSIM_NAI_AT_BYTE = '@';


enum eap_gsmsim_version
{
	GSMSIM_ILLEGAL_VERSION = 0x0000,
	GSMSIM_VERSION_1       = 0x0001,
	GSMSIM_LAST_VERSION    = 0x0001, ///< Keep this same as the last acceptable version.
};


enum gsmsim_subtype_e
{
	gsmsim_subtype_NONE              =  0,
	gsmsim_subtype_Start             = 10,
	gsmsim_subtype_Challenge         = 11,
	gsmsim_subtype_Notification      = 12,
	gsmsim_subtype_Re_authentication = 13,
	gsmsim_subtype_Client_Error      = 14,
};

enum gsmsim_payload_AT_type_e
{
	gsmsim_payload_NONE                      =   0,

	gsmsim_payload_AT_RAND                   =   1,
	gsmsim_payload_AT_PADDING                =   6,
	gsmsim_payload_AT_NONCE_MT               =   7,
	gsmsim_payload_AT_PERMANENT_ID_REQ       =  10,
	gsmsim_payload_AT_MAC                    =  11,
	gsmsim_payload_AT_NOTIFICATION           =  12,
	gsmsim_payload_AT_ANY_ID_REQ             =  13,
	gsmsim_payload_AT_IDENTITY               =  14,
	gsmsim_payload_AT_VERSION_LIST           =  15,
	gsmsim_payload_AT_SELECTED_VERSION       =  16,
	gsmsim_payload_AT_FULLAUTH_ID_REQ        =  17,
	gsmsim_payload_AT_COUNTER                =  19,
	gsmsim_payload_AT_COUNTER_TOO_SMALL      =  20,
	gsmsim_payload_AT_NONCE_S                =  21,
	gsmsim_payload_AT_CLIENT_ERROR_CODE      =  22,

	gsmsim_payload_AT_IV                     = 129,
	gsmsim_payload_AT_ENCR_DATA              = 130,
	gsmsim_payload_AT_NEXT_PSEUDONYM         = 132,
	gsmsim_payload_AT_NEXT_REAUTH_ID         = 133,
	gsmsim_payload_AT_RESULT_IND             = 135,
};

enum eap_gsmsim_client_error_code_e
{
	eap_gsmsim_client_error_code_unable_to_process_packet          = 0,
	eap_gsmsim_client_error_code_unsupported_version               = 1,
	eap_gsmsim_client_error_code_insufficient_number_of_challenges = 2,
	eap_gsmsim_client_error_code_rands_are_not_fresh               = 3,
	eap_gsmsim_client_error_code_maximum_value                     = eap_gsmsim_client_error_code_rands_are_not_fresh,
	eap_gsmsim_client_error_code_none                              = 0xff,
};


/**
 * This is the internal state of the GSMSIM EAP type.
 */
enum eap_type_gsmsim_state_variable_e
{
	eap_type_gsmsim_state_none                                                  , ///< This is the initial state
	eap_type_gsmsim_state_waiting_for_identity_request                          , ///< Client state waiting_for_identity_request
	eap_type_gsmsim_state_pending_identity_query                                , ///< Client state pending_identity_query
	eap_type_gsmsim_state_waiting_for_start_request                             , ///< Client state imsi_waiting_for_start_request
	eap_type_gsmsim_state_imsi_waiting_for_start_request                        , ///< Client state imsi_waiting_for_start_request
	eap_type_gsmsim_state_pseydonym_waiting_for_start_request                   , ///< Client state pseydonym_waiting_for_start_request
	eap_type_gsmsim_state_analyse_start_request                                 , ///< Client state analyse_start_request
	eap_type_gsmsim_state_waiting_for_challenge_request                         , ///< Client state waiting_for_challenge_request
	eap_type_gsmsim_state_analyses_challenge_request                            , ///< Client state analyses_challenge_request
	eap_type_gsmsim_state_pending_kc_sres_query                                 , ///< Client state pending_kc_sres_query
	eap_type_gsmsim_state_waiting_for_notification_request_success              , ///< Client state waiting_for_notification_request_success
	eap_type_gsmsim_state_waiting_for_success                                   , ///< Client state waiting_for_success
	eap_type_gsmsim_state_waiting_for_reauth_request                            , ///< Client state waiting_for_reauth_request
	eap_type_gsmsim_state_analyses_reauthentication_request                     , ///< Client state analyses_reauthentication_request

	eap_type_gsmsim_state_pending_pseudonym_decode_query                        , ///< Server state pending_pseudonym_decode_query
	eap_type_gsmsim_state_waiting_for_identity_response                         , ///< Server state waiting_for_identity_response
	eap_type_gsmsim_state_waiting_for_start_response_with_at_permanent_identity , ///< Server state waiting_for_start_response_with_at_permanen_identity
	eap_type_gsmsim_state_waiting_for_start_response_with_at_full_auth_identity , ///< Server state waiting_for_start_response_with_at_identity
	eap_type_gsmsim_state_waiting_for_start_response_with_at_any_identity       , ///< Server state waiting_for_start_response_with_at_identity
	eap_type_gsmsim_state_waiting_for_start_response                            , ///< Server state waiting_for_start_response
	eap_type_gsmsim_state_waiting_for_challenge_response                        , ///< Server state waiting_for_challenge_response
	eap_type_gsmsim_state_pending_triplet_query                                 , ///< Server state pending_triplet_query
	eap_type_gsmsim_state_analyses_challenge_response                           , ///< Server state analyses_challenge_response
	eap_type_gsmsim_state_analyses_start_response                               , ///< Server state analyses_start_response
	eap_type_gsmsim_state_waiting_for_notification_response_failure             , ///< Server state waiting_for_notification_response, authentication failed
	eap_type_gsmsim_state_waiting_for_notification_response_success             , ///< Server state waiting_for_notification_response, authentication success
	eap_type_gsmsim_state_waiting_for_reauth_response                           , ///< Server state waiting_for_reauth_response
	eap_type_gsmsim_state_analyses_reauthentication_response                    , ///< Server state analyses_reauthentication_response

	eap_type_gsmsim_state_success                                               , ///< State state_success
	eap_type_gsmsim_state_failure                                               , ///< State state_failure

	eap_type_gsmsim_state_last_value                                              ///< Keep this enum the last one.
};


/**
 * This is the required completion after a asyncronous call.
 */
enum eap_type_gsmsim_complete_e
{
	eap_type_gsmsim_complete_none, ///< No completion required
	eap_type_gsmsim_complete_start_request, ///< GSMSIM start request must be completed
	eap_type_gsmsim_complete_query_eap_identity, ///< GSMSIM EAP-identity query must be completed
	eap_type_gsmsim_complete_handle_imsi_from_username,
	eap_type_gsmsim_complete_handle_start_response_message_completion,
};


/**
 * This is the status of the triplet.
 */
enum eap_gsmsim_triplet_status_e
{
	eap_gsmsim_triplet_status_ok                                               =    0,
	eap_gsmsim_triplet_status_no_roaming_agreement                             = 1024, ///< No roaming agreement.
	eap_gsmsim_triplet_status_users_calls_are_barred                           = 1026, ///< User's calls are barred.
	eap_gsmsim_triplet_status_user_has_not_subscribed_to_the_requested_service = 1031, ///< User has not subrcibed to the requested service.
};


enum eap_gsmsim_notification_codes_e
{
   eap_gsmsim_notification_no_F_no_P_general_failure                                  =      0, ///< General failure. (implies failure, used after successful authentication)
   eap_gsmsim_notification_no_F_P_set_general_failure                                 =  16384, ///< General failure. (implies failure, used before authentication)
   eap_gsmsim_notification_F_set_no_P_user_authenticated                              =  32768, ///< User has been successfully authenticated. (does not imply failure, used after successful authentication). The usage of this code is discussed in Section 4.4.2.
   eap_gsmsim_notification_no_F_no_P_users_calls_are_barred                           =   1026, ///< User has been temporarily denied access to the requested service. (Implies failure, used after successful authentication)
   eap_gsmsim_notification_no_F_no_P_user_has_not_subscribed_to_the_requested_service =   1031, ///< User has not subscribed to the requested service (implies failure, used after successful authentication)
   eap_gsmsim_notification_none                                                       = 0xffff, ///< No code.
};


enum gsmsim_notification_code_bits_e
{
	gsmsim_notification_code_bit_f = 0x8000,
	gsmsim_notification_code_bit_p = 0x4000,
	gsmsim_notification_code_value = 0x3FFF,
};


/** See eap_gsmsim_triplet_status_e. */
const u8_t EAP_GSMSIM_NOTIFICATION_NO_ROAMING_AGREEMENT[]
	= "1024 Visited network does not have a roaming agreement with user's home operator";
/** See eap_gsmsim_triplet_status_e. */
const u8_t EAP_GSMSIM_NOTIFICATION_USERS_CALLS_ARE_BARRED[]
	= "1026 User's calls are barred";
/** See eap_gsmsim_triplet_status_e. */
const u8_t EAP_GSMSIM_NOTIFICATION_USER_HAS_NOT_SUBSCRIBED_TO_THE_REQUESTED_SERVICE[]
	= "1031 User has not subscribed to the requested service";

/**
 * This is the type of the GSMSIM identity.
 */
enum eap_type_gsmsim_identity_type
{
	GSMSIM_IDENTITY_TYPE_NONE,
	GSMSIM_IDENTITY_TYPE_IMSI_ID,
	GSMSIM_IDENTITY_TYPE_PSEUDONYM_ID,
	GSMSIM_IDENTITY_TYPE_RE_AUTH_ID,
};

enum eap_gsmsim_authentication_type_e
{
	GSMSIM_AUTHENTICATION_TYPE_NONE,
	GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH,
	GSMSIM_AUTHENTICATION_TYPE_REAUTHENTICATION,
};

const u8_t GSMSIM_IMSI_PREFIX_CHARACTER[] = "1";
const u32_t GSMSIM_IMSI_PREFIX_CHARACTER_LENGTH = sizeof(GSMSIM_IMSI_PREFIX_CHARACTER)-1ul;

const u8_t GSMSIM_AT_CHARACTER[] = "@";
const u32_t GSMSIM_AT_CHARACTER_LENGTH = sizeof(GSMSIM_AT_CHARACTER)-1ul;

const u8_t GSMSIM_OWLAN_ORG_PREFIX_STRING[] = "wlan";
const u32_t GSMSIM_OWLAN_ORG_PREFIX_STRING_LENGTH = sizeof(GSMSIM_OWLAN_ORG_PREFIX_STRING)-1ul;

const u8_t GSMSIM_UMA_PREFIX_STRING[] = "uma";
const u32_t GSMSIM_UMA_PREFIX_STRING_LENGTH = sizeof(GSMSIM_UMA_PREFIX_STRING)-1ul;

const u8_t GSMSIM_OWLAN_MNC_STRING[] = "mnc";
const u32_t GSMSIM_OWLAN_MNC_STRING_LENGTH = sizeof(GSMSIM_OWLAN_MNC_STRING)-1ul;

const u8_t GSMSIM_OWLAN_DOT_STRING[] = ".";
const u32_t GSMSIM_OWLAN_DOT_STRING_LENGTH = sizeof(GSMSIM_OWLAN_DOT_STRING)-1ul;

const u8_t GSMSIM_OWLAN_MCC_STRING[] = "mcc";
const u32_t GSMSIM_OWLAN_MCC_STRING_LENGTH = sizeof(GSMSIM_OWLAN_MCC_STRING)-1ul;

const u8_t GSMSIM_OWLAN_ORG_STRING[] = "3gppnetwork.org";
const u32_t GSMSIM_OWLAN_ORG_STRING_LENGTH = sizeof(GSMSIM_OWLAN_ORG_STRING)-1ul;


enum eap_type_gsmsim_constants_e
{
	EAP_TYPE_GSMSIM_NONCE_MT_SIZE = 16u, ///< bytes = 128 bits
	EAP_TYPE_GSMSIM_MAC_SIZE = 16u, ///< bytes = 128 bits
	EAP_TYPE_GSMSIM_KEYMAT_SIZE = 20u, ///< bytes = 160 bits
	EAP_TYPE_GSMSIM_MASTER_SESSION_KEY_SIZE = 4u*32u, ///< bytes
	EAP_TYPE_GSMSIM_MAX_NAI_LENGTH = 255u, ///< bytes
	EAP_TYPE_GSMSIM_MAX_USER_NAI_LENGTH = 255u, ///< bytes
	EAP_TYPE_GSMSIM_DEFAULT_MINIMUM_RAND_COUNT = 2ul, ///< count
	EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH = 512u, ///< This is the size of the local send buffer.
	EAP_TYPE_GSMSIM_PADDING_MODULUS = 4ul, ///< Padding length is always mudulus of 4.
	EAP_TYPE_GSMSIM_PADDING_MAX_VALUE = 12ul, ///< Maximum padding length is 12 bytes.
	EAP_TYPE_GSMSIM_INITIAL_REAUTH_COUNTER = 1ul,
	EAP_TYPE_GSMSIM_DEFAULT_MNC_LENGTH_3_BYTES = 3ul,
	EAP_TYPE_GSMSIM_MNC_LENGTH_2_BYTES = 2ul,
	EAP_TYPE_GSMSIM_MNC_OFFSET = 3ul,
	EAP_TYPE_GSMSIM_MCC_LENGTH = 3ul,
	EAP_TYPE_GSMSIM_MCC_OFFSET = 0ul,
	EAP_TYPE_GSMSIM_MINIMUM_IMSI_LENGTH = EAP_TYPE_GSMSIM_MCC_LENGTH+EAP_TYPE_GSMSIM_MNC_LENGTH_2_BYTES+1,
};

enum eap_type_gsmsim_timer_id_e
{
	EAP_TYPE_GSMSIM_TIMER_DELAY_FAILURE_MESSAGE_SENT_ID,
	EAP_TYPE_GSMSIM_TIMER_DELAY_NOTIFICATION_MESSAGE_ID,
};

enum eap_type_gsmsim_timer_timeout_value_e
{
	EAP_TYPE_GSMSIM_TIMER_TIMEOUT_VALUE_DELAY_FAILURE_MESSAGE_SENT = 0ul, ///< This is the default value. Zero means error message is handled immediately.
};

enum eap_type_gsmsim_stored_e
{
	eap_type_gsmsim_stored_none,
	eap_type_gsmsim_stored_reauth_xkey,
	eap_type_gsmsim_stored_reauth_k_aut,
	eap_type_gsmsim_stored_reauth_k_encr,
	eap_type_gsmsim_stored_pseudonym_identity,
	eap_type_gsmsim_stored_reauth_identity,
	eap_type_gsmsim_stored_pseudonym_key,
	eap_type_gsmsim_stored_pseudonym_mac_key,
	eap_type_gsmsim_stored_prev_pseudonym_key,
	eap_type_gsmsim_stored_prev_pseudonym_mac_key,
	eap_type_gsmsim_stored_pseudonym_key_index,
	eap_type_gsmsim_stored_pseudonym_key_use_count,
	eap_type_gsmsim_stored_pseudonym_use_count,
	eap_type_gsmsim_stored_reauth_use_count,
	eap_type_gsmsim_stored_saved_reauth_counter,
	eap_type_gsmsim_stored_saved_dublicate_rand,
};

/**
 *  @defgroup GSMSIM_config_options Configuration options of GSMSIM.
 *  The following configuration options are read through abs_eap_base_type_c::read_configure() function.
 *  @{
 */

/**
 *  This u32_t configuration option is timeout in milli seconds before erroneous message is processed.
 *  This is useful in protocol testing or if some delay is needed in final application.
 *  Default value is 0.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_failure_message_delay_time,
	"EAP_GSMSIM_failure_message_delay_time",
	eap_configure_type_u32_t,
	false);

/**
 *  This u32_t configuration option is minimum count of allowed RANDs in GSMSIM.
 *  Default value is 2.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_minimum_rand_count,
	"EAP_GSMSIM_minimum_rand_count",
	eap_configure_type_u32_t,
	false);

/**
 *  This boolean configuration option specifies whether the username should
 *  be generated automatically. 
 *  Default value is 0. That will cause use of automatic username. If this is 1
 *  then cf_str_EAP_GSMSIM_manual_username is used as the username.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_use_manual_username,
	"EAP_GSMSIM_use_manual_username",
	eap_configure_type_boolean,
	false);

/**
 *  This string configuration option is the username part of EAP-type GSMSIM identity.
 *  Default value is empty string. That will cause use of automatic username.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_manual_username,
	"EAP_GSMSIM_manual_username",
	eap_configure_type_string,
	false);

/**
 *  This boolean configuration option specifies whether the realm should
 *  be generated automatically. 
 *  Default value is 0. That will cause use of automatic realm. If this is 1
 *  then cf_str_EAP_GSMSIM_manual_realm is used as the realm.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_use_manual_realm,
	"EAP_GSMSIM_use_manual_realm",
	eap_configure_type_boolean,
	false);

/**
 *  This string configuration option is the realm part of EAP-type GSMSIM identity.
 *  Default value is empty string. That will cause use of automatic realm.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_manual_realm,
	"EAP_GSMSIM_manual_realm",
	eap_configure_type_string,
	false);

/**
 *  This is boolean configuration option.
 *  True value means on successfull authentication EAP-type GSMSIM waits the EAP-Success message.
 *  False value means on successfull authentication EAP-type GSMSIM does NOT wait the EAP-Success message.
 *  NOTE: True value is needed in Windows RAS.
 *  Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_wait_eap_success_packet,
	"EAP_GSMSIM_wait_eap_success_packet",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  True value means on EAP-type GSMSIM must check identifier of EAP-Response/Identity message.
 *  False value means on EAP-type GSMSIM does not check identifier of EAP-Response/Identity message.
 *  This is not possible in cases where identifier of the EAP-Request/Identity is generated by other network entities.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_check_identifier_of_eap_identity_response,
	"EAP_GSMSIM_check_identifier_of_eap_identity_response",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  This flag activates NAI realm check. Default value is false.
 *  When active NAI realm muts be the same as realm given by EAP_GSMSIM_manual_realm option.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_check_nai_realm,
	"EAP_GSMSIM_check_nai_realm",
	eap_configure_type_boolean,
	false);

/**
 *  This is for testing.
 *  This string configuration option is the full path name of the nonce_mt file.
 *  Default value is empty string.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_nonce_mt_file,
	"EAP_GSMSIM_nonce_mt_file",
	eap_configure_type_string,
	false);

/**
 *  This is for testing.
 *  This string configuration option is the full path name of the triplet file.
 *  Default value is empty string.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_triplet_file,
	"EAP_GSMSIM_triplet_file",
	eap_configure_type_string,
	false);

/**
 *  This is for testing.
 *  This string configuration option is the full path name of the pseudonym file.
 *  Default value is empty string.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_pseudonym_file,
	"EAP_GSMSIM_pseudonym_file",
	eap_configure_type_string,
	false);

/**
 *  This is for testing.
 *  This string configuration option is the full path name of the reauthentication file.
 *  Default value is empty string.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_reauthentication_file,
	"EAP_GSMSIM_reauthentication_file",
	eap_configure_type_string,
	false);

/**
 *  This is for testing.
 *  This string configuration option is the full path name of the encryption IV file.
 *  Default value is empty string.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_encryption_iv_file,
	"EAP_GSMSIM_encryption_iv_file",
	eap_configure_type_string,
	false);

/**
 *  This is boolean configuration option.
 *  True value means client of EAP-type GSMSIM responds to every re-transmitted EAP-SIM request packets.
 *  False value means client of EAP-type GSMSIM does not respond to any re-transmitted EAP-SIM request packets,
 *  instead the EAP layer does re-transmit the response.
 *  The default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_client_responds_retransmitted_packets,
	"EAP_GSMSIM_client_responds_retransmitted_packets",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  This is for testing.
 *  True value means test version of EAP-type GSMSIM is used.
 *  Test version tries to make as many authentications as it is possible.
 *  False value means on real version of EAP-type GSMSIM is used.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_test_version,
	"EAP_GSMSIM_test_version",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  This is for testing.
 *  True value means server refuses EAP-identity randomly.
 *  False value means does not refuse EAP-identity randomly.
 *  NOTE EAP_GSMSIM_test_version option must be true also.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_randomly_refuse_eap_identity,
	"EAP_GSMSIM_randomly_refuse_eap_identity",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  True value means on test of re-authentication counter of EAP-type GSMSIM will fail always.
 *  NOTE EAP_GSMSIM_test_version option must be true also.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_fail_re_authentication_counter_check,
	"EAP_GSMSIM_fail_re_authentication_counter_check",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  True value of this flag allows server accept the EAP-Response/Identity message.
 *  False value does not allow server accept the EAP-Response/Identity message.
 *  Instead server queries identity in EAP-Request/SIM/Start with AT_ANY_ID_REQ attribute.
 *  Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_accept_eap_identity_response,
	"EAP_GSMSIM_accept_eap_identity_response",
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
	cf_str_EAP_GSMSIM_use_random_identity_on_eap_identity_response,
	"EAP_GSMSIM_use_random_identity_on_eap_identity_response",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  True value of this flag causes client check the RANDs are unique.
 *  False value causes client skip the uniqueness check of the RANDs.
 *  Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_do_rand_uniqueness_check,
	"EAP_GSMSIM_do_rand_uniqueness_check",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  True value means progress bar is shown to user.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_enable_progress_bar,
	"EAP_GSMSIM_enable_progress_bar",
	eap_configure_type_boolean,
	false);

/**
 * This is string configuration option.
 * This option selects the SIM algorithm used in simulation.
 * Possible values are "nokia_test_network_xor" or "tls_prf_with_shared_secret".
 * The default value is nokia_test_network_xor.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_simulator_sim_algorithm,
	"EAP_GSMSIM_simulator_sim_algorithm",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_simulator_sim_algorithm_config_value_nokia_test_network_xor,
	"nokia_test_network_xor",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_simulator_sim_algorithm_config_value_tls_prf_with_shared_secret,
	"tls_prf_with_shared_secret",
	eap_configure_type_string,
	false);

/**
 * This is hex data configuration option.
 * This Ki is used in software-SIM (SW-SIM).
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_simulator_sim_ki,
	"EAP_GSMSIM_simulator_sim_ki",
	eap_configure_type_hex_data,
	false);

/**
 * This is boolean configuration option.
 * This flag tells whether the UMA profile is used (true) or not (false).
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_UMA_profile,
	"EAP_GSMSIM_UMA_profile",
	eap_configure_type_boolean,
	false);

/**
 * This is string configuration option.
 * The string is the prefix of automatic realm in the UMA profile.
 * Note also the EAP_GSMSIM_UMA_profile must be true before
 * this option is used.
 * Default value is empty.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_UMA_realm_prefix,
	"EAP_GSMSIM_UMA_realm_prefix",
	eap_configure_type_string,
	false);

/**
 * This is boolean configuration option.
 * This flag tells whether the pseudonym identity could be used (true) or not (false).
 * Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_use_pseudonym_identity,
	"EAP_GSMSIM_use_pseudonym_identity",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * This flag tells whether the re-authentication identity could be used (true) or not (false).
 * Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_use_reauthentication_identity,
	"EAP_GSMSIM_use_reauthentication_identity",
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
	cf_str_EAP_GSMSIM_do_asyncronous_completions,
	"EAP_GSMSIM_do_asyncronous_completions",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * This is used in simulator testing.
 * True value means triplet queries to AM are failed randomly.
 * False value means triplet queries to AM are not failed.
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_fail_SIM_triplets_query_randomly,
	"EAP_GSMSIM_fail_SIM_triplets_query_randomly",
	eap_configure_type_boolean,
	false);


/**
 * This is boolean configuration option.
 * This is used in simulator testing.
 * True value means server sends dublicate RANDS.
 * False value means server sends random RANDs.
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_test_dublicate_triplets,
	"EAP_GSMSIM_test_dublicate_triplets",
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
	cf_str_EAP_GSMSIM_do_asyncronous_completions_randomly,
	"EAP_GSMSIM_do_asyncronous_completions_randomly",
	eap_configure_type_boolean,
	false);


/**
 * This is boolean configuration option.
 * This is used in simulator testing.
 * True value means EAP-SIM server fails randomly successfull authentication.
 * False value means EAP-SIM server does NOT fail randomly successfull authentication.
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_randomly_fail_successfull_authentication,
	"EAP_GSMSIM_randomly_fail_successfull_authentication",
	eap_configure_type_boolean,
	false);


/**
 * This is boolean configuration option.
 * This is used in simulator testing.
 * True value means EAP-SIM client and server allows result indications.
 * False value means EAP-SIM client and server does NOT allow result indications.
 * Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_allow_use_result_indication,
	"EAP_GSMSIM_allow_use_result_indication",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * This is used in simulator testing.
 * True value means EAP-SIM server allows result indications.
 * False value means EAP-SIM server does NOT allow result indications.
 * NOTE this option over rides cf_str_EAP_GSMSIM_allow_use_result_indication
 * in server.
 * Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_server_allow_use_result_indication,
	"EAP_GSMSIM_server_allow_use_result_indication",
	eap_configure_type_boolean,
	false);


/**
 *  This u32_t array configuration option is includes those MCCs that uses 2 digit MNC.
 *  Default value is empty array.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_2_digit_mnc_map_of_mcc_of_imsi_array,
	"EAP_AKA_GSMSIM_2_digit_mnc_map_of_mcc_of_imsi_array",
	eap_configure_type_u32array,
	false);



/**
 * This is boolean configuration option.
 * This is used in simulator testing.
 * True value means EAP-SIM server randomly skip pseudonym and fast-reauth identity generation.
 * False value means EAP-SIM server does generate those identities.
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_server_randomly_skip_identity_generation,
	"EAP_GSMSIM_server_randomly_skip_identity_generation",
	eap_configure_type_boolean,
	false);


/**
 *  This is boolean configuration option. True value activates use of expanded EAP type field of 64-bits in length.
 *  False value forces to use the normal 8-bit EAP type field.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_use_eap_expanded_type,
	"EAP_GSMSIM_use_eap_expanded_type",
	eap_configure_type_boolean,
	false);

/**
 *  This u32_t configuration value specifies the maximum session validity time in seconds.
 *  Default value is 12 hours in seconds, which is 43200 seconds.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_GSMSIM_max_session_validity_time,
	"EAP_GSMSIM_max_session_validity_time",
	eap_configure_type_u32_t,
	false);


/** @} */ // End of group GSMSIM_config_options.

#endif //#if !defined(_GSMSIM_TYPES_H_)

//--------------------------------------------------



// End.
