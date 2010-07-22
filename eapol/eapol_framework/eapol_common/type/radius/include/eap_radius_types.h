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

#if !defined(_RADIUS_TYPES_H_)
#define _RADIUS_TYPES_H_

#include "eap_type_all_types.h"
#include "eap_configuration_field.h"

/** @file eap_radius_types.h 
 *  @brief This file defines the constants of the RADIUS EAP type.
 */

const u32_t RADIUS_FIRST_SEQUENCE = 1u;
const u32_t RADIUS_PAYLOAD_LENGTH_ALIGN = 4u;
const u32_t RADIUS_PAYLOAD_ZERO_DATA_LENGTH = 0u;
const u8_t RADIUS_NAI_AT_BYTE = '@';

enum eap_radius_protocol_e
{
	eap_radius_protocol,
};


/**
 * This is the internal state of the RADIUS EAP type.
 */
enum eap_radius_state_variable_e
{
	eap_radius_state_none                                                  , ///< This is the initial state
	eap_radius_state_waiting_for_identity_request                          , ///< Client state waiting_for_identity_request
	eap_radius_state_pending_identity_query                                , ///< Client state pending_identity_query
	eap_radius_state_waiting_for_start_request                             , ///< Client state imsi_waiting_for_start_request
	eap_radius_state_imsi_waiting_for_start_request                        , ///< Client state imsi_waiting_for_start_request
	eap_radius_state_pseydonym_waiting_for_start_request                   , ///< Client state pseydonym_waiting_for_start_request
	eap_radius_state_analyse_start_request                                 , ///< Client state analyse_start_request
	eap_radius_state_waiting_for_challenge_request                         , ///< Client state waiting_for_challenge_request
	eap_radius_state_analyses_challenge_request                            , ///< Client state analyses_challenge_request
	eap_radius_state_pending_kc_sres_query                                 , ///< Client state pending_kc_sres_query
	eap_radius_state_waiting_for_notification_request_success              , ///< Client state waiting_for_notification_request_success
	eap_radius_state_waiting_for_success                                   , ///< Client state waiting_for_success
	eap_radius_state_waiting_for_reauth_request                            , ///< Client state waiting_for_reauth_request
	eap_radius_state_analyses_reauthentication_request                     , ///< Client state analyses_reauthentication_request

	eap_radius_state_pending_pseudonym_decode_query                        , ///< Server state pending_pseudonym_decode_query
	eap_radius_state_waiting_for_identity_response                         , ///< Server state waiting_for_identity_response
	eap_radius_state_waiting_for_start_response_with_at_permanent_identity , ///< Server state waiting_for_start_response_with_at_permanen_identity
	eap_radius_state_waiting_for_start_response_with_at_full_auth_identity , ///< Server state waiting_for_start_response_with_at_identity
	eap_radius_state_waiting_for_start_response_with_at_any_identity       , ///< Server state waiting_for_start_response_with_at_identity
	eap_radius_state_waiting_for_start_response                            , ///< Server state waiting_for_start_response
	eap_radius_state_waiting_for_challenge_response                        , ///< Server state waiting_for_challenge_response
	eap_radius_state_pending_triplet_query                                 , ///< Server state pending_triplet_query
	eap_radius_state_analyses_challenge_response                           , ///< Server state analyses_challenge_response
	eap_radius_state_analyses_start_response                               , ///< Server state analyses_start_response
	eap_radius_state_waiting_for_notification_response_failure             , ///< Server state waiting_for_notification_response, authentication failed
	eap_radius_state_waiting_for_notification_response_success             , ///< Server state waiting_for_notification_response, authentication success
	eap_radius_state_waiting_for_reauth_response                           , ///< Server state waiting_for_reauth_response
	eap_radius_state_analyses_reauthentication_response                    , ///< Server state analyses_reauthentication_response

	eap_radius_state_success                                               , ///< State state_success
	eap_radius_state_failure                                               , ///< State state_failure

	eap_radius_state_last_value                                              ///< Keep this enum the last one.
};


/**
 * This is the required completion after a asyncronous call.
 */
enum eap_radius_complete_e
{
	eap_radius_complete_none, ///< No completion required
	eap_radius_complete_start_request, ///< RADIUS start request must be completed
	eap_radius_complete_query_eap_identity, ///< RADIUS EAP-identity query must be completed
	eap_radius_complete_handle_imsi_from_username,
	eap_radius_complete_handle_start_response_message_completion,
};


/**
 * This is the status of the triplet.
 */
enum eap_radius_triplet_status_e
{
	eap_radius_triplet_status_ok                                               =    0,
	eap_radius_triplet_status_no_roaming_agreement                             = 1024, ///< No roaming agreement.
	eap_radius_triplet_status_users_calls_are_barred                           = 1026, ///< User's calls are barred.
	eap_radius_triplet_status_user_has_not_subscribed_to_the_requested_service = 1031, ///< User has not subrcibed to the requested service.
};


enum eap_radius_notification_codes_e
{
   eap_radius_notification_no_F_no_P_general_failure                                  =      0, ///< General failure. (implies failure, used after successful authentication)
   eap_radius_notification_no_F_P_set_general_failure                                 =  16384, ///< General failure. (implies failure, used before authentication)
   eap_radius_notification_F_set_no_P_user_authenticated                              =  32768, ///< User has been successfully authenticated. (does not imply failure, used after successful authentication). The usage of this code is discussed in Section 4.4.2.
   eap_radius_notification_no_F_no_P_users_calls_are_barred                           =   1026, ///< User has been temporarily denied access to the requested service. (Implies failure, used after successful authentication)
   eap_radius_notification_no_F_no_P_user_has_not_subscribed_to_the_requested_service =   1031, ///< User has not subscribed to the requested service (implies failure, used after successful authentication)
   eap_radius_notification_none                                                       = 0xffff, ///< No code.
};


enum radius_notification_code_bits_e
{
	radius_notification_code_bit_f = 0x8000,
	radius_notification_code_bit_p = 0x4000,
};


/** See eap_radius_triplet_status_e. */
const u8_t EAP_RADIUS_NOTIFICATION_NO_ROAMING_AGREEMENT[]
	= "1024 Visited network does not have a roaming agreement with user's home operator";
/** See eap_radius_triplet_status_e. */
const u8_t EAP_RADIUS_NOTIFICATION_USERS_CALLS_ARE_BARRED[]
	= "1026 User's calls are barred";
/** See eap_radius_triplet_status_e. */
const u8_t EAP_RADIUS_NOTIFICATION_USER_HAS_NOT_SUBSCRIBED_TO_THE_REQUESTED_SERVICE[]
	= "1031 User has not subscribed to the requested service";

/**
 * This is the type of the RADIUS identity.
 */
enum eap_radius_identity_type
{
	RADIUS_IDENTITY_TYPE_NONE,
	RADIUS_IDENTITY_TYPE_IMSI_ID,
	RADIUS_IDENTITY_TYPE_PSEUDONYM_ID,
	RADIUS_IDENTITY_TYPE_RE_AUTH_ID,
};

enum eap_radius_authentication_type_e
{
	RADIUS_AUTHENTICATION_TYPE_NONE,
	RADIUS_AUTHENTICATION_TYPE_FULL_AUTH,
	RADIUS_AUTHENTICATION_TYPE_REAUTHENTICATION,
};

const u8_t RADIUS_IMSI_PREFIX_CHARACTER[] = "1";

const u8_t RADIUS_AT_CHARACTER[] = "@";

const u8_t RADIUS_OWLAN_ORG_PREFIX_STRING[] = "wlan";
const u32_t RADIUS_OWLAN_ORG_PREFIX_STRING_LENGTH = sizeof(RADIUS_OWLAN_ORG_PREFIX_STRING)-1ul;

const u8_t RADIUS_UMA_PREFIX_STRING[] = "wlan";
const u32_t RADIUS_UMA_PREFIX_STRING_LENGTH = sizeof(RADIUS_UMA_PREFIX_STRING)-1ul;

const u8_t RADIUS_OWLAN_MNC_STRING[] = "mnc";
const u32_t RADIUS_OWLAN_MNC_STRING_LENGTH = sizeof(RADIUS_OWLAN_MNC_STRING)-1ul;

const u8_t RADIUS_OWLAN_DOT_STRING[] = ".";
const u32_t RADIUS_OWLAN_DOT_STRING_LENGTH = sizeof(RADIUS_OWLAN_DOT_STRING)-1ul;

const u8_t RADIUS_OWLAN_MCC_STRING[] = "mcc";
const u32_t RADIUS_OWLAN_MCC_STRING_LENGTH = sizeof(RADIUS_OWLAN_MCC_STRING)-1ul;

const u8_t RADIUS_OWLAN_ORG_STRING[] = "3gppnetwork.org";
const u32_t RADIUS_OWLAN_ORG_STRING_LENGTH = sizeof(RADIUS_OWLAN_ORG_STRING)-1ul;


enum eap_radius_constants_e
{
	EAP_TYPE_RADIUS_NONCE_MT_SIZE = 16u, ///< bytes = 128 bits
	EAP_TYPE_RADIUS_MAC_SIZE = 16u, ///< bytes = 128 bits
	EAP_TYPE_RADIUS_KEYMAT_SIZE = 20u, ///< bytes = 160 bits
	EAP_TYPE_RADIUS_MASTER_SESSION_KEY_SIZE = 4u*32u, ///< bytes
	EAP_TYPE_RADIUS_MAX_NAI_LENGTH = 255u, ///< bytes
	EAP_TYPE_RADIUS_MAX_USER_NAI_LENGTH = 255u, ///< bytes
	EAP_TYPE_RADIUS_DEFAULT_MINIMUM_RAND_COUNT = 2ul, ///< count
	EAP_TYPE_RADIUS_LOCAL_PACKET_BUFFER_LENGTH = 512u, ///< This is the size of the local send buffer.
	EAP_TYPE_RADIUS_PADDING_MODULUS = 4ul, ///< Padding length is always mudulus of 4.
	EAP_TYPE_RADIUS_PADDING_MAX_VALUE = 12ul, ///< Maximum padding length is 12 bytes.
	EAP_TYPE_RADIUS_INITIAL_REAUTH_COUNTER = 1ul,
};

enum eap_radius_timer_id_e
{
	EAP_TYPE_RADIUS_TIMER_DELAY_FAILURE_MESSAGE_SENT_ID,
	EAP_TYPE_RADIUS_TIMER_DELAY_NOTIFICATION_MESSAGE_ID,
};

enum eap_radius_timer_timeout_value_e
{
	EAP_TYPE_RADIUS_TIMER_TIMEOUT_VALUE_DELAY_FAILURE_MESSAGE_SENT = 0ul, ///< This is the default value. Zero means error message is handled immediately.
};


/**
 *  @defgroup RADIUS_config_options Configuration options of RADIUS.
 *  The following configuration options are read through abs_eap_base_type_c::read_configure() function.
 *  @{
 */


EAP_CONFIGURATION_FIELD(
	cf_str_EAP_RADIUS_SERVER_client,
	"EAP_RADIUS_SERVER_client",
	eap_configure_type_section,
	false);

/**
 *  This string configuration option is the username part of EAP-type RADIUS identity.
 *  Default value is empty string. That will cause use of automatic username.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_RADIUS_SERVER_shared_secret,
	"EAP_RADIUS_SERVER_shared_secret",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_RADIUS_SERVER_test_time,
	"EAP_RADIUS_SERVER_test_time",
	eap_configure_type_u32_t,
	false);


/** @} */ // End of group RADIUS_config_options.

#endif //#if !defined(_RADIUS_TYPES_H_)

//--------------------------------------------------



// End.
