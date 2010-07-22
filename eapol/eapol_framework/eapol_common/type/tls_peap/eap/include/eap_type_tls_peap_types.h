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

#if !defined(_EAP_TYPE_TLS_PEAP_TYPES_H_)
#define _EAP_TYPE_TLS_PEAP_TYPES_H_

#include "eap_buffer.h"
#include "eap_type_all_types.h"
#include "tls_peap_types.h"
#include "eap_configuration_field.h"

/** @file eap_type_tls_peap_types.h 
 *  @brief This file defines the constants of the TLS_PEAP EAP type.
 */

/**
 * This is the internal state of the TLS_PEAP EAP type.
 */
enum eap_type_tls_peap_state_variable_e
{
	eap_type_tls_peap_state_waiting_for_identity_request                          , ///< Client state waiting_for_identity_request
	eap_type_tls_peap_state_pending_identity_query                                , ///< Client state pending_identity_query
	eap_type_tls_peap_state_waiting_for_tls_start                                 , ///< Client state waiting_for_eap_start
	eap_type_tls_peap_state_process_tls_start                                     , ///< Client state process_tls_start
	eap_type_tls_peap_state_waiting_for_request                                   , ///< Client state waiting_for_request
	eap_type_tls_peap_state_waiting_for_success                                   , ///< Client state waiting_for_success
	eap_type_tls_peap_state_tppd_peapv1_waits_eap_success_or_tunneled_packet     , ///< Client state PEAPv1 waits EAP-Success or tunneled packet.

	eap_type_tls_peap_state_waiting_for_identity_response                         , ///< Server state waiting_for_identity_response
	eap_type_tls_peap_state_waiting_for_first_response                            , ///< Server state waiting_for_first_response, This is needed in PEAP version negotiation.
	eap_type_tls_peap_state_waiting_for_response                                  , ///< Server state waiting_for_response
	eap_type_tls_peap_state_waiting_for_empty_response                            , ///< Server state waiting_for_empty_response
	eap_type_tls_peap_state_waiting_for_empty_tppd_peap_v1_acknowledge           , ///< Server state waiting_for_empty_tppd_peap_v1_response

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	eap_type_tls_peap_state_server_waits_ttls_plain_ms_chap_v2_empty_ack          , ///< This is state notification to server to wait empty TTLS/plain MsChapv2 Ack.
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

	eap_type_tls_peap_state_process_tls_message                                   , ///< Client or server state process_tls_message

	eap_type_tls_peap_state_success                                               , ///< State state_success
	eap_type_tls_peap_state_failure                                               , ///< State state_failure

	eap_type_tls_peap_state_last_value                                            , ///< Keep this enum the last one.
};


enum eap_type_tls_peap_reassembly_state_e
{
	eap_type_tls_peap_reassembly_state_none,
	eap_type_tls_peap_reassembly_state_wait_first_message,
	eap_type_tls_peap_reassembly_state_wait_last_fragment,
	eap_type_tls_peap_reassembly_state_message_reassembled,
};


/**
 * This is the type of the TLS_PEAP authentication.
 */
enum eap_tls_peap_authentication_type_e
{
	TLS_PEAP_AUTHENTICATION_TYPE_NONE,
	TLS_PEAP_AUTHENTICATION_TYPE_TLS,
	TLS_PEAP_AUTHENTICATION_TYPE_PEAP,
};

enum eap_type_tls_peap_stored_e
{
	eap_type_tls_peap_stored_none,
	eap_type_tls_peap_stored_session_id,
	eap_type_tls_peap_stored_master_secret,
	eap_type_tls_peap_stored_used_cipher_suite,
	eap_type_tls_peap_stored_count_of_session_resumes,
	eap_type_tls_peap_stored_test_every_cipher_suite_counter,
#if defined(USE_EAP_TLS_SESSION_TICKET)
	eap_type_tls_peap_stored_session_ticket_encryption_key,
	eap_type_tls_peap_stored_session_ticket_authentication_key,
	eap_type_tls_peap_stored_session_ticket_lifetime_hint,
	eap_type_tls_peap_stored_session_ticket_data,
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
#if defined(USE_FAST_EAP_TYPE)
	eap_type_tls_peap_stored_tunnel_pac_is_fresh,
	eap_type_tls_peap_stored_tunnel_pac,
	eap_type_tls_peap_stored_user_authorization_pac,
	eap_type_tls_peap_stored_provisioning_successfull,
	eap_type_tls_peap_stored_provisioning_mode,
	eap_type_tls_peap_stored_provisioning_pac_type,
	eap_type_tls_peap_stored_tls_session_type,
#endif //#if defined(USE_FAST_EAP_TYPE)
};

/**
 * This is the size of the local send buffer.
 */
const u32_t EAP_TLS_PEAP_LOCAL_PACKET_BUFFER_LENGTH = EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH;

/**
 * This is the at character used in NAI.
 */
const u8_t EAP_TLS_PEAP_AT_CHARACTER = '@';


/**
 * This is the maximum size of the EAP-TLS/PEAP message.
 * This value limits the maximum size of the received EAP-TLS/PEAP message.
 */
const u32_t EAP_TLS_PEAP_MAX_MESSAGE_LENGTH = 65536ul;


/**
 *  @defgroup EAP_TLS_PEAP_config_options Configuration options of EAP-TLS/PEAP.
 *  The following configuration options are read through abs_eap_base_type_c::read_configure() function.
 *  @{
 */

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_use_automatic_ca_certificate,
	"EAP_TLS_PEAP_use_automatic_ca_certificate",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_use_manual_username,
	"EAP_TLS_PEAP_use_manual_username",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_manual_username,
	"EAP_TLS_PEAP_manual_username",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_use_manual_realm,
	"EAP_TLS_PEAP_use_manual_realm",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_manual_realm,
	"EAP_TLS_PEAP_manual_realm",
	eap_configure_type_string,
	false);

#if defined(USE_EAP_TLS_SESSION_TICKET)
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_use_session_ticket,
	"EAP_TLS_PEAP_use_session_ticket",
	eap_configure_type_boolean,
	false);
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)


#if defined(USE_EAP_TLS_SESSION_TICKET)
EAP_CONFIGURATION_FIELD(
	cf_str_TLS_fail_with_illegal_session_ticket_or_pac,
	"TLS_fail_with_illegal_session_ticket_or_pac",
	eap_configure_type_boolean,
	false);
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)


EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_disable_certificates,
	"EAP_TLS_PEAP_disable_certificates",
	eap_configure_type_boolean,
	false);


EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_ttls_pap_password_prompt,
	"EAP_TLS_PEAP_ttls_pap_password_prompt",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_ttls_pap_username,
	"EAP_TLS_PEAP_ttls_pap_username",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_ttls_pap_password,
	"EAP_TLS_PEAP_ttls_pap_password",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_ttls_pap_max_session_validity_time,
	"EAP_TLS_PEAP_ttls_pap_max_session_validity_time",
	eap_configure_type_u32_t,
	false);


EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_ttls_pap_randomly_fail_password,
	"EAP_TLS_PEAP_ttls_pap_randomly_fail_password",
	eap_configure_type_boolean,
	false);


EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_authority_identity,
	"EAP_FAST_authority_identity",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_authority_identity_hex_data,
	"EAP_FAST_authority_identity",
	eap_configure_type_hex_data,
	false);

/**
 * This is boolean configuration option.
 * True value means every cipher suite is tested during test run.
 * False value means only selected cipher suite is tested. See EAP_TLS_PEAP_cipher_suite.
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_test_every_cipher_suite,
	"EAP_TLS_PEAP_test_every_cipher_suite",
	eap_configure_type_boolean,
	false);

/**
 *  This u32_t configuration option is the cipher suite.
 *  Default value is 19 = 0x0013 (TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA).
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_cipher_suite,
	"EAP_TLS_PEAP_cipher_suite",
	eap_configure_type_u32_t,
	false);

/**
 *  This u32array_t configuration option is the array of accepted cipher suites.
 *  Default value is 19 = 0x0013 (TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA).
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_allowed_cipher_suites,
	"EAP_TLS_PEAP_allowed_cipher_suites",
	eap_configure_type_u32array,
	false);

/**
 *  This u32_t configuration option is the maximum count of session resumes.
 *  Default value is 0.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_max_count_of_session_resumes,
	"EAP_TLS_PEAP_max_count_of_session_resumes",
	eap_configure_type_u32_t,
	false);

/**
 *  This u32_t configuration option is the count of session resumes.
 *  Default value is 0.
 */
#if defined(USE_EAP_FIXED_DATABASE_FIELDS)
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_count_of_session_resumes,
	"EAP_TLS_PEAP_count_of_session_resumes",
	eap_configure_type_u32_t,
	false);
#else
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_count_of_session_resumes,
	"session_resume_count",
	eap_configure_type_u32_t,
	false);
#endif


/**
 *  This hex data configuration option is the saved session ID.
 *  Default value is 0.
 */
#if defined(USE_EAP_FIXED_DATABASE_FIELDS)
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_saved_session_id,
	"EAP_TLS_PEAP_saved_session_id",
	eap_configure_type_hex_data,
	false);
#else
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_saved_session_id,
	"session_id",
	eap_configure_type_hex_data,
	false);
#endif

/**
 * This hex data or u32array configuration option value is list of EAP-types client accepts inside PEAP.
 * Values in the u32array are type of u32_t.
 * This is used in simulator testing.
 */
#if defined(USE_EAP_FIXED_DATABASE_FIELDS)
EAP_CONFIGURATION_FIELD(
	cf_str_PEAP_accepted_tunneled_client_types_hex_data,
	"PEAP_accepted_tunneled_client_types",
	eap_configure_type_hex_data,
	false);
EAP_CONFIGURATION_FIELD(
	cf_str_PEAP_accepted_tunneled_client_types_u32array,
	"PEAP_accepted_tunneled_client_types",
	eap_configure_type_u32array,
	false);
EAP_CONFIGURATION_FIELD(
	cf_str_PEAP_unaccepted_tunneled_client_types_hex_data,
	"PEAP_unaccepted_tunneled_client_types",
	eap_configure_type_hex_data,
	false);
EAP_CONFIGURATION_FIELD(
	cf_str_PEAP_unaccepted_tunneled_client_types_u32array,
	"PEAP_unaccepted_tunneled_client_types",
	eap_configure_type_u32array,
	false);	
#else
EAP_CONFIGURATION_FIELD(
	cf_str_PEAP_accepted_tunneled_client_types_hex_data,
	"PEAP_tunneled_types",
	eap_configure_type_hex_data,
	false);
EAP_CONFIGURATION_FIELD(
	cf_str_PEAP_accepted_tunneled_client_types_u32array,
	"PEAP_tunneled_types",
	eap_configure_type_u32array,
	false);

#endif

/**
 * This hex data or u32array configuration option value is list of EAP-types server accepts inside PEAP.
 * Values in the array are type of u32_t.
 * This is used in simulator testing.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_PEAP_accepted_tunneled_server_types_hex_data,
	"PEAP_accepted_tunneled_server_types",
	eap_configure_type_hex_data,
	false);
EAP_CONFIGURATION_FIELD(
	cf_str_PEAP_accepted_tunneled_server_types_u32array,
	"PEAP_accepted_tunneled_server_types",
	eap_configure_type_u32array,
	false);

/**
 *  This boolean configuration option value true allows PEAP restore tunneled session.
 *  This means PEAP does not run the tunneled EAP-type when
 *  PEAP session is resumed successfully.
 *  Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_PEAP_allow_tunneled_session_resumption,
	"PEAP_allow_tunneled_session_resumption",
	eap_configure_type_boolean,
	false);

/**
 *  This boolean configuration option value true allows PEAP server restore tunneled session.
 *  This means PEAP version 0 does not run the tunneled EAP-type when
 *  PEAP session is resumed successfully.
 *  Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_PEAP_server_allow_tunneled_session_resumption,
	"PEAP_server_allow_tunneled_session_resumption",
	eap_configure_type_boolean,
	false);

/**
 *  This boolean configuration option value true commands PEAPv1 server use tunneled Extensions Request message.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_PEAPv1_server_use_extensions_request,
	"PEAPv1_server_use_extensions_request",
	eap_configure_type_boolean,
	false);

/**
 *  This hex data configuration option is the saved master secret.
 *  Default value is 0.
 */
#if defined(USE_EAP_FIXED_DATABASE_FIELDS)
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_saved_master_secret,
	"EAP_TLS_PEAP_saved_master_secret",
	eap_configure_type_hex_data,
	true);
#else
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_saved_master_secret,
	"master_secret",
	eap_configure_type_hex_data,
	true);
#endif

/**
 *  This u32_t configuration option is the saved cipher suite.
 *  Default value is 0.
 */
#if defined(USE_EAP_FIXED_DATABASE_FIELDS)
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_saved_cipher_suite,
	"EAP_TLS_PEAP_saved_cipher_suite",
	eap_configure_type_u32_t,
	false);
#else
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_saved_cipher_suite,
	"saved_cipher_suite",
	eap_configure_type_u32_t,
	false);
#endif


/**
 *  This string configuration option is the filename for the client DSA certificate used 
 *  in EAP-type TLS_PEAP.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_DSA_client_certificate_file,
	"EAP_TLS_PEAP_DSA_client_certificate_file",
	eap_configure_type_string,
	false);

/**
 *  This string configuration option is the filename for the client DSA private key used 
 *  in EAP-type TLS_PEAP.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_DSA_client_private_key_file,
	"EAP_TLS_PEAP_DSA_client_private_key_file",
	eap_configure_type_string,
	false);

/**
 *  This string configuration option is the filename for the server DSA certificate used 
 *  in EAP-type TLS_PEAP.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_DSA_server_certificate_file,
	"EAP_TLS_PEAP_DSA_server_certificate_file",
	eap_configure_type_string,
	false);

/**
 *  This string configuration option is the filename for the server DSA private key used 
 *  in EAP-type TLS_PEAP.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_DSA_server_private_key_file,
	"EAP_TLS_PEAP_DSA_server_private_key_file",
	eap_configure_type_string,
	false);

/**
 *  This string configuration option is the filename for the client's CA 
 *	DSA certificate used for verifying server's identity in EAP-type TLS_PEAP.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_DSA_client_ca_certificate_file,
	"EAP_TLS_PEAP_DSA_client_ca_certificate_file",
	eap_configure_type_string,
	false);

/**
 *  This string configuration option is the filename for the server's CA 
 *	DSA certificate used for verifying client's identity in EAP-type TLS_PEAP.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_DSA_server_ca_certificate_file,
	"EAP_TLS_PEAP_DSA_server_ca_certificate_file",
	eap_configure_type_string,
	false);


/**
 *  This string configuration option is the filename for the client RSA certificate used 
 *  in EAP-type TLS_PEAP.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_RSA_client_certificate_file,
	"EAP_TLS_PEAP_RSA_client_certificate_file",
	eap_configure_type_string,
	false);

/**
 *  This string configuration option is the filename for the client RSA private key used 
 *  in EAP-type TLS_PEAP.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_RSA_client_private_key_file,
	"EAP_TLS_PEAP_RSA_client_private_key_file",
	eap_configure_type_string,
	false);

/**
 *  This string configuration option is the filename for the server RSA certificate used 
 *  in EAP-type TLS_PEAP.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_RSA_server_certificate_file,
	"EAP_TLS_PEAP_RSA_server_certificate_file",
	eap_configure_type_string,
	false);

/**
 *  This string configuration option is the filename for the server RSA private key used 
 *  in EAP-type TLS_PEAP.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_RSA_server_private_key_file,
	"EAP_TLS_PEAP_RSA_server_private_key_file",
	eap_configure_type_string,
	false);

/**
 *  This string configuration option is the filename for the client's CA 
 *	RSA certificate used for verifying server's identity in EAP-type TLS_PEAP.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_RSA_client_ca_certificate_file,
	"EAP_TLS_PEAP_RSA_client_ca_certificate_file",
	eap_configure_type_string,
	false);

/**
 *  This string configuration option is the filename for the server's CA 
 *	RSA certificate used for verifying client's identity in EAP-type TLS_PEAP.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_RSA_server_ca_certificate_file,
	"EAP_TLS_PEAP_RSA_server_ca_certificate_file",
	eap_configure_type_string,
	false);


#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
/**
 *  This is boolean configuration option.
 *  True value means on TLS client uses privacy.
 *  False value means on TLS client does not use privacy.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_use_identity_privacy,
	"EAP_TLS_PEAP_use_identity_privacy",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  True value means on TLS server uses privacy.
 *  False value means on TLS server does not use privacy.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_use_identity_privacy_server,
	"EAP_TLS_PEAP_use_identity_privacy_server",
	eap_configure_type_boolean,
	false);
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)


/**
 *  This is boolean configuration option.
 *  True value means EAP-FAST server sends piggypacked EAP-Identity/Request.
 *  False value means EAP-FAST server does not send piggypacked EAP-Identity/Request, instead it waits empty Ack-message from client.
 *  Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_send_piggypacked_eap_identity_request,
	"EAP_FAST_send_piggypacked_eap_identity_request",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  True value means EAP-FAST can run server unauthenticated provisioning.
 *  False value means no EAP-FAST server unauthenticated provisioning is allowed.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP,
	"EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * True value means EAP-FAST can run server authenticated provisioning.
 * False value means no EAP-FAST server authenticated provisioning is allowed.
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_allow_server_authenticated_provisioning_mode,
	"EAP_FAST_allow_server_authenticated_provisioning_mode",
	eap_configure_type_boolean,
	false);


/**
 * This is boolean configuration option.
 * True value means EAP-FAST client can provisioning User Authorization PAC.
 * False value means EAP-FAST client can not provisioning User Authorization PAC.
 * Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_allow_user_authorization_pac_provisioning,
	"EAP_FAST_allow_user_authorization_pac_provisioning",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * True value means EAP-FAST server randomly refuses provisioning User Authorization PAC.
 * False value means EAP-FAST server does provisioning User Authorization PAC.
 * Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_randomly_does_not_provision_user_authorization_pac,
	"EAP_FAST_randomly_does_not_provision_user_authorization_pac",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * True value means EAP-FAST server randomly fail successfull authentication with EAP-Failure.
 * False value means EAP-FAST server does not ramdomly fail authentication.
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_server_randomly_fail_authentication,
	"EAP_FAST_server_randomly_fail_authentication",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * True value means EAP-FAST client accepts A-ID.
 * False value means no EAP-FAST client does not accept A-ID.
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_accept_a_id,
	"EAP_TLS_PEAP_accept_a_id",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * True value means EAP-FAST server fail check of User Authorization PAC randomly.
 * False value means no EAP-FAST server does not fail check of User Authorization PAC randomly.
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_test_fail_user_authorization_pac_randomly,
	"EAP_FAST_test_fail_user_authorization_pac_randomly",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * True value means EAP-FAST server fail check of Tunnel PAC randomly.
 * False value means no EAP-FAST server does not fail check of Tunnel PAC randomly.
 * Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_test_fail_tunnel_pac_randomly,
	"EAP_FAST_test_fail_tunnel_pac_randomly",
	eap_configure_type_boolean,
	false);

/**
 *  This string configuration option is the password of PAC store.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_PAC_store_password,
	"EAP_FAST_PAC_store_password",
	eap_configure_type_string,
	false);

/**
 *  This string configuration option is the password of PAC file.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_tppds_PAC_file_password,
	"EAP_FAST_tppds_PAC_file_password",
	eap_configure_type_string,
	false);

/**
 *  This string configuration option is the device seed of PAC store password.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_PAC_store_device_seed,
	"EAP_FAST_PAC_store_device_seed",
	eap_configure_type_string,
	false);


/**
 *  This string configuration option is the directory path to PAC store.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_PAC_store_path,
	"EAP_FAST_PAC_store_path",
	eap_configure_type_string,
	false);


/**
 *  This string configuration option is the directory path of import directory of PAC store.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_import_path,
	"EAP_FAST_import_path",
	eap_configure_type_string,
	false);


/**
 *  This hex data configuration option is the encryption key server uses with PAC.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_PAC_encryption_key,
	"EAP_FAST_PAC_encryption_key",
	eap_configure_type_hex_data,
	false);

/**
 *  This hex data configuration option is the authentication key server uses with PAC.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_PAC_authentication_key,
	"EAP_FAST_PAC_authentication_key",
	eap_configure_type_hex_data,
	false);

/**
 *  This hex data configuration option is the IAP reference the client uses.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_IAP_reference,
	"EAP_FAST_IAP_reference",
	eap_configure_type_hex_data,
	false);

/**
 *  This hex data configuration option is the Group reference the client uses.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_Group_reference,
	"EAP_FAST_Group_reference",
	eap_configure_type_hex_data,
	false);


/**
 *  This u32_t data configuration option is the timeout of the PAC store key.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_PAC_store_key_timeout_ms,
	"EAP_FAST_PAC_store_key_timeout_ms",
	eap_configure_type_u32_t,
	false);


EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_test_remove_IAP_reference,
	"EAP_FAST_test_remove_IAP_reference",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_test_add_imported_PAC_file,
	"EAP_FAST_test_add_imported_PAC_file",
	eap_configure_type_boolean,
	false);


/**
 *  This u32_t data configuration option is the timeout before finish successfull authentication. This is leave time for UI.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_delay_successfull_finish_timeout,
	"EAP_FAST_delay_successfull_finish_timeout",
	eap_configure_type_u32_t,
	false);

/**
 *  This boolean data configuration option activate prompt to warn when client encouters a server that has provisioned 
 *  the client with a PAC before but is not currently selected as the default server. EAP-FAST specific.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_warn_ADHP_not_default_server,
	"EAP_FAST_warn_ADHP_not_default_server",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  True value means on successfull authentication EAP-type TLS_PEAP waits the EAP-Success message.
 *  False value means on successfull authentication EAP-type TLS_PEAP does NOT wait the EAP-Success message.
 *  NOTE: True value is needed in Windows RAS.
 *  Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_wait_eap_success_packet,
	"EAP_TLS_PEAP_wait_eap_success_packet",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  True value means on EAP-type TLS_PEAP must check identifier of EAP-Response/Identity message.
 *  False value means on EAP-type TLS_PEAP does not check identifier of EAP-Response/Identity message.
 *  This is not possible in cases where identifier of the EAP-Request/Identity is generated by other network entities.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_check_identifier_of_eap_identity_response,
	"EAP_TLS_PEAP_check_identifier_of_eap_identity_response",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  This flag activates NAI realm check. Default value is false.
 *  When active NAI realm muts be the same as realm given by EAP_TLS_PEAP_manual_realm option.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_check_nai_realm,
	"EAP_TLS_PEAP_check_nai_realm",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  This is for testing.
 *  True value means on test version of EAP-type TLS_PEAP is used.
 *  Test version tries to make as many authentications as it is possible.
 *  False value means on real version of EAP-type TLS_PEAP is used.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_test_version,
	"EAP_TLS_test_version",
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
	cf_str_EAP_TLS_PEAP_use_random_identity_on_eap_identity_response,
	"EAP_TLS_PEAP_use_random_identity_on_eap_identity_response",
	eap_configure_type_boolean,
	false);

/**
 * This is u32_t configuration option.
 * Server selects the proposed PEAP version with this option.
 * Possible values are 2, 1 and 0.
 * See: PEAPv0 draft-kamath-pppext-peapv0-00.txt
 *      PEAPv1 draft-josefsson-pppext-eap-tls-eap-05.txt
 *      PEAPv2 draft-josefsson-pppext-eap-tls-eap-XX.txt
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_used_PEAP_version,
	"EAP_TLS_PEAP_used_PEAP_version",
	eap_configure_type_u32_t,
	false);

/**
 * This is u32array configuration option.
 * Client and server accepts and selects the PEAP version with this option.
 * Possible values are 2, 1 and 0.
 * See: PEAPv0 draft-kamath-pppext-peapv0-00.txt
 *      PEAPv1 draft-josefsson-pppext-eap-tls-eap-05.txt
 *      PEAPv2 draft-josefsson-pppext-eap-tls-eap-XX.txt
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_accepted_PEAP_versions,
	"EAP_TLS_PEAP_accepted_PEAP_versions",
	eap_configure_type_u32array,
	false);

/**
 * This is u32array configuration option.
 * Server accepts and selects the PEAP version with this option.
 * Possible values are 2, 1 and 0.
 * See: PEAPv0 draft-kamath-pppext-peapv0-00.txt
 *      PEAPv1 draft-josefsson-pppext-eap-tls-eap-05.txt
 *      PEAPv2 draft-josefsson-pppext-eap-tls-eap-XX.txt
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_server_accepted_PEAP_versions,
	"EAP_TLS_PEAP_server_accepted_PEAP_versions",
	eap_configure_type_u32array,
	false);

/**
 * This is boolean configuration option.
 * This will select whether the different TLS and PEAP version is used.
 * Different TLS and PEAP versions use TLS message length in all first message fragments
 * even the message fits to one fragment except EAP-TLS-start, EAP-TLS-Acknowledge and
 * PEAP-application data. The client acknowledges tunneled EAP-Success message
 * with empty PEAP message.
 * Microsoft's and other's TLS and PEAP does use TLS message only
 * in the first fragmented TLS message.
 * True value means TLS message length is included (different style).
 * False value means TLS message length is NOT included (normal style).
 * Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_use_tppd_tls_peap,
	"EAP_TLS_PEAP_use_tppd_tls_peap",
	eap_configure_type_boolean,
	false);

/**
 * On fast session resume Tppd's server does not send tunneled EAP-Success.
 * Instead it sends plain EAP-Success.
 * This configuration flag when set true allows this functionality in client and server.
 * False value disables this functionality in client and server.
 * Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_use_tppd_peapv1_acknowledge_hack,
	"EAP_TLS_use_tppd_peapv1_acknowledge_hack",
	eap_configure_type_boolean,
	false);

/**
 * This is for server only.
 * On fast session resume Tppd's server does not send tunneled EAP-Success.
 * Instead it sends plain EAP-Success.
 * This configuration flag when set true allows this functionality in server.
 * False value disables this functionality in server.
 * Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_server_use_tppd_peapv1_acknowledge_hack,
	"EAP_TLS_server_use_tppd_peapv1_acknowledge_hack",
	eap_configure_type_boolean,
	false);


/**
 * This is boolean configuration option.
 * This is used in simulator testing.
 * True value means queries to AM are completed asyncronous.
 * False value means queries to AM are completed syncronous.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_do_asyncronous_completions,
	"EAP_TLS_PEAP_do_asyncronous_completions",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * This is used in simulator testing.
 * True value means queries to AM are randomly completed asyncronous.
 * False value means queries to AM are randomly completed syncronous.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_do_asyncronous_completions_randomly,
	"EAP_TLS_PEAP_do_asyncronous_completions_randomly",
	eap_configure_type_boolean,
	false);

/**
 * This is u32_t configuration option.
 * This is used in simulator testing.
 * Value is the maximum completion time (ms) when completitions are
 * completed randomly.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_max_tls_completion_time,
	"EAP_TLS_PEAP_max_tls_completion_time",
	eap_configure_type_u32_t,
	false);

/**
 * This is boolean configuration option.
 * This is used in client simulator testing.
 * True value means query_certificate_chain() to AM fails always automatically in client.
 * False value means query_certificate_chain() to AM works normally in client.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_fail_query_certificate_chain,
	"EAP_TLS_PEAP_fail_query_certificate_chain",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  This flag activates NAI realm check of certificate.
 *  Both client and server will check this.
 *  When this is active *server* checks the NAI realm of EAP-response/Identity is
 *  the same as realm given in the certificate of the client.
 *  When this is active *client* checks the NAI realm of EAP-response/Identity is
 *  the same as realm given in the certificate of the server.
 *  Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_verify_certificate_realm,
	"EAP_TLS_PEAP_verify_certificate_realm",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  This flag activates "relaxed" NAI realm check of certificate. Realm does not have to 
 *  match exactly in this mode. For example server.eapsim.foo and eapsim.foo are considered 
 *  to be the same realm.
 *  Only client will check this.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_allow_subdomain_matching,
	"EAP_TLS_PEAP_allow_subdomain_matching",
	eap_configure_type_boolean,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_PEAP_use_eap_expanded_type,
	"EAP_TLS_PEAP_use_eap_expanded_type",
	eap_configure_type_boolean,
	false);

/**
 *  This u32_t configuration value specifies the maximum session validity time in seconds.
 *  Default value is 12 hours in seconds, which is 43200 seconds.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TLS_max_session_validity_time,
	"EAP_TLS_max_session_validity_time",
	eap_configure_type_u32_t,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_PEAP_max_session_validity_time,
	"EAP_PEAP_max_session_validity_time",
	eap_configure_type_u32_t,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_TTLS_max_session_validity_time,
	"EAP_TTLS_max_session_validity_time",
	eap_configure_type_u32_t,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_max_session_validity_time,
	"EAP_FAST_max_session_validity_time",
	eap_configure_type_u32_t,
	false);

/** @} */ // End of group EAP_TLS_PEAP_config_options.

//--------------------------------------------------


#endif //#if !defined(_EAP_TYPE_TLS_PEAP_TYPES_H_)

//--------------------------------------------------



// End.
