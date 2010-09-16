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

#if !defined(_ABS_TLS_AM_SERVICES_H_)
#define _ABS_TLS_AM_SERVICES_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_TLS_AM_SERVICES_H)
	#define EAP_CLASS_VISIBILITY_ABS_TLS_AM_SERVICES_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_TLS_AM_SERVICES_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_TLS_AM_SERVICES_H 
	#define EAP_FUNC_EXPORT_ABS_TLS_AM_SERVICES_H 
	#define EAP_C_FUNC_EXPORT_ABS_TLS_AM_SERVICES_H 
#elif defined(EAP_EXPORT_ABS_TLS_AM_SERVICES_H)
	#define EAP_CLASS_VISIBILITY_ABS_TLS_AM_SERVICES_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_TLS_AM_SERVICES_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_TLS_AM_SERVICES_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_TLS_AM_SERVICES_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_TLS_AM_SERVICES_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_TLS_AM_SERVICES_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_TLS_AM_SERVICES_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_TLS_AM_SERVICES_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_TLS_AM_SERVICES_H 
	#define EAP_C_FUNC_EXPORT_ABS_TLS_AM_SERVICES_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_array.h"

#if defined(USE_EAP_TLS_SESSION_TICKET)
class tls_extension_c;
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)

/// This class declares the functions adaptation module of TLS
/// requires from the TLS.
class EAP_CLASS_VISIBILITY_ABS_TLS_AM_SERVICES_H abs_tls_am_services_c
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/// Destructor does nothing.
	virtual ~abs_tls_am_services_c()
	{
	}

	/// Constructor does nothing.
	abs_tls_am_services_c()
	{
	}

	// This is commented in eap_base_type_c::configure().
	virtual eap_status_e configure() = 0;

	/**
	 * This function completes the asyncronous
	 * tls_am_services_c::query_cipher_suites_and_previous_session() function call.
	 * The list of cipher suites and the list of compression methods are saved.
	 * All pending actions are checked and completed during this call.
	 * The parameter completion_status must be eap_status_ok when query is successfull.
	 */
	virtual eap_status_e complete_query_cipher_suites_and_previous_session(
		const tls_session_type_e session_type,
		EAP_TEMPLATE_CONST eap_array_c<u16_t> * const cipher_suites,
		EAP_TEMPLATE_CONST eap_array_c<u8_t> * const compression_methods,
#if defined(USE_EAP_TLS_SESSION_TICKET)
		EAP_TEMPLATE_CONST eap_array_c<tls_extension_c> * const tls_extensions,
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
		const eap_variable_data_c * const resumed_session_id,
		const eap_variable_data_c * const resumed_master_secret,
		const tls_cipher_suites_e resumed_cipher_suite,
		const eap_status_e completion_status) = 0;

	/**
	 * This function completes the asyncronous
	 * tls_am_services_c::select_cipher_suite_and_check_session_id() function call.
	 * The cipher suite, the session id and master secret are saved.
	 * NOTE the the session id and master secret are optional.
	 * Adaptation module can make independent
	 * decision to restore previous session or not. The selected cipher suite must be the same as
	 * was used in resumed session. The resumed cipher suite must be read from database.
	 * All pending actions are checked and completed during this call.
	 * The parameter completion_status must be eap_status_ok when query is successfull.
	 */
	virtual eap_status_e complete_select_cipher_suite_and_check_session_id(
		const tls_session_type_e session_type,
		const u16_t selected_cipher_suite,
		const eap_variable_data_c * const resumed_session_id,
		const eap_variable_data_c * const resumed_master_secret,
#if defined(USE_EAP_TLS_SESSION_TICKET)
		const tls_extension_c * const new_session_ticket_or_null,
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
		const eap_status_e completion_status) = 0;

#if defined(USE_EAP_TLS_SESSION_TICKET)
	/**
	 * This function completes the asyncronous
	 * tls_am_services_c::query_new_session_ticket() function call.
	 * The parameter new_session_ticket_or_null is pointer to the
	 * new session ticket or null if new session ticket is omitted.
	 */
	virtual eap_status_e complete_query_new_session_ticket(
		const tls_extension_c * const new_session_ticket_or_null) = 0;
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)

	/**
	 * This function completes the tls_am_services_c::asyncronous verify_certificate_chain()
	 * function call.
	 * The parameter result must be eap_status_ok when certificate chain is valid.
	 * All pending actions are checked and completed during this call.
	 */
	virtual eap_status_e complete_verify_certificate_chain(
		const eap_status_e result) = 0;

	/**
	 * This function completes the tls_am_services_c::asyncronous
	 * query_certificate_chain() function call.
	 * The parameter certificate_chain is saved.
	 * All pending actions are checked and completed during this call.
	 * The parameter completion_status must be eap_status_ok when query is successfull.
	 */
	virtual eap_status_e complete_query_certificate_chain(
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_chain,
		const eap_status_e completion_status) = 0;

	/**
	 * This function completes the tls_am_services_c::asyncronous
	 * query_certificate_authorities_and_types() function call.
	 * The parameters authorities and types are saved.
	 * All pending actions are checked and completed during this call.
	 * The parameter completion_status must be eap_status_ok when query is successfull.
	 */
	virtual eap_status_e complete_query_certificate_authorities_and_types(
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const authorities,
		EAP_TEMPLATE_CONST eap_array_c<u8_t> * const types,
		const eap_status_e completion_status) = 0;

	/**
	 * This function completes the tls_am_services_c::asyncronous query_dh_parameters()
	 * function call.
	 * The parameter dhe_prime and dhe_group_generator are saved.
	 * All pending actions are checked and completed during this call.
	 * The parameter completion_status must be eap_status_ok when query is successfull.
	 */
	virtual eap_status_e complete_query_dh_parameters(
		const eap_variable_data_c * const dh_prime,
		const eap_variable_data_c * const dh_group_generator,
		const eap_status_e completion_status) = 0;

	/**
	 * This function completes the asyncronous tls_am_services_c::query_realm() function call.
	 * The parameter realm is saved.
	 * All pending actions are checked and completed during this call.
	 * The parameter completion_status must be eap_status_ok when query is successfull.
	 */
	virtual eap_status_e complete_query_realm(
		const eap_variable_data_c * const realm,
		const eap_status_e completion_status) = 0;

	/**
	 * This function completes the asyncronous tls_am_services_c::rsa_encrypt_with_public_key() function call.
	 * The parameter encrypted_premaster_secret is saved.
	 * All pending actions are checked and completed during this call.
	 * The parameter completion_status must be eap_status_ok when query is successfull.
	 */
	virtual eap_status_e complete_rsa_encrypt_with_public_key(
		const eap_variable_data_c * const encrypted_premaster_secret,
		const eap_status_e completion_status) = 0;

	/**
	 * This function completes the asyncronous tls_am_services_c::rsa_decrypt_with_private_key() function call.
	 * The parameter premaster_secret is saved.
	 * All pending actions are checked and completed during this call.
	 * The parameter completion_status must be eap_status_ok when query is successfull.
	 */
	virtual eap_status_e complete_rsa_decrypt_with_private_key(
		const eap_variable_data_c * const premaster_secret,
		const eap_status_e completion_status) = 0;

	/**
	 * This function completes the asyncronous tls_am_services_c::sign_with_private_key() function call.
	 * The parameter message_hash is saved.
	 * All pending actions are checked and completed during this call.
	 * The parameter completion_status must be eap_status_ok when query is successfull.
	 */
	virtual eap_status_e complete_sign_with_private_key(
		const eap_variable_data_c * const signed_message_hash,
		const eap_status_e completion_status) = 0;

	/**
	 * This function completes the asyncronous tls_am_services_c::verify_with_public_key() function call.
	 * The parameter verify_status must be eap_status_ok when verification is successfull.
	 * All pending actions are checked and completed during this call.
	 */
	virtual eap_status_e complete_verify_with_public_key(
		const eap_status_e verify_status) = 0;

	virtual eap_status_e complete_query_ttls_pap_username_and_password(
		const eap_variable_data_c * const ttls_pap_username,
		const eap_variable_data_c * const ttls_pap_password,
		const eap_status_e query_result) = 0;

	virtual eap_status_e complete_verify_ttls_pap_username_and_password(
		const eap_status_e authentication_result,
		const eap_variable_data_c * const ttls_pap_reply_message) = 0;

	//--------------------------------------------------
}; // class abs_tls_am_services_c

#endif //#if !defined(_ABS_TLS_AM_SERVICES_H_)

//--------------------------------------------------



// End.
