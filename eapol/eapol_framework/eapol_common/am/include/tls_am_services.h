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

#if !defined(_TLS_AM_SERVICES_H_)
#define _TLS_AM_SERVICES_H_

#include "eap_tools.h"
#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_TLS_AM_SERVICES_H)
	#define EAP_CLASS_VISIBILITY_TLS_AM_SERVICES_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_TLS_AM_SERVICES_H 
	#define EAP_C_FUNC_VISIBILITY_TLS_AM_SERVICES_H 
	#define EAP_FUNC_EXPORT_TLS_AM_SERVICES_H 
	#define EAP_C_FUNC_EXPORT_TLS_AM_SERVICES_H 
#elif defined(EAP_EXPORT_TLS_AM_SERVICES_H)
	#define EAP_CLASS_VISIBILITY_TLS_AM_SERVICES_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_TLS_AM_SERVICES_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_AM_SERVICES_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_TLS_AM_SERVICES_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_TLS_AM_SERVICES_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_TLS_AM_SERVICES_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_TLS_AM_SERVICES_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_AM_SERVICES_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_TLS_AM_SERVICES_H 
	#define EAP_C_FUNC_EXPORT_TLS_AM_SERVICES_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_am_type_tls_peap.h"
#include "eap_am_network_id.h"
#include "eap_array.h"
#include "tls_peap_types.h"

class abs_tls_am_services_c;

#if defined(USE_EAP_TLS_SESSION_TICKET)
class tls_extension_c;
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)


/// This class is interface to adaptation module of TLS.
class EAP_CLASS_VISIBILITY_TLS_AM_SERVICES_H tls_am_services_c
{
private:
	//--------------------------------------------------

	/// This function returns pointer to adaptation module of TLS. See abs_tls_am_services_c.
	virtual abs_tls_am_services_c * get_tls_am_partner() = 0;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	virtual ~tls_am_services_c()
	{
	}

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	virtual bool get_is_valid() = 0;

	/// This function sets pointer to adaptation module of TLS. See abs_tls_am_services_c.
	virtual void set_tls_am_partner(abs_tls_am_services_c * const tls_am_partner) = 0;

	/**
	 * The configure() function is called after the constructor of the 
	 * object is successfully executed. During the function call the object 
	 * could query the configuration. Each derived class must define this function.
	 */
	virtual eap_status_e configure() = 0;

	/**
	 * The shutdown() function is called before the destructor of the 
	 * object is executed. During the function call the object 
	 * could shutdown the operations, for example cancel timers.
	 * Each derived class must define this function.
	 */
	virtual eap_status_e shutdown() = 0;

	/**
	 * This function is called when TLS-Alert message is received.
	 * Adaptation module could record this event.
	 */
	virtual eap_status_e alert_received(
		const tls_alert_level_e alert_level,
		const tls_alert_description_e alert_description) = 0;

	/**
	 * This function queries from AM cipher suites and previous session.
	 * abs_tls_am_services_c::complete_query_cipher_suites_and_previous_session() completes this query.
	 */
	virtual eap_status_e query_cipher_suites_and_previous_session() = 0;

#if defined(USE_EAP_TLS_SESSION_TICKET)
	/**
	 * This function queries from AM a new session ticket, see RFC 4507.
	 * abs_tls_am_services_c::complete_query_new_session_ticket() completes this query.
	 */
	virtual eap_status_e query_new_session_ticket() = 0;
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)

	/**
	 * This function queries AM to select cipher suite and check session id.
	 * abs_tls_am_services_c::complete_select_cipher_suite_and_check_session_id() completes this query.
	 */
	virtual eap_status_e select_cipher_suite_and_check_session_id(
		EAP_TEMPLATE_CONST eap_array_c<u16_t> * const cipher_suite_proposal,
		const eap_variable_data_c * const session_id
#if defined(USE_EAP_TLS_SESSION_TICKET)
		, const tls_extension_c * const session_ticket
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)
		) = 0; 


	/**
	 * This function queries AM to verify certificate chain.
	 * abs_tls_am_services_c::complete_verify_certificate_chain() completes this query.
	 */
	virtual eap_status_e verify_certificate_chain(
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_chain,
		const tls_cipher_suites_e required_cipher_suite) = 0;

	/**
	 * This function queries AM certificate chain.
	 * abs_tls_am_services_c::complete_query_certificate_chain() completes this query.
	 */
	virtual eap_status_e query_certificate_chain(
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_authorities,
		EAP_TEMPLATE_CONST eap_array_c<u8_t> * const certificate_types,
		const tls_cipher_suites_e required_cipher_suite) = 0;

	/**
	 * This function queries AM certificate authorities and certifica types.
	 * abs_tls_am_services_c::complete_query_certificate_authorities_and_types() completes this query.
	 */
	virtual eap_status_e query_certificate_authorities_and_types() = 0;

	/**
	 * This function queries AM ephemeral Diffie-Hellman parameters.
	 * abs_tls_am_services_c::complete_query_dh_parameters() completes this query.
	 */
	virtual eap_status_e query_dh_parameters(
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_chain,
		const tls_cipher_suites_e required_cipher_suite) = 0;

	/**
	 * This function queries AM NAI realm.
	 * abs_tls_am_services_c::complete_query_realm() completes this query.
	 */
	virtual eap_status_e query_realm(
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_chain) = 0;

	/**
	 * This function tells AM to save TLS-session ID and master secret.
	 * If AM does not support TLS-session resumption AM could dischard these paramteters.
	 * This is always syncronous call.
	 */
	virtual eap_status_e save_tls_session(
		const eap_variable_data_c * const session_id,
		const eap_variable_data_c * const master_secret,
		const tls_cipher_suites_e used_cipher_suite
#if defined(USE_EAP_TLS_SESSION_TICKET)
		, const tls_extension_c * const new_session_ticket
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)
		) = 0;

	/**
	 * This function encrypts data with own RSA private key.
	 * abs_tls_am_services_c::complete_rsa_encrypt_with_public_key() completes this query.
	 */
	virtual eap_status_e rsa_encrypt_with_public_key(
		const eap_variable_data_c * const premaster_secret) = 0;

	/**
	 * This function decrypts data with own RSA private key.
	 * abs_tls_am_services_c::complete_rsa_decrypt_with_private_key() completes this query.
	 */
	virtual eap_status_e rsa_decrypt_with_private_key(
		const eap_variable_data_c * const encrypted_premaster_secret) = 0;

	/** 
	 * Function signs data with own PKI private key.
	 * abs_tls_am_services_c::complete_sign_with_private_key() completes this query.
	 */
	virtual eap_status_e sign_with_private_key(
		const eap_variable_data_c * const message_hash) = 0;

	/**
	 * This function verifies signed data with peer PKI public key.
	 * abs_tls_am_services_c::complete_verify_with_public_key() completes this query.
	 */
	virtual eap_status_e verify_with_public_key(
		const eap_variable_data_c * const message_hash,
		const eap_variable_data_c * const signed_message_hash) = 0;


	/**
	 * This function cancels query_cipher_suites_and_previous_session() query.
	 * After this call AM must not complete related query.
	 */
	virtual eap_status_e cancel_query_cipher_suites_and_previous_session() = 0;

	/**
	 * This function cancels select_cipher_suite_and_check_session_id() query.
	 * After this call AM must not complete related query.
	 */
	virtual eap_status_e cancel_select_cipher_suite_and_check_session_id() = 0;

	/**
	 * This function cancels verify_certificate_chain() query.
	 * After this call AM must not complete related query.
	 */
	virtual eap_status_e cancel_verify_certificate_chain() = 0;

	/**
	 * This function cancels query_certificate_chain() query.
	 * After this call AM must not complete related query.
	 */
	virtual eap_status_e cancel_query_certificate_chain() = 0;

	/**
	 * This function cancels query_certificate_authorities_and_types() query.
	 * After this call AM must not complete related query.
	 */
	virtual eap_status_e cancel_query_certificate_authorities_and_types() = 0;

	/**
	 * This function cancels query_dh_parameters() query.
	 * After this call AM must not complete related query.
	 */
	virtual eap_status_e cancel_query_dh_parameters() = 0;

	/**
	 * This function cancels query_realm() query.
	 * After this call AM must not complete related query.
	 */
	virtual eap_status_e cancel_query_realm() = 0;

	/**
	 * This function cancels rsa_encrypt_with_public_key() query.
	 * After this call AM must not complete related query.
	 */
	virtual eap_status_e cancel_rsa_encrypt_with_public_key() = 0;

	/**
	 * This function cancels rsa_decrypt_with_private_key() query.
	 * After this call AM must not complete related query.
	 */
	virtual eap_status_e cancel_rsa_decrypt_with_private_key() = 0;

	/**
	 * This function cancels sign_with_private_key() query.
	 * After this call AM must not complete related query.
	 */
	virtual eap_status_e cancel_sign_with_private_key() = 0;

	/**
	 * This function cancels verify_with_public_key() query.
	 * After this call AM must not complete related query.
	 */
	virtual eap_status_e cancel_verify_with_public_key() = 0;

	/**
	 * This function sets the tunnel type.
	 */
	virtual void set_peap_version(
		const peap_version_e peap_version,
		const bool use_tppd_tls_peap,
		const bool use_tppd_peapv1_acknowledge_hack) = 0;

	virtual bool is_ttls_pap_session_valid() = 0;

	virtual eap_status_e query_ttls_pap_username_and_password(
		const eap_variable_data_c * const reply_message) = 0;

	virtual eap_status_e verify_ttls_pap_username_and_password(
		const eap_variable_data_c * const user_name,
		const eap_variable_data_c * const user_password) = 0;

	//--------------------------------------------------
}; // class tls_am_services_c


/** @file */ 

/**
 * This function creates a new instance of adaptation module of TLS.
 * @param tools is pointer to the abs_eap_am_tools class created by the adaptation module.
 * Adaptation module of TLS will callback caller using the partner pointer.
 */
EAP_C_FUNC_VISIBILITY_TLS_AM_SERVICES_H  tls_am_services_c *new_tls_am_services(
	abs_eap_am_tools_c * const tools);


#endif //#if !defined(_TLS_AM_SERVICES_H_)

//--------------------------------------------------



// End.
