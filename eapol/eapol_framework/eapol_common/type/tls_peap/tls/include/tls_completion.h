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

#if !defined(_TLS_COMPLETION_H_)
#define _TLS_COMPLETION_H_

#include "eap_tools.h"
#include "eap_array.h"
#include "tls_record_message.h"
#include "abs_tls_message_hash.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_TLS_COMPLETION_H)
	#define EAP_CLASS_VISIBILITY_TLS_COMPLETION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_TLS_COMPLETION_H 
	#define EAP_C_FUNC_VISIBILITY_TLS_COMPLETION_H 
	#define EAP_FUNC_EXPORT_TLS_COMPLETION_H 
	#define EAP_C_FUNC_EXPORT_TLS_COMPLETION_H 
#elif defined(EAP_EXPORT_TLS_COMPLETION_H)
	#define EAP_CLASS_VISIBILITY_TLS_COMPLETION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_TLS_COMPLETION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_COMPLETION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_TLS_COMPLETION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_TLS_COMPLETION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_TLS_COMPLETION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_TLS_COMPLETION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_COMPLETION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_TLS_COMPLETION_H 
	#define EAP_C_FUNC_EXPORT_TLS_COMPLETION_H 
#endif
// End: added by script change_export_macros.sh.


/** @file */

/**
 * This is enumeration of TLS competion actions.
 */
enum tls_completion_action_e
{
	tls_completion_action_none,                                               ///< Initialization value means no action.
	tls_completion_action_create_handshake_type_hello_request,                ///< create_handshake_type_hello_request
	tls_completion_action_create_handshake_type_client_hello,                 ///< create_handshake_type_client_hello
	tls_completion_action_create_handshake_type_server_hello,                 ///< create_handshake_type_server_hello
	tls_completion_action_create_handshake_type_certificate,                  ///< create_handshake_type_certificate
	tls_completion_action_create_handshake_type_server_key_exchange,          ///< create_handshake_type_server_key_exchange
	tls_completion_action_create_handshake_type_certificate_request,          ///< create_handshake_type_certificate_request
	tls_completion_action_create_handshake_type_server_hello_done,            ///< create_handshake_type_server_hello_done
	tls_completion_action_create_handshake_type_certificate_verify,           ///< create_handshake_type_certificate_verify
	tls_completion_action_create_handshake_type_client_key_exchange,          ///< create_handshake_type_client_key_exchange
	tls_completion_action_create_handshake_type_finished,                     ///< create_handshake_type_finished
	tls_completion_action_finish_handshake,                                   ///< finish_handshake
#if defined(USE_EAP_TLS_SESSION_TICKET)
	tls_completion_action_create_handshake_type_new_session_ticket,           ///< create_handshake_type_new_session_ticket
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)
	tls_completion_action_create_change_cipher_spec_type_change_cipher_spec,  ///< create_change_cipher_spec_type_change_cipher_spec
	tls_completion_action_query_dh_parameters,                                ///< query_dh_parameters
	tls_completion_action_verify_certificate_chain,                           ///< verify_certificate_chain
	tls_completion_action_process_tls_records,                                ///< process_tls_records
	tls_completion_action_check_sent_tls_message,                             ///< check_sent_tls_message
	tls_completion_action_complete_create_handshake_type_server_key_exchange, ///< complete_create_handshake_type_server_key_exchange
	tls_completion_action_complete_create_handshake_type_certificate_verify,  ///< complete_create_handshake_type_certificate_verify
	tls_completion_action_complete_create_handshake_type_client_key_exchange, ///< complete_create_handshake_type_client_key_exchange
	tls_completion_action_query_cipher_suites_and_previous_session,           ///< query_cipher_suites_and_previous_session
	tls_completion_action_check_tunnel_authentication_runs,                   ///< check_tunnel_authentication_runs
};

//----------------------------------------------------------------------------


/// This class defines one TLS completion action.
class EAP_CLASS_VISIBILITY_TLS_COMPLETION_H tls_completion_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class. @see abs_eap_am_tools_c.
	abs_eap_am_tools_c * const m_am_tools;

	/// This variable stores the completion action.
	tls_completion_action_e m_completion_action;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/**
	 * The set_is_valid() function sets the state of the object valid.
	 * The creator of this object calls this function after it is initialized. 
	 */
	EAP_FUNC_VISIBILITY_TLS_COMPLETION_H void set_is_valid();

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * Destructor does nothing special.
	 */
	EAP_FUNC_VISIBILITY_TLS_COMPLETION_H virtual ~tls_completion_c();

	/**
	 * Constructor initializes object.
	 */
	EAP_FUNC_VISIBILITY_TLS_COMPLETION_H tls_completion_c(
		abs_eap_am_tools_c * const tools,
		tls_completion_action_e completion_action);

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	EAP_FUNC_VISIBILITY_TLS_COMPLETION_H bool get_is_valid();

	/**
	 * This function sets the completion action type.
	 */
	EAP_FUNC_VISIBILITY_TLS_COMPLETION_H void set_completion_action(tls_completion_action_e completion_action);

	/**
	 * This function gets the completion action type.
	 */
	EAP_FUNC_VISIBILITY_TLS_COMPLETION_H tls_completion_action_e get_completion_action() const;

	/**
	 * This function gets the debug string of the completion action type.
	 */
	EAP_FUNC_VISIBILITY_TLS_COMPLETION_H eap_const_string  get_completion_action_string() const;

	// 
	//--------------------------------------------------
}; // class tls_completion_c


//--------------------------------------------------

#endif //#if !defined(_TLS_COMPLETION_H_)



// End.
