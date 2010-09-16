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

#if !defined(_EAP_SESSION_CORE_BASE_H_)
#define _EAP_SESSION_CORE_BASE_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_SESSION_CORE_BASE_H)
	#define EAP_CLASS_VISIBILITY_EAP_SESSION_CORE_BASE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_SESSION_CORE_BASE_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_SESSION_CORE_BASE_H 
	#define EAP_FUNC_EXPORT_EAP_SESSION_CORE_BASE_H 
	#define EAP_C_FUNC_EXPORT_EAP_SESSION_CORE_BASE_H 
#elif defined(EAP_EXPORT_EAP_SESSION_CORE_BASE_H)
	#define EAP_CLASS_VISIBILITY_EAP_SESSION_CORE_BASE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_SESSION_CORE_BASE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_SESSION_CORE_BASE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_SESSION_CORE_BASE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_SESSION_CORE_BASE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_SESSION_CORE_BASE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_SESSION_CORE_BASE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_SESSION_CORE_BASE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_SESSION_CORE_BASE_H 
	#define EAP_C_FUNC_EXPORT_EAP_SESSION_CORE_BASE_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_core.h"
#include "eap_core_map.h"
#include "eap_database_reference_if.h"
#include "eapol_key_types.h"

class abs_eap_session_core_c;

/// A eap_session_core_base_c class implements mapping of EAP authentication sessions.
/// Network identity separates parallel EAP authentication sessions.
class EAP_CLASS_VISIBILITY_EAP_SESSION_CORE_BASE_H eap_session_core_base_c
: public eap_database_reference_if_c
{
private:
	//--------------------------------------------------


	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the eap_core class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_SESSION_CORE_BASE_H virtual ~eap_session_core_base_c();

	/**
	 * The constructor initializes member attributes using parameters passed to it.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 * @param partner is back pointer to object which created this object.
	 * @param is_client_when_true indicates whether the network entity should act
	 * as a client (true) or server (false), in terms of EAP-protocol
	 * whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	 */
	EAP_FUNC_VISIBILITY_EAP_SESSION_CORE_BASE_H eap_session_core_base_c();

	/**
	 * This function must reset the state of object to same as 
	 * state was after the configure() function call.
	 * If object reset succeeds this function must return eap_status_ok.
	 * If object reset fails this function must return corresponding error status.
	 * @return This function returns the status of reset operation.
	 */
	virtual eap_status_e reset() = 0;

	// This is documented in abs_eap_stack_interface_c::packet_process().
	virtual eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id,
		eap_general_header_base_c * const packet_data,
		const u32_t packet_length) = 0; 

	/**
	 * The adaptation module calls the eap_acknowledge() function after
	 * any Network Protocol packet is received. This is used as a success indication.
	 * This is described in RFC 2284 "PPP Extensible Authentication Protocol (EAP)".
	 * @param connection_handle separates the context of the acknowledged session.
	 * Mostly there is only one session in the client.
	 * The server does not need eap_acknowledge() function because
	 * server (EAP-authenticator) sends the EAP-success message.
	 */
	virtual eap_status_e eap_acknowledge(
		const eap_am_network_id_c * const receive_network_id) = 0; 

#if defined(USE_EAP_CORE_SERVER)
	/**
	 * The EAP Core calls the send_eap_identity_request() function
	 * when EAP-authentication is needed with another peer.
	 * @param network_id includes the addresses (network identity) and packet type.
	 */
	virtual eap_status_e send_eap_identity_request(
		const eap_am_network_id_c * const network_id) = 0;
#endif //#if defined(USE_EAP_CORE_SERVER)

	// This is documented in abs_eap_stack_interface_c::configure().
	virtual eap_status_e configure() = 0;

	// This is documented in abs_eap_stack_interface_c::shutdown().
	virtual eap_status_e shutdown() = 0;

	// This is documented in abs_eap_stack_interface_c::get_is_valid().
	virtual bool get_is_valid() = 0;

	/**
	 * This function cancels all EAP-sessions.
	 * If this succeeds this function must return eap_status_ok.
	 * If this fails this function must return corresponding error status.
	 * @return This function returns the status of operation.
	 */
	virtual eap_status_e cancel_all_eap_sessions() = 0;

	/**
	 * This function creates EAP session object synchronously.
	 * @param receive_network_id identifies the removed EAP session.
	 */
	virtual eap_status_e create_eap_session(
		const eap_am_network_id_c * const receive_network_id) = 0;

	/**
	 * This function removes EAP session object synchronously.
	 * @param receive_network_id identifies the removed EAP session.
	 */
	virtual eap_status_e remove_eap_session(
		const bool complete_to_lower_layer,
		const eap_am_network_id_c * const receive_network_id) = 0;

	virtual eap_status_e get_802_11_authentication_mode(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const SSID,
		const eap_variable_data_c * const preshared_key) = 0;

	//--------------------------------------------------

	EAP_FUNC_VISIBILITY_EAP_SESSION_CORE_BASE_H static eap_session_core_base_c * new_eap_session_core_c(
		abs_eap_am_tools_c * const tools,
		abs_eap_session_core_c * const partner,
		const bool is_client_when_true,
		const u32_t MTU);

	//--------------------------------------------------
}; // class eap_session_core_base_c

eap_session_core_base_c * new_eap_core_client_message_if_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_session_core_c * const partner,
	const bool is_client_when_true,
	const u32_t MTU);

//--------------------------------------------------

#endif //#if !defined(_EAP_SESSION_CORE_BASE_H_)

//--------------------------------------------------



// End.
