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
* %version: 23 %
*/

#if !defined(_EAP_CORE_CLIENT_MESSAGE_IF_H_)
#define _EAP_CORE_CLIENT_MESSAGE_IF_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_CORE_CLIENT_MESSAGE_IF_H)
	#define EAP_CLASS_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H 
	#define EAP_FUNC_EXPORT_EAP_CORE_CLIENT_MESSAGE_IF_H 
	#define EAP_C_FUNC_EXPORT_EAP_CORE_CLIENT_MESSAGE_IF_H 
#elif defined(EAP_EXPORT_EAP_CORE_CLIENT_MESSAGE_IF_H)
	#define EAP_CLASS_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_CORE_CLIENT_MESSAGE_IF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_CORE_CLIENT_MESSAGE_IF_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_CORE_CLIENT_MESSAGE_IF_H 
	#define EAP_C_FUNC_EXPORT_EAP_CORE_CLIENT_MESSAGE_IF_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_session_core_base.h"
#include "abs_eap_session_core.h"
#include "eap_core_map.h"
#include "abs_eap_stack_interface.h"
#include "abs_eap_am_message_if.h"
#include "eap_am_message_if.h"
#include "eap_process_tlv_message_data.h"
#include "eap_database_reference_if.h"

class eap_tlv_header_c;


/// A eap_core_client_message_if_c class implements mapping of EAP authentication sessions.
/// Network identity separates parallel EAP authentication sessions.
class EAP_CLASS_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H eap_core_client_message_if_c
: public abs_eap_am_message_if_c
, public eap_session_core_base_c
, public abs_eap_base_timer_c
, public abs_eap_stack_interface_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// eap_core_client_message_if_c deletes m_server_if in destructor.
	eap_am_message_if_c * m_server_if;

	/// This is back pointer to object which created this object.
	/// Packets are sent to the partner.
	abs_eap_session_core_c * const m_partner;

	eap_status_e m_error_code;

	eap_tlv_message_type_function_e m_error_function;

	/// This is offset in bytes of the EAP header.
	u32_t m_eap_header_offset;

	/// This is maximum transfer unit in bytes.
	u32_t m_MTU;

	/// This is length of the trailer in bytes.
	u32_t m_trailer_length;

	/// This indicates whether this object is client (true) or server (false).
	/// In terms of EAP-protocol whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	bool m_is_client;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	bool m_shutdown_was_called;

	// This is documented in abs_eap_stack_interface_c::set_is_valid().
	void set_is_valid();

	eap_status_e process_message(eap_process_tlv_message_data_c * const message);

	eap_status_e process_error_message(
		const eap_status_e error_code,
		const eap_tlv_message_type_function_e function);

	eap_status_e process_message_type_error(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e packet_send(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e state_notification(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e packet_data_crypto_keys(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e restart_authentication(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e new_protected_setup_credentials(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e complete_get_802_11_authentication_mode(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e complete_remove_eap_session(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e eap_mtu(
		const u32_t MTU);

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the eap_core class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H virtual ~eap_core_client_message_if_c();

	/**
	 * The constructor initializes member attributes using parameters passed to it.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 * @param partner is back pointer to object which created this object.
	 * @param is_client_when_true indicates whether the network entity should act
	 * as a client (true) or server (false), in terms of EAP-protocol
	 * whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H eap_core_client_message_if_c(
		abs_eap_am_tools_c * const tools,
		eap_am_message_if_c * const server,
		abs_eap_session_core_c * const partner,
		const bool is_client_when_true);

	void set_partner(abs_eap_am_message_if_c * const client);

	/**
	 * This function must reset the state of object to same as 
	 * state was after the configure() function call.
	 * If object reset succeeds this function must return eap_status_ok.
	 * If object reset fails this function must return corresponding error status.
	 * @return This function returns the status of reset operation.
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H eap_status_e reset();

	/**
	 * This function cancels all EAP-sessions.
	 * If this succeeds this function must return eap_status_ok.
	 * If this fails this function must return corresponding error status.
	 * @return This function returns the status of operation.
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H eap_status_e cancel_all_eap_sessions();

	// This is documented in abs_eap_stack_interface_c::packet_process().
	EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id,
		eap_general_header_base_c * const packet_data,
		const u32_t packet_length); 

	/**
	 * The adaptation module calls the eap_acknowledge() function after
	 * any Network Protocol packet is received. This is used as a success indication.
	 * This is described in RFC 2284 "PPP Extensible Authentication Protocol (EAP)".
	 * @param connection_handle separates the context of the acknowledged session.
	 * Mostly there is only one session in the client.
	 * The server does not need eap_acknowledge() function because
	 * server (EAP-authenticator) sends the EAP-success message.
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H eap_status_e eap_acknowledge(
		const eap_am_network_id_c * const receive_network_id); 

#if defined(USE_EAP_CORE_SERVER)
	/**
	 * The EAP Core calls the send_eap_identity_request() function
	 * when EAP-authentication is needed with another peer.
	 * @param network_id includes the addresses (network identity) and packet type.
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H eap_status_e send_eap_identity_request(
		const eap_am_network_id_c * const network_id);
#endif //#if defined(USE_EAP_CORE_SERVER)

	// This is documented in abs_eap_stack_interface_c::configure().
	EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H eap_status_e configure();

	// This is documented in abs_eap_stack_interface_c::shutdown().
	EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H eap_status_e shutdown();

	// This is documented in abs_eap_stack_interface_c::get_is_valid().
	EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H bool get_is_valid();

	/**
	 * This function creates EAP session object synchronously.
	 * @param receive_network_id identifies the removed EAP session.
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H eap_status_e create_eap_session(
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * This function removes EAP session object synchronously.
	 * @param receive_network_id identifies the removed EAP session.
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H eap_status_e remove_eap_session(
		const bool complete_to_lower_layer,
		const eap_am_network_id_c * const receive_network_id);

	// See abs_eap_base_timer_c::timer_expired().
	EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H eap_status_e timer_expired(
		const u32_t id, void *data);

	// See abs_eap_base_timer_c::timer_delete_data().
	EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H eap_status_e timer_delete_data(
		const u32_t id, void *data);

	// See abs_eap_am_message_if_c::send_data().
	EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H eap_status_e send_data(const void * const data, const u32_t length);


	EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H eap_status_e set_eap_database_reference_values(
		const eap_variable_data_c * const reference);

	EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H eap_status_e get_802_11_authentication_mode(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const SSID,
		const eap_variable_data_c * const preshared_key);

	EAP_FUNC_VISIBILITY_EAP_CORE_CLIENT_MESSAGE_IF_H eap_status_e complete_get_802_11_authentication_mode(
		const eap_status_e completion_status,
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_802_11_authentication_mode_e mode);

	//--------------------------------------------------
}; // class eap_core_client_message_if_c

//--------------------------------------------------

#endif //#if !defined(_EAP_CORE_CLIENT_MESSAGE_IF_H_)

//--------------------------------------------------



// End.
