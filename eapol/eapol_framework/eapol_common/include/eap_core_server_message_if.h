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
* %version: 17 %
*/

#if !defined(_EAP_CORE_SERVER_MESSAGE_IF_H_)
#define _EAP_CORE_SERVER_MESSAGE_IF_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_CORE_SERVER_MESSAGE_IF_H)
	#define EAP_CLASS_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H 
	#define EAP_FUNC_EXPORT_EAP_CORE_SERVER_MESSAGE_IF_H 
	#define EAP_C_FUNC_EXPORT_EAP_CORE_SERVER_MESSAGE_IF_H 
#elif defined(EAP_EXPORT_EAP_CORE_SERVER_MESSAGE_IF_H)
	#define EAP_CLASS_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_CORE_SERVER_MESSAGE_IF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_CORE_SERVER_MESSAGE_IF_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_CORE_SERVER_MESSAGE_IF_H 
	#define EAP_C_FUNC_EXPORT_EAP_CORE_SERVER_MESSAGE_IF_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_session_core.h"
#include "eap_variable_data.h"
#include "abs_eap_am_mutex.h"
#include "eap_session_core_base.h"
#include "abs_eap_am_message_if.h"
#include "eap_am_message_if.h"
#include "eap_process_tlv_message_data.h"
#include "abs_eap_am_stack.h"
#include "eap_am_stack.h"

#if defined(USE_EAP_SIMPLE_CONFIG)
#include "simple_config_types.h"
#include "simple_config_credential.h"
#include "simple_config_payloads.h"
#include "abs_eap_configuration_if.h"
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)


/** @file */


/// A eap_core_server_message_if_c class implements the basic functionality of EAPOL.
class EAP_CLASS_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_core_server_message_if_c
: public abs_eap_session_core_c
, public eap_am_message_if_c
, public abs_eap_base_timer_c
, public abs_eap_am_stack_c
{

private:
	//--------------------------------------------------

	/// This is back pointer to object which created this object.
	abs_eap_am_message_if_c * m_partner;

	/// This is pointer to the eap_core object. The eapol_core object gives
	/// the received packets to the eap_core object. The eap_core object sends
	/// packets through the eapol_core object.
	eap_session_core_base_c * const m_eap_core;

	eap_am_stack_c * const m_am_stack;

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is offset in bytes of the EAP header.
	u32_t m_eap_header_offset;

	/// This is maximum transfer unit in bytes.
	u32_t m_MTU;

	/// This is length of the trailer in bytes.
	u32_t m_trailer_length;

	eap_status_e m_error_code;

	eap_tlv_message_type_function_e m_error_function;

	/// This indicates whether this object is client (true) or server (false).
	/// In terms of EAP-protocol whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	bool m_is_client;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	bool m_shutdown_was_called;

	eap_status_e send_error_message(
		const eap_status_e error_code,
		const eap_tlv_message_type_function_e function);

	eap_status_e send_message(eap_process_tlv_message_data_c * const message);

	eap_status_e process_message_type_error(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e process_message(eap_process_tlv_message_data_c * const message);

	eap_status_e create_eap_session(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e remove_eap_session(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e send_eap_identity_request(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e packet_process(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e eap_acknowledge(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e set_eap_database_reference_values(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e eap_mtu(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e get_802_11_authentication_mode(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);


	eap_status_e complete_remove_eap_session(
		const bool complete_to_lower_layer,
		const eap_am_network_id_c * const receive_network_id);


	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor deletes the m_eap_core object.
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H virtual ~eap_core_server_message_if_c();

	/**
	 * The constructor creates the eap_core object and initializes the m_eap_core
	 * to point the eap_core object.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 * @param partner is back pointer to object which created this object.
	 * @param is_client_when_true indicates whether the network entity should act
	 * as a client (true) or server (false), in terms of EAP-protocol whether
	 * this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_core_server_message_if_c(
		abs_eap_am_tools_c * const tools,
		const bool is_client_when_true,
		const u32_t MTU);

	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H void set_partner(abs_eap_am_message_if_c * const partner);

	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e process_data(const void * const data, const u32_t length);

	/**
	 * The class could send packets to partner class with this function.
	 * eap_core_server_message_if_c adds EAPOL header to the send packet.
	 * @param send_network_id carries the addresses (network identity) and type of the packet.
	 * @param sent_packet includes the buffer for the whole packet and initialized 
	 * EAP-packet in correct offset.
	 * @param header_offset is offset of the EAP-header within the sent_packet.
	 * @param data_length is length in bytes of the EAP-packet.
	 * @param buffer_length is length in bytes of the whole packet buffer.
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e packet_send(
		const eap_am_network_id_c * const send_network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length); 

	/**
	 * The get_header_offset() function obtains the header offset of EAP-packet.
	 * @param MTU_length is pointer to variable to store the maximum transfer unit (MTU).
	 * MTU is the maximum EAP-packet length in bytes
	 * @param trailer_length is pointer to the variable to store length
	 * of trailer needed by lower levels.
	 * @return Function returns the offset of EAP-header.
	 * @see abs_eap_core_c::get_header_offset().
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length);

	/**
	 * The load_module() function function indicates the lower level to
	 * load new module of EAP-type.
	 * @see abs_eap_core_c::load_module().
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e /* tunneling_type */,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * The unload_module() function unloads the module of a EAP-type. 
	 * @see abs_eap_core_c::unload_module().
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e unload_module(
		const eap_type_value_e type); 

	/**
	 * Note this function is just an example. Parameters will change later.
	 * The packet_data_crypto_keys() function gives the generated keys to lower level.
	 * After EAP-authentication has generated the keys it calls this function
	 * to offer the keys to lower level.
	 * @see abs_eap_base_type_c::packet_data_crypto_keys().
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e packet_data_crypto_keys(
		const eap_am_network_id_c * const send_network_id,
		const eap_master_session_key_c * const master_session_key
		);

	// This is documented in abs_eap_stack_interface_c::configure().
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e configure(
		const eap_variable_data_c * const client_configuration);

	// This is documented in abs_eap_stack_interface_c::shutdown().
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e shutdown();

	/**
	 * The read_configure() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @see abs_eap_base_type_c::read_configure().
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	/**
	 * The write_configure() function writes the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the action to some persistent store.
	 * @see abs_eap_base_type_c::write_configure().
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	// This is documented in abs_eap_stack_interface_c::set_is_valid().
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H void set_is_valid();

	// This is documented in abs_eap_stack_interface_c::get_is_valid().
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H bool get_is_valid();

	// See abs_eap_base_type_c::state_notification().
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H void state_notification(
		const abs_eap_state_notification_c * const state);

	// See abs_eap_base_timer_c::timer_expired().
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e timer_expired(
		const u32_t id, void *data);

	// See abs_eap_base_timer_c::timer_delete_data().
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e timer_delete_data(
		const u32_t id, void *data);

	/**
	 * This function tells lower layer to remove EAP session object asyncronously.
	 * @param send_network_id is pointer to network id that identifies the removed EAP session.
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e asynchronous_init_remove_eap_session(
		const eap_am_network_id_c * const send_network_id);

	/**
	 * The upper layer calls the asynchronous_start_authentication() function
	 * when EAP-authentication is needed with another peer.
	 * @see abs_eap_core_c::asynchronous_start_authentication().
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e asynchronous_start_authentication(
		const eap_am_network_id_c * const /* receive_network_id */,
		const bool /* is_client_when_true */);

	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e restart_authentication(
		const eap_am_network_id_c * const send_network_id,
		const bool is_client_when_true,
		const bool force_clean_restart,
		const bool from_timer = false);

	//
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e set_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id, 
		void * const p_data,
		const u32_t p_time_ms);

	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e cancel_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id);

	//
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e check_is_valid_eap_type(const eap_type_value_e eap_type);

	// See abs_eap_core_c::get_eap_type_list().
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e get_eap_type_list(
		eap_array_c<eap_type_value_e> * const eap_type_list);

	/// @see abs_eap_core_c::add_rogue_ap().
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e add_rogue_ap(eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list);

	// This is documented in abs_eap_core_c::set_session_timeout().
	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e set_session_timeout(
		const u32_t session_timeout_ms);

#if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e save_simple_config_session(
		const simple_config_state_e state,
		EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
		const eap_variable_data_c * const new_password,
		const simple_config_Device_Password_ID_e Device_Password_ID,
		const simple_config_payloads_c * const other_configuration);

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_EAP_CORE_SERVER_MESSAGE_IF_H eap_status_e complete_get_802_11_authentication_mode(
		const eap_status_e completion_status,
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_802_11_authentication_mode_e mode);

	//--------------------------------------------------
}; // class eap_core_server_message_if_c

#endif //#if !defined(_EAP_CORE_SERVER_MESSAGE_IF_H_)

//--------------------------------------------------



// End.
