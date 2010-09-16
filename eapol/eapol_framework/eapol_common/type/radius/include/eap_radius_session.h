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

#if !defined(_EAP_RADIUS_SESSION_H_)
#define _EAP_RADIUS_SESSION_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_RADIUS_SESSION_H)
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_SESSION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_SESSION_H 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_SESSION_H 
#elif defined(EAP_EXPORT_EAP_RADIUS_SESSION_H)
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_SESSION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_SESSION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_SESSION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_SESSION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_SESSION_H 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_SESSION_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_core.h"
#include "eap_core_map.h"
#include "abs_eap_stack_interface.h"
#include "eap_core.h"
#include "eap_radius_payloads.h"
#include "abs_eap_radius_session.h"
#include "eap_protocol_layer.h"
#include "eap_master_session_key.h"


class eap_core_c;
class eap_network_id_selector_c;


/**
 * This is the timer ID used with abs_eap_am_tools_c::set_timer() and abs_eap_am_tools_c::cancel_timer().
 */
enum eap_radius_session_timer_id
{
	EAP_RADIUS_SESSION_REMOVE_SESSION_ID, ///< See EAP_RADIUS_SESSION_REMOVE_SESSION_TIMEOUT.
};

/**
 * This is time after a EAP session is removed. This must be zero.
 */
const u32_t EAP_RADIUS_SESSION_REMOVE_SESSION_TIMEOUT = 0u;


/// A eap_radius_session_c class implements mapping of EAP authentication sessions.
/// Network identity separates parallel EAP authentication sessions.
class EAP_CLASS_VISIBILITY_EAP_RADIUS_SESSION_H eap_radius_session_c
: public abs_eap_core_c
, public abs_eap_core_map_c
, public abs_eap_base_timer_c
, public abs_eap_stack_interface_c
{
private:
	//--------------------------------------------------

	/// This is back pointer to object which created this object.
	/// Packets are sent to the partner.
	abs_eap_radius_session_c * const m_partner;

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is EAP core for this session.
	eap_core_c * m_eap_core;

	/// m_master_session_key includes also EAP-type.
	/// Note the LEAP type uses different key than other EAP-types.
	eap_master_session_key_c m_master_session_key;

	eap_variable_data_c m_request_authenticator;

	eap_variable_data_c m_shared_secret;

	u8_t m_identifier;

	eap_radius_variable_data_c * m_user_name;

	eap_radius_variable_data_c * m_nas_ip_address;

	eap_state_variable_e m_state;

	u32_t m_remove_session_timeout;

	/// This indicates whether this object is client (true) or server (false).
	/// In terms of EAP-protocol whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	bool m_is_client;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	bool m_shutdown_was_called;


	/**
	 * Function creates a new session.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_core_c * create_new_session(
		const eap_am_network_id_c * const receive_network_id);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H static eap_status_e shutdown_operation(
		eap_core_c * const core,
		abs_eap_am_tools_c * const m_am_tools);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e reset();

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the eap_core class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H virtual ~eap_radius_session_c();

	/**
	 * The constructor initializes member attributes using parameters passed to it.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 * @param partner is back pointer to object which created this object.
	 * @param is_client_when_true indicates whether the network entity should act
	 * as a client (true) or server (false), in terms of EAP-protocol
	 * whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_radius_session_c(
		abs_eap_am_tools_c * const tools,
		abs_eap_radius_session_c * const partner,
		const bool is_client_when_true,
		const eap_radius_variable_data_c * const user_name,
		const eap_radius_variable_data_c * const nas_ip_address);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e save_request_data(
		const void * const data,
		const u32_t data_length,
		const u8_t identifier);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H u8_t get_identifier();

	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H const eap_variable_data_c * get_shared_secret() const;

	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H const eap_variable_data_c * get_request_authenticator();

	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H const eap_radius_variable_data_c * get_user_name();

	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_state_variable_e get_state();

	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_variable_data_c * get_master_session_key();

	// This is documented in abs_eap_stack_interface_c::packet_process().
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id,
		eap_general_header_base_c * const packet_data,
		const u32_t packet_length); 

	/**
	 * The class could send packets to partner class with this function.
	 * @param send_network_id carries the addresses (network identity) and type of the packet.
	 * @param sent_packet includes the buffer for the whole packet and initialized 
	 * EAP-packet in correct offset.
	 * @param header_offset is offset of the EAP-header within the sent_packet.
	 * @param data_length is length in bytes of the EAP-packet.
	 * @param buffer_length is length in bytes of the whole packet buffer.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e packet_send(
		const eap_am_network_id_c * const send_network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length); 

	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H void object_increase_reference_count();

	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H u32_t object_decrease_reference_count();

	/**
	 * The get_partner() function returns pointer to partner class.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H abs_eap_radius_session_c * get_partner();

	/**
	 * The get_header_offset() function obtains the header offset of EAP-packet.
	 * @param MTU_length is pointer to variable to store the maximum transfer unit (MTU).
	 * MTU is the maximum EAP-packet length in bytes
	 * @param trailer_length is pointer to the variable to store length
	 * of trailer needed by lower levels.
	 * @return Function returns the offset of EAP-header.
	 * @see abs_eap_base_type_c::get_header_offset().
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length);

	/**
	 * The unload_module() function initializes un-load of desired EAP-type.
	 * After the EAP-type is not needed this function should be called.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e unload_module(
		const eap_type_value_e type); 

	/**
	 * The adaptation module calls the eap_acknowledge() function after
	 * any Network Protocol packet is received. This is used as a success indication.
	 * This is described in RFC 2284 "PPP Extensible Authentication Protocol (EAP)".
	 * @param connection_handle separates the context of the acknowledged session.
	 * Mostly there is only one session in the client.
	 * The server does not need eap_acknowledge() function because
	 * server (EAP-authenticator) sends the EAP-success message.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e eap_acknowledge(
		const eap_am_network_id_c * const receive_network_id); 

	/**
	 * This function restarts authentication using current object.
	 * This is used for testing.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e restart_authentication(
		const eap_am_network_id_c * const send_network_id,
		const bool is_client_when_true);

#if defined(USE_EAP_CORE_SERVER)
	/**
	 * The EAP Core calls the send_eap_identity_request() function
	 * when EAP-authentication is needed with another peer.
	 * @param network_id includes the addresses (network identity) and packet type.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e send_eap_identity_request(
		const eap_am_network_id_c * const network_id);
#endif //#if defined(USE_EAP_CORE_SERVER)

	/**
	 * The EAP Core calls the send_eap_nak_response() function
	 * when EAP-authentication with requested EAP type is not possible.
	 * @param network_id includes the addresses (network identity) and packet type.
	 * @param eap_identifier is the EAP-Identifier to be used with EAP-Nak message.
	 * @param preferred_eap_type is the acceptable EAP-Type to be informed with an other peer.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e send_eap_nak_response(
		const eap_am_network_id_c * const receive_network_id,
		const u8_t eap_identifier,
		const eap_type_value_e preferred_eap_type);

	/**
	 * Note this function is just an example. Parameters will change later.
	 * The packet_data_crypto_keys() function gives the generated keys to lower level.
	 * After EAP-authentication has generated the keys it calls this function
	 * to offer the keys to lower level.
	 * @param authentication_key is pointer to the first byte of the authentication key.
	 * @param auth_key_length is count of bytes in the authentication key.
	 * @param encryption_key is pointer to the first byte of the encryption key.
	 * @param encr_key_length is count of bytes in the encryption key.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e packet_data_crypto_keys(
		const eap_am_network_id_c * const send_network_id,
		const eap_master_session_key_c * const master_session_key
		);

	// This is documented in abs_eap_stack_interface_c::configure().
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e configure();

	// This is documented in abs_eap_stack_interface_c::shutdown().
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e shutdown();

	/**
	 * The read_configure() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H virtual eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	/**
	 * The write_configure() function writes the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the action to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H virtual eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	// This is documented in abs_eap_stack_interface_c::set_is_valid().
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H void set_is_valid();

	// This is documented in abs_eap_stack_interface_c::get_is_valid().
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H bool get_is_valid();

	// See abs_eap_base_type_c::state_notification().
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H void state_notification(
		const abs_eap_state_notification_c * const state);

	// See abs_eap_base_timer_c::timer_expired().
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e timer_expired(
		const u32_t id, void *data);

	// See abs_eap_base_timer_c::timer_delete_data().
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e timer_delete_data(
		const u32_t id, void *data);

	/**
	 * The load_module() function function indicates the lower level to
	 * load new module of EAP-type.
	 * @see abs_eap_core_c::load_module().
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e /* tunneling_type */,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * The adaptation module calls the restart_authentication() function
	 * when EAP-authentication is needed with another peer.
	 * @see abs_eap_core_c::restart_authentication().
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e restart_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const bool is_client_when_true,
		const bool force_clean_restart,
		const bool from_timer = false);

	/**
	 * This function removes EAP session object synchronously.
	 * @param receive_network_id identifies the removed EAP session.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e remove_eap_session(
		const bool complete_to_lower_layer,
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * This function removes EAP session object asynchronously.
	 * @param send_network_id identifies the removed EAP session.
	 */
	eap_status_e asynchronous_init_remove_eap_session(
		const eap_am_network_id_c * const send_network_id);

	/**
	 * This function tells lower layer to remove EAP session object asynchronously.
	 * @param eap_type is pointer to selector that identifies the removed EAP session.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e asynchronous_init_remove_eap_session(
		const eap_network_id_selector_c * const state_selector);

	//
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e set_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id, 
		void * const p_data,
		const u32_t p_time_ms);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e cancel_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id);

	//
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e cancel_all_timers();

	//
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e check_is_valid_eap_type(const eap_type_value_e eap_type);

	/// @see abs_eap_core_c::get_eap_type_list().
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e get_eap_type_list(
		eap_array_c<eap_type_value_e> * const eap_type_list);

	/// @see abs_eap_core_c::add_rogue_ap().
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e add_rogue_ap(eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list);

	// This is documented in abs_eap_core_c::set_session_timeout().
	EAP_FUNC_VISIBILITY_EAP_RADIUS_SESSION_H eap_status_e set_session_timeout(
		const u32_t session_timeout_ms);

	//--------------------------------------------------
}; // class eap_radius_session_c

#endif //#if !defined(_EAP_RADIUS_SESSION_H_)

//--------------------------------------------------



// End.
