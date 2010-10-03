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

#if !defined(_RADIUS_CORE_H_)
#define _RADIUS_CORE_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_RADIUS_H)
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_H 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_H 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_H 
#elif defined(EAP_EXPORT_EAP_RADIUS_H)
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_H 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_base_type.h"
#include "eap_variable_data.h"
#include "eap_radius_header.h"
#include "eap_radius_types.h"
#include "eap_radius_payloads.h"
#include "eap_radius_state.h"
#include "eap_radius_initialized.h"
#include "abs_eap_base_timer.h"
#include "abs_eap_am_radius.h"
#include "eap_am_radius.h"
#include "eap_crypto_api.h"
#include "eap_radius_session.h"
#include "abs_eap_radius.h"
#include "abs_eap_radius_session.h"
#include "eap_radius_session.h"
#include "eap_diameter_avp_code.h"

class eap_radius_MAC_attributes_c;
class eap_radius_header_base_c;

//--------------------------------------------------


/// This class is implementation of RADIUS EAP-type.
class EAP_CLASS_VISIBILITY_EAP_RADIUS_H eap_radius_c
: public abs_eap_radius_session_c
, public abs_eap_radius_state_c
, public abs_eap_base_timer_c
, public abs_eap_core_map_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	abs_eap_radius_c * const m_partner;

	/// This stores  objects using eap_variable_data selector.
	eap_core_map_c<eap_radius_session_c, abs_eap_core_map_c, eap_variable_data_c> m_session_map;

	eap_variable_data_c m_pseudo_ethernet_header;

	/// This is offset in bytes of the EAP-type header in the packet buffer.
	/// Offset is described in abs_eap_base_type_c::get_header_offset().
	u32_t m_radius_header_offset;

	/// This is maximum transfer unit in bytes.
	/// MTU is described in abs_eap_base_type_c::get_header_offset().
	u32_t m_MTU;

	/// This is length of the trailer in bytes.
	/// Trailer length is described in abs_eap_base_type_c::get_header_offset().
	u32_t m_trailer_length;

	u16_t m_salt;

	/// This flag is set true when shutdown() function is called.
	bool m_shutdown_was_called;

	/// This indicates whether this object is client (true) or server (false).
	/// In terms of EAP-protocol whether this network entity is EAP-supplicant (true)
	/// or EAP-authenticator (false).
	bool m_is_client;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	//--------------------------------------------------


	/**
	 * This function sends and traces all messages.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e packet_send(
		const eap_am_network_id_c * const network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length,
		eap_radius_session_c * const session
		);

#if defined(USE_EAP_TRACE)

	/**
	 * This function traces the EAP packet.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H void packet_trace(
		eap_const_string prefix,
		const eap_am_network_id_c * const receive_network_id,
		eap_radius_header_base_c * const received_eap,
		const u32_t eap_packet_length);

	#define EAP_RADIUS_PACKET_TRACE(prefix, receive_network_id, \
		received_eap, eap_packet_length) \
			packet_trace((prefix), (receive_network_id), (received_eap), (eap_packet_length))

#else

	#define EAP_RADIUS_PACKET_TRACE(prefix, receive_network_id, \
		received_eap, eap_packet_length)

#endif //#if !defined(USE_EAP_TRACE)


	/**
	 * This function processes the RADIUS packets.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e radius_packet_process(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		eap_radius_header_base_c * const received_radius, ///< This is pointer to EAP header including RADIUS fields.
		const u32_t radius_packet_length, ///< This is length of received RADIUS EAP packet.
		const bool is_client_when_true ///< Indicates whether this is client (true) or server (false).
		);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e cancel_error_message_delay_timer();

	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e set_error_message_delay_timer();

	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e handle_error_packet();

	EAP_FUNC_VISIBILITY_EAP_RADIUS_H bool random_selection();

	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e add_ms_mppe_key_attributes(
		const eap_variable_data_c * const shared_secret,
		const eap_variable_data_c * const master_session_key,
		const eap_variable_data_c * const request_authenticator,
		eap_radius_header_base_c * const radius_header,
		u32_t * const attribute_offset,
		crypto_hmac_c * const hmac_message_auth,
		crypto_md5_c * const md5_response_auth);


	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e add_user_name_attribute(
		const eap_radius_variable_data_c * const user_name,
		eap_radius_header_base_c * const radius_header,
		u32_t * const radius_attribute_offset,
		crypto_hmac_c * const hmac_message_auth,
		crypto_md5_c * const md5_response_auth);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e xor_values(
		u8_t * const plaintext,
		const u32_t plaintext_length,
		const eap_variable_data_c * const intermediate_value);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e encrypt_ms_mppe_key_attribute(
		const eap_variable_data_c * const shared_secret,
		const eap_variable_data_c * const request_authenticator,
		const u8_t * salt,
		const u32_t salt_length,
		u8_t * const data,
		const u32_t data_length);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e add_one_ms_mppe_key_attribute(
		const eap_variable_data_c * const shared_secret,
		const eap_variable_data_c * const request_authenticator,
		eap_radius_header_base_c * const radius_header,
		u32_t * const attribute_offset,
		const u8_t * const key,
		const u32_t key_length,
		const eap_diameter_avp_code_c mppe_key_type,
		crypto_hmac_c * const hmac_message_auth,
		crypto_md5_c * const md5_response_auth);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_H static eap_status_e shutdown_operation(
		eap_radius_session_c * const session,
		abs_eap_am_tools_c * const m_am_tools);

	/**
	 * This function parses all payloads of the whole RADIUS EAP packet.
	 * Payloads are stored to p_radius_payloads.
	 * @see parse_radius_payload().
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e parse_radius_packet(
		eap_radius_header_base_c * const radius, ///< This is pointer to EAP header including RADIUS fields.
		const u32_t radius_packet_length, ///< This is length of received RADIUS EAP packet.
		eap_radius_payloads_c * const p_radius_payloads);

	/**
	 * This function handles the received RADIUS EAP packet.
	 *
	 * First is checked the valid massage is received in valid state.
	 * See also eap_radius_state_c::check_valid_state().
	 *
	 * Second is parsed the payloads and checked syntax of the received RADIUS EAP packet.
	 * See also parse_radius_packet().
	 *
	 * Third is analysed the RADIUS EAP packet. This includes the payload and values of each payload.
	 * See also analyse_radius_packet().
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e handle_radius_packet(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		eap_radius_header_base_c * const radius, ///< This is pointer to EAP header including RADIUS fields.
		const u32_t radius_length, ///< This is length of received RADIUS EAP packet.
		eap_radius_payloads_c * const p_radius_payloads ///< This is pointer to all payloads of the received EAP packet.
		);

	/**
	 * This function analyses the received RADIUS EAP packet.
	 * Each sub-type is handled in separate function.
	 * @see Client messages are handled in handle_start_request_message() and handle_challenge_request_message(). 
	 * @see Server messages are handled in handle_start_response_message() and handle_challenge_response_message(). 
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e analyse_radius_packet(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		eap_radius_header_base_c * const received_radius, ///< This is pointer to EAP header including RADIUS fields.
		const u32_t radius_packet_length, ///< This is length of received RADIUS EAP packet.
		eap_radius_payloads_c * const p_radius_payloads ///< This is pointer to all payloads of the received EAP packet.
		);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_H void trace_tunneled_packet(
		eap_const_string prefix,
		const eap_header_base_c * const eap_packet);

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * Destructor cancels all timers and deletes member attributes.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H virtual ~eap_radius_c();

	/**
	 * Constructor initializes all member attributes.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_radius_c(
		abs_eap_am_tools_c * const tools, ///< This is pointer to the tools AM of current platform.
		abs_eap_radius_c * const partner, ///< This is back pointer to object which created this object.
		eap_am_radius_c * const am_radius, ///< This is pointer to adaptation module of RADIUS EAP type.
		const bool free_am_radius, ///< True value means m_am_radius is allocated within eap_radius_c and m_am_radius must be freed in destructor.
		const bool is_client_when_true ///< Indicates whether this is client (true) or server (false).
		);

	/**
	 * This function returns string of the state. This is for trace purposes.
	 * NOTE this is static member function.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H static eap_const_string get_state_string(eap_radius_state_variable_e state);

	/**
	 * This function tells if the object is a client or a server..
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H bool get_is_client();

	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e tunneling_type,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e unload_module(const eap_type_value_e eap_type);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e restart_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const bool is_client_when_true,
		const bool force_clean_restart,
		const bool from_timer = false);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e asynchronous_init_remove_eap_session(
		const eap_am_network_id_c * const send_network_id);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e check_is_valid_eap_type(const eap_type_value_e eap_type);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e get_eap_type_list(
		eap_array_c<eap_type_value_e> * const eap_type_list);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e add_rogue_ap(
		eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e set_session_timeout(
		const u32_t session_timeout_ms);

	/**
	 * The partner class calls this function when EAP/RADIUS packet is received.
	 * see also eap_base_type_c::packet_process().
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		eap_radius_header_base_c * const radius, ///< This is pointer to RADIUS header and data.
		const u32_t radius_packet_length ///< This is length of received RADIUS packet.
		);

	/**
	 * This function obtains header offset, MTU and trailer length.
	 * See also abs_eap_base_type_c::get_header_offset().
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length
		);

	/**
	 * This function creates a message authentication code (MAC)
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e create_message_authentication_code(
		eap_radius_MAC_attributes_c *MAC_attributes, ///< This includes required parameters.
		const eap_radius_code_value_e code,
		const eap_variable_data_c * const authentication_key
		);

	// This is commented in abs_eap_base_timer_c::timer_delete_data().
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e timer_expired(
		const u32_t id, void *data
		);

	// This is commented in abs_eap_base_timer_c::timer_delete_data().
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e timer_delete_data(
		const u32_t id, void *data
		);

	// This is commented in eap_base_type_c::set_is_valid().
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H void set_is_valid();

	// This is commented in eap_base_type_c::get_is_valid().
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H bool get_is_valid();

	// This is commented in eap_base_type_c::configure().
	/**
	 * EAP-type RADIUS reads configuration.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e configure();

	// This is commented in eap_base_type_c::shutdown().
	/**
	 * The shutdown() function is called before the destructor of the 
	 * object is executed. During the function call the object 
	 * could shutdown the operations, for example cancel timers.
	 * Each derived class must define this function.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e shutdown();

	/**
	 * The read_configure() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H virtual eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data
		);

	/**
	 * The write_configure() function writes the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the action to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H virtual eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data
		);

	// This is commented in eap_base_type_c::eap_acknowledge().
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e eap_acknowledge(
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * This function must reset the state of object to same as 
	 * state was after the configure() function call.
	 * If object reset succeeds this function must return eap_status_ok.
	 * If object reset fails this function must return corresponding error status.
	 * @return This function returns the status of reset operation.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e reset();

	//
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e set_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id, 
		void * const p_data,
		const u32_t p_time_ms);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e cancel_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id);

	//
	EAP_FUNC_VISIBILITY_EAP_RADIUS_H eap_status_e cancel_all_timers();

	//--------------------------------------------------
}; // class eap_radius_c

#endif //#if !defined(_RADIUS_CORE_H_)

//--------------------------------------------------



// End.
