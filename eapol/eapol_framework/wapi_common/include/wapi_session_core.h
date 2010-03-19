/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/wapi_session_core.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 9.1.1 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.2
*/



#if !defined(_WAPI_SESSION_CORE_H_)
#define _WAPI_SESSION_CORE_H_

#include "eap_tools.h"
#include "eap_am_export.h"
#include "abs_wapi_core.h"
#include "eap_core_map.h"
#include "abs_eap_stack_interface.h"
#include "eapol_rsna_key_header.h"

class wapi_core_c;
class eap_network_id_selector_c;


/**
 * This is the timer ID used with abs_eap_am_tools_c::set_timer() and abs_eap_am_tools_c::cancel_timer().
 */
enum wapi_session_core_timer_id
{
	WAPI_SESSION_CORE_REMOVE_SESSION_ID ///< See WAPI_SESSION_CORE_REMOVE_SESSION_TIMEOUT.
};

/**
 * This is time after a WAPI session is removed. This must be zero.
 */
const u32_t WAPI_SESSION_CORE_REMOVE_SESSION_TIMEOUT = 0u;


/// A wapi_session_core_c class implements mapping of WAPI authentication sessions.
/// Network identity separates parallel WAPI authentication sessions.
class EAP_EXPORT wapi_session_core_c
: public abs_wapi_core_c
, public abs_eap_core_map_c
, public abs_eap_base_timer_c
, public abs_eap_stack_interface_c
{
private:
	//--------------------------------------------------

	/// This is back pointer to object which created this object.
	/// Packets are sent to the partner.
	abs_wapi_core_c * const m_partner;

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This stores WAPI authentication session objects using eap_variable_data selector.
	eap_core_map_c<wapi_core_c, abs_eap_core_map_c, eap_variable_data_c> m_session_map;

	u32_t m_remove_session_timeout;

	/// This indicates whether this object is client (true) or server (false).
	bool m_is_client;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	bool m_use_wapi_session_core_reset_session;

	bool m_shutdown_was_called;


	/**
	 * Function creates a new session.
	 */
	EAP_FUNC_IMPORT wapi_core_c * create_new_session(
		const eap_am_network_id_c * const receive_network_id);

	EAP_FUNC_IMPORT eap_status_e reset_or_remove_session(
		wapi_core_c ** const session,
		const eap_network_id_selector_c * const selector,
		const bool reset_immediately);


	EAP_FUNC_IMPORT static eap_status_e shutdown_operation(
		wapi_core_c * const core,
		abs_eap_am_tools_c * const m_am_tools);

	static eap_status_e cancel_authentication_session(
		wapi_core_c * const handler,
		abs_eap_am_tools_c * const m_am_tools);

	eap_status_e init_eapol_key_bksa_caching_timeout(
		const eap_am_network_id_c * const send_network_id);

	eap_status_e remove_wapi_state(
		const eap_am_network_id_c * const send_network_id);

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the wapi_core class does nothing special.
	 */
	EAP_FUNC_IMPORT virtual ~wapi_session_core_c();

	/**
	 * The constructor initializes member attributes using parameters passed to it.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 * @param partner is back pointer to object which created this object.
	 * @param is_client_when_true indicates whether the network entity should act
	 * as a client (true) or server (false), in terms of WAPI-protocol
	 * whether this network entity is WAPI-ASUE (true) or WAPI-ASU (false).
	 */
	EAP_FUNC_IMPORT wapi_session_core_c(
		abs_eap_am_tools_c * const tools,
		abs_wapi_core_c * const partner,
		const bool is_client_when_true);

	/**
	 * This function must reset the state of object to same as 
	 * state was after the configure() function call.
	 * If object reset succeeds this function must return eap_status_ok.
	 * If object reset fails this function must return corresponding error status.
	 * @return This function returns the status of reset operation.
	 */
	EAP_FUNC_IMPORT eap_status_e reset();

	/**
	 * This function cancels all WAPI-sessions.
	 * If this succeeds this function must return eap_status_ok.
	 * If this fails this function must return corresponding error status.
	 * @return This function returns the status of operation.
	 */
	EAP_FUNC_IMPORT eap_status_e synchronous_cancel_all_wapi_sessions();

	// This is documented in abs_eap_stack_interface_c::packet_process().
	EAP_FUNC_IMPORT eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id,
		eap_general_header_base_c * const packet_data,
		const u32_t packet_length); 

	/**
	 * The class could send packets to partner class with this function.
	 * @param send_network_id carries the addresses (network identity) and type of the packet.
	 * @param sent_packet includes the buffer for the whole packet and initialized 
	 * packet in correct offset.
	 * @param header_offset is offset of the header within the sent_packet.
	 * @param data_length is length in bytes of the packet.
	 * @param buffer_length is length in bytes of the whole packet buffer.
	 */
	EAP_FUNC_IMPORT eap_status_e packet_send(
		const eap_am_network_id_c * const send_network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length); 

	/**
	 * The get_partner() function returns pointer to partner class.
	 */
	EAP_FUNC_IMPORT abs_wapi_core_c * get_partner();

	/**
	 * The get_header_offset() function obtains the header offset of WAI-packet.
	 * @param MTU_length is pointer to variable to store the maximum transfer unit (MTU).
	 * MTU is the maximum packet length in bytes
	 * @param trailer_length is pointer to the variable to store length
	 * of trailer needed by lower levels.
	 * @return Function returns the offset of header.
	 * @see abs_eap_base_type_c::get_header_offset().
	 */
	EAP_FUNC_IMPORT u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length);

	/**
	 * This function restarts authentication using current object.
	 * This is used for testing.
	 */
	EAP_FUNC_IMPORT eap_status_e restart_authentication(
		const eap_am_network_id_c * const send_network_id,
		const bool is_client_when_true);

	/**
	 * The packet_data_session_key() function passes one traffic encryption key to 
	 * the lower layers. Ultimately the key can end up to the WLAN hardware.
	 * @param send_network_id carries the addresses (network identity) and type of the packet.
	 * @param key is the encryption key
	 * @param key_length is the length of the key
	 * @param key_type describes the type of the key (WEP or something else...)
	 * @param key_index is the index of the encryption key (there can be four broadcast keys in WEP for example)
	 */
	EAP_FUNC_IMPORT eap_status_e packet_data_session_key(
		const eap_am_network_id_c * const send_network_id,
		const eapol_session_key_c * const key);

	// This is documented in abs_eap_stack_interface_c::configure().
	EAP_FUNC_IMPORT eap_status_e configure();

	// This is documented in abs_eap_stack_interface_c::shutdown().
	EAP_FUNC_IMPORT eap_status_e shutdown();

	/**
	 * The read_configure() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	EAP_FUNC_IMPORT virtual eap_status_e read_configure(
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
	EAP_FUNC_IMPORT virtual eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	// This is documented in abs_eap_stack_interface_c::set_is_valid().
	EAP_FUNC_IMPORT void set_is_valid();

	// This is documented in abs_eap_stack_interface_c::get_is_valid().
	EAP_FUNC_IMPORT bool get_is_valid();

	// See abs_eap_base_type_c::state_notification().
	EAP_FUNC_IMPORT void state_notification(
		const abs_eap_state_notification_c * const state);

	// See abs_eap_base_timer_c::timer_expired().
	EAP_FUNC_IMPORT eap_status_e timer_expired(
		const u32_t id, void *data);

	// See abs_eap_base_timer_c::timer_delete_data().
	EAP_FUNC_IMPORT eap_status_e timer_delete_data(
		const u32_t id, void *data);

	/**
	 * The adaptation module calls the restart_authentication() function
	 * when WAPI-authentication is needed with another peer.
	 * @see abs_eap_core_c::restart_authentication().
	 */
	EAP_FUNC_IMPORT eap_status_e restart_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const bool is_client_when_true,
		const bool force_clean_restart,
		const bool from_timer = false);

	/**
	 * This function creates WAPI-session object synchronously.
	 * @param receive_network_id identifies the removed WAPI-session.
	 */
	EAP_FUNC_IMPORT eap_status_e synchronous_create_wapi_session(
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * This function removes session object synchronously.
	 * @param receive_network_id identifies the removed WAPI-session.
	 */
	EAP_FUNC_IMPORT eap_status_e synchronous_remove_wapi_session(
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * This function removes session object asynchronously.
	 * @param send_network_id identifies the removed session.
	 */
	eap_status_e asynchronous_init_remove_wapi_session(
		const eap_am_network_id_c * const send_network_id);

	/**
	 * This function tells lower layer to remove session object asynchronously.
	 * @param eap_type is pointer to selector that identifies the removed session.
	 */
	EAP_FUNC_IMPORT eap_status_e asynchronous_init_remove_wapi_session(
		const eap_network_id_selector_c * const state_selector);

	//
	EAP_FUNC_IMPORT eap_status_e set_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id, 
		void * const p_data,
		const u32_t p_time_ms);

	EAP_FUNC_IMPORT eap_status_e cancel_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id);

	//
	EAP_FUNC_IMPORT eap_status_e cancel_all_timers();

	// This is documented in abs_eap_core_c::set_session_timeout().
	EAP_FUNC_IMPORT eap_status_e set_session_timeout(
		const u32_t session_timeout_ms);

	EAP_FUNC_IMPORT eap_status_e read_reassociation_parameters(
		const eap_am_network_id_c * const old_receive_network_id, ///< source includes remote address, destination includes local address.
		const eap_am_network_id_c * const new_receive_network_id, ///< source includes remote address, destination includes local address.
		const eapol_key_authentication_type_e authentication_type,
		eap_variable_data_c * const BKID,
		const eap_variable_data_c * const received_WAPI_ie,
		const eap_variable_data_c * const sent_WAPI_ie);

	EAP_FUNC_IMPORT eap_status_e cancel_all_authentication_sessions();

	EAP_FUNC_IMPORT eap_status_e check_bksa_cache(
		eap_array_c<eap_am_network_id_c> * const bssid_sta_receive_network_ids,
		const eapol_key_authentication_type_e selected_eapol_key_authentication_type,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite);

	EAP_FUNC_IMPORT eap_status_e association(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const wapi_ie_ae,
		const eap_variable_data_c * const wapi_ie_asue,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_pairwise_cipher,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_group_cipher,
		const eap_variable_data_c * const pre_shared_key);

	EAP_FUNC_IMPORT eap_status_e disassociation(
		const eap_am_network_id_c * const receive_network_id
		);

	EAP_FUNC_IMPORT eap_status_e create_state(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type
		);

	EAP_FUNC_IMPORT eap_status_e remove_bksa_from_cache(
		const eap_am_network_id_c * const receive_network_id);

	//--------------------------------------------------
}; // class wapi_session_core_c

#endif //#if !defined(_WAPI_SESSION_CORE_H_)

//--------------------------------------------------



// End.
