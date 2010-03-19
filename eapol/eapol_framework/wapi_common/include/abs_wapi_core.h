/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/abs_wapi_core.h
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



#if !defined(_ABS_WAPI_CORE_H_)
#define _ABS_WAPI_CORE_H_

#include "eap_header.h"
#include "eap_array.h"

class eap_am_network_id_c;
class eap_buf_chain_wr_c;
class eap_configuration_field_c;
class eap_variable_data_c;
class abs_eap_state_notification_c;
class eap_master_session_key_c;
class eapol_session_key_c;


/// This class defines the interface the wapi_core_c class
/// will use with the partner class (lower layer).
class EAP_EXPORT abs_wapi_core_c
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
	 * The destructor of the abs_eap_core class does nothing special.
	 */
	virtual ~abs_wapi_core_c()
	{
	}

	/**
	 * The constructor of the abs_eap_core class does nothing special.
	 */
	abs_wapi_core_c()
	{
	}

	/**
	 * The derived class could send packets to partner class with this function.
	 * @see abs_eap_base_type_c::packet_send().
	 */
	virtual eap_status_e packet_send(
		const eap_am_network_id_c * const network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length) = 0;

	/**
	 * The get_header_offset() function obtains the header offset of WAPI-packet.
	 * @see abs_eap_base_type_c::get_header_offset().
	 */
	virtual u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length) = 0;

	/**
	 * The session calls the restart_authentication() function
	 * when WAPI-authentication is needed with another peer.
	 * This is also used when session restarts authentication.
	 * @param receive_network_id includes the addresses (network identity) and packet type.
	 * @param is_client_when_true indicates whether the WAPI should act as a client or server,
	 * in terms of WAPI whether this network entity is WAPI-ASUE (true) or WAPI-ASU (false).
	 * @param force_clean_restart this selects whether the server removes this session (true) or not (false).
	 * @param from_timer tells whether the timer calls this function (true) or not (false).
	 */
	virtual eap_status_e restart_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const bool is_client_when_true,
		const bool force_clean_restart,
		const bool from_timer = false) = 0;

	/**
	 * The packet_data_session_key() function passes one traffic encryption key to 
	 * the lower layers. Ultimately the key can end up to the WLAN hardware.
	 * @param send_network_id carries the addresses (network identity) and type of the packet.
	 * @param key is the encryption key
	 * @param key_length is the length of the key
	 * @param key_type describes the type of the key (WEP or something else...)
	 * @param key_index is the index of the encryption key (there can be four broadcast keys in WEP for example)
	 */
	virtual eap_status_e packet_data_session_key(
		const eap_am_network_id_c * const send_network_id,
		const eapol_session_key_c * const key
		) = 0;

	/**
	 * The read_configure() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @see abs_eap_base_type_c::read_configure().
	 */
	virtual eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	/**
	 * The write_configure() function writes the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the action to some persistent store.
	 * @see abs_eap_base_type_c::write_configure().
	 */
	virtual eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	/**
	 * This is notification of internal state transition.
	 * This is used for notifications, debugging and protocol testing.
	 * The primal notifications are eap_state_variable_e::eap_state_authentication_finished_successfully
	 * and eap_state_variable_e::eap_state_authentication_terminated_unsuccessfully.
	 * These two notifications are sent from WAPI layer (eap_protocol_layer_e::eap_protocol_layer_wapi).
	 * These two notifications tells the end state of authentication session. These are the only
	 * reliable indications of the final status of authentication session.
	 * You MUST NOT make decision based on the return value of abs_eap_stack_interface_c::packet_process().
	 */
	virtual void state_notification(
		const abs_eap_state_notification_c * const state) = 0;

	/**
	 * This function tells lower layer to remove WAPI-session object asyncronously.
	 * @param eap_type is pointer to selector that identifies the removed WAPI-session.
	 */
	virtual eap_status_e asynchronous_init_remove_wapi_session(
		const eap_am_network_id_c * const send_network_id) = 0;

	/**
	 * The set_timer() function initializes timer to be elapsed after time_ms milliseconds.
	 * @param initializer is pointer to object which timer_expired() function will
	 * be called after timer elapses.
	 * @param id is identifier which will be returned in timer_expired() function.
	 * The user selects and interprets the id for this timer.
	 * @param data is pointer to any user selected data which will be returned in timer_expired() function.
	 * @param time_ms is the time of timer in milli seconds.
	 *
	 * Adaptation module internally implements the timer.
	 */
	virtual eap_status_e set_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id, 
		void * const data,
		const u32_t time_ms) = 0;

	/**
	 * The cancel_timer() function cancels the timer id initiated by initializer.
	 * @param initializer is pointer to object which set the cancelled timer.
	 * @param id is identifier which will be returned in timer_expired() function.
	 * The user selects and interprets the id for this timer.
	 *
	 * Adaptation module internally implements the timer.
	 */
	virtual eap_status_e cancel_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id) = 0;

	/**
	 * The cancel_all_timers() function cancels all timers.
	 * User should use this in termination of the stack before
	 * the adaptation module of tools is deleted.
	 * Preferred mode is to cancel each timer directly
	 * using cancel_timer() function.
	 *
	 * Adaptation module internally implements the timer.
	 */
	virtual eap_status_e cancel_all_timers() = 0;

	/**
	 * The set_session_timeout() function changes the session timeout timer to be elapsed after session_timeout_ms milliseconds.
	 */
	virtual eap_status_e set_session_timeout(
		const u32_t session_timeout_ms) = 0;

	//--------------------------------------------------
}; // class abs_wapi_core_c

#endif //#if !defined(_ABS_WAPI_CORE_H_)

//--------------------------------------------------



// End.
