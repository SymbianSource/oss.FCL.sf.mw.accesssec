/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/abs_wapi_ethernet_core.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 4.1.1 % << Don't touch! Updated by Synergy at check-out.
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



#if !defined(_ABS_WAPI_ETHERNET_CORE_H_)
#define _ABS_WAPI_ETHERNET_CORE_H_

#include "eap_header.h"
#include "eap_array.h"


class abs_wapi_core_c;
class eap_am_network_id_c;
class eap_buf_chain_wr_c;
class eapol_session_key_c;
class abs_eap_state_notification_c;

/// The abs_wapi_ethernet_core_c class defines the interface the wapi_ethernet_core_c class
/// will use with the partner class.
class EAP_EXPORT abs_wapi_ethernet_core_c
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~abs_wapi_ethernet_core_c()
	{
	}

	// 
	abs_wapi_ethernet_core_c()
	{
	}

	// 
	virtual eap_status_e packet_send(
		const eap_am_network_id_c * const network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length) = 0;

	//
	virtual u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length) = 0;

	/**
	 * The packet_data_session_key() function passes one traffic encryption key to 
	 * the lower layers. Ultimately the key can end up to the WLAN hardware.
	 * @see abs_eapol_core_c::packet_data_session_key(). 
	 */
	virtual eap_status_e packet_data_session_key(
		const eap_am_network_id_c * const send_network_id,
		const eapol_session_key_c * const key
		) = 0;

	virtual eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	virtual eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	/**
	 * This is notification of internal state transition.
	 * This is used for notifications, debugging and protocol testing.
	 * The primal notifications are eap_state_variable_e::eap_state_authentication_finished_successfully
	 * and eap_state_variable_e::eap_state_authentication_terminated_unsuccessfully.
	 * These two notifications are sent from WAPI layer (eap_protocol_layer_e::eap_protocol_layer_wapi).
	 */
	virtual void state_notification(
		const abs_eap_state_notification_c * const state) = 0;

	virtual bool get_is_client() = 0;

	/**
	 * The set_timer() function initializes timer to be elapsed after p_time_ms milliseconds.
	 * @param initializer is pointer to object which timer_expired() function will
	 * be called after timer elapses.
	 * @param id is identifier which will be returned in timer_expired() function.
	 * The user selects and interprets the id for this timer.
	 * @param data is pointer to any user selected data which will be returned in timer_expired() function.
	 *
	 * Adaptation module internally implements the timer.
	 */
	virtual eap_status_e set_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id, 
		void * const data,
		const u32_t p_time_ms) = 0;

	/**
	 * The cancel_timer() function cancels the timer id initiated by initializer.
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

	//--------------------------------------------------
}; // class abs_wapi_ethernet_core_c

#endif //#if !defined(_ABS_WAPI_ETHERNET_CORE_H_)

//--------------------------------------------------



// End.
