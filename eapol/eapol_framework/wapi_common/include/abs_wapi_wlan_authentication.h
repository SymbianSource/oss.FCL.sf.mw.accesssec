/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/abs_wapi_wlan_authentication.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 6.1.1 % << Don't touch! Updated by Synergy at check-out.
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



#if !defined(_ABS_WAPI_WLAN_AUTHENTICATION_H_)
#define _ABS_WAPI_WLAN_AUTHENTICATION_H_

#include "eap_header.h" // << TODO: this needs to be created
#include "eap_array.h"

class abs_wapi_core_c;
class eap_am_network_id_c;
class eap_buf_chain_wr_c;
class eapol_session_key_c;
class abs_eap_state_notification_c;

/// The abs_wapi_wlan_authentication_c class defines the interface 
/// the wapi_wlan_authentication_c class will use with its partner class.
class EAP_EXPORT abs_wapi_wlan_authentication_c
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
	virtual ~abs_wapi_wlan_authentication_c()
	{
	}

	// 
	abs_wapi_wlan_authentication_c()
	{
	}

	// Look at abs_eap_base_type_c::packet_send().
	virtual eap_status_e packet_send(
		const eap_am_network_id_c * const send_network_id, ///< source includes local address, destination includes remote address.
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length) = 0;

	// Look at abs_eap_base_type_c::get_header_offset().
	virtual u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length) = 0;

	/**
	 * This function call tells lower layer to associate with 
	 * the selected 802.11 authentication mode.
	 * In WAPI only the open mode is allowed.
	 */
	virtual eap_status_e associate(
		eapol_key_802_11_authentication_mode_e authentication_mode) = 0;

	/**
	 * Lower layer must return value of self_disassociation when
	 * it calls eapol_wlan_authentication_c::disassociation().
	 * This tells eapol_wlan_authentication_c object the cause
	 * of disassociation.
	 */
	virtual eap_status_e disassociate(
		const eap_am_network_id_c * const receive_network_id, ///< source includes remote address, destination includes local address.
		const bool self_disassociation) = 0;

	/**
	 * The packet_data_session_key() function passes one traffic encryption key to 
	 * the lower layers. Ultimately the key can end up to the WLAN hardware.
	 * @see abs_wapi_core_c::packet_data_session_key(). 
	 */
	virtual eap_status_e packet_data_session_key(
		const eap_am_network_id_c * const send_network_id, ///< source includes local address, destination includes remote address.
		const eapol_session_key_c * const key 
		) = 0;

	/**
	 * This is notification of internal state transition.
	 * This is used for notifications, debugging and protocol testing.
	 * The primal notifications are eap_state_variable_e::eap_state_authentication_finished_successfully
	 * and eap_state_variable_e::eap_state_authentication_terminated_unsuccessfully.
	 * These two notifications are sent from WAPI layer (eap_protocol_layer_e::eap_protocol_layer_wapi).
	 */
	virtual void state_notification(
		const abs_eap_state_notification_c * const state) = 0;

	/**
	 * This function call tells lower layer to re-associate with the selected network ID,
	 * authentication type and WAPI BKID.
	 */
	virtual eap_status_e reassociate(
		const eap_am_network_id_c * const send_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const BKID) = 0;

	//--------------------------------------------------
}; // class abs_wapi_wlan_authentication_c

#endif //#if !defined(_ABS_WAPI_WLAN_AUTHENTICATION_H_)

//--------------------------------------------------


// End.
