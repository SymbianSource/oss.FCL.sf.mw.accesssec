/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/wapi_ethernet_core.h
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



#if !defined(_WAPI_ETHERNET_CORE_H_)
#define _WAPI_ETHERNET_CORE_H_

#include "eap_tools.h"
#include "eap_am_export.h"
#include "abs_wapi_ethernet_core.h"
#include "abs_wapi_core.h"
#include "wapi_core.h"
#include "wapi_session_core.h"
#include "eap_variable_data.h"
#include "eap_core_map.h"
#include "abs_eap_stack_interface.h"
#include "eapol_rsna_key_header.h"


/// This class defines the ethernet protocol layer.
class EAP_EXPORT wapi_ethernet_core_c
: public abs_wapi_core_c
, public abs_eap_stack_interface_c
{
private:
	//--------------------------------------------------

	abs_wapi_ethernet_core_c *m_partner;

	wapi_session_core_c *m_wapi_core;

	abs_eap_am_tools_c * const m_am_tools;

	bool m_is_client;

	bool m_is_valid;

	bool m_shutdown_was_called;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	EAP_FUNC_IMPORT virtual ~wapi_ethernet_core_c();

	// 
	EAP_FUNC_IMPORT wapi_ethernet_core_c(
		abs_eap_am_tools_c * const m_am_tools,
		abs_wapi_ethernet_core_c * const partner,
		const bool is_client_when_true);

	EAP_FUNC_IMPORT eap_status_e cancel_all_authentication_sessions();


	// This is documented in abs_eap_stack_interface_c::packet_process().
	EAP_FUNC_IMPORT eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id,
		eap_general_header_base_c * const packet_data,
		const u32_t packet_length); 

	//
	EAP_FUNC_IMPORT eap_status_e packet_send(
		const eap_am_network_id_c * const send_network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length); 

	//
	EAP_FUNC_IMPORT u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length);  

	/**
	 * This function checks whether WAPI BKID is cached to each eap_am_network_id_c object.
	 * Function removes eap_am_network_id_c object from bssid_sta_receive_network_ids if there are
	 * no cached BKID for eap_am_network_id_c object.
	 * All eap_am_network_id_c objects that exist in bssid_sta_receive_network_ids
	 * after function returns have BKID cached and read_reassociation_parameters() can be called
	 * with those eap_am_network_id_c objects.
	 */
	EAP_FUNC_IMPORT eap_status_e check_bksa_cache(
		eap_array_c<eap_am_network_id_c> * const bssid_sta_receive_network_ids,
		const eapol_key_authentication_type_e selected_eapol_key_authentication_type,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite);

	/**
	 * This function removes BKID from cache.
	 * @param receive_network_id carries the MAC addresses.
	 * MAC address of Authenticator should be in source address.
	 * MAC address of Supplicant should be in destination address.
	 */
	EAP_FUNC_IMPORT eap_status_e remove_bksa_from_cache(
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * This function starts the WAPI authentication.
	 * The first parameter includes the network addresses of the protocol
	 * over the WAPI packets are transmitted.
	 * The type attribute of the eap_am_network_id_c object MUST be set
	 * WAPI Ethernet type.
	 * The second parameter is_client_when_true tells whether this stack
	 * is client (true) or server (false).
	 */ 
	EAP_FUNC_IMPORT eap_status_e start_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const bool is_client_when_true);

	EAP_FUNC_IMPORT eap_status_e start_reassociation(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const BKID);

	EAP_FUNC_IMPORT eap_status_e read_reassociation_parameters(
		const eap_am_network_id_c * const old_receive_network_id, ///< source includes remote address, destination includes local address.
		const eap_am_network_id_c * const new_receive_network_id, ///< source includes remote address, destination includes local address.
		const eapol_key_authentication_type_e authentication_type,
		eap_variable_data_c * const BKID,
		const eap_variable_data_c * const received_WAPI_ie,
		const eap_variable_data_c * const sent_WAPI_ie);


	EAP_FUNC_IMPORT eap_status_e complete_reassociation(
		const eapol_wlan_authentication_state_e reassociation_result,
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const received_WAPI_IE,
		const eap_variable_data_c * const sent_WAPI_IE,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite);

	// This is documented in abs_eap_stack_interface_c::set_is_valid().
	EAP_FUNC_IMPORT void set_is_valid();

	// This is documented in abs_eap_stack_interface_c::get_is_valid().
	EAP_FUNC_IMPORT bool get_is_valid();

	// This is documented in abs_eap_stack_interface_c::configure().
	EAP_FUNC_IMPORT eap_status_e configure();

	// This is documented in abs_eap_stack_interface_c::shutdown().
	EAP_FUNC_IMPORT eap_status_e shutdown();

	EAP_FUNC_IMPORT eap_status_e packet_data_session_key(
		const eap_am_network_id_c * const send_network_id,
		const eapol_session_key_c * const key);

	EAP_FUNC_IMPORT eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	EAP_FUNC_IMPORT eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	// See abs_eap_base_type_c::state_notification().
	EAP_FUNC_IMPORT void state_notification(
		const abs_eap_state_notification_c * const state);


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

	/**
	 * Function creates a state for later use. This is for optimazing 4-Way Handshake.
	 * @param receive_network_id carries the MAC addresses.
	 * MAC address of Authenticator should be in source address. MAC address of 
	 * Supplicant should be in destination address.
	 * @param authentication_type is the selected authentication type.
	 */
	EAP_FUNC_IMPORT eap_status_e create_state(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type
		);

	/**
	 * This function need to be called when client STA (re)associates to AP.
	 * @param receive_network_id carries the MAC addresses.
	 * MAC address of Authenticator should be in source address. MAC address of Supplicant should be in destination address.
	 * @param authenticator_RSNA_IE is RSN IE of authenticator. Authenticator sends this in Beacon or Probe message.
	 * @param supplicant_RSNA_IE is RSN IE of supplicant. Supplicant sends this in (re)association request message.
	 * @param eapol_pairwise_cipher is the selected pairwise cipher.
	 * @param eapol_group_cipher is the selected group cipher.
	 */
	EAP_FUNC_IMPORT eap_status_e association(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const authenticator_RSNA_IE,
		const eap_variable_data_c * const supplicant_RSNA_IE,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_pairwise_cipher,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_group_cipher,
		const eap_variable_data_c * const pre_shared_key);

	/**
	 * This function need to be called when client STA disassociates from AP.
	 * @param receive_network_id carries the MAC addresses.
	 * MAC address of Authenticator should be in source address. MAC address of Supplicant should be in destination address.
	 */
	EAP_FUNC_IMPORT eap_status_e disassociation(
		const eap_am_network_id_c * const receive_network_id
		);

	EAP_FUNC_IMPORT eap_status_e restart_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const bool is_client_when_true,
		const bool force_clean_restart,
		const bool from_timer = false);

	EAP_FUNC_IMPORT eap_status_e asynchronous_init_remove_wapi_session(
		const eap_am_network_id_c * const send_network_id);

	EAP_FUNC_IMPORT eap_status_e set_session_timeout(
		const u32_t session_timeout_ms);

	//--------------------------------------------------
}; // class wapi_ethernet_core_c

#endif //#if !defined(_WAPI_ETHERNET_CORE_H_)

//--------------------------------------------------



// End.
