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
* %version: 33 %
*/

#if !defined(_ETHERNET_CORE_H_)
#define _ETHERNET_CORE_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ETHERNET_CORE_H)
	#define EAP_CLASS_VISIBILITY_ETHERNET_CORE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ETHERNET_CORE_H 
	#define EAP_C_FUNC_VISIBILITY_ETHERNET_CORE_H 
	#define EAP_FUNC_EXPORT_ETHERNET_CORE_H 
	#define EAP_C_FUNC_EXPORT_ETHERNET_CORE_H 
#elif defined(EAP_EXPORT_ETHERNET_CORE_H)
	#define EAP_CLASS_VISIBILITY_ETHERNET_CORE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ETHERNET_CORE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ETHERNET_CORE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ETHERNET_CORE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ETHERNET_CORE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ETHERNET_CORE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ETHERNET_CORE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ETHERNET_CORE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ETHERNET_CORE_H 
	#define EAP_C_FUNC_EXPORT_ETHERNET_CORE_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_ethernet_core.h"
#include "abs_eapol_core.h"
#include "eapol_core.h"
#include "eap_base_type.h"
#include "eap_variable_data.h"
#include "eap_core_map.h"
#include "abs_eap_stack_interface.h"
#include "eapol_rsna_key_header.h"
#include "eap_database_reference_if.h"


/// This class defines the ethernet protocol layer.
class EAP_CLASS_VISIBILITY_ETHERNET_CORE_H ethernet_core_c
: public abs_eapol_core_c
, public abs_eap_stack_interface_c
, public eap_database_reference_if_c
{
private:
	//--------------------------------------------------

	abs_ethernet_core_c *m_partner;

	eapol_core_c *m_eapol_core;

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
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H virtual ~ethernet_core_c();

	// 
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H ethernet_core_c(
		abs_eap_am_tools_c * const m_am_tools,
		abs_ethernet_core_c * const partner,
		const bool is_client_when_true);

	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e cancel_all_authentication_sessions();

	//
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_base_type_c * load_type(const eap_type_value_e type);

	// This is documented in abs_eap_stack_interface_c::packet_process().
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id,
		eap_general_header_base_c * const packet_data,
		const u32_t packet_length); 

	//
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e packet_send(
		const eap_am_network_id_c * const send_network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length); 

	//
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length);

	//
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e eap_acknowledge(const eap_am_network_id_c * const receive_network_id); 

	//
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e /* tunneling_type */,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id);

	//
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e unload_module(const eap_type_value_e type); 

	/**
	 * This function checks whether PMKSA is cached to each eap_am_network_id_c object.
	 * Function removes eap_am_network_id_c object from bssid_sta_receive_network_ids if there are
	 * no cached PMKSA for removes eap_am_network_id_c object.
	 * All eap_am_network_id_c objects that exist in bssid_sta_receive_network_ids
	 * after function returns have PMKSA cached and read_reassociation_parameters() can be called
	 * with those eap_am_network_id_c objects.
	 */
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e check_pmksa_cache(
		eap_array_c<eap_am_network_id_c> * const bssid_sta_receive_network_ids,
		const eapol_key_authentication_type_e selected_eapol_key_authentication_type,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite);

	/**
	 * This function removes PMKSA from cache.
	 * @param receive_network_id carries the MAC addresses.
	 * MAC address of Authenticator should be in source address.
	 * MAC address of Supplicant should be in destination address.
	 */
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e remove_pmksa_from_cache(
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * This function starts the EAP-authentication.
	 * The first parameter includes the network addresses of the protocol
	 * over the EAP-packets are transmitted.
	 * The type attribute of the eap_am_network_id_c object MUST be set
	 * eapol_ethernet_type_e::eapol_ethernet_type_pae.
	 * Value eapol_ethernet_type_e::eapol_ethernet_type_pae starts normal EA-authentication.
	 * The second parameter is_client_when_true tells whether this stack
	 * is client (true) or server (false).
	 */ 
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e start_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const bool is_client_when_true);

	/**
	 * This function starts the preauthentication.
	 * The first parameter includes the network addresses of the protocol
	 * over the EAP-packets are transmitted.
	 * The type attribute of the eap_am_network_id_c object MUST be set
	 * eapol_ethernet_type_e::eapol_ethernet_type_preauthentication.
	 * Value eapol_ethernet_type_e::eapol_ethernet_type_preauthentication is used 802.11i preauthentication.
	 * The adaptation module calls the start_preauthentication() function
	 * when preauthentication is needed with another AP.
	 */
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e start_preauthentication(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type);

	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e read_reassociation_parameters(
		const eap_am_network_id_c * const old_receive_network_id, ///< source includes remote address, destination includes local address.
		const eap_am_network_id_c * const new_receive_network_id, ///< source includes remote address, destination includes local address.
		const eapol_key_authentication_type_e authentication_type,
		eap_variable_data_c * const PMKID,
		const eap_variable_data_c * const received_WPA_ie,
		const eap_variable_data_c * const sent_WPA_ie);

	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e start_reassociation(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const PMKID);

	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e complete_reassociation(
		const eapol_wlan_authentication_state_e reassociation_result,
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const received_WPA_IE, // WLM must give only the WPA IE to EAPOL
		const eap_variable_data_c * const sent_WPA_IE,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite);

	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e start_WPXM_reassociation(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		eap_variable_data_c * const send_reassociation_request_ie);

	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e complete_WPXM_reassociation(
		const eapol_wlan_authentication_state_e reassociation_result,
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const received_reassociation_ie);

	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e send_logoff(
		const eap_am_network_id_c * const receive_network_id);

	// This is documented in abs_eap_stack_interface_c::set_is_valid().
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H void set_is_valid();

	// This is documented in abs_eap_stack_interface_c::get_is_valid().
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H bool get_is_valid();

	// This is documented in abs_eap_stack_interface_c::configure().
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e configure();

	// This is documented in abs_eap_stack_interface_c::shutdown().
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e shutdown();

	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e packet_data_session_key(
		const eap_am_network_id_c * const send_network_id,
		const eapol_session_key_c * const key);

	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	// See abs_eap_base_type_c::state_notification().
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H void state_notification(
		const abs_eap_state_notification_c * const state);


	//
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e set_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id, 
		void * const p_data,
		const u32_t p_time_ms);

	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e cancel_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id);

	//
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e cancel_all_timers();

	//
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e check_is_valid_eap_type(const eap_type_value_e eap_type);

	// See abs_eap_core_c::get_eap_type_list().
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e get_eap_type_list(
		eap_array_c<eap_type_value_e> * const eap_type_list);

	/**
	 * Function creates a state for later use. This is for optimazing 4-Way Handshake.
	 * @param receive_network_id carries the MAC addresses.
	 * MAC address of Authenticator should be in source address. MAC address of 
	 * Supplicant should be in destination address.
	 * @param authentication_type is the selected authentication type.
	 */
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e create_state(
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
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e association(
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
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e disassociation(
		const bool complete_to_lower_layer,
		const eap_am_network_id_c * const receive_network_id
		);

	/// @see abs_eap_core_c::add_rogue_ap().
	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e add_rogue_ap(eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list);

	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e tkip_mic_failure(
		const eap_am_network_id_c * const receive_network_id,
		const bool fatal_failure_when_true,
		const eapol_RSNA_key_header_c::eapol_tkip_mic_failure_type_e tkip_mic_failure_type);

	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e complete_check_pmksa_cache(
		EAP_TEMPLATE_CONST eap_array_c<eap_am_network_id_c> * const bssid_sta_receive_network_ids);

#if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e save_simple_config_session(
		const simple_config_state_e state,
		EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
		const eap_variable_data_c * const new_password,
		const simple_config_Device_Password_ID_e Device_Password_ID,
		const simple_config_payloads_c * const other_configuration);

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e set_eap_database_reference_values(
		const eap_variable_data_c * const reference);

	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e get_802_11_authentication_mode(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const SSID,
		const eap_variable_data_c * const preshared_key);

	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e complete_get_802_11_authentication_mode(
		const eap_status_e completion_status,
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_802_11_authentication_mode_e mode);

	EAP_FUNC_VISIBILITY_ETHERNET_CORE_H eap_status_e complete_disassociation(
		const bool complete_to_lower_layer,
		const eap_am_network_id_c * const receive_network_id);

	//--------------------------------------------------
}; // class ethernet_core_c

#endif //#if !defined(_ETHERNET_CORE_H_)

//--------------------------------------------------



// End.
