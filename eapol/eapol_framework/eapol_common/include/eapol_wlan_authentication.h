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

#if !defined(_EAPOL_WLAN_AUTHENTICATION_H_)
#define _EAPOL_WLAN_AUTHENTICATION_H_

// INCLUDES
#include "eapol_am_wlan_authentication.h"
#include "abs_eapol_am_wlan_authentication.h"
#include "abs_ethernet_core.h"
#include "abs_eapol_wlan_authentication.h"
#include "eapol_key_types.h"
#include "eap_type_selection.h"
#include "eap_array.h"
#include "eapol_key_state.h"
#include "eapol_test_stack_if.h"
#include "eap_database_reference_if.h"
#include "abs_eap_configuration_if.h"

#if defined(USE_EAP_SIMPLE_CONFIG)
#include "abs_eap_configuration_if.h"
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPOL_WLAN_AUTHENTICATION_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H 
	#define EAP_FUNC_EXPORT_EAPOL_WLAN_AUTHENTICATION_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_WLAN_AUTHENTICATION_H 
#elif defined(EAP_EXPORT_EAPOL_WLAN_AUTHENTICATION_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPOL_WLAN_AUTHENTICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPOL_WLAN_AUTHENTICATION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPOL_WLAN_AUTHENTICATION_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_WLAN_AUTHENTICATION_H 
#endif
// End: added by script change_export_macros.sh.

// FORWARD DECLARATIONS
class ethernet_core_c;
class eap_am_tools_symbian_c;
class eap_file_config_c;


// CLASS DECLARATION
class EAP_CLASS_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eapol_wlan_authentication_c
: public abs_eapol_am_wlan_authentication_c
, public abs_ethernet_core_c
, public abs_eap_base_timer_c
#if defined(USE_TEST_EAPOL_WLAN_AUTHENTICATION)
, public eapol_test_stack_if_c
#endif //#if defined(USE_TEST_EAPOL_WLAN_AUTHENTICATION)
, public eap_database_reference_if_c
#if defined(USE_EAP_SIMPLE_CONFIG)
, public abs_eap_configuration_if_c
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)
{
public:

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H static eapol_wlan_authentication_c * new_eapol_wlan_authentication(
		abs_eap_am_tools_c * const tools,
		abs_eapol_wlan_authentication_c * const partner,
		const bool is_client_when_true);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eapol_wlan_authentication_c(
		abs_eap_am_tools_c * const tools,
		abs_eapol_wlan_authentication_c * const partner,
		eapol_am_wlan_authentication_c * const am_wauth, ///< eapol_wlan_authentication_c must always delete the am_wauth object.
		const bool is_client_when_true);

	// Something in RVCT 2 forces this function cannot be exported.
	virtual ~eapol_wlan_authentication_c();

	///////////////////////////////////////////////////////////////
	/* These are called from WLM */

	/**
	 * This function checks whether PMKSA is cached to each eap_am_network_id_c object.
	 * Function removes eap_am_network_id_c object from bssid_sta_receive_network_ids if there are
	 * no cached PMKSA for removes eap_am_network_id_c object.
	 * All eap_am_network_id_c objects that exist in bssid_sta_receive_network_ids
	 * after function returns have PMKSA cached and read_reassociation_parameters() can be called
	 * with those eap_am_network_id_c objects.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e check_pmksa_cache(
		eap_array_c<eap_am_network_id_c> * const bssid_sta_receive_network_ids,
		const eapol_key_authentication_type_e selected_eapol_key_authentication_type,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e start_authentication(
		const eap_variable_data_c * const SSID,
		const eapol_key_authentication_type_e selected_eapol_key_authentication_type,
		const eap_variable_data_c * const wpa_preshared_key,
		const bool WPA_override_enabled,
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e complete_association(
		const eapol_wlan_authentication_state_e association_result,
		const eap_am_network_id_c * const receive_network_id, ///< source includes remote address, destination includes local address.
		const eap_variable_data_c * const received_WPA_IE, // WLM must give only the WPA IE to EAPOL
		const eap_variable_data_c * const sent_WPA_IE,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite
		);
	
	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e disassociation(
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		);
		
	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e start_preauthentication(
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e start_reassociation(
		const eap_am_network_id_c * const old_receive_network_id, ///< source includes remote address, destination includes local address.
		const eap_am_network_id_c * const new_receive_network_id, ///< source includes remote address, destination includes local address.
		const eapol_key_authentication_type_e selected_eapol_key_authentication_type ///< In WPXM this must be the same in old and new APs, other connections can change authentication type.
		);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e complete_reassociation(
		const eapol_wlan_authentication_state_e reassociation_result,
		const eap_am_network_id_c * const receive_network_id,
		const eap_variable_data_c * const received_WPA_IE, // WLM must give only the WPA IE to EAPOL
		const eap_variable_data_c * const sent_WPA_IE,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e start_WPXM_reassociation(
		const eap_am_network_id_c * const old_receive_network_id, ///< source includes remote address, destination includes local address.
		const eap_am_network_id_c * const new_receive_network_id, ///< source includes remote address, destination includes local address.
		eap_variable_data_c * const send_reassociation_request_ie,
		const eap_variable_data_c * const received_WPA_ie,
		const eap_variable_data_c * const sent_WPA_ie);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e complete_WPXM_reassociation(
		const eapol_wlan_authentication_state_e reassociation_result,
		const eap_am_network_id_c * const receive_network_id,
		const eap_variable_data_c * const received_reassociation_ie);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id, ///< source includes remote address, destination includes local address.
		eap_general_header_base_c * const packet_data,
		const u32_t packet_length
		);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e tkip_mic_failure(
		const eap_am_network_id_c * const receive_network_id, ///< source includes remote address, destination includes local address.
		const bool fatal_failure_when_true,
		const eapol_RSNA_key_header_c::eapol_tkip_mic_failure_type_e tkip_mic_failure_type
		);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e eap_acknowledge(
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		); 

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e set_eap_database_reference_values(
		const eap_variable_data_c * const reference);

	/////////////////////////////////////////
	/* These are called from ethernet_core */
	
	/**
	* Sends packet to lower layers
	*/
	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e packet_send(
		const eap_am_network_id_c * const send_network_id, ///< source includes local address, destination includes remote address.
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length); 

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length);

	/**
	* Loads an EAP type plug-in.
	* @param type Type to be loaded.
	* @param partner Pointer to the partner class for the EAP type.
	* @param eap_type The pointer for the loaded type should be set here.
	* @param is_client_when_true Indicates whether the loaded EAP type should be client or server.
	* @param receive_network_id Network address.
	*/
	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e /* tunneling_type */,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e unload_module(const eap_type_value_e type); 	

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H void set_is_valid();

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H bool get_is_valid();

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H void increment_authentication_counter();

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H u32_t get_authentication_counter();

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H bool get_is_client();

	/**
	* This does the initial configuration of the class.
	*/
	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e configure();

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e shutdown();

	/**
	* Reads a configuration parameter value from the database. 
	* In Symbian this function is only a TRAP wrapper for read_configure_L.
	*/
	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	// See abs_eap_base_type_c::state_notification().
	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H void state_notification(const abs_eap_state_notification_c * const state);
	
	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e set_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id, 
		void * const p_data,
		const u32_t p_time_ms);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e cancel_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e cancel_all_timers();

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e check_is_valid_eap_type(const eap_type_value_e eap_type);

	/**
	* Forwards the keys to lower layer (= WLM).
	*/
	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e packet_data_session_key(
		const eap_am_network_id_c * const send_network_id, ///< source includes local address, destination includes remote address.
		const eapol_session_key_c * const key);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e timer_expired(const u32_t id, void *data);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e timer_delete_data(const u32_t id, void *data);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e get_eap_type_list(
		eap_array_c<eap_type_value_e> * const eap_type_list);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e add_rogue_ap(eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H u32_t get_current_eap_index();

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H void set_current_eap_index(u32_t eap_index);


#if defined(USE_TEST_EAPOL_WLAN_AUTHENTICATION)
	/// These are called by testing application.
	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H u32_t get_wrong_send_packet_index();

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H void reset_authentication_can_succeed();

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H void set_authentication_can_succeed();

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H void restore_authentication_can_succeed();

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H void set_authentication_must_not_succeed(
        const u32_t wrong_packet_index,
        const u32_t packet_index,
        const void * const wrong_packet_stack);
#endif //#if defined(USE_TEST_EAPOL_WLAN_AUTHENTICATION)

#if defined(USE_EAP_SIMPLE_CONFIG)
	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e save_simple_config_session(
		const simple_config_state_e state,
		EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
		const eap_variable_data_c * const new_password,
		const simple_config_Device_Password_ID_e Device_Password_ID,
		const simple_config_payloads_c * const other_configuration);
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e complete_get_802_11_authentication_mode(
		const eap_status_e completion_status,
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_802_11_authentication_mode_e mode);

	EAP_FUNC_VISIBILITY_EAPOL_WLAN_AUTHENTICATION_H eap_status_e complete_disassociation(
		const bool complete_to_lower_layer,
		const eap_am_network_id_c * const receive_network_id);

private:

	eap_status_e eapol_indication(
		const eap_am_network_id_c * const receive_network_id, ///< source includes remote address, destination includes local address.
		const eapol_wlan_authentication_state_e notification);

	eap_status_e create_upper_stack();

	eap_status_e disassociation_mutex_must_be_reserved(
		const bool complete_to_lower_layer,
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		);

	eap_status_e internal_disassociation(
		const bool complete_to_lower_layer,
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		);

	eap_status_e cancel_all_authentication_sessions();

	eap_status_e complete_check_pmksa_cache(
		EAP_TEMPLATE_CONST eap_array_c<eap_am_network_id_c> * const bssid_sta_receive_network_ids);

	eap_status_e cancel_timer_this_ap_failed();

	eap_status_e cancel_timer_failed_completely();

	eap_status_e cancel_timer_no_response();

	eap_status_e cancel_timer_authentication_cancelled();

private:

	/// Pointer to the lower layer in the stack
	abs_eapol_wlan_authentication_c * m_partner;

	/// Pointer to the AM of WAUTH.
	eapol_am_wlan_authentication_c * m_am_wauth;

	/// Pointer to the upper layer in the stack
	ethernet_core_c * m_ethernet_core;

	/// Pointer to the tools class
	abs_eap_am_tools_c * m_am_tools;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	//eap_array_c<eap_type_selection_c> m_selected_eap_types;

	eap_variable_data_c m_wpa_preshared_key_hash;

	eapol_key_authentication_type_e m_authentication_type;

	eapol_key_802_11_authentication_mode_e m_802_11_authentication_mode;

	eap_variable_data_c m_received_WPA_IE; // WLM must give only the WPA IE to EAPOL

	eap_variable_data_c m_sent_WPA_IE;

	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e m_group_key_cipher_suite;

	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e m_pairwise_key_cipher_suite;

	u32_t m_current_eap_index;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t m_authentication_counter;

	u32_t m_successful_authentications;

	u32_t m_failed_authentications;

	bool m_is_valid;

	bool m_is_client;	

	bool m_shutdown_was_called;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(USE_EAP_ERROR_TESTS)
	bool m_randomly_drop_packets;

	u32_t m_randomly_drop_packets_probability;

	u32_t m_error_probability;

	u32_t m_generate_multiple_error_packets;

	u32_t m_packet_index;

	bool m_enable_random_errors;

	bool m_manipulate_ethernet_header;

	bool m_send_original_packet_first;
#endif //#if defined(USE_EAP_ERROR_TESTS)

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	
	//--------------------------------------------------
}; // class eapol_wlan_authentication_c

#endif //#if !defined(_EAPOL_WLAN_AUTHENTICATION_H_)

//--------------------------------------------------


// End of file
