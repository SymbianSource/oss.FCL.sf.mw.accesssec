/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/wapi_wlan_authentication.h
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



#if !defined(_WAPI_WLAN_AUTHENTICATION_H_)
#define _WAPI_WLAN_AUTHENTICATION_H_

// INCLUDES
#include "wapi_am_wlan_authentication.h"
#include "abs_wapi_am_wlan_authentication.h"
#include "abs_wapi_ethernet_core.h"
#include "abs_wapi_wlan_authentication.h"
#include "eapol_key_types.h"
#include "eap_array.h"
#include "eapol_rsna_key_header.h"
#include "eapol_test_stack_if.h"
#include "eap_am_network_id.h"

// FORWARD DECLARATIONS
class wapi_ethernet_core_c;

class eap_file_config_c;
class eapol_wlan_database_reference_c;


// CLASS DECLARATION
class EAP_EXPORT wapi_wlan_authentication_c
: public abs_wapi_am_wlan_authentication_c
, public abs_wapi_ethernet_core_c
, public abs_eap_base_timer_c
#if defined(USE_TEST_EAPOL_WLAN_AUTHENTICATION)
, public eapol_test_stack_if_c
#endif
{
public:

	EAP_FUNC_IMPORT static wapi_wlan_authentication_c * new_wapi_wlan_authentication(
		abs_eap_am_tools_c * const tools,
		abs_wapi_wlan_authentication_c * const partner,
		const bool is_client_when_true,
		const abs_eapol_wlan_database_reference_if_c * const wlan_database_reference);

	EAP_FUNC_IMPORT wapi_wlan_authentication_c(
		abs_eap_am_tools_c * const tools,
		abs_wapi_wlan_authentication_c * const partner,
		wapi_am_wlan_authentication_c * const am_wauth, ///< wapi_wlan_authentication_c must always delete the am_wauth object.
		const bool is_client_when_true);

#if defined(EXPORT_DESTRUCTORS)
	EAP_FUNC_IMPORT virtual ~wapi_wlan_authentication_c();	 // For GCC compilation
#else
	virtual ~wapi_wlan_authentication_c();	 // For RVCT compilation
#endif
	
	
	///////////////////////////////////////////////////////////////
	/* These are called from WLM */

	/**
	 * This function checks whether WAPI BKSA is cached to each eap_am_network_id_c object.
	 * Function removes eap_am_network_id_c object from bssid_sta_receive_network_ids if there are
	 * no cached BKSA for removes eap_am_network_id_c object.
	 * All eap_am_network_id_c objects that exist in bssid_sta_receive_network_ids
	 * after function returns have BKSA cached and read_reassociation_parameters() can be called
	 * with those eap_am_network_id_c objects.
	 */
	EAP_FUNC_IMPORT eap_status_e check_bksa_cache(
		eap_array_c<eap_am_network_id_c> * const bssid_sta_receive_network_ids,
		const eapol_key_authentication_type_e selected_eapol_key_authentication_type,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite);

	EAP_FUNC_IMPORT eap_status_e start_authentication(
		const eap_variable_data_c * const SSID,
		const eapol_key_authentication_type_e selected_eapol_key_authentication_type,
		// In WAPI these are used for the PSK mode
		const eap_variable_data_c * const preshared_key,
		const bool WAPI_override_enabled,
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		);

	EAP_FUNC_IMPORT eap_status_e complete_association(
		const eapol_wlan_authentication_state_e association_result,
		const eap_am_network_id_c * const receive_network_id, ///< source includes remote address, destination includes local address.
		const eap_variable_data_c * const received_WAPI_IE,
		const eap_variable_data_c * const sent_WAPI_IE,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite
		);
	
	EAP_FUNC_IMPORT eap_status_e disassociation(
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		);
		
	EAP_FUNC_IMPORT eap_status_e start_reassociation(
		const eap_am_network_id_c * const old_receive_network_id, ///< source includes remote address, destination includes local address.
		const eap_am_network_id_c * const new_receive_network_id, ///< source includes remote address, destination includes local address.
		const eapol_key_authentication_type_e selected_eapol_key_authentication_type 
		);

	EAP_FUNC_IMPORT eap_status_e complete_reassociation(
		const eapol_wlan_authentication_state_e reassociation_result,
		const eap_am_network_id_c * const receive_network_id,
		const eap_variable_data_c * const received_WAPI_IE,
		const eap_variable_data_c * const sent_WAPI_IE,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite);

	EAP_FUNC_IMPORT eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id, ///< source includes remote address, destination includes local address.
		eap_general_header_base_c * const packet_data,
		const u32_t packet_length
		);


	/////////////////////////////////////////
	/* These are called from wapi_ethernet_core */
	
	/**
	* Sends packet to lower layers
	*/
	EAP_FUNC_IMPORT eap_status_e packet_send(
		const eap_am_network_id_c * const send_network_id, ///< source includes local address, destination includes remote address.
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length); 

	EAP_FUNC_IMPORT u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length);

	EAP_FUNC_IMPORT void set_is_valid();

	EAP_FUNC_IMPORT bool get_is_valid();

	EAP_FUNC_IMPORT void increment_authentication_counter();

	EAP_FUNC_IMPORT u32_t get_authentication_counter();

#if defined(USE_TEST_EAPOL_WLAN_AUTHENTICATION)

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// For testing 

	EAP_FUNC_IMPORT u32_t get_wrong_send_packet_index();

	EAP_FUNC_IMPORT void set_authentication_can_succeed();

	EAP_FUNC_IMPORT void reset_authentication_can_succeed();

	EAP_FUNC_IMPORT void restore_authentication_can_succeed();

	EAP_FUNC_IMPORT void set_authentication_must_not_succeed(
        const u32_t wrong_packet_index,
        const u32_t packet_index,
        const void * const wrong_packet_stack);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#endif // #if defined(USE_TEST_EAPOL_WLAN_AUTHENTICATION)

	EAP_FUNC_IMPORT bool get_is_client();

	/**
	* This does the initial configuration of the class.
	*/
	EAP_FUNC_IMPORT eap_status_e configure();

	EAP_FUNC_IMPORT eap_status_e shutdown();

	/**
	* Reads a configuration parameter value from the database. 
	* In Symbian this function is only a TRAP wrapper for read_configure_L.
	*/
	EAP_FUNC_IMPORT eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	EAP_FUNC_IMPORT eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	// See abs_eap_base_type_c::state_notification().
	EAP_FUNC_IMPORT void state_notification(const abs_eap_state_notification_c * const state);
	
	EAP_FUNC_IMPORT eap_status_e set_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id, 
		void * const p_data,
		const u32_t p_time_ms);

	EAP_FUNC_IMPORT eap_status_e cancel_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id);

	EAP_FUNC_IMPORT eap_status_e cancel_all_timers();

	/**
	* Forwards the keys to lower layer (= WLM).
	*/
	EAP_FUNC_IMPORT eap_status_e packet_data_session_key(
		const eap_am_network_id_c * const send_network_id, ///< source includes local address, destination includes remote address.
		const eapol_session_key_c * const key);

	EAP_FUNC_IMPORT eap_status_e timer_expired(const u32_t id, void *data);

	EAP_FUNC_IMPORT eap_status_e timer_delete_data(const u32_t id, void *data);


private:

	EAP_FUNC_IMPORT eap_status_e wapi_indication(
		const eap_am_network_id_c * const receive_network_id, ///< source includes remote address, destination includes local address.
		const eapol_wlan_authentication_state_e notification);

	EAP_FUNC_IMPORT eap_status_e create_upper_stack();

	eap_status_e disassociation_mutex_must_be_reserved(
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		);

	eap_status_e cancel_all_authentication_sessions();

	eap_status_e cancel_timer_this_ap_failed();

	eap_status_e cancel_timer_failed_completely();

	eap_status_e cancel_timer_no_response();

	eap_status_e cancel_timer_authentication_cancelled();

#if defined(USE_EAP_ERROR_TESTS)

	eap_status_e random_error(
		eap_buf_chain_wr_c * const sent_packet,
		const bool forse_error,
		const u32_t packet_index);

#endif //#if defined(USE_EAP_ERROR_TESTS)


private:


	/// Pointer to the lower layer in the stack
	abs_wapi_wlan_authentication_c * m_partner;

	/// Pointer to the AM of WAUTH.
	wapi_am_wlan_authentication_c * m_am_wauth;

	/// Pointer to the upper layer in the stack
	wapi_ethernet_core_c * m_ethernet_core;

	/// Pointer to the tools class
	abs_eap_am_tools_c * m_am_tools;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	
	eap_variable_data_c m_preshared_key;
	
	eapol_key_authentication_type_e m_authentication_type;

	eapol_key_802_11_authentication_mode_e m_802_11_authentication_mode;

	eap_variable_data_c m_received_WAPI_IE;

	eap_variable_data_c m_sent_WAPI_IE;

	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e m_group_key_cipher_suite;

	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e m_pairwise_key_cipher_suite;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t m_authentication_counter;

	u32_t m_successful_authentications;

	u32_t m_failed_authentications;

	bool m_is_valid;

	bool m_is_client;	

	bool m_shutdown_was_called;

#if defined(USE_EAP_ERROR_TESTS)

	u32_t m_error_probability;

	u32_t m_randomly_drop_packets_probability;

	u32_t m_generate_multiple_error_packets;

	bool m_enable_random_errors;

	bool m_randomly_drop_packets;

	bool m_manipulate_ethernet_header;

	bool m_send_original_packet_first;

#endif //#if defined(USE_EAP_ERROR_TESTS)

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	
	//--------------------------------------------------
}; // class wapi_wlan_authentication_c

#endif //#if !defined(_WAPI_WLAN_AUTHENTICATION_H_)

//--------------------------------------------------


// End of file
