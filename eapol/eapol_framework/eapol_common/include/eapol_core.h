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
* %version: 49 %
*/

#if !defined(_EAPOL_CORE_H_)
#define _EAPOL_CORE_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPOL_CORE_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_CORE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPOL_CORE_H 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_CORE_H 
	#define EAP_FUNC_EXPORT_EAPOL_CORE_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_CORE_H 
#elif defined(EAP_EXPORT_EAPOL_CORE_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_CORE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_CORE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_CORE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPOL_CORE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPOL_CORE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPOL_CORE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_CORE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_CORE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPOL_CORE_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_CORE_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_session_core.h"
#include "eap_core.h"
#include "abs_eapol_core.h"
#include "eap_base_type.h"
#include "eap_variable_data.h"
#include "abs_eap_am_mutex.h"
#include "eap_session_core_base.h"
#include "abs_eap_stack_interface.h"
#include "abs_eapol_key_state.h"
#include "eapol_rsna_key_header.h"
#include "eapol_key_state.h"
#include "abs_eapol_key_state_map.h"
#include "eap_database_reference_if.h"


/** @file */

/**
 * This is the timer ID used with abs_eap_am_tools_c::set_timer() and abs_eap_am_tools_c::cancel_timer().
 */
enum eapol_core_timer_id
{
	EAPOL_CORE_TIMER_SEND_START_AGAIN_ID, ///< See EAPOL_CORE_TIMER_SEND_START_AGAIN_TIMEOUT.
	EAPOL_REMOVE_EAPOL_KEY_HANDSHAKE_ID,
};

/**
 * This is the default time after a EAPOL-Start message is sent again from client.
 */
const u32_t EAPOL_CORE_TIMER_SEND_START_AGAIN_TIMEOUT = 2000u;

/**
 * This is the time after a EAPOL-Key Handshake will be removed.
 */
const u32_t EAPOL_REMOVE_EAPOL_KEY_HANDSHAKE_TIMEOUT = 0ul;

/**
 * This is the default value for how many time EAPOL-Start is sent.
 */
const u32_t EAPOL_CORE_MAX_EAPOL_START_SENDINGS = 3u;


class eapol_RC4_key_header_c;


/// A eapol_core_c class implements the basic functionality of EAPOL.
class EAP_CLASS_VISIBILITY_EAPOL_CORE_H eapol_core_c
: public abs_eap_session_core_c
, public abs_eap_base_timer_c
, public abs_eap_stack_interface_c
, public abs_eapol_key_state_c
, public abs_eapol_key_state_map_c
, public eap_database_reference_if_c
{

private:
	//--------------------------------------------------

	/// This is back pointer to object which created this object.
	abs_eapol_core_c * const m_partner;

	/// This is pointer to the eap_core object. The eapol_core object gives
	/// the received packets to the eap_core object. The eap_core object sends
	/// packets through the eapol_core object.
	eap_session_core_base_c * m_eap_core;

	/// This stores eapol_key_state_c objects using eap_variable_data selector.
	/// Selector data includes send addresses of the Ethernet packet.
	eap_core_map_c<eapol_key_state_c, abs_eapol_key_state_map_c, eap_variable_data_c> m_eapol_key_state_map;

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is the master session key derived from a successful authentication
	eap_variable_data_c m_master_session_key;

	eapol_key_authentication_type_e m_authentication_type;

	/// This is offset in bytes of the EAPOL header.
	u32_t m_eapol_header_offset;

	/// This is maximum transfer unit in bytes.
	u32_t m_MTU;

	/// This is length of the trailer in bytes.
	u32_t m_trailer_length;

	/// This indicates the maximum number of EAPOL-starts to be sent.
	u32_t m_max_eapol_starts;

	/// This indicates the interval for EAPOL-start sending.
	u32_t m_eapol_start_interval;

	/// This is the counter for EAPOL-start sending.
	u32_t m_eapol_starts_sent;

	/// This indicates whether this object is client (true) or server (false).
	/// In terms of EAP-protocol whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	bool m_is_client;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	bool m_shutdown_was_called;

	bool m_block_state_notifications;

	/// This flag will skip start of 4-Way Handshake with true value.
	bool m_skip_start_4_way_handshake;


	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e indicate_eapol_key_state_started_eap_authentication(
		const eap_am_network_id_c * const send_network_id);

	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e init_eapol_key_pmksa_caching_timeout(
		const eap_am_network_id_c * const send_network_id);

	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e remove_eapol_key_state(
		const eap_am_network_id_c * const send_network_id,
		const bool force_remove);

	eap_status_e copy_eapol_key_state(
		const eap_am_network_id_c * const old_receive_network_id, ///< source includes remote address, destination includes local address.
		const eap_am_network_id_c * const new_receive_network_id ///< source includes remote address, destination includes local address.
		);

	eap_status_e generate_new_pmksa(
		eapol_key_state_c * * const eapol_key_state,
		const eap_am_network_id_c * const old_receive_network_id, ///< source includes remote address, destination includes local address.
		const eap_am_network_id_c * const new_receive_network_id ///< source includes remote address, destination includes local address.
		);

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor deletes the m_eap_core object.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H virtual ~eapol_core_c();

	/**
	 * The constructor creates the eap_core object and initializes the m_eap_core
	 * to point the eap_core object.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 * @param partner is back pointer to object which created this object.
	 * @param is_client_when_true indicates whether the network entity should act
	 * as a client (true) or server (false), in terms of EAP-protocol whether
	 * this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	 */
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eapol_core_c(
		abs_eap_am_tools_c * const tools,
		abs_eapol_core_c * const partner,
		const bool is_client_when_true);

	/**
	 * This function removes all authentication sessions.
	 * If this succeeds this function must return eap_status_ok.
	 * If this fails this function must return corresponding error status.
	 * @return This function returns the status of operation.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e cancel_all_authentication_sessions();

	// This is documented in abs_eap_stack_interface_c::packet_process().
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id,
		eap_general_header_base_c * const packet_data,
		const u32_t packet_length); 

	/**
	 * The class could send packets to partner class with this function.
	 * eapol_core_c adds EAPOL header to the send packet.
	 * @param send_network_id carries the addresses (network identity) and type of the packet.
	 * @param sent_packet includes the buffer for the whole packet and initialized 
	 * EAP-packet in correct offset.
	 * @param header_offset is offset of the EAP-header within the sent_packet.
	 * @param data_length is length in bytes of the EAP-packet.
	 * @param buffer_length is length in bytes of the whole packet buffer.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e packet_send(
		const eap_am_network_id_c * const send_network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length); 

	/**
	 * The get_header_offset() function obtains the header offset of EAP-packet.
	 * @param MTU_length is pointer to variable to store the maximum transfer unit (MTU).
	 * MTU is the maximum EAP-packet length in bytes
	 * @param trailer_length is pointer to the variable to store length
	 * of trailer needed by lower levels.
	 * @return Function returns the offset of EAP-header.
	 * @see abs_eap_core_c::get_header_offset().
	 */
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length);

	/**
	 * The adaptation module calls the eap_acknowledge() function after
	 * any Network Protocol packet is received. This is used as a success indication.
	 * This is described in RFC 2284 "PPP Extensible Authentication Protocol (EAP)".
	 * @param connection_handle separates the context of the acknowledged session.
	 * Mostly there is only one session in the client.
	 * The server does not need eap_acknowledge() function because
	 * server (EAP-authenticator) sends the EAP-success message.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e eap_acknowledge(
		const eap_am_network_id_c * const receive_network_id); 

	/**
	 * The load_module() function function indicates the lower level to
	 * load new module of EAP-type.
	 * @see abs_eap_core_c::load_module().
	 */
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e /* tunneling_type */,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * The unload_module() function unloads the module of a EAP-type. 
	 * @see abs_eap_core_c::unload_module().
	 */
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e unload_module(
		const eap_type_value_e type); 

	/**
	 * This function checks whether PMKSA is cached to each eap_am_network_id_c object.
	 * Function removes eap_am_network_id_c object from bssid_sta_receive_network_ids if there are
	 * no cached PMKSA for removes eap_am_network_id_c object.
	 * All eap_am_network_id_c objects that exist in bssid_sta_receive_network_ids
	 * after function returns have PMKSA cached and read_reassociation_parameters() can be called
	 * with those eap_am_network_id_c objects.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e check_pmksa_cache(
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
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e remove_pmksa_from_cache(
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * This function starts the EAP-authentication.
	 * The first parameter includes the network addresses of the protocol
	 * over the EAP-packets are transmitted.
	 * The type attribute of the eap_am_network_id_c object MUST be set
	 * either eapol_ethernet_type_e::eapol_ethernet_type_pae.
	 * Value eapol_ethernet_type_e::eapol_ethernet_type_pae is used in normal EA-authentication.
	 * The second parameter is_client_when_true tells whether this stack
	 * is client (true) or server (false).
	 * The adaptation module calls the restart_authentication() function
	 * when EAP-authentication is needed with another peer.
	 * @see abs_eap_core_c::restart_authentication().
	 */
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e restart_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const bool is_client_when_true,
		const bool force_clean_restart,
		const bool from_timer = false);

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
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e start_preauthentication(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type);

	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e read_reassociation_parameters(
		const eap_am_network_id_c * const old_receive_network_id, ///< source includes remote address, destination includes local address.
		const eap_am_network_id_c * const new_receive_network_id, ///< source includes remote address, destination includes local address.
		const eapol_key_authentication_type_e authentication_type,
		eap_variable_data_c * const PMKID,
		const eap_variable_data_c * const received_WPA_ie,
		const eap_variable_data_c * const sent_WPA_ie);

	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e start_reassociation(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const PMKID);

	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e complete_reassociation(
		const eapol_wlan_authentication_state_e reassociation_result,
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const received_WPA_IE, // WLM must give only the WPA IE to EAPOL
		const eap_variable_data_c * const sent_WPA_IE,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite);

	eap_status_e start_WPXM_reassociation(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		eap_variable_data_c * const send_reassociation_request_ie);

	eap_status_e complete_WPXM_reassociation(
		const eapol_wlan_authentication_state_e reassociation_result,
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const received_reassociation_ie);

	/**
	 * he adaptation module calls the send_logoff() function to send a EAPOL-Logoff message.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e send_logoff(
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * Note this function is just an example. Parameters will change later.
	 * The packet_data_crypto_keys() function gives the generated keys to lower level.
	 * After EAP-authentication has generated the keys it calls this function
	 * to offer the keys to lower level.
	 * @see abs_eap_base_type_c::packet_data_crypto_keys().
	 */
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e packet_data_crypto_keys(
		const eap_am_network_id_c * const send_network_id,
		const eap_master_session_key_c * const master_session_key
		);

	// See abs_eapol_key_state_c::packet_data_session_key().
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e packet_data_session_key(
		const eap_am_network_id_c * const send_network_id,
		const eapol_session_key_c * const key);

	// This is documented in abs_eap_stack_interface_c::configure().
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e configure();

	// This is documented in abs_eap_stack_interface_c::shutdown().
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e shutdown();

	/**
	 * The read_configure() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @see abs_eap_base_type_c::read_configure().
	 */
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	/**
	 * The write_configure() function writes the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the action to some persistent store.
	 * @see abs_eap_base_type_c::write_configure().
	 */
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	// This is documented in abs_eap_stack_interface_c::set_is_valid().
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H void set_is_valid();

	// This is documented in abs_eap_stack_interface_c::get_is_valid().
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H bool get_is_valid();

	// See abs_eap_base_type_c::state_notification().
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H void state_notification(
		const abs_eap_state_notification_c * const state);

	// See abs_eap_base_timer_c::timer_expired().
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e timer_expired(
		const u32_t id, void *data);

	// See abs_eap_base_timer_c::timer_delete_data().
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e timer_delete_data(
		const u32_t id, void *data);

	/**
	 * This function tells lower layer to remove EAP session object asyncronously.
	 * @param send_network_id is pointer to network id that identifies the removed EAP session.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e asynchronous_init_remove_eap_session(
		const eap_am_network_id_c * const send_network_id);

	/**
	 * The upper layer calls the asynchronous_start_authentication() function
	 * when EAP-authentication is needed with another peer.
	 * @see abs_eap_core_c::asynchronous_start_authentication().
	 */
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e asynchronous_start_authentication(
		const eap_am_network_id_c * const /* receive_network_id */,
		const bool /* is_client_when_true */);

	//
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e set_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id, 
		void * const p_data,
		const u32_t p_time_ms);

	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e cancel_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id);

	//
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e check_is_valid_eap_type(const eap_type_value_e eap_type);

	// See abs_eap_core_c::get_eap_type_list().
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e get_eap_type_list(
		eap_array_c<eap_type_value_e> * const eap_type_list);

	// See abs_eapol_key_state_c::get_and_increment_global_key_counter().
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e get_and_increment_global_key_counter(
		eap_variable_data_c * const key_counter);


	/**
	 * Function creates a state for later use. This is for optimazing 4-Way Handshake.
	 * @param receive_network_id carries the MAC addresses.
	 * MAC address of Authenticator should be in source address. MAC address of 
	 * Supplicant should be in destination address.
	 * @param authentication_type is the selected authentication type.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e create_state(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type
		);

	/**
	 * This function need to be called when client STA (re)associates to AP.
	 * @param receive_network_id carries the MAC addresses.
	 * MAC address of Authenticator should be in source address. MAC address of Supplicant should be in destination address.
	 * @param authentication_type is the authentication type. One of RSNA, WPA or 802.1X.
	 * @param authenticator_RSNA_IE is RSN IE of authenticator. Authenticator sends this in Beacon or Probe message.
	 * @param supplicant_RSNA_IE is RSN IE of supplicant. Supplicant sends this in (re)association request message.
	 * @param eapol_pairwise_cipher is the selected pairwise cipher.
	 * @param eapol_group_cipher is the selected group cipher.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e association(
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
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e disassociation(
		const bool complete_to_lower_layer,
		const eap_am_network_id_c * const receive_network_id);

	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e asynchronous_init_remove_eapol_key_state(
		const eap_am_network_id_c * const send_netword_id);

	EAP_FUNC_VISIBILITY_EAPOL_CORE_H static eap_status_e shutdown_operation(
		eapol_key_state_c * const handler,
		abs_eap_am_tools_c * const m_am_tools);

	EAP_FUNC_VISIBILITY_EAPOL_CORE_H static eap_status_e cancel_authentication_session(
		eapol_key_state_c * const handler,
		abs_eap_am_tools_c * const m_am_tools);

	/// @see abs_eap_core_c::add_rogue_ap().
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e add_rogue_ap(eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list);

	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e tkip_mic_failure(
		const eap_am_network_id_c * const receive_network_id,
		const bool fatal_failure_when_true,
		const eapol_RSNA_key_header_c::eapol_tkip_mic_failure_type_e tkip_mic_failure_type);

	// This is documented in abs_eap_core_c::set_session_timeout().
	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e set_session_timeout(
		const u32_t session_timeout_ms);

#if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e save_simple_config_session(
		const simple_config_state_e state,
		EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
		const eap_variable_data_c * const new_password,
		const simple_config_Device_Password_ID_e Device_Password_ID,
		const simple_config_payloads_c * const other_configuration);

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e set_eap_database_reference_values(
		const eap_variable_data_c * const reference);

	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e get_802_11_authentication_mode(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const SSID,
		const eap_variable_data_c * const preshared_key);

	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e complete_get_802_11_authentication_mode(
		const eap_status_e completion_status,
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_802_11_authentication_mode_e mode);

	EAP_FUNC_VISIBILITY_EAPOL_CORE_H eap_status_e complete_remove_eap_session(
		const bool complete_to_lower_layer,
		const eap_am_network_id_c * const receive_network_id);

private:

	//--------------------------------------------------
}; // class eapol_core_c

#endif //#if !defined(_EAPOL_CORE_H_)

//--------------------------------------------------



// End.
