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
* %version: 16 %
*/

#if !defined(_ABS_EAPOL_CORE_H_)
#define _ABS_EAPOL_CORE_H_

#include "eap_am_types.h"
#include "eapol_key_state.h"
#if defined(USE_EAP_SIMPLE_CONFIG)
	#include "abs_eap_configuration_if.h"
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAPOL_CORE_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAPOL_CORE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAPOL_CORE_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAPOL_CORE_H 
	#define EAP_FUNC_EXPORT_ABS_EAPOL_CORE_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAPOL_CORE_H 
#elif defined(EAP_EXPORT_ABS_EAPOL_CORE_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAPOL_CORE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAPOL_CORE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAPOL_CORE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAPOL_CORE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAPOL_CORE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAPOL_CORE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAPOL_CORE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAPOL_CORE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAPOL_CORE_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAPOL_CORE_H 
#endif
// End: added by script change_export_macros.sh.

class eap_am_network_id_c;
class eapol_session_key_c;
class abs_eap_base_type_c;
class eap_rogue_ap_entry_c;
class eap_base_type_c;


/// The abs_eapol_core_c class defines the interface the eapol_core_c class
/// will use with the partner class.
/// Later eapol and ethernet could be integrated. Now I am too lazy.
class EAP_CLASS_VISIBILITY_ABS_EAPOL_CORE_H abs_eapol_core_c
#if defined(USE_EAP_SIMPLE_CONFIG)
: public abs_eap_configuration_if_c
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)
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
	 * The destructor does nothing special.
	 */
	virtual ~abs_eapol_core_c()
	{
	}

	/**
	 * The constructor does nothing special.
	 */
	abs_eapol_core_c()
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
	 * The get_header_offset() function obtains the header offset of EAP-packet.
	 * @see abs_eap_base_type_c::get_header_offset().
	 */
	virtual u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length) = 0;

	/**
	 * The load_module() function function indicates the lower level to
	 * load new module of EAP-type.
	 * @see abs_eap_core_c::load_module().
	 */
	virtual eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e /* tunneling_type */,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id) = 0;

	/**
	 * The unload_module() function unloads the module of a EAP-type. 
	 * @param type is the requested EAP-type.
	 */
	virtual eap_status_e unload_module(
		const eap_type_value_e type) = 0;

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
	 * These two notifications are sent from EAP-protocol layer (eap_protocol_layer_e::eap_protocol_layer_eap).
	 */
	virtual void state_notification(
		const abs_eap_state_notification_c * const state) = 0;

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

	/**
	 * This function queries the validity of EAP-type.
	 * Lower layer should return eap_status_ok if this EAP-type is supported.
	 */
	virtual eap_status_e check_is_valid_eap_type(const eap_type_value_e eap_type) = 0;

	/**
	 * This function queries the list of supported EAP-types.
	 * Lower layer should return eap_status_ok if this call succeeds.
	 * @param eap_type_list will include the list of supported EAP-types. Each value in list
	 * is type of u32_t and represent one supported EAP-type. List consists of subsequent u32_t type values.
	 */
	virtual eap_status_e get_eap_type_list(
		eap_array_c<eap_type_value_e> * const eap_type_list) = 0;

	virtual eap_status_e add_rogue_ap(eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list) = 0;

	virtual eap_status_e complete_check_pmksa_cache(
		EAP_TEMPLATE_CONST eap_array_c<eap_am_network_id_c> * const bssid_sta_receive_network_ids) = 0;

	virtual eap_status_e complete_get_802_11_authentication_mode(
		const eap_status_e completion_status,
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_802_11_authentication_mode_e mode) = 0;

	virtual eap_status_e complete_disassociation(
		const bool complete_to_lower_layer,
		const eap_am_network_id_c * const receive_network_id) = 0;

	//--------------------------------------------------
}; // class abs_eapol_core_c

#endif //#if !defined(_ABS_EAPOL_CORE_H_)

//--------------------------------------------------



// End.
