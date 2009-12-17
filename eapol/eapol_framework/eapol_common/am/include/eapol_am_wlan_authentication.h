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




#if !defined(_EAPOL_AM_WLAN_AUTHENTICATION_H_)
#define _EAPOL_AM_WLAN_AUTHENTICATION_H_

#include "eap_am_export.h"
#include "eap_status.h"
#include "eap_header.h"
#include "eap_array.h"
#include "eapol_key_types.h"

class abs_eapol_am_wlan_authentication_c;
class abs_eap_am_tools_c;
class abs_eap_base_type_c;
class eap_base_type_c;
class eap_am_network_id_c;
class eap_type_selection_c;
class abs_eapol_wlan_database_reference_if_c;
class abs_eap_state_notification_c;

#if defined(USE_EAP_SIMPLE_CONFIG)
class abs_eap_configuration_if_c;
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)


/// This is interface to adaptation module of class eapol_wlan_authentication_c.
class EAP_EXPORT eapol_am_wlan_authentication_c
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
	virtual ~eapol_am_wlan_authentication_c();

	/// @param tools: Constructor takes parameter tools that is pointer to adaptation of the platform.
	/// @param is_client_when_true: Second parameter is true when object is client and false when object is server.
	/// @param wlan_database_reference: third parameter is pointer to interface to read the current database reference.
	EAP_FUNC_IMPORT static eapol_am_wlan_authentication_c * new_eapol_am_wlan_authentication(
		abs_eap_am_tools_c * const tools,
		const bool is_client_when_true,
		const abs_eapol_wlan_database_reference_if_c * const wlan_database_reference
		);

	/// This is documented in abs_eap_stack_interface_c::get_is_valid().
	virtual bool get_is_valid() = 0;

	/// This is documented in abs_eap_stack_interface_c::configure().
	virtual eap_status_e configure() = 0;

	/// This is documented in abs_eap_stack_interface_c::shutdown().
	virtual eap_status_e shutdown() = 0;

	/// Function sets the parther object of this object.
	virtual eap_status_e set_am_partner(
		abs_eapol_am_wlan_authentication_c * am_partner
#if defined(USE_EAP_SIMPLE_CONFIG)
		, abs_eap_configuration_if_c * const configuration_if
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)
		) = 0;

	/// Function resets current EAP-configuration.
	virtual eap_status_e reset_eap_configuration() = 0;

	/// Function sets the new WLAN parameters.
	virtual eap_status_e set_wlan_parameters(
		const eap_variable_data_c * const SSID,
		const bool WPA_override_enabled,
		const eap_variable_data_c * const wpa_preshared_key,
		const eapol_key_authentication_type_e selected_eapol_key_authentication_type) = 0;

	/// New association is completed.
	virtual eap_status_e association(
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		) = 0;

	/// Previous connection was disassiciated.
	virtual eap_status_e disassociation(
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		) = 0;

	/**
	 * This function queries the selected and active EAP-types that can be used
	 * in current connection.
	 */
	virtual eap_status_e get_selected_eap_types(
		eap_array_c<eap_type_selection_c> * const selected_eap_types) = 0;

	/// Function gets the current WLAN configuration, now only the HASH of the WPA(2)-PSK.
	virtual eap_status_e get_wlan_configuration(
		eap_variable_data_c * const wpa_preshared_key_hash) = 0;

	/**
	 * This function indicates finish of the authentication to adatation module.
	 * @param when_true_successfull tells whether authentication was successfull (true) or not (false).
	 * @param eap_type tells the used EAP-type.
	 * @param authentication_type tells the used WLAN authentication type.
	 */
	virtual eap_status_e authentication_finished(
		const bool when_true_successfull,
		const eap_type_value_e eap_type,
		const eapol_key_authentication_type_e authentication_type) = 0;

	/**
	 * The load_module() function function indicates the lower level to
	 * load new module of EAP-type.
	 * @param type is the requested EAP-type.
	 * @param tunneling_type is the EAP-type that tunnels the type. When plain EAP-type is used this parameter is eap_type_none.
	 * @param partner is pointer to the caller object.
	 * The partner of the new created EAP-type object is the caller object.
	 * @param eap_type is a pointer to a pointer of EAP-type object.
	 * Adaptation module sets eap_type pointer to created EAP-type object.
	 * @param is_client_when_true parameter indicates whether the network entity should
	 * act as a client (true) or server (false), in terms of EAP-protocol whether
	 * this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	 * @param receive_network_id includes the addresses (network identity) and packet type.
	 */
	virtual eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e tunneling_type,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		) = 0;

	/**
	 * The unload_module() function unloads the module of a EAP-type. 
	 * @param eap_type is the requested EAP-type.
	 */
	virtual eap_status_e unload_module(
		const eap_type_value_e type) = 0;

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
	 * The set_timer() function initializes timer to be elapsed after p_time_ms milliseconds.
	 * @param initializer is pointer to object which timer_expired() function will
	 * be called after timer elapses.
	 * @param id is identifier which will be returned in timer_expired() function.
	 * The user selects and interprets the id for this timer.
	 * @param data is pointer to any user selected data which will be returned in timer_expired() function.
	 * @param p_time_ms is time of timer to elapse in milli seconds.
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
	 * @param initializer is the object that initialised the timer.
	 * @param id is the identity of the timer.
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

	/**
	 * This is notification of internal state transition.
	 * This is used for notifications, debugging and protocol testing.
	 * The primal notifications are eap_state_variable_e::eap_state_authentication_finished_successfully
	 * and eap_state_variable_e::eap_state_authentication_terminated_unsuccessfully.
	 * These two notifications are sent from EAP-protocol layer (eap_protocol_layer_e::eap_protocol_layer_eap).
	 */
	virtual void state_notification(
		const abs_eap_state_notification_c * const state) = 0;

	//--------------------------------------------------
}; // class eapol_am_wlan_authentication_c

#endif //#if !defined(_EAPOL_AM_WLAN_AUTHENTICATION_H_)

//--------------------------------------------------



// End.
