/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/wapi_am_wlan_authentication.h
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



#if !defined(_WAPI_AM_WLAN_AUTHENTICATION_H_)
#define _WAPI_AM_WLAN_AUTHENTICATION_H_

#include "eap_am_export.h"
#include "eap_status.h"
#include "eap_header.h"
#include "eap_array.h"
#include "eapol_key_types.h"

class abs_wapi_am_wlan_authentication_c;
class abs_eap_am_tools_c;
class eap_am_network_id_c;
class abs_eapol_wlan_database_reference_if_c;
class abs_eap_state_notification_c;


/// This is interface to adaptation module of class wapi_wlan_authentication_c.
class EAP_EXPORT wapi_am_wlan_authentication_c
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
	virtual ~wapi_am_wlan_authentication_c();

	/// @param tools: Constructor takes parameter tools that is pointer to adaptation of the platform.
	/// @param is_client_when_true: Second parameter is true when object is client and false when object is server.
	/// @param wlan_database_reference: third parameter is pointer to interface to read the current database reference.
	EAP_FUNC_IMPORT static wapi_am_wlan_authentication_c * new_wapi_am_wlan_authentication(
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
		abs_wapi_am_wlan_authentication_c * am_partner
		) = 0;

	/// Function resets current WAPI-configuration.
	virtual eap_status_e reset_wapi_configuration() = 0;

	/// Function sets the new WLAN parameters.
	virtual eap_status_e set_wlan_parameters(
		const eap_variable_data_c * const SSID,
		const bool WAPI_override_enabled,
		const eap_variable_data_c * const preshared_key,
		const eapol_key_authentication_type_e selected_eapol_key_authentication_type) = 0;

	/// New association is completed.
	virtual eap_status_e association(
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		) = 0;

	/// Previous connection was disassociated.
	virtual eap_status_e disassociation(
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		) = 0;

	// ****
	// TODO: Is this needed in WAPI?
	/// Function gets the current WLAN configuration
	virtual eap_status_e get_wlan_configuration(
		eap_variable_data_c * const preshared_key) = 0;

	/**
	 * This function indicates finish of the authentication to adatation module.
	 * @param when_true_successfull indicates whether authentication was successfull (true) or not (false).
	 * @param authentication_type indicates the used WAPI authentication type (PSK or certificate).
	 */
	virtual eap_status_e authentication_finished(
		const bool when_true_successfull,
		const eapol_key_authentication_type_e authentication_type) = 0;

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
	 * This is notification of internal state transition.
	 * This is used for notifications, debugging and protocol testing.
	 * The primal notifications are eap_state_variable_e::eap_state_authentication_finished_successfully
	 * and eap_state_variable_e::eap_state_authentication_terminated_unsuccessfully.
	 * These two notifications are sent from WAPI-protocol layer (eap_protocol_layer_e::eap_protocol_layer_wapi).
	 */
	virtual void state_notification(
		const abs_eap_state_notification_c * const state) = 0;

	//--------------------------------------------------
}; // class wapi_am_wlan_authentication_c

#endif //#if !defined(_WAPI_AM_WLAN_AUTHENTICATION_H_)

//--------------------------------------------------



// End.
