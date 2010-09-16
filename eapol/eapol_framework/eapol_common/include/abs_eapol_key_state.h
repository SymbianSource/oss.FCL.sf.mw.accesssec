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
* %version: %
*/

#if !defined(_ABS_EAPOL_KEY_STATE_H_)
#define _ABS_EAPOL_KEY_STATE_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAPOL_KEY_STATE_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAPOL_KEY_STATE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAPOL_KEY_STATE_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAPOL_KEY_STATE_H 
	#define EAP_FUNC_EXPORT_ABS_EAPOL_KEY_STATE_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAPOL_KEY_STATE_H 
#elif defined(EAP_EXPORT_ABS_EAPOL_KEY_STATE_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAPOL_KEY_STATE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAPOL_KEY_STATE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAPOL_KEY_STATE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAPOL_KEY_STATE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAPOL_KEY_STATE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAPOL_KEY_STATE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAPOL_KEY_STATE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAPOL_KEY_STATE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAPOL_KEY_STATE_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAPOL_KEY_STATE_H 
#endif
// End: added by script change_export_macros.sh.

class eapol_session_key_c;


/// This class defines the interface the eapol_key_state_c class
/// will use with the partner class (lower layer).
class EAP_CLASS_VISIBILITY_ABS_EAPOL_KEY_STATE_H abs_eapol_key_state_c
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
	 * The destructor of the abs_eap_core class does nothing special.
	 */
	virtual ~abs_eapol_key_state_c()
	{
	}

	/**
	 * The constructor of the abs_eap_core class does nothing special.
	 */
	abs_eapol_key_state_c()
	{
	}

	/**
	 * A eapol_key_state_c object calls this function when
	 * a new temporary key (PTK, GTK or STAKey) is generated.
	 */
	virtual eap_status_e packet_data_session_key(
		const eap_am_network_id_c * const receive_network_id,
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
	 * These two notifications tells the end state of authentication session. These are the only
	 * reliable indications of the final status of authentication session.
	 * You MUST NOT make decision based on the return value of abs_eap_stack_interface_c::packet_process().
	 */
	virtual void state_notification(
		const abs_eap_state_notification_c * const state) = 0;

	/**
	 * The set_timer() function initializes timer to be elapsed after time_ms milliseconds.
	 * @param initializer is pointer to object which timer_expired() function will
	 * be called after timer elapses.
	 * @param id is identifier which will be returned in timer_expired() function.
	 * The user selects and interprets the id for this timer.
	 * @param data is pointer to any user selected data which will be returned in timer_expired() function.
	 * @param time_ms is the time of timer in milli seconds.
	 *
	 * Adaptation module internally implements the timer.
	 */
	virtual eap_status_e set_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id, 
		void * const data,
		const u32_t time_ms) = 0;

	/**
	 * The cancel_timer() function cancels the timer id initiated by initializer.
	 * @param initializer is pointer to object which set the cancelled timer.
	 * @param id is identifier which will be returned in timer_expired() function.
	 * The user selects and interprets the id for this timer.
	 *
	 * Adaptation module internally implements the timer.
	 */
	virtual eap_status_e cancel_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id) = 0;

	/**
	 * All STAs contain a global Key Counter which is 256 bits in size.
	 * It should be initialized at system boot up time to a fresh cryptographic quality random number.
	 * Refer to Annex I.9 on random number generation. It is recommended that the counter value is initialized to:
	 * PRF-256(Random number, "Init Counter", Local MAC Address || Time)
	 * The Local MAC Address should be AA on the Authenticator and SA on the Supplicant.
	 * The random number is 256 bits in size. Time should be the current time
	 * (from NTP or another time in NTP format) whenever possible. 
	 * This initialization is to ensure that different initial Key Counter 
	 * values occur across system restarts whether a real-time clock is available or not.
	 * The Key Counter must be incremented (all 256 bits) each time a value is used as a nonce or IV.
	 * The Key Counter must not be allowed to wrap to the initialization value.
	 */
	virtual eap_status_e get_and_increment_global_key_counter(
		eap_variable_data_c * const key_counter) = 0;

	/**
	 * This function tells lower layer to remove EAPOL-Key Handshake session object asynchronously.
	 * @param send_netword_id carries the send addresses (network identity).
	 */
	virtual eap_status_e asynchronous_init_remove_eapol_key_state(
		const eap_am_network_id_c * const send_netword_id) = 0;

	//--------------------------------------------------
}; // class abs_eapol_key_state_c

#endif //#if !defined(_ABS_EAPOL_KEY_STATE_H_)

//--------------------------------------------------



// End.
