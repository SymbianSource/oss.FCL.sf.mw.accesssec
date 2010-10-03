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

#ifndef _ABS_MSCHAPV2_STATE_H_
#define _ABS_MSCHAPV2_STATE_H_

#include "eap_tools.h"
#include "eap_variable_data.h"
#include "eap_buffer.h"
#include "eap_base_type.h"
#include "eap_config.h"
#include "eap_type_mschapv2_types.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_TYPE_SECURID_STATE_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_TYPE_SECURID_STATE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_TYPE_SECURID_STATE_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_TYPE_SECURID_STATE_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_TYPE_SECURID_STATE_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_TYPE_SECURID_STATE_H 
#elif defined(EAP_EXPORT_ABS_EAP_TYPE_SECURID_STATE_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_TYPE_SECURID_STATE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_TYPE_SECURID_STATE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_TYPE_SECURID_STATE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_TYPE_SECURID_STATE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_TYPE_SECURID_STATE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_TYPE_SECURID_STATE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_TYPE_SECURID_STATE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_TYPE_SECURID_STATE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_TYPE_SECURID_STATE_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_TYPE_SECURID_STATE_H 
#endif
// End: added by script change_export_macros.sh.



/// This class declares the functions eap_type_gsmsim_state_c
/// requires from the partner class.
class EAP_CLASS_VISIBILITY_ABS_EAP_TYPE_SECURID_STATE_H abs_eap_type_mschapv2_state_c
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
	 * Constructor does nothing.
	 */
	virtual ~abs_eap_type_mschapv2_state_c()
	{
	}

	/**
	 * Desstructor does nothing.
	 */
	abs_eap_type_mschapv2_state_c()
	{
	}

	/**
	 * The get_header_offset() function obtains the header offset of EAP-packet.
	 * @see abs_eap_base_type_c::get_header_offset().
	 */
	virtual const u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length) = 0;

	/**
	 * The read_configure() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @see abs_eap_base_type_c::read_configure().
	 */
	virtual const eap_status_e read_configure(
		eap_config_string field,
		const u32_t field_length,
		eap_variable_data_c * const data) = 0;

	/**
	 * The write_configure() function writes the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the action to some persistent store.
	 * @see abs_eap_base_type_c::write_configure().
	 */
	virtual const eap_status_e write_configure(
		eap_config_string field,
		const u32_t field_length,
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
	virtual const eap_status_e set_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id, 
		void * const data,
		const u32_t p_time_ms) = 0;

	/**
	 * The cancel_timer() function cancels the timer id initiated by initializer.
	 *
	 * Adaptation module internally implements the timer.
	 */
	virtual const eap_status_e cancel_timer(
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
	virtual const eap_status_e cancel_all_timers() = 0;

	//--------------------------------------------------
}; // class abs_eap_type_gsmsim_state_c



#endif // _ABS_MSCHAPV2_STATE_H_
