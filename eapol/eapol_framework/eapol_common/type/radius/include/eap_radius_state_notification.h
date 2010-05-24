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

#if !defined(_EAP_RADIUS_STATE_NOTIFICATION_H_)
#define _EAP_RADIUS_STATE_NOTIFICATION_H_

#include "eap_variable_data.h"
#include "eap_am_export.h"
#include "eap_protocol_layer.h"
#include "abs_eap_state_notification.h"


/// A eap_radius_state_notification_c class.
/// This is used for debugging and protocol testing.
class EAP_EXPORT eap_radius_state_notification_c
: public abs_eap_state_notification_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools; ///< This is pointer to the tools class. @see abs_eap_am_tools_c.

	eap_protocol_layer_e m_layer; ///< Here is the protocol layer (EAP type).

	eap_variable_data_c m_notification_string; ///< Here is the notification string.

	bool m_needs_confirmation_from_user; ///< This flag tells whether user interaction is required.

	u32_t m_protocol; ///< Here are other protocols than EAP-types.

	eap_type_value_e m_eap_type; ///< Here is the EAP type. This is needed for extented EAP-types.

	u32_t m_previous_state; ///< Here is the previous state of the EAP type.
	
	u32_t m_current_state; ///< Here is the current state of the EAP type.
	
	const eap_am_network_id_c *m_send_network_id;
	
	bool m_is_client;
	
	u8_t m_eap_identifier;
	
	bool m_allow_send_eap_success;

	EAP_FUNC_IMPORT eap_const_string get_state_string(const u32_t state) const;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the eap_radius_state_notification_c class does nothing special.
	 */
	EAP_FUNC_IMPORT virtual ~eap_radius_state_notification_c();

	/**
	 * The constructor of the eap_radius_state_notification_c class does nothing special.
	 */
	EAP_FUNC_IMPORT eap_radius_state_notification_c(
		abs_eap_am_tools_c * const tools,
		const eap_am_network_id_c * const send_network_id,
		bool is_client,
		eap_state_notification_generic_e,
		eap_protocol_layer_e layer,
		u32_t protocol,
		u32_t previous_state,
		u32_t current_state,
		u8_t eap_identifier,
		bool allow_send_eap_success);


	EAP_FUNC_IMPORT eap_radius_state_notification_c(
		abs_eap_am_tools_c * const tools,
		const eap_am_network_id_c * const send_network_id,
		bool is_client,
		eap_state_notification_eap_e,
		eap_protocol_layer_e layer,
		eap_type_value_e eap_type,
		u32_t previous_state,
		u32_t current_state,
		u8_t eap_identifier,
		bool allow_send_eap_success);


	EAP_FUNC_IMPORT eap_radius_state_notification_c(
		abs_eap_am_tools_c * const tools,
		const eap_am_network_id_c * const send_network_id,
		bool is_client,
		eap_state_notification_eap_e,
		eap_protocol_layer_e layer,
		eap_type_ietf_values_e eap_type,
		u32_t previous_state,
		u32_t current_state,
		u8_t eap_identifier,
		bool allow_send_eap_success);

	// This is commented in abs_eap_state_notification_c::get_send_network_id().
	EAP_FUNC_IMPORT const eap_am_network_id_c * get_send_network_id() const;

	// This is commented in abs_eap_state_notification_c::get_protocol_layer().
	EAP_FUNC_IMPORT eap_protocol_layer_e get_protocol_layer() const;

	// This is commented in abs_eap_state_notification_c::get_protocol().
	EAP_FUNC_IMPORT u32_t get_protocol() const;

	// This is commented in abs_eap_state_notification_c::get_eap_type().
	EAP_FUNC_IMPORT eap_type_value_e get_eap_type() const;

	// This is commented in abs_eap_state_notification_c::get_previous_state().
	EAP_FUNC_IMPORT u32_t get_previous_state() const;

	// This is commented in abs_eap_state_notification_c::get_previous_state_string().
	EAP_FUNC_IMPORT eap_const_string get_previous_state_string() const;

	// This is commented in abs_eap_state_notification_c::get_current_state().
	EAP_FUNC_IMPORT u32_t get_current_state() const;

	// This is commented in abs_eap_state_notification_c::get_current_state_string().
	EAP_FUNC_IMPORT eap_const_string get_current_state_string() const;

	// This is commented in abs_eap_state_notification_c::get_is_client().
	EAP_FUNC_IMPORT bool get_is_client() const;

	// This is commented in abs_eap_state_notification_c::get_eap_identifier().
	EAP_FUNC_IMPORT u8_t get_eap_identifier() const;

	// This is commented in abs_eap_state_notification_c::get_allow_send_eap_success().
	EAP_FUNC_IMPORT bool get_allow_send_eap_success() const;

	// This is commented in abs_eap_state_notification_c::set_notification_string().
	EAP_FUNC_IMPORT eap_status_e set_notification_string(
		const eap_variable_data_c * const notification_string,
		const bool needs_confirmation_from_user);

	// This is commented in abs_eap_state_notification_c::get_notification_string().
	EAP_FUNC_IMPORT const eap_variable_data_c * get_notification_string() const;

	// This is commented in abs_eap_state_notification_c::get_needs_confirmation_from_user().
	EAP_FUNC_IMPORT bool get_needs_confirmation_from_user() const;

	//--------------------------------------------------
}; // class eap_radius_state_notification_c

#endif //#if !defined(_EAP_RADIUS_STATE_NOTIFICATION_H_)

//--------------------------------------------------



// End.
