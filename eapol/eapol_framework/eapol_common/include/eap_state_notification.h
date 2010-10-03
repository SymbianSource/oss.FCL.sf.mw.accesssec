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

#if !defined(_EAP_STATE_NOTIFICATION_H_)
#define _EAP_STATE_NOTIFICATION_H_

#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_STATE_NOTIFICATION_H)
	#define EAP_CLASS_VISIBILITY_EAP_STATE_NOTIFICATION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H 
	#define EAP_FUNC_EXPORT_EAP_STATE_NOTIFICATION_H 
	#define EAP_C_FUNC_EXPORT_EAP_STATE_NOTIFICATION_H 
#elif defined(EAP_EXPORT_EAP_STATE_NOTIFICATION_H)
	#define EAP_CLASS_VISIBILITY_EAP_STATE_NOTIFICATION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_STATE_NOTIFICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_STATE_NOTIFICATION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_STATE_NOTIFICATION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_STATE_NOTIFICATION_H 
	#define EAP_C_FUNC_EXPORT_EAP_STATE_NOTIFICATION_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_protocol_layer.h"
#include "abs_eap_state_notification.h"


/// A eap_state_notification_c class.
/// This is used for state change indications of EAP-protocol.
/// EAP-Success and EAP-Failure are sent based on eap_state_variable_e::eap_state_authentication_finished_successfully
/// and eap_state_variable_e::eap_state_authentication_terminated_unsuccessfully notifications.
class EAP_CLASS_VISIBILITY_EAP_STATE_NOTIFICATION_H eap_state_notification_c
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

	const eap_am_network_id_c *m_send_network_id; ///< This is the send network identity the notification concerns.

	bool m_is_client; ///< This indicates whether the notifier is client (true) or server (false).

	u8_t m_eap_identifier; ///< EAP-Identifier could be used in EAP packet send. EAP-Success and EAP-Failure are sent using this value.

	bool m_allow_send_eap_success;

	eap_status_e m_authentication_error; ///< This shows the error when m_layer is eap_protocol_layer_general and m_current_state is eap_general_state_authentication_error.

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the eap_state_notification_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H virtual ~eap_state_notification_c();

	/**
	 * The constructor of the eap_state_notification_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H eap_state_notification_c(
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

	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H eap_state_notification_c(
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

	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H eap_state_notification_c(
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
	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H const eap_am_network_id_c * get_send_network_id() const;

	// This is commented in abs_eap_state_notification_c::get_protocol_layer().
	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H eap_protocol_layer_e get_protocol_layer() const;

	// This is commented in abs_eap_state_notification_c::get_protocol().
	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H u32_t get_protocol() const;

	// This is commented in abs_eap_state_notification_c::get_eap_type().
	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H eap_type_value_e get_eap_type() const;

	// This is commented in abs_eap_state_notification_c::get_previous_state().
	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H u32_t get_previous_state() const;

	// This is commented in abs_eap_state_notification_c::get_previous_state_string().
	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H eap_const_string get_previous_state_string() const;

	// This is commented in abs_eap_state_notification_c::get_current_state().
	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H u32_t get_current_state() const;

	// This is commented in abs_eap_state_notification_c::get_current_state_string().
	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H eap_const_string get_current_state_string() const;

	// This is commented in abs_eap_state_notification_c::get_is_client().
	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H bool get_is_client() const;

	// This is commented in abs_eap_state_notification_c::get_eap_identifier().
	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H u8_t get_eap_identifier() const;

	// This is commented in abs_eap_state_notification_c::get_allow_send_eap_success().
	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H bool get_allow_send_eap_success() const;

	// This is commented in abs_eap_state_notification_c::set_notification_string().
	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H eap_status_e set_notification_string(
		const eap_variable_data_c * const notification_string,
		const bool needs_confirmation_from_user);

	// This is commented in abs_eap_state_notification_c::get_notification_string().
	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H const eap_variable_data_c * get_notification_string() const;

	// This is commented in abs_eap_state_notification_c::get_needs_confirmation_from_user().
	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H bool get_needs_confirmation_from_user() const;


	// This is commented in abs_eap_state_notification_c::set_authentication_error().
	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H void set_authentication_error(const eap_status_e error);

	// This is commented in abs_eap_state_notification_c::get_authentication_error().
	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H eap_status_e get_authentication_error() const;


	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H static eap_const_string get_state_string(const u32_t protocol_layer, const u32_t state);
	

	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H static eap_const_string get_protocol_layer_string(const u32_t protocol_layer);

	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H eap_const_string get_protocol_layer_string() const;


	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H static eap_const_string get_protocol_string(const u32_t protocol_layer, const u32_t state);

	EAP_FUNC_VISIBILITY_EAP_STATE_NOTIFICATION_H eap_const_string get_protocol_string() const;

	//--------------------------------------------------
}; // class eap_state_notification_c

#endif //#if !defined(_EAP_STATE_NOTIFICATION_H_)

//--------------------------------------------------



// End.
