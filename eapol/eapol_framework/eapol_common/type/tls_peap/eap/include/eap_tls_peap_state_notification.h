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

#if !defined(_EAP_TLS_PEAP_STATE_NOTIFICATION_H_)
#define _EAP_TLS_PEAP_STATE_NOTIFICATION_H_

#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TLS_PEAP_STATE_NOTIFICATION_H)
	#define EAP_CLASS_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H 
	#define EAP_FUNC_EXPORT_EAP_TLS_PEAP_STATE_NOTIFICATION_H 
	#define EAP_C_FUNC_EXPORT_EAP_TLS_PEAP_STATE_NOTIFICATION_H 
#elif defined(EAP_EXPORT_EAP_TLS_PEAP_STATE_NOTIFICATION_H)
	#define EAP_CLASS_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TLS_PEAP_STATE_NOTIFICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TLS_PEAP_STATE_NOTIFICATION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TLS_PEAP_STATE_NOTIFICATION_H 
	#define EAP_C_FUNC_EXPORT_EAP_TLS_PEAP_STATE_NOTIFICATION_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_protocol_layer.h"
#include "abs_eap_state_notification.h"


/// A eap_tls_peap_state_notification_c class.
/// This is used for debugging and protocol testing.
class EAP_CLASS_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H eap_tls_peap_state_notification_c
: public abs_eap_state_notification_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools; ///< This is pointer to the tools class. @see abs_eap_am_tools_c.

	eap_protocol_layer_e m_layer; ///< Here is the protocol layer (EAP type).

	eap_variable_data_c m_notification_string; ///< Here is the notification string.

	eap_boolean_e m_needs_confirmation_from_user; ///< This flag tells whether user interaction is required.

	u32_t m_protocol; ///< Here is the EAP type.
	
	u32_t m_previous_state; ///< Here is the previous state of the EAP type.
	
	u32_t m_current_state; ///< Here is the current state of the EAP type.
	
	const eap_am_network_id_c *m_send_network_id;
	
	eap_boolean_e m_is_client;
	
	u8_t m_eap_identifier;
	
	eap_boolean_e m_allow_send_eap_success;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the eap_tls_peap_state_notification_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H virtual ~eap_tls_peap_state_notification_c();

	/**
	 * The constructor of the eap_tls_peap_state_notification_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H eap_tls_peap_state_notification_c(
		abs_eap_am_tools_c * const tools,
		const eap_am_network_id_c * const send_network_id,
		eap_boolean_e is_client,
		eap_protocol_layer_e layer,
		u32_t protocol,
		u32_t previous_state,
		u32_t current_state,
		u8_t eap_identifier,
		eap_boolean_e allow_send_eap_success);

	// This is commented in abs_eap_state_notification_c::set_notification_string().
	EAP_FUNC_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H const eap_am_network_id_c * const get_send_network_id() const;

	// This is commented in abs_eap_state_notification_c::set_notification_string().
	EAP_FUNC_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H const eap_protocol_layer_e get_protocol_layer() const;

	// This is commented in abs_eap_state_notification_c::set_notification_string().
	EAP_FUNC_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H const u32_t get_protocol() const;

	// This is commented in abs_eap_state_notification_c::set_notification_string().
	EAP_FUNC_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H const u32_t get_previous_state() const;

	// This is commented in abs_eap_state_notification_c::set_notification_string().
	EAP_FUNC_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H const u32_t get_current_state() const;

	// This is commented in abs_eap_state_notification_c::set_notification_string().
	EAP_FUNC_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H eap_const_string get_current_state_string() const;

	// This is commented in abs_eap_state_notification_c::set_notification_string().
	EAP_FUNC_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H eap_const_string get_previous_state_string() const;

	// This is commented in abs_eap_state_notification_c::set_notification_string().
	EAP_FUNC_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H const eap_boolean_e get_is_client() const;

	// This is commented in abs_eap_state_notification_c::set_notification_string().
	EAP_FUNC_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H const u8_t get_eap_identifier() const;

	// This is commented in abs_eap_state_notification_c::set_notification_string().
	EAP_FUNC_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H eap_boolean_e get_allow_send_eap_success() const;

	// This is commented in abs_eap_state_notification_c::set_notification_string().
	EAP_FUNC_VISIBILITY_EAP_TLS_PEAP_STATE_NOTIFICATION_H const eap_status_e set_notification_string(
		const eap_variable_data_c * const notification_string,
		const eap_boolean_e needs_confirmation_from_user);

	//--------------------------------------------------
}; // class eap_tls_peap_state_notification_c

#endif //#if !defined(_EAP_TLS_PEAP_STATE_NOTIFICATION_H_)

//--------------------------------------------------



// End.
