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

#if !defined(_ABS_EAP_STATE_NOTIFICATION_H_)
#define _ABS_EAP_STATE_NOTIFICATION_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_STATE_NOTIFICATION_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_STATE_NOTIFICATION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_STATE_NOTIFICATION_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_STATE_NOTIFICATION_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_STATE_NOTIFICATION_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_STATE_NOTIFICATION_H 
#elif defined(EAP_EXPORT_ABS_EAP_STATE_NOTIFICATION_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_STATE_NOTIFICATION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_STATE_NOTIFICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_STATE_NOTIFICATION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_STATE_NOTIFICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_STATE_NOTIFICATION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_STATE_NOTIFICATION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_STATE_NOTIFICATION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_STATE_NOTIFICATION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_STATE_NOTIFICATION_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_STATE_NOTIFICATION_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_protocol_layer.h"
#include "eap_header.h"

class eap_am_network_id_c;

enum eap_state_notification_eap_e
{
	eap_state_notification_eap,
};

enum eap_state_notification_generic_e
{
	eap_state_notification_generic,
};


/// This class is the interface to state notification class.
/// This is mostly used for state indications, debugging and protocol testing.
/// The lower level could get information of the authentication states.
class EAP_CLASS_VISIBILITY_ABS_EAP_STATE_NOTIFICATION_H abs_eap_state_notification_c
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
	 * The destructor of the abs_eap_state_notification_c class does nothing special.
	 */
	virtual ~abs_eap_state_notification_c()
	{
	}

	/**
	 * The constructor of the abs_eap_state_notification_c class does nothing special.
	 */
	abs_eap_state_notification_c()
	{
	}

	/**
	 * This returns send network id.
	 */
	virtual const eap_am_network_id_c * get_send_network_id() const = 0;

	/**
	 * This returns the protocol layer that send this notification.
	 */
	virtual eap_protocol_layer_e get_protocol_layer() const = 0;

	/**
	 * This returns the protocol on the layer that send this notification.
	 * This is plain 32-bit value because of easy abstraction.
	 * Later we could do more detailed information.
	 * Each protocol layer and EAP type should define own internal states.
	 */
	virtual u32_t get_protocol() const = 0;

	/**
	 * This returns the protocol on the layer that send this notification.
	 * This is eap_type_value_e value.
	 * Before using this check the get_protocol_layer() returns eap_protocol_layer_eap,
	 * eap_protocol_layer_eap_type, eap_protocol_layer_general or eap_protocol_layer_internal_type.
	 */
	virtual eap_type_value_e get_eap_type() const = 0;

	/**
	 * This returns the previous state.
	 * This is plain 32-bit value because of easy abstraction.
	 * Later we could do more detailed information.
	 * Each protocol layer and EAP type should define own internal states.
	 */
	virtual u32_t get_previous_state() const = 0;

	/**
	 * This returns the previous state string.
	 */
	virtual eap_const_string get_previous_state_string() const = 0;

	/**
	 * This returns the current state.
	 * This is plain 32-bit value because of easy abstraction.
	 * Later we could do more detailed information.
	 * Each protocol layer and EAP type should define own internal states.
	 */
	virtual u32_t get_current_state() const = 0;

	/**
	 * This returns the current state string.
	 */
	virtual eap_const_string get_current_state_string() const = 0;

	/**
	 * This returns true when notifier is client, false when server.
	 */
	virtual bool get_is_client() const = 0;

	/**
	 * This returns EAP-Identifier.
	 */
	virtual u8_t get_eap_identifier() const = 0;

	/**
	 * This function sets flag that allows EAP-Core to send EAP-Response/Success.
	 */
	virtual bool get_allow_send_eap_success() const = 0;

	/**
	 * This function sets notification text that is displayed to user.
	 * Text must be localized string. Type of the string is known to adaptation modules.
	 * Type depends on the running environment.
	 * Value true of the parameter needs_confirmation_from_user tells whether
	 * there should be user action to confirm the text.
	 * When notification is information where user action is not needed
	 * the needs_confirmation_from_user parameter should be false.
	 * Mostly it is better to set this false to disrupt the user less.
	 */
	virtual eap_status_e set_notification_string(
		const eap_variable_data_c * const notification_string,
		const bool needs_confirmation_from_user) = 0;

	/**
	 * This function gets the notification text that is displayed to user.
	 */
	virtual const eap_variable_data_c * get_notification_string() const = 0;

	/**
	 * This function gets flag that tells whether
	 * there should be user action to confirm the text.
	 */
	virtual bool get_needs_confirmation_from_user() const = 0;

	/**
	 * The authentication error must be set when get_protocol_layer() returns eap_protocol_layer_general
	 * and get_current_state() returns eap_general_state_authentication_error.
	 */
	virtual void set_authentication_error(const eap_status_e error) = 0;

	/**
	 * This function returns the authentication error when get_protocol_layer() returns eap_protocol_layer_general
	 * and get_current_state() returns eap_general_state_authentication_error.
	 */
	virtual eap_status_e get_authentication_error() const = 0;

	/**
	 * This returns the protocol layer string string.
	 */
	virtual eap_const_string get_protocol_layer_string() const = 0;

	/**
	 * This returns the protocol string string.
	 */
	virtual eap_const_string get_protocol_string() const = 0;

	//--------------------------------------------------
}; // class abs_eap_state_notification_c

#endif //#if !defined(_ABS_EAP_STATE_NOTIFICATION_H_)

//--------------------------------------------------



// End.
