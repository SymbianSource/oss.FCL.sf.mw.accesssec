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

#if !defined(_EAP_SIMPLE_CONFIG_STATE_NOTIFICATION_H_)
#define _EAP_SIMPLE_CONFIG_STATE_NOTIFICATION_H_

#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H 
	#define EAP_FUNC_EXPORT_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H 
#elif defined(EAP_EXPORT_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_protocol_layer.h"
#include "eap_state_notification.h"


/// A eap_type_simple_config_state_notification_c class.
/// This is used for debugging and protocol testing.
class EAP_CLASS_VISIBILITY_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H eap_type_simple_config_state_notification_c
: public eap_state_notification_c
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
	 * The destructor of the eap_type_simple_config_state_notification_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H virtual ~eap_type_simple_config_state_notification_c();

	/**
	 * The constructor of the eap_type_simple_config_state_notification_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H eap_type_simple_config_state_notification_c(
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


	EAP_FUNC_VISIBILITY_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H eap_type_simple_config_state_notification_c(
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


	EAP_FUNC_VISIBILITY_EAP_TYPE_SIMPLE_CONFIG_STATE_NOTIFICATION_H eap_type_simple_config_state_notification_c(
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


	//--------------------------------------------------
}; // class eap_type_simple_config_state_notification_c

#endif //#if !defined(_EAP_SIMPLE_CONFIG_STATE_NOTIFICATION_H_)

//--------------------------------------------------



// End.
