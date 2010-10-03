/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  Class creates and reads the messages used in EAP-general settings interface on the server side.
*
*/

/*
* %version: 10 %
*/

#if !defined(_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H_)
#define _EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H)
	#define EAP_CLASS_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H 
	#define EAP_FUNC_EXPORT_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H 
	#define EAP_C_FUNC_EXPORT_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H 
#elif defined(EAP_EXPORT_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H)
	#define EAP_CLASS_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H 
	#define EAP_C_FUNC_EXPORT_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_session_core.h"
#include "eap_variable_data.h"
#include "abs_eap_am_mutex.h"
#include "eap_session_core_base.h"
#include "abs_eap_am_message_if.h"
#include "eap_am_message_if.h"
#include "eap_process_tlv_message_data.h"
#include "abs_eap_am_general_settings.h"
#include "eap_am_general_settings.h"


/** @file */


/// Class creates and reads the messages used in EAP-general settings interface on the server side.
class EAP_CLASS_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H eap_general_settings_server_message_if_c
: public abs_eap_am_general_settings_c
, public eap_am_message_if_c
, public abs_eap_base_timer_c
{

private:
	//--------------------------------------------------

	/// This is back pointer to object which created this object.
	abs_eap_am_message_if_c * m_partner;

	eap_am_general_settings_c * const m_am_settings;

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	eap_status_e m_error_code;

	eap_tlv_message_type_function_e m_error_function;

	/// This indicates whether this object is client (true) or server (false).
	/// In terms of EAP-protocol whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	bool m_is_client;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	bool m_shutdown_was_called;

	eap_status_e send_error_message(
		const eap_status_e error_code,
		const eap_tlv_message_type_function_e function);

	eap_status_e send_message(eap_process_tlv_message_data_c * const message);

	eap_status_e process_message_type_error(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e process_message(eap_process_tlv_message_data_c * const message);

	eap_status_e set_eap_methods(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e get_eap_methods(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e get_certificate_lists(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e delete_all_eap_settings(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e copy_all_eap_settings(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor deletes the m_eap_core object.
	 */
	EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H virtual ~eap_general_settings_server_message_if_c();

	/**
	 * The constructor creates the eap_core object and initializes the m_eap_core
	 * to point the eap_core object.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 */
	EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H eap_general_settings_server_message_if_c(
		abs_eap_am_tools_c * const tools);

	EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H void set_partner(abs_eap_am_message_if_c * const partner);

	EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H eap_status_e process_data(const void * const data, const u32_t length);

	// This is documented in abs_eap_stack_interface_c::configure().
	EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H eap_status_e configure(
		const eap_variable_data_c * const client_configuration);

	// This is documented in abs_eap_stack_interface_c::shutdown().
	EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H eap_status_e shutdown();

	// This is documented in abs_eap_stack_interface_c::set_is_valid().
	EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H void set_is_valid();

	// This is documented in abs_eap_stack_interface_c::get_is_valid().
	EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H bool get_is_valid();

	// See abs_eap_base_timer_c::timer_expired().
	EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H eap_status_e timer_expired(
		const u32_t id, void *data);

	// See abs_eap_base_timer_c::timer_delete_data().
	EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H eap_status_e timer_delete_data(
		const u32_t id, void *data);


	EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H eap_status_e complete_set_eap_methods(const eap_method_settings_c * const internal_settings);

	EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H eap_status_e complete_get_eap_methods(const eap_method_settings_c * const internal_settings);

	EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H eap_status_e complete_get_certificate_lists(const eap_method_settings_c * const internal_settings);

	EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H eap_status_e complete_delete_all_eap_settings(const eap_method_settings_c * const internal_settings);

	EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H eap_status_e complete_copy_all_eap_settings(const eap_method_settings_c * const internal_settings);

	//--------------------------------------------------
}; // class eap_general_settings_server_message_if_c

#endif //#if !defined(_EAP_GENERAL_SETTINGS_SERVER_MESSAGE_IF_H_)

//--------------------------------------------------



// End.
