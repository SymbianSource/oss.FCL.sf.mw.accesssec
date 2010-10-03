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
* Description:  EAP-plugin interface message class.
*
*/

/*
* %version: 7 %
*/

#if !defined(_EAP_PLUGIN_CLIENT_MESSAGE_IF_H_)
#define _EAP_PLUGIN_CLIENT_MESSAGE_IF_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_PLUGIN_CLIENT_MESSAGE_IF_H)
	#define EAP_CLASS_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H 
	#define EAP_FUNC_EXPORT_EAP_PLUGIN_CLIENT_MESSAGE_IF_H 
	#define EAP_C_FUNC_EXPORT_EAP_PLUGIN_CLIENT_MESSAGE_IF_H 
#elif defined(EAP_EXPORT_EAP_PLUGIN_CLIENT_MESSAGE_IF_H)
	#define EAP_CLASS_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_PLUGIN_CLIENT_MESSAGE_IF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_PLUGIN_CLIENT_MESSAGE_IF_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_PLUGIN_CLIENT_MESSAGE_IF_H 
	#define EAP_C_FUNC_EXPORT_EAP_PLUGIN_CLIENT_MESSAGE_IF_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_plugin_message_base.h"
#include "abs_eap_am_message_if.h"
#include "eap_array.h"
#include "eap_process_tlv_message_data.h"

class eap_method_settings_c;
class eap_am_message_if_c;
class abs_eap_plugin_message_c;
class eap_tlv_header_c;

/// A eap_plugin_client_message_if_c class implements mapping of EAP authentication sessions.
/// Network identity separates parallel EAP authentication sessions.
class EAP_CLASS_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H eap_plugin_client_message_if_c
: public eap_plugin_message_base_c
, public abs_eap_am_message_if_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// eap_plugin_client_message_if_c deletes m_client_if in destructor.
	eap_am_message_if_c * m_client_if;

	/// This is back pointer to object which created this object.
	/// Packets are sent to the partner.
	abs_eap_plugin_message_c * const m_partner;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	eap_status_e m_error_code;

	eap_tlv_message_type_function_e m_error_function;


	eap_status_e complete_get_configuration(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e complete_set_configuration(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e complete_delete_configuration(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e complete_copy_configuration(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e complete_set_index(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e complete_get_type_info(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	eap_status_e complete_invoke_ui(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);


	eap_status_e process_message_type_error(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the eap_core class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H virtual ~eap_plugin_client_message_if_c();

	/**
	 * The constructor initializes member attributes using parameters passed to it.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 * @param partner is back pointer to object which created this object.
	 * @param is_client_when_true indicates whether the network entity should act
	 * as a client (true) or server (false), in terms of EAP-protocol
	 * whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	 */
	EAP_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H eap_plugin_client_message_if_c(
		abs_eap_am_tools_c * const tools,
		eap_am_message_if_c * const client_if,
		abs_eap_plugin_message_c * const partner);

	/**
	 * This function must reset the state of object to same as 
	 * state was after the configure() function call.
	 * If object reset succeeds this function must return eap_status_ok.
	 * If object reset fails this function must return corresponding error status.
	 * @return This function returns the status of reset operation.
	 */
	EAP_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H eap_status_e reset();

	// This is documented in abs_eap_stack_interface_c::configure().
	EAP_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H eap_status_e configure();

	// This is documented in abs_eap_stack_interface_c::shutdown().
	EAP_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H eap_status_e shutdown();

	// This is documented in abs_eap_stack_interface_c::get_is_valid().
	EAP_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H bool get_is_valid();

	EAP_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H eap_status_e process_message(eap_process_tlv_message_data_c * const message);

	EAP_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H eap_status_e get_configuration(const eap_method_settings_c * const internal_settings);

	EAP_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H eap_status_e set_configuration(const eap_method_settings_c * const internal_settings);

	EAP_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H eap_status_e copy_configuration(const eap_method_settings_c * const internal_settings);

	EAP_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H eap_status_e delete_configuration(const eap_method_settings_c * const internal_settings);

	EAP_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H eap_status_e set_index(const eap_method_settings_c * const internal_settings);

	EAP_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H eap_status_e get_type_info(const eap_method_settings_c * const internal_settings);

	EAP_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H eap_status_e invoke_ui(const eap_method_settings_c * const internal_settings);

	EAP_FUNC_VISIBILITY_EAP_PLUGIN_CLIENT_MESSAGE_IF_H eap_status_e send_data(const void * const data, const u32_t length);

	//--------------------------------------------------
}; // class eap_plugin_client_message_if_c

//--------------------------------------------------

#endif //#if !defined(_EAP_PLUGIN_CLIENT_MESSAGE_IF_H_)

//--------------------------------------------------



// End.
