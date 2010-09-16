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
* Description:  virtual functions of EAP-plugin interface.
*
*/

/*
* %version: 7 %
*/

#if !defined(_EAP_PLUGIN_MESSAGE_BASE_H_)
#define _EAP_PLUGIN_MESSAGE_BASE_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_PLUGIN_MESSAGE_BASE_H)
	#define EAP_CLASS_VISIBILITY_EAP_PLUGIN_MESSAGE_BASE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_PLUGIN_MESSAGE_BASE_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_PLUGIN_MESSAGE_BASE_H 
	#define EAP_FUNC_EXPORT_EAP_PLUGIN_MESSAGE_BASE_H 
	#define EAP_C_FUNC_EXPORT_EAP_PLUGIN_MESSAGE_BASE_H 
#elif defined(EAP_EXPORT_EAP_PLUGIN_MESSAGE_BASE_H)
	#define EAP_CLASS_VISIBILITY_EAP_PLUGIN_MESSAGE_BASE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_PLUGIN_MESSAGE_BASE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_PLUGIN_MESSAGE_BASE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_PLUGIN_MESSAGE_BASE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_PLUGIN_MESSAGE_BASE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_PLUGIN_MESSAGE_BASE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_PLUGIN_MESSAGE_BASE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_PLUGIN_MESSAGE_BASE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_PLUGIN_MESSAGE_BASE_H 
	#define EAP_C_FUNC_EXPORT_EAP_PLUGIN_MESSAGE_BASE_H 
#endif
// End: added by script change_export_macros.sh.

class eap_method_settings_c;
class abs_eap_plugin_message_c;

class EAP_CLASS_VISIBILITY_EAP_PLUGIN_MESSAGE_BASE_H eap_plugin_message_base_c
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
	 * The destructor of the eap_core class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_PLUGIN_MESSAGE_BASE_H virtual ~eap_plugin_message_base_c();

	/**
	 * The constructor initializes member attributes using parameters passed to it.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 * @param partner is back pointer to object which created this object.
	 * @param is_client_when_true indicates whether the network entity should act
	 * as a client (true) or server (false), in terms of EAP-protocol
	 * whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	 */
	EAP_FUNC_VISIBILITY_EAP_PLUGIN_MESSAGE_BASE_H eap_plugin_message_base_c();

	/**
	 * This function must reset the state of object to same as 
	 * state was after the configure() function call.
	 * If object reset succeeds this function must return eap_status_ok.
	 * If object reset fails this function must return corresponding error status.
	 * @return This function returns the status of reset operation.
	 */
	virtual eap_status_e reset() = 0;

	// This is documented in abs_eap_stack_interface_c::configure().
	virtual eap_status_e configure() = 0;

	// This is documented in abs_eap_stack_interface_c::shutdown().
	virtual eap_status_e shutdown() = 0;

	// This is documented in abs_eap_stack_interface_c::get_is_valid().
	virtual bool get_is_valid() = 0;

	virtual eap_status_e get_configuration(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e set_configuration(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e copy_configuration(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e delete_configuration(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e set_index(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e get_type_info(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e invoke_ui(const eap_method_settings_c * const internal_settings) = 0;

	//--------------------------------------------------

	static eap_plugin_message_base_c * new_eap_plugin_client_message_if_c(
		abs_eap_am_tools_c * const tools,
		abs_eap_plugin_message_c * const partner);

	//--------------------------------------------------
}; // class eap_plugin_message_base_c

//--------------------------------------------------

#endif //#if !defined(_EAP_PLUGIN_MESSAGE_BASE_H_)

//--------------------------------------------------



// End.
