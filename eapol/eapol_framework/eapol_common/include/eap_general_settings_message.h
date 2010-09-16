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
* Description:  Class is interface from user of EAP-general settings to eap_general_settings_client_message_if_c.
*
*/

/*
* %version: 8 %
*/

#if !defined(_EAP_GENERAL_SETTINGS_MESSAGE_BASE_H_)
#define _EAP_GENERAL_SETTINGS_MESSAGE_BASE_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_GENERAL_SETTINGS_MESSAGE_H)
	#define EAP_CLASS_VISIBILITY_EAP_GENERAL_SETTINGS_MESSAGE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_MESSAGE_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_MESSAGE_H 
	#define EAP_FUNC_EXPORT_EAP_GENERAL_SETTINGS_MESSAGE_H 
	#define EAP_C_FUNC_EXPORT_EAP_GENERAL_SETTINGS_MESSAGE_H 
#elif defined(EAP_EXPORT_EAP_GENERAL_SETTINGS_MESSAGE_H)
	#define EAP_CLASS_VISIBILITY_EAP_GENERAL_SETTINGS_MESSAGE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_MESSAGE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_MESSAGE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_GENERAL_SETTINGS_MESSAGE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_GENERAL_SETTINGS_MESSAGE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_GENERAL_SETTINGS_MESSAGE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_MESSAGE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_MESSAGE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_GENERAL_SETTINGS_MESSAGE_H 
	#define EAP_C_FUNC_EXPORT_EAP_GENERAL_SETTINGS_MESSAGE_H 
#endif
// End: added by script change_export_macros.sh.

class abs_eap_general_settings_message_c;
class eap_method_settings_c;

/// Class is interface from user of EAP-general settings to eap_general_settings_client_message_if_c.
class EAP_CLASS_VISIBILITY_EAP_GENERAL_SETTINGS_MESSAGE_H eap_general_settings_message_c
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
	EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_MESSAGE_H virtual ~eap_general_settings_message_c();

	/**
	 * The constructor initializes member attributes.
	 */
	EAP_FUNC_VISIBILITY_EAP_GENERAL_SETTINGS_MESSAGE_H eap_general_settings_message_c();

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

	virtual eap_status_e get_eap_methods(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e set_eap_methods(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e get_certificate_lists(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e delete_all_eap_settings(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e copy_all_eap_settings(const eap_method_settings_c * const internal_settings) = 0;

	//--------------------------------------------------
}; // class eap_general_settings_message_c

/// Function creates new eap_general_settings_message_c object.
eap_general_settings_message_c * new_eap_general_settings_client_message_if_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_general_settings_message_c * const partner);

//--------------------------------------------------

#endif //#if !defined(_EAP_GENERAL_SETTINGS_MESSAGE_BASE_H_)

//--------------------------------------------------



// End.
