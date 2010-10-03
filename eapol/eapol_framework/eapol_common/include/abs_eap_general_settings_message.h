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
* Description:  This class defines the callback interface from eap_general_settings_client_message_if_c to the user of EAP-general settings.
*
*/

/*
* %version: 8 %
*/

#if !defined(_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H_)
#define _ABS_EAP_GENERAL_SETTINGS_MESSAGE_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H 
#elif defined(EAP_EXPORT_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H 
#endif
// End: added by script change_export_macros.sh.

class eap_method_settings_c;

/// This class defines the callback interface from eap_general_settings_client_message_if_c to the user of EAP-general settings.
class EAP_CLASS_VISIBILITY_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H abs_eap_general_settings_message_c
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
	 * The destructor of the abs_eap_core class does nothing special.
	 */
	virtual ~abs_eap_general_settings_message_c()
	{
	}

	/**
	 * The constructor of the abs_eap_core class does nothing special.
	 */
	abs_eap_general_settings_message_c()
	{
	}

	virtual eap_status_e complete_get_eap_methods(
		const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e complete_set_eap_methods(
		const eap_status_e completion_status) = 0;

	virtual eap_status_e complete_get_certificate_lists(
		const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e complete_delete_all_eap_settings(
		const eap_status_e completion_status) = 0;

	virtual eap_status_e complete_copy_all_eap_settings(
		const eap_status_e completion_status) = 0;

	//--------------------------------------------------
}; // class abs_eap_general_settings_message_c

#endif //#if !defined(_ABS_EAP_GENERAL_SETTINGS_MESSAGE_H_)

//--------------------------------------------------



// End.
