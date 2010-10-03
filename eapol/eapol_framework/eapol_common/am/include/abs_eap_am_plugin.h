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
* %version: 5 %
*/

#if !defined(_ABS_EAP_AM_PLUGIN_H_)
#define _ABS_EAP_AM_PLUGIN_H_

#include "eap_tools.h"
#include "eap_status.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_AM_PLUGIN_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_PLUGIN_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_PLUGIN_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_PLUGIN_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_PLUGIN_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_PLUGIN_H 
#elif defined(EAP_EXPORT_ABS_EAP_AM_PLUGIN_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_PLUGIN_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_PLUGIN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_PLUGIN_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_PLUGIN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_PLUGIN_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_PLUGIN_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_PLUGIN_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_PLUGIN_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_PLUGIN_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_PLUGIN_H 
#endif
// End: added by script change_export_macros.sh.

class eap_method_settings_c;

/** @file */

/// This class is the common part of EAP message interface.
/// This class is interface to the message creation and parsing function.
class EAP_CLASS_VISIBILITY_ABS_EAP_AM_PLUGIN_H abs_eap_am_plugin_c
{

private:

	// ----------------------------------------------------------------------

public:

	virtual ~abs_eap_am_plugin_c()
	{
	}

	virtual eap_status_e complete_get_configuration(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e complete_set_configuration(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e complete_delete_configuration(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e complete_copy_configuration(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e complete_set_index(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e complete_get_type_info(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e complete_invoke_ui(const eap_method_settings_c * const internal_settings) = 0;

	// ----------------------------------------------------------------------
};

#endif //#if !defined(_ABS_EAP_AM_PLUGIN_H_)


//--------------------------------------------------
// End
