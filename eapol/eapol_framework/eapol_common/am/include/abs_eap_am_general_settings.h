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

#if !defined(_ABS_EAP_AM_GENERAL_SETTINGS_H_)
#define _ABS_EAP_AM_GENERAL_SETTINGS_H_

#include "eap_tools.h"
#include "eap_status.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_AM_GENERAL_SETTINGS_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_GENERAL_SETTINGS_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_GENERAL_SETTINGS_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_GENERAL_SETTINGS_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_GENERAL_SETTINGS_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_GENERAL_SETTINGS_H 
#elif defined(EAP_EXPORT_ABS_EAP_AM_GENERAL_SETTINGS_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_GENERAL_SETTINGS_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_GENERAL_SETTINGS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_GENERAL_SETTINGS_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_GENERAL_SETTINGS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_GENERAL_SETTINGS_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_GENERAL_SETTINGS_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_GENERAL_SETTINGS_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_GENERAL_SETTINGS_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_GENERAL_SETTINGS_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_GENERAL_SETTINGS_H 
#endif
// End: added by script change_export_macros.sh.

/** @file */

/// This class is the common part of EAP message interface.
/// This class is interface to the message creation and parsing function.
class EAP_CLASS_VISIBILITY_ABS_EAP_AM_GENERAL_SETTINGS_H abs_eap_am_general_settings_c
{

private:

	// ----------------------------------------------------------------------

public:

	virtual ~abs_eap_am_general_settings_c()
	{
	}

	virtual eap_status_e complete_get_eap_methods(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e complete_set_eap_methods(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e complete_get_certificate_lists(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e complete_delete_all_eap_settings(const eap_method_settings_c * const internal_settings) = 0;

	virtual eap_status_e complete_copy_all_eap_settings(const eap_method_settings_c * const internal_settings) = 0;

	// ----------------------------------------------------------------------
};

#endif //#if !defined(_ABS_EAP_AM_GENERAL_SETTINGS_H_)


//--------------------------------------------------
// End
