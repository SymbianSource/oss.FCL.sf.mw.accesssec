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

#if !defined(_ABS_SIMPLE_CONFIG_AM_SERVICES_H_)
#define _ABS_SIMPLE_CONFIG_AM_SERVICES_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_SIMPLE_CONFIG_AM_SERVICES_H)
	#define EAP_CLASS_VISIBILITY_ABS_SIMPLE_CONFIG_AM_SERVICES_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_SIMPLE_CONFIG_AM_SERVICES_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_SIMPLE_CONFIG_AM_SERVICES_H 
	#define EAP_FUNC_EXPORT_ABS_SIMPLE_CONFIG_AM_SERVICES_H 
	#define EAP_C_FUNC_EXPORT_ABS_SIMPLE_CONFIG_AM_SERVICES_H 
#elif defined(EAP_EXPORT_ABS_SIMPLE_CONFIG_AM_SERVICES_H)
	#define EAP_CLASS_VISIBILITY_ABS_SIMPLE_CONFIG_AM_SERVICES_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_SIMPLE_CONFIG_AM_SERVICES_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_SIMPLE_CONFIG_AM_SERVICES_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_SIMPLE_CONFIG_AM_SERVICES_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_SIMPLE_CONFIG_AM_SERVICES_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_SIMPLE_CONFIG_AM_SERVICES_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_SIMPLE_CONFIG_AM_SERVICES_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_SIMPLE_CONFIG_AM_SERVICES_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_SIMPLE_CONFIG_AM_SERVICES_H 
	#define EAP_C_FUNC_EXPORT_ABS_SIMPLE_CONFIG_AM_SERVICES_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_array.h"

class simple_config_payloads_c;

/// This class declares the functions adaptation module of SIMPLE_CONFIG
/// requires from the SIMPLE_CONFIG.
class EAP_CLASS_VISIBILITY_ABS_SIMPLE_CONFIG_AM_SERVICES_H abs_simple_config_am_services_c
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/// Destructor does nothing.
	virtual ~abs_simple_config_am_services_c()
	{
	}

	/// Constructor does nothing.
	abs_simple_config_am_services_c()
	{
	}

	// This is commented in eap_base_type_c::configure().
	virtual eap_status_e configure() = 0;


	/**
	 * This function completes the asyncronous
	 * simple_config_am_services_c::query_network_and_device_parameters() function call.
	 * The parameter completion_status must be eap_status_ok when query is successfull.
	 */
	virtual eap_status_e complete_query_network_and_device_parameters(
		const simple_config_state_e state,
		simple_config_payloads_c * const network_and_device_parameters,
		const eap_status_e completion_status) = 0;


	//--------------------------------------------------
}; // class abs_simple_config_am_services_c

#endif //#if !defined(_ABS_SIMPLE_CONFIG_AM_SERVICES_H_)

//--------------------------------------------------



// End.
