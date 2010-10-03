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

#if !defined(_SIMPLE_CONFIG_AM_SERVICES_H_)
#define _SIMPLE_CONFIG_AM_SERVICES_H_

#include "eap_tools.h"
#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_SIMPLE_CONFIG_AM_SERVICES_H)
	#define EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_AM_SERVICES_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_AM_SERVICES_H 
	#define EAP_C_FUNC_VISIBILITY_SIMPLE_CONFIG_AM_SERVICES_H 
	#define EAP_FUNC_EXPORT_SIMPLE_CONFIG_AM_SERVICES_H 
	#define EAP_C_FUNC_EXPORT_SIMPLE_CONFIG_AM_SERVICES_H 
#elif defined(EAP_EXPORT_SIMPLE_CONFIG_AM_SERVICES_H)
	#define EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_AM_SERVICES_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_AM_SERVICES_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_SIMPLE_CONFIG_AM_SERVICES_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_SIMPLE_CONFIG_AM_SERVICES_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_SIMPLE_CONFIG_AM_SERVICES_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_AM_SERVICES_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_AM_SERVICES_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_SIMPLE_CONFIG_AM_SERVICES_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_SIMPLE_CONFIG_AM_SERVICES_H 
	#define EAP_C_FUNC_EXPORT_SIMPLE_CONFIG_AM_SERVICES_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_am_type_simple_config.h"
#include "eap_am_network_id.h"
#include "eap_array.h"
#include "simple_config_types.h"

class abs_simple_config_am_services_c;
class simple_config_payloads_c;
class simple_config_credential_c;


/// This class is interface to adaptation module of SIMPLE_CONFIG.
class EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_AM_SERVICES_H simple_config_am_services_c
{
private:
	//--------------------------------------------------

	/// This function returns pointer to adaptation module of SIMPLE_CONFIG. See abs_simple_config_am_services_c.
	virtual abs_simple_config_am_services_c * get_simple_config_am_partner() = 0;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/* The destructor does nothing */
	virtual ~simple_config_am_services_c()
	{
	}
	
	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	virtual bool get_is_valid() = 0;

	/// This function sets pointer to adaptation module of SIMPLE_CONFIG. See abs_simple_config_am_services_c.
	virtual void set_simple_config_am_partner(abs_simple_config_am_services_c * const tls_am_partner) = 0;

	/**
	 * The configure() function is called after the constructor of the 
	 * object is successfully executed. During the function call the object 
	 * could query the configuration. Each derived class must define this function.
	 */
	virtual eap_status_e configure() = 0;

	/**
	 * The shutdown() function is called before the destructor of the 
	 * object is executed. During the function call the object 
	 * could shutdown the operations, for example cancel timers.
	 * Each derived class must define this function.
	 */
	virtual eap_status_e shutdown() = 0;

	/**
	 * This function queries all network and device parameters.
	 * abs_simple_config_am_services_c::complete_query_network_and_device_parameters() completes this query.
	 */
	virtual eap_status_e query_network_and_device_parameters(
		const simple_config_state_e state) = 0;

	/**
	 * This function tells AM to save SIMPLE_CONFIG configuration parameters.
	 * This is always syncronous call.
	 */
	virtual eap_status_e save_simple_config_session(
		const simple_config_state_e state,
		EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
		const eap_variable_data_c * const new_password,
		const simple_config_Device_Password_ID_e Device_Password_ID,
		const simple_config_payloads_c * const other_configuration
		) = 0;

	/**
	 * This function forwards all payloads received in M2D messages.
	 * Adaptation layer could show this information to user.
	 * This is always syncronous call.
	 */
	virtual eap_status_e received_registrar_information(
		EAP_TEMPLATE_CONST eap_array_c<simple_config_payloads_c> * const M2D_payloads) = 0;

	/**
	 * This function cancels query_network_and_device_parameters() query.
	 * After this call AM must not complete related query.
	 */
	virtual eap_status_e cancel_query_network_and_device_parameters() = 0;

	//--------------------------------------------------
}; // class simple_config_am_services_c


/** @file */ 

/**
 * This function creates a new instance of adaptation module of SIMPLE_CONFIG.
 * @param tools is pointer to the abs_eap_am_tools class created by the adaptation module.
 * Adaptation module of SIMPLE_CONFIG will callback caller using the partner pointer.
 */
EAP_C_FUNC_VISIBILITY_SIMPLE_CONFIG_AM_SERVICES_H  simple_config_am_services_c *new_simple_config_am_services(
	abs_eap_am_tools_c * const tools);


#endif //#if !defined(_SIMPLE_CONFIG_AM_SERVICES_H_)

//--------------------------------------------------



// End.
