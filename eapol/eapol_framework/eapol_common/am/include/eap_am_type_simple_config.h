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

#if !defined(_EAP_AM_TYPE_SIMPLE_CONFIG_H_)
#define _EAP_AM_TYPE_SIMPLE_CONFIG_H_

#include "eap_tools.h"
#include "eap_variable_data.h"
#include "eap_header.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_TYPE_SIMPLE_CONFIG_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_SIMPLE_CONFIG_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_SIMPLE_CONFIG_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_SIMPLE_CONFIG_H 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_SIMPLE_CONFIG_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_SIMPLE_CONFIG_H 
#elif defined(EAP_EXPORT_EAP_AM_TYPE_SIMPLE_CONFIG_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_SIMPLE_CONFIG_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_SIMPLE_CONFIG_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_SIMPLE_CONFIG_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_SIMPLE_CONFIG_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_SIMPLE_CONFIG_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_SIMPLE_CONFIG_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_SIMPLE_CONFIG_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_SIMPLE_CONFIG_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_SIMPLE_CONFIG_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_SIMPLE_CONFIG_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_am_type_simple_config.h"
#include "eap_am_network_id.h"
#include "simple_config_am_services.h"

class abs_eap_base_type_c;
class eap_base_type_c;
class abs_eap_am_type_simple_config_c;
class abs_eap_configuration_if_c;

/// This class is interface to adaptation module of EAP/SIMPLE_CONFIG.
class EAP_CLASS_VISIBILITY_EAP_AM_TYPE_SIMPLE_CONFIG_H eap_am_type_simple_config_c
: public simple_config_am_services_c
{	
private:
	//--------------------------------------------------

	/** Function returns partner object of adaptation module of EAP-SIMPLE_CONFIG.
	 *  Partner object is the EAP-SIMPLE_CONFIG object.
	 */
	virtual abs_eap_am_type_simple_config_c * get_am_partner() = 0;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	virtual ~eap_am_type_simple_config_c()
	{
	}

	/** Function sets partner object of adaptation module of EAP-SIMPLE_CONFIG.
	 *  Partner object is the EAP-SIMPLE_CONFIG object.
	 */
	virtual void set_am_partner(abs_eap_am_type_simple_config_c * const partner) = 0;

	virtual eap_status_e configure() = 0;

	/**
	 * The shutdown() function is called before the destructor of the 
	 * object is executed. During the function call the object 
	 * could shutdown the operations, for example cancel timers.
	 * Each derived class must define this function.
	 */
	virtual eap_status_e shutdown() = 0;

	virtual bool get_is_valid() = 0;

	/** Client calls this function.
	 *  EAP-SIMPLE_CONFIG AM could do finishing operations to databases etc. based on authentication status and type.
	 */
	virtual eap_status_e reset() = 0;

	/** Client calls this function.
	 *  EAP-SIMPLE_CONFIG AM could make some fast operations here, heavy operations should be done in the reset() function.
	 */
	virtual eap_status_e authentication_finished(
		const bool true_when_successfull,
		const bool true_when_session_resumed) = 0;

	/** Client calls this function.
	 *  AM must copy identity to output parameters if call is syncronous.
	 *  This function could be completed asyncronously with abs_eap_am_type_simple_config_c::complete_query_eap_identity_query() function call.
	 */
	virtual eap_status_e query_eap_identity(
		const eap_am_network_id_c * const receive_network_id,
		const u8_t eap_identifier,
		bool * const use_manual_username,
		eap_variable_data_c * const manual_username,
		bool *const use_manual_realm,
		eap_variable_data_c * const manual_realm
		) = 0;

	/** Client calls this function.
	 *  This call cancels asyncronous query_SIM_IMSI_or_pseudonym_or_reauthentication_id() function call.
	 *  AM must not complete query_SIM_IMSI_or_pseudonym_or_reauthentication_id()
	 *  with abs_eap_am_type_gsmsim_c::complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query() after
	 *  cancel_SIM_IMSI_or_pseudonym_or_reauthentication_id_query() call.
	 */
	virtual eap_status_e cancel_identity_query() = 0;

	/**
	 * The type_configure_read() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	virtual eap_status_e type_configure_read(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	/**
	 * The type_configure_write() function writes the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the action to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	virtual eap_status_e type_configure_write(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	/**
	 * This is needed by PEAP type.
	 * The load_module() function function indicates the lower level to
	 * load new module of EAP-type.
	 * @param type is the requested EAP-type.
	 * @param partner is pointer to the caller object.
	 * The partner of the new created EAP-type object is the caller object.
	 * @param eap_type is a pointer to a pointer of EAP-type object.
	 * Adaptation module sets eap_type pointer to created EAP-type object.
	 * @param is_client_when_true parameter indicates whether the network entity should
	 * act as a client (true) or server (false), in terms of EAP-protocol whether
	 * this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	 */
	virtual eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e /* tunneling_type */,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id) = 0;

	/**
	 * This is needed by PEAP type.
	 * This function queries the validity of EAP-type.
	 * Lower layer should return eap_status_ok if this EAP-type is supported.
	 */
	virtual eap_status_e check_is_valid_eap_type(const eap_type_value_e eap_type) = 0;

	/**
	 * This function queries the list of supported EAP-types.
	 * Lower layer should return eap_status_ok if this call succeeds.
	 * @param eap_type_list will include the list of supported EAP-types. Each value in list
	 * is type of u32_t and represent one supported EAP-type. List consists of subsequent u32_t type values.
	 */
	virtual eap_status_e get_eap_type_list(
		eap_array_c<eap_type_value_e> * const eap_type_list) = 0;

	/**
	 * This is needed by PEAP type.
	 * The unload_module() function unloads the module of a EAP-type. 
	 * @param type is the requested EAP-type.
	 */
	virtual eap_status_e unload_module(const eap_type_value_e type) = 0;


	//--------------------------------------------------
}; // class eap_am_type_simple_config_c


/** @file */ 

/**
 * This function creates a new instance of adaptation module of EAP-SIMPLE_CONFIG-type.
 * @param tools is pointer to the abs_eap_am_tools class created by the adaptation module.
 * EAP-SIMPLE_CONFIG-type will callback caller using the partner pointer.
 */
EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_SIMPLE_CONFIG_H  eap_am_type_simple_config_c *new_eap_am_type_simple_config(
	abs_eap_am_tools_c * const tools,
	abs_eap_base_type_c * const partner,
	const eap_type_value_e eap_type,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id,
	abs_eap_configuration_if_c * const configuration_if);


#endif //#if !defined(_EAP_AM_TYPE_SIMPLE_CONFIG_H_)

//--------------------------------------------------



// End.
