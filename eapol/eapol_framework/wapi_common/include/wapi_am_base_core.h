/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/wapi_am_base_core.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 12 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.2
*/



#if !defined(_WAPI_AM_BASE_CORE_H_)
#define _WAPI_AM_BASE_CORE_H_

#if defined(USE_WAPI_CORE)

#include "eap_tools.h"
#include "eap_variable_data.h"
#include "eap_am_export.h"
#include "eap_am_network_id.h"
#include "ec_am_base_certificate_store.h"

class abs_wapi_am_core_c;

/// This class is interface to adaptation module of WAPI core.
class EAP_EXPORT wapi_am_base_core_c
: public ec_am_base_certificate_store_c
{	
private:
	//--------------------------------------------------

	/** Function returns partner object of adaptation module of WAPI.
	 *  Partner object is the WAPI core object.
	 */
	//virtual abs_wapi_am_core_c * get_am_partner() = 0;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	virtual ~wapi_am_base_core_c()
	{
	}

	/**
	 * This function creates a new instance of adaptation module of WAPI core.
	 * @param tools is pointer to the abs_eap_am_tools class created by the adaptation module.
	 * WAPI core AM will callback caller using the partner pointer.
	 */
	EAP_FUNC_IMPORT static wapi_am_base_core_c *new_wapi_am_core(
		abs_eap_am_tools_c * const tools,
		abs_wapi_am_core_c * const partner,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id);

	/** Function sets partner object of adaptation module of WAPI.
	 *  Partner object is the WAPI core object.
	 */
	//virtual void set_am_partner(abs_wapi_am_core_c * const partner) = 0;

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
	 *  WAPI AM could do finishing operations to databases etc. based on authentication status and type.
	 */
	virtual eap_status_e reset() = 0;

	/** Client calls this function.
	 *  WAPI AM could make some fast operations here, heavy operations should be done in the reset() function.
	 */
	virtual eap_status_e authentication_finished(
		const bool true_when_successfull) = 0;

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

	//--------------------------------------------------
}; // class wapi_am_base_core_c


/** @file */ 


#endif //#if defined(USE_WAPI_CORE)

#endif //#if !defined(_WAPI_AM_BASE_CORE_H_)

//--------------------------------------------------



// End.
