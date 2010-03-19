/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/abs_ec_am_algorithms.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 7 % << Don't touch! Updated by Synergy at check-out.
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



#if !defined(_ABS_EC_AM_ALGORITHMS_H_)
#define _ABS_EC_AM_ALGORITHMS_H_

#if defined(USE_WAPI_CORE)

#include "eap_am_export.h"
#include "eap_tools.h"
#include "ec_cs_types.h"

/** @file */

//----------------------------------------------------------------------------

class abs_eap_am_tools_c;
class eap_configuration_field_c;


class EAP_EXPORT abs_ec_am_algorithms_c
{
	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the abs_ec_am_algorithms_c class does nothing special.
	 */
	EAP_FUNC_IMPORT virtual ~abs_ec_am_algorithms_c();

	virtual eap_status_e complete_create_signature_with_private_key(
		const eap_variable_data_c * const signature,
		const eap_status_e signature_status) = 0;

	virtual eap_status_e complete_verify_signature_with_public_key(
		const eap_status_e verification_status) = 0;

	virtual eap_status_e complete_create_ecdh_temporary_keys(
		const eap_variable_data_c * const private_key_d,
		const eap_variable_data_c * const public_key_x,
		const eap_variable_data_c * const public_key_y) = 0;

	virtual eap_status_e complete_create_ecdh(
		const eap_variable_data_c * const K_AB_x4,
		const eap_variable_data_c * const K_AB_y4) = 0;

	/**
	 * The read_configure() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	virtual eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	//--------------------------------------------------
}; // abs_ec_am_algorithms_c

//----------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

#endif //#if !defined(_ABS_EC_AM_ALGORITHMS_H_)


// End.
