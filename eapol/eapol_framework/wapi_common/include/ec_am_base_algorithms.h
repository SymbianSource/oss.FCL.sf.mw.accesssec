/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/ec_base_algorithms.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 8 % << Don't touch! Updated by Synergy at check-out.
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



#if !defined(_EC_AM_BASE_ALGORITHMS_H_)
#define _EC_AM_BASE_ALGORITHMS_H_

#if defined(USE_WAPI_CORE)

#include "eap_am_export.h"
#include "eap_tools.h"
#include "ec_cs_types.h"

/** @file */

//----------------------------------------------------------------------------

class abs_eap_am_tools_c;
class eap_configuration_field_c;
class abs_ec_am_algorithms_c;


class EAP_EXPORT ec_am_base_algorithms_c
{
	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the ec_am_base_algorithms_c class does nothing special.
	 */
	EAP_FUNC_IMPORT virtual ~ec_am_base_algorithms_c();

	/**
	 * Function creates a new object.
	 */
	EAP_FUNC_IMPORT static ec_am_base_algorithms_c * new_ec_base_algorithms_c(
		abs_eap_am_tools_c * const tools,
		abs_ec_am_algorithms_c * const partner,
		const bool is_client_when_true);

	virtual eap_status_e configure() = 0;

	virtual bool get_is_valid() const = 0;

	virtual eap_status_e create_signature_with_private_key(
		const eap_variable_data_c * const hash_of_message,
		const eap_variable_data_c * const private_key) = 0;

	virtual eap_status_e verify_signature_with_public_key(
		const eap_variable_data_c * const public_key,
		const eap_variable_data_c * const hash_of_message,
		const eap_variable_data_c * const signature) = 0;

	virtual eap_status_e create_ecdh_temporary_keys() = 0;

	virtual eap_status_e create_ecdh(
		const eap_variable_data_c * const own_private_key_d,
		const eap_variable_data_c * const peer_public_key_x,
		const eap_variable_data_c * const peer_public_key_y) = 0;

	//--------------------------------------------------
}; // ec_am_base_algorithms_c

//----------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

#endif //#if !defined(_EC_AM_BASE_ALGORITHMS_H_)


// End.
