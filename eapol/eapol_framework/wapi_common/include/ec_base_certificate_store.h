/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/ec_base_certificate_store.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 18 % << Don't touch! Updated by Synergy at check-out.
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



#if !defined(_EC_BASE_CERTIFICATE_STORE_H_)
#define _EC_BASE_CERTIFICATE_STORE_H_

#if defined(USE_WAPI_CORE)

#include "eap_am_export.h"
#include "eap_tools.h"
#include "ec_cs_types.h"

/** @file */

//----------------------------------------------------------------------------

class abs_eap_am_tools_c;
class abs_ec_certificate_store_c;
class ec_am_base_certificate_store_c;
class eap_am_network_id_c;


class EAP_EXPORT ec_base_certificate_store_c
{
	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the ec_base_certificate_store_c class does nothing.
	 */
	EAP_FUNC_IMPORT virtual ~ec_base_certificate_store_c();

	/**
	 * Function creates a new object.
	 */
	EAP_FUNC_IMPORT static ec_base_certificate_store_c * new_ec_base_certificate_store_c(
		abs_eap_am_tools_c * const tools,
		abs_ec_certificate_store_c * const partner,
		ec_am_base_certificate_store_c * const am_certificate_store,
		const bool is_client_when_true);

	/**
	 * Function initializes the certificate store.
	 * This function is completed by complete_initialize_certificate_store() function call.
	 */
	virtual eap_status_e initialize_certificate_store() = 0;

	virtual eap_status_e configure() = 0;

	virtual eap_status_e shutdown() = 0;

	virtual bool get_is_valid() const = 0;

	virtual eap_status_e query_asu_id() = 0;

	virtual eap_status_e get_own_certificate() = 0;

	virtual eap_status_e set_ae_certificate(
		const eap_variable_data_c * const ae_certificate) = 0;

	virtual eap_status_e select_certificate(
		const eap_variable_data_c * const issuer_ID) = 0;

	virtual eap_status_e read_id_of_certificate(
		const eap_variable_data_c * const certificate) = 0;

	virtual eap_status_e create_signature_with_private_key(
		const eap_variable_data_c * const hash_of_message,
		const eap_variable_data_c * const id_of_certificate) = 0;

	virtual eap_status_e verify_signature_with_public_key(
		const eap_variable_data_c * const peer_identity,
		const eap_variable_data_c * const hash_of_message,
		const eap_variable_data_c * const signature,
		const bool allow_use_of_ae_certificate) = 0;

	virtual eap_status_e create_ecdh_temporary_keys() = 0;

	virtual eap_status_e create_ecdh(
		const eap_variable_data_c * const own_private_key_d,
		const eap_variable_data_c * const peer_public_key_x,
		const eap_variable_data_c * const peer_public_key_y) = 0;

	virtual eap_status_e set_receive_network_id(const eap_am_network_id_c * const receive_network_id) = 0;

	//--------------------------------------------------
}; // ec_base_certificate_store_c

//----------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

#endif //#if !defined(_EC_BASE_CERTIFICATE_STORE_H_)


// End.
