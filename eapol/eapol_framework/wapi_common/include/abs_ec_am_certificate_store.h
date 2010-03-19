/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/abs_ec_am_certificate_store.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 11 % << Don't touch! Updated by Synergy at check-out.
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



#if !defined(_ABS_EC_AM_CERTIFICATE_STORE_H_)
#define _ABS_EC_AM_CERTIFICATE_STORE_H_

#if defined(USE_EC_CERTIFICATE_STORE)

#include "eap_am_export.h"
#include "eap_array.h"
#include "wapi_types.h"
#include "ec_cs_types.h"
#include "ec_cs_data.h"

/// This class declares the functions adaptation module of elliptic curve sertificate store
/// requires from the elliptic curve sertificate store.
class EAP_EXPORT abs_ec_am_certificate_store_c
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
	virtual ~abs_ec_am_certificate_store_c()
	{
	}

	/// Constructor does nothing.
	abs_ec_am_certificate_store_c()
	{
	}

	/**
	 * This function call completes initialize_certificate_store() function call.
	 * After all imported certificate files are handled, AM must call this function.
	 * WAPI authentication will continue within this function call.
	 */
	virtual eap_status_e complete_initialize_certificate_store(
		const wapi_completion_operation_e completion_operation) = 0;

	/**
	 * This function call removes cached certificate store data.
	 */
	virtual eap_status_e remove_cached_certificate_store_data() = 0;

	/**
	 * This function call adds certificate to certificate store.
	 * this function call is completed with complete_add_imported_certificate_file() function.
	 */
	virtual eap_status_e add_imported_certificate_file(
		const eap_variable_data_c * const in_imported_certificate_file_data,
		const eap_variable_data_c * const in_imported_certificate_filename) = 0;

	/**
	 * This function call completes read_certificate_store_data() function call.
	 */
	virtual eap_status_e complete_read_certificate_store_data(
		const eap_status_e in_completion_status,
		const ec_cs_pending_operation_e in_pending_operation,
		EAP_TEMPLATE_CONST eap_array_c<ec_cs_data_c> * const in_references_and_data_blocks) = 0;
	
	/**
	 * This function call completes write_certificate_store_data() function call.
	 */
	virtual eap_status_e complete_write_certificate_store_data(
		const eap_status_e in_completion_status,
		const ec_cs_pending_operation_e in_pending_operation) = 0;

	/**
	 * This function call queries list of certificates.
	 */
	virtual eap_status_e query_certificate_list() = 0;

	/**
	 * This function call starts import of certificate files.
	 */
	virtual eap_status_e start_certificate_import() = 0;

	//--------------------------------------------------
}; // class abs_ec_am_certificate_store_c

#endif //#if defined(USE_EC_CERTIFICATE_STORE)

#endif //#if !defined(_ABS_EC_AM_CERTIFICATE_STORE_H_)

//--------------------------------------------------



// End.
