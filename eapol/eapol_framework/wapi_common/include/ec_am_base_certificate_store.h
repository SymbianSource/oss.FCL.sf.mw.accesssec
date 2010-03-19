/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/ec_am_base_certificate_store.h
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



#if !defined(_EC_AM_BASE_CERTIFICATE_STORE_H_)
#define _EC_AM_BASE_CERTIFICATE_STORE_H_

#if defined(USE_EC_CERTIFICATE_STORE)

#include "eap_am_export.h"
#include "eap_tools.h"
#include "wapi_types.h"
#include "ec_cs_types.h"
#include "ec_cs_data.h"
#include "eap_array.h"

class eap_variable_data_c;
class abs_eap_state_notification_c;
class abs_ec_am_certificate_store_c;

/** @file */

//----------------------------------------------------------------------------

/// This class defines interface of elliptic curve certificate store AM.
/**
 * Interface of elliptic curve certificate store AM.
 */
class EAP_EXPORT ec_am_base_certificate_store_c
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	virtual ~ec_am_base_certificate_store_c() {}

	/** Function sets partner object of adaptation module of certificate store.
	 *  Partner object is the certificate store object.
	 */
	virtual void set_am_certificate_store_partner(abs_ec_am_certificate_store_c * const partner) = 0;

	/**
	 * Function initializes the certificate store.
	 * This function is completed by complete_initialize_certificate_store() function call.
	 */
	virtual eap_status_e initialize_certificate_store(
		const wapi_completion_operation_e completion_operation) = 0;

	/**
	 * Function reads the certificate store data referenced by parameter in_references.
	 * This function is completed by complete_read_certificate_store_data() function call.
	 */
	virtual eap_status_e read_certificate_store_data(
		const ec_cs_pending_operation_e in_pending_operation,
		EAP_TEMPLATE_CONST eap_array_c<ec_cs_data_c> * const in_references) = 0;

	/**
	 * Function writes the certificate store data referenced by parameter in_references_and_data_blocks.
	 * This function is completed by complete_write_certificate_store_data() function call.
	 */
	virtual eap_status_e write_certificate_store_data(
		const bool when_true_must_be_synchronous_operation,
		const ec_cs_pending_operation_e in_pending_operation,
		EAP_TEMPLATE_CONST eap_array_c<ec_cs_data_c> * const in_references_and_data_blocks) = 0;

	/**
	 * Function completes the add_imported_certificate_file() function call.
	 */
	virtual eap_status_e complete_add_imported_certificate_file(
		const eap_status_e in_completion_status,
		const eap_variable_data_c * const in_imported_certificate_filename) = 0;

	/**
	 * Function completes the remove_certificate_store() function call.
	 */
	virtual eap_status_e complete_remove_certificate_store(
		const eap_status_e in_completion_status) = 0;

	/**
	 * Function cancels all certificate_store store operations.
	 */
	virtual eap_status_e cancel_certificate_store_store_operations() = 0;

	virtual eap_status_e complete_query_certificate_list(
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const ca_certificates,
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const user_certificates) = 0;

	virtual eap_status_e complete_start_certificate_import() = 0;

	//--------------------------------------------------
}; // class ec_am_base_certificate_store_c


#endif //#if defined(USE_EC_CERTIFICATE_STORE)

#endif //#if !defined(_EC_AM_BASE_CERTIFICATE_STORE_H_)


// End.
