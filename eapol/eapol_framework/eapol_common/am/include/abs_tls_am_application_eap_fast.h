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

#if !defined(_ABS_TLS_AM_APPLICATION_EAP_FAST_H_)
#define _ABS_TLS_AM_APPLICATION_EAP_FAST_H_

#if defined(USE_FAST_EAP_TYPE)

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_TLS_AM_APPLICATION_EAP_FAST_H)
	#define EAP_CLASS_VISIBILITY_ABS_TLS_AM_APPLICATION_EAP_FAST_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_TLS_AM_APPLICATION_EAP_FAST_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_TLS_AM_APPLICATION_EAP_FAST_H 
	#define EAP_FUNC_EXPORT_ABS_TLS_AM_APPLICATION_EAP_FAST_H 
	#define EAP_C_FUNC_EXPORT_ABS_TLS_AM_APPLICATION_EAP_FAST_H 
#elif defined(EAP_EXPORT_ABS_TLS_AM_APPLICATION_EAP_FAST_H)
	#define EAP_CLASS_VISIBILITY_ABS_TLS_AM_APPLICATION_EAP_FAST_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_TLS_AM_APPLICATION_EAP_FAST_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_TLS_AM_APPLICATION_EAP_FAST_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_TLS_AM_APPLICATION_EAP_FAST_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_TLS_AM_APPLICATION_EAP_FAST_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_TLS_AM_APPLICATION_EAP_FAST_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_TLS_AM_APPLICATION_EAP_FAST_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_TLS_AM_APPLICATION_EAP_FAST_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_TLS_AM_APPLICATION_EAP_FAST_H 
	#define EAP_C_FUNC_EXPORT_ABS_TLS_AM_APPLICATION_EAP_FAST_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_array.h"

#if defined(USE_EAP_TLS_SESSION_TICKET)
class tls_extension_c;
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)

/// This class declares the functions adaptation module of TLS
/// requires from the TLS.
class EAP_CLASS_VISIBILITY_ABS_TLS_AM_APPLICATION_EAP_FAST_H abs_tls_am_application_eap_fast_c
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
	virtual ~abs_tls_am_application_eap_fast_c()
	{
	}

	/// Constructor does nothing.
	abs_tls_am_application_eap_fast_c()
	{
	}

	/**
	 * This function call completes initialize_PAC_store() function call.
	 * After all imported PAC files are handled, AM must call this function.
	 * EAP-FAST authentication will continue within this function call.
	 */
	virtual eap_status_e complete_initialize_PAC_store(
		const eap_fast_completion_operation_e completion_operation,
		const eap_fast_initialize_pac_store_completion_e completion) = 0;

	/**
	 * This function call completes query_pac_of_type() function call.
	 * This function is used in test server.
	 */
	virtual eap_status_e complete_query_pac_of_type(
		const eap_fast_variable_data_c * const pac_tlv,
		const eap_fast_pac_type_e pac_type) = 0;

	/**
	 * This function call completes verify_pac() function call.
	 * This function is used in test server.
	 */
	virtual eap_status_e complete_verify_pac(
		const eap_status_e verification_status,
		const eap_fast_pac_type_e pac_type) = 0;

	/**
	 * This function call removes cached PAC store data.
	 */
	virtual eap_status_e remove_cached_pac_store_data() = 0;

	// This is commented in eap_fast_pac_store_c::add_imported_PAC_file().
	virtual eap_status_e add_imported_PAC_file(
		const eap_variable_data_c * const in_IAP_reference,
		const eap_fast_pac_store_data_c * const in_opt_group_reference_and_data,
		const eap_variable_data_c * const in_imported_PAC_data,
		const eap_variable_data_c * const in_imported_PAC_filename) = 0;

	// This is commented in eap_fast_pac_store_c::remove_IAP_reference().
	virtual eap_status_e remove_IAP_reference(
		const eap_variable_data_c * const in_IAP_reference,
		const eap_fast_pac_store_data_c * const in_opt_group_reference_and_data) = 0;


	// This is commented in eap_fast_pac_store_c::complete_query_user_permission_for_A_ID().
	virtual eap_status_e complete_query_user_permission_for_A_ID(
		const eap_status_e in_completion_status,
		const eap_fast_pac_store_pending_operation_e in_pending_operation) = 0;

	// This is commented in eap_fast_pac_store_c::complete_read_PAC_store_data().
	virtual eap_status_e complete_read_PAC_store_data(
		const eap_status_e in_completion_status,
		const eap_fast_pac_store_pending_operation_e in_pending_operation,
		EAP_TEMPLATE_CONST eap_array_c<eap_fast_pac_store_data_c> * const in_references_and_data_blocks) = 0;
	
	// This is commented in eap_fast_pac_store_c::complete_write_PAC_store_data().
	virtual eap_status_e complete_write_PAC_store_data(
		const eap_status_e in_completion_status,
		const eap_fast_pac_store_pending_operation_e in_pending_operation) = 0;

	//--------------------------------------------------
}; // class abs_tls_am_application_eap_fast_c

#endif //#if defined(USE_FAST_EAP_TYPE)

#endif //#if !defined(_ABS_TLS_AM_APPLICATION_EAP_FAST_H_)

//--------------------------------------------------



// End.
