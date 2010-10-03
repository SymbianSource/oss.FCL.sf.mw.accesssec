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

#if !defined(_TLS_AM_APPLICATION_EAP_FAST_H_)
#define _TLS_AM_APPLICATION_EAP_FAST_H_

#if defined(USE_FAST_EAP_TYPE)

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_TLS_AM_APPLICATION_EAP_FAST_H)
	#define EAP_CLASS_VISIBILITY_TLS_AM_APPLICATION_EAP_FAST_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_TLS_AM_APPLICATION_EAP_FAST_H 
	#define EAP_C_FUNC_VISIBILITY_TLS_AM_APPLICATION_EAP_FAST_H 
	#define EAP_FUNC_EXPORT_TLS_AM_APPLICATION_EAP_FAST_H 
	#define EAP_C_FUNC_EXPORT_TLS_AM_APPLICATION_EAP_FAST_H 
#elif defined(EAP_EXPORT_TLS_AM_APPLICATION_EAP_FAST_H)
	#define EAP_CLASS_VISIBILITY_TLS_AM_APPLICATION_EAP_FAST_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_TLS_AM_APPLICATION_EAP_FAST_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_AM_APPLICATION_EAP_FAST_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_TLS_AM_APPLICATION_EAP_FAST_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_TLS_AM_APPLICATION_EAP_FAST_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_TLS_AM_APPLICATION_EAP_FAST_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_TLS_AM_APPLICATION_EAP_FAST_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_AM_APPLICATION_EAP_FAST_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_TLS_AM_APPLICATION_EAP_FAST_H 
	#define EAP_C_FUNC_EXPORT_TLS_AM_APPLICATION_EAP_FAST_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_array.h"
#include "eap_fast_pac_store_types.h"

#include "eap_fast_tlv_header.h"

#if defined(USE_EAP_TLS_SESSION_TICKET)
class tls_extension_c;
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)

class abs_tls_am_application_eap_fast_c;
class eap_fast_variable_data_c;


/// This class declares the functions adaptation module of TLS
/// requires from the TLS.
class EAP_CLASS_VISIBILITY_TLS_AM_APPLICATION_EAP_FAST_H tls_am_application_eap_fast_c
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
	virtual ~tls_am_application_eap_fast_c()
	{
	}

	/// Constructor does nothing.
	tls_am_application_eap_fast_c()
	{
	}

	/// This function sets pointer to application of TLS. See abs_tls_am_application_eap_fast_c.
	virtual void set_tls_application(abs_tls_am_application_eap_fast_c * const tls_application) = 0;

	// This is commented in eap_base_type_c::configure().
	virtual eap_status_e configure() = 0;

	/**
	 * This function initializes PAC store.
	 * Imported PACs and other configuration can be done within this function call.
	 * If asyncronous operations are needed the operations must be completed
	 * by complete_initialize_PAC_store() function call.
	 */
	virtual eap_status_e initialize_PAC_store(
		const eap_fast_completion_operation_e completion_operation,
		const eap_fast_initialize_pac_store_completion_e completion) = 0;

	/**
	 * This function reads the authority identity (A-ID) of server.
	 * This is used in EAP-FAST.
	 * Parameter includes the TLV of A-ID.
	 */
	virtual eap_status_e read_authority_identity(eap_variable_data_c * const authority_identity_payload) = 0;

	/**
	 * This function call is always asyncronous.
	 * It will be completed always with complete_query_pac_of_type() function call.
	 * Function creates a new PAC.
	 */
	virtual eap_status_e query_pac_of_type(const eap_fast_pac_type_e pac_type) = 0;

#if defined(USE_EAP_CORE_SERVER)
	/**
	 * This function call is always asyncronous.
	 * It will be completed always with complete_verify_pac() function call.
	 * Function verifies the received PAC is valid.
	 */
	virtual eap_status_e verify_pac(const eap_fast_variable_data_c * const tlv_pac) = 0;
#endif //#if defined(USE_EAP_CORE_SERVER)


	virtual eap_status_e indicates_eap_fast_provisioning_starts(
		const eap_fast_completion_operation_e provisioning_mode,
		const eap_fast_pac_type_e pac_type) = 0;

	virtual eap_status_e indicates_eap_fast_provisioning_ends(
		const bool provisioning_successfull,
		const eap_fast_completion_operation_e provisioning_mode,
		const eap_fast_pac_type_e pac_type) = 0;

	// This is commented in eap_am_fast_pac_store_services_c::query_user_permission_for_A_ID().
	virtual eap_status_e query_user_permission_for_A_ID(
		const eap_fast_pac_store_pending_operation_e in_pending_operation,
		const eap_fast_variable_data_c * const in_pac_attribute_A_ID_info,
		const eap_fast_variable_data_c * const in_pac_attribute_A_ID) = 0;

	// This is commented in eap_am_fast_pac_store_services_c::read_PAC_store_data().
	virtual eap_status_e read_PAC_store_data(
		const eap_fast_pac_store_pending_operation_e in_pending_operation,
		EAP_TEMPLATE_CONST eap_array_c<eap_fast_pac_store_data_c> * const in_references) = 0;

	// This is commented in eap_am_fast_pac_store_services_c::write_PAC_store_data().
	virtual eap_status_e write_PAC_store_data(
		const bool when_true_must_be_synchronous_operation,
		const eap_fast_pac_store_pending_operation_e in_pending_operation,
		EAP_TEMPLATE_CONST eap_array_c<eap_fast_pac_store_data_c> * const in_references_and_data_blocks) = 0;

	// This is commented in eap_am_fast_pac_store_services_c::complete_add_imported_PAC_file().
	virtual eap_status_e complete_add_imported_PAC_file(
		const eap_status_e in_completion_status,
		const eap_variable_data_c * const in_imported_PAC_filename,
		const eap_variable_data_c * const out_used_group_reference) = 0;

	// This is commented in eap_am_fast_pac_store_services_c::complete_remove_PAC().
	virtual eap_status_e complete_remove_PAC(
		const eap_status_e in_completion_status,
		const eap_variable_data_c * const out_used_group_reference) = 0;

	// This is commented in eap_am_fast_pac_store_services_c::complete_remove_IAP_reference().
	virtual eap_status_e complete_remove_IAP_reference(
		const eap_status_e in_completion_status) = 0;

	// This is commented in eap_am_fast_pac_store_services_c::cancel_PAC_store_operations().
	virtual eap_status_e cancel_PAC_store_operations() = 0;

	//--------------------------------------------------
}; // class tls_am_application_eap_fast_c

#endif //#if defined(USE_FAST_EAP_TYPE)

#endif //#if !defined(_TLS_AM_APPLICATION_EAP_FAST_H_)

//--------------------------------------------------

// End.
