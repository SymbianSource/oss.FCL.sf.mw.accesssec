/*
* Copyright (c) 2001-2007 Nokia Corporation and/or its subsidiary(-ies).
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

#if !defined(_EAP_AM_FAST_PAC_STORE_SERVICES_H_)
#define _EAP_AM_FAST_PAC_STORE_SERVICES_H_

#if defined(USE_FAST_EAP_TYPE)

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_FAST_PAC_STORE_SERVICES_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_FAST_PAC_STORE_SERVICES_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_FAST_PAC_STORE_SERVICES_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_FAST_PAC_STORE_SERVICES_H 
	#define EAP_FUNC_EXPORT_EAP_AM_FAST_PAC_STORE_SERVICES_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_FAST_PAC_STORE_SERVICES_H 
#elif defined(EAP_EXPORT_EAP_AM_FAST_PAC_STORE_SERVICES_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_FAST_PAC_STORE_SERVICES_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_FAST_PAC_STORE_SERVICES_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_FAST_PAC_STORE_SERVICES_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_FAST_PAC_STORE_SERVICES_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_FAST_PAC_STORE_SERVICES_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_FAST_PAC_STORE_SERVICES_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_FAST_PAC_STORE_SERVICES_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_FAST_PAC_STORE_SERVICES_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_FAST_PAC_STORE_SERVICES_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_FAST_PAC_STORE_SERVICES_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_tools.h"
#include "eap_fast_pac_store_types.h"
#include "eap_fast_tlv_header.h"

class eap_variable_data_c;
class eap_fast_variable_data_c;
class abs_eap_state_notification_c;

/** @file */

//----------------------------------------------------------------------------

/// This class defines PAC TLV.
/**
 * PAC TLV is constructed with Attribute-Value Pairs.
 */
class EAP_CLASS_VISIBILITY_EAP_AM_FAST_PAC_STORE_SERVICES_H eap_am_fast_pac_store_services_c
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	virtual ~eap_am_fast_pac_store_services_c() {}

	/**
	 * Function queries user the permission for A-ID.
	 * This function is completed by complete_query_user_permission_for_A_ID() function call.
	 */
	virtual eap_status_e query_user_permission_for_A_ID(
		const eap_fast_pac_store_pending_operation_e in_pending_operation,
		const eap_fast_variable_data_c * const in_pac_attribute_A_ID_info,
		const eap_fast_variable_data_c * const in_pac_attribute_A_ID) = 0;

	/**
	 * Function reads the PAC store data referenced by parameter in_references.
	 * This function is completed by complete_read_PAC_store_data() function call.
	 */
	virtual eap_status_e read_PAC_store_data(
		const eap_fast_pac_store_pending_operation_e in_pending_operation,
		EAP_TEMPLATE_CONST eap_array_c<eap_fast_pac_store_data_c> * const in_references) = 0;

	/**
	 * Function writes the PAC store data referenced by parameter in_references_and_data_blocks.
	 * This function is completed by complete_write_PAC_store_data() function call.
	 */
	virtual eap_status_e write_PAC_store_data(
		const bool when_true_must_be_synchronous_operation,
		const eap_fast_pac_store_pending_operation_e in_pending_operation,
		EAP_TEMPLATE_CONST eap_array_c<eap_fast_pac_store_data_c> * const in_references_and_data_blocks) = 0;

	/**
	 * Function completes the add_PAC_TLV() function call.
	 */
	virtual eap_status_e complete_add_PAC_TLV(
		const eap_status_e in_completion_status,
		const eap_fast_completion_operation_e in_completion_operation,
		EAP_TEMPLATE_CONST eap_array_c<eap_fast_pac_type_e> * const in_saved_pac_types) = 0;

	/**
	 * This function call removes cached PAC store data.
	 */
	virtual eap_status_e remove_cached_pac_store_data() = 0;

	/**
	 * Function completes the add_imported_PAC_file() function call.
	 */
	virtual eap_status_e complete_add_imported_PAC_file(
		const eap_status_e in_completion_status,
		const eap_variable_data_c * const in_imported_PAC_filename,
		const eap_variable_data_c * const out_used_group_reference) = 0;

	/**
	 * Function completes the query_PACs() function call.
	 */
	virtual eap_status_e complete_query_PACs(
		const eap_status_e in_completion_status,
		EAP_TEMPLATE_CONST eap_array_c<eap_fast_variable_data_c> * const out_matched_PACs,
		const eap_variable_data_c * const out_used_group_reference) = 0;

	/**
	 * Function completes the remove_PAC() function call.
	 */
	virtual eap_status_e complete_remove_PAC(
		const eap_status_e in_completion_status,
		const eap_variable_data_c * const out_used_group_reference) = 0;

	/**
	 * Function completes the remove_IAP_reference() function call.
	 */
	virtual eap_status_e complete_remove_IAP_reference(
		const eap_status_e in_completion_status) = 0;

	/**
	 * Function cancels all PAC store operations.
	 */
	virtual eap_status_e cancel_PAC_store_operations() = 0;

	/**
	 * The set_session_timeout() function changes the session timeout timer to be elapsed after session_timeout_ms milliseconds.
	 */
	virtual eap_status_e set_session_timeout(
		const u32_t session_timeout_ms) = 0;

	/**
	 * This is notification of internal state transition.
	 * This is used for notifications, debugging and protocol testing.
	 * The primal notifications are eap_state_variable_e::eap_state_authentication_finished_successfully
	 * and eap_state_variable_e::eap_state_authentication_terminated_unsuccessfully. EAP-type MUST send these
	 * two notifications to lower layer.
	 * These two notifications are sent using EAP-protocol layer (eap_protocol_layer_e::eap_protocol_layer_eap).
	 * See also eap_state_notification_c.
	 */
	virtual void state_notification(
		const abs_eap_state_notification_c * const state) = 0;

	/**
	 * The read_configure() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 * 
	 * EAP-type should store it's parameters to an own database. The own database should be accessed
	 * through adaptation module of EAP-type. See eap_am_type_tls_peap_simulator_c::type_configure_read.
	 */
	virtual eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	//--------------------------------------------------
}; // class eap_am_fast_pac_store_services_c


#endif //#if defined(USE_FAST_EAP_TYPE)

#endif //#if !defined(_EAP_AM_FAST_PAC_STORE_SERVICES_H_)


// End.
