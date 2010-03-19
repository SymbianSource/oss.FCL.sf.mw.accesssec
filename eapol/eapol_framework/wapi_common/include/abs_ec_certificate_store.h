/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/abs_ec_certificate_store.h
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



#if !defined(_ABS_EC_CERTIFICATE_STORE_H_)
#define _ABS_EC_CERTIFICATE_STORE_H_

#if defined(USE_WAPI_CORE)

#include "eap_am_export.h"
#include "eap_tools.h"
#include "ec_cs_types.h"

/** @file */

//----------------------------------------------------------------------------

class abs_eap_am_tools_c;
class eap_configuration_field_c;
class abs_eap_state_notification_c;


class EAP_EXPORT abs_ec_certificate_store_c
{
	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the abs_ec_certificate_store_c class does nothing.
	 */
	EAP_FUNC_IMPORT virtual ~abs_ec_certificate_store_c();

	virtual eap_status_e complete_get_own_certificate(
		const eap_variable_data_c * const own_certificate) = 0;

	virtual eap_status_e complete_query_asu_id(
		const eap_variable_data_c * const asn1_der_subject_name,
		const eap_variable_data_c * const asn1_der_issuer_name,
		const eap_variable_data_c * const asn1_der_sequence_number,
		const eap_status_e id_status) = 0;

	virtual eap_status_e complete_select_certificate(
		const eap_variable_data_c * const issuer_ID,
		const eap_variable_data_c * const certificate_ID,
		const eap_variable_data_c * const certificate) = 0;

	virtual eap_status_e complete_read_id_of_certificate(
		const eap_variable_data_c * const ID) = 0;

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
	 * The set_session_timeout() function changes the session timeout timer to be elapsed after session_timeout_ms milliseconds.
	 */
	virtual eap_status_e set_session_timeout(
		const u32_t session_timeout_ms) = 0;

	/**
	 * This is notification of internal state transition.
	 * This is used for notifications, debugging and protocol testing.
	 * The primal notifications are eap_state_variable_e::eap_state_authentication_finished_successfully
	 * and eap_state_variable_e::eap_state_authentication_terminated_unsuccessfully. CS MUST send these
	 * two notifications to lower layer.
	 * These two notifications are sent using WAPI-protocol layer (eap_protocol_layer_e::eap_protocol_layer_wapi).
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
	 * WAPI should store it's parameters to an own database. The own database should be accessed
	 * through adaptation module of WAPI. See eap_am_type_gsmsim_simulator_c::type_configure_read.
	 */
	virtual eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	//--------------------------------------------------
}; // abs_ec_certificate_store_c

//----------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

#endif //#if !defined(_ABS_EC_CERTIFICATE_STORE_H_)


// End.
