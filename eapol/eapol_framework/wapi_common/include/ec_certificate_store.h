/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/ec_certificate_store.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 52.1.10 % << Don't touch! Updated by Synergy at check-out.
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



#if !defined(_EC_CERTIFICATE_STORE_H_)
#define _EC_CERTIFICATE_STORE_H_

#if defined(USE_WAPI_CORE)

#include "eap_am_export.h"
#include "eap_tools.h"
#include "ec_cs_types.h"
#include "ec_base_certificate_store.h"
#include "eap_configuration_field.h"
#include "abs_ec_am_algorithms.h"
#include "abs_ec_am_certificate_store.h"
#include "ec_cs_completion.h"
#include "ec_cs_tlv_payloads.h"
#include "eap_am_network_id.h"

class abs_ec_certificate_store_c;


/** @file */

const u32_t WAPI_CS_KEY_TIMER_ID = 0ul;

//----------------------------------------------------------------------------

/**
 *  This is the ASUE's ECC certificate file. It must be in DER format.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_WAPI_ASUE_certificate_file,
	"WAPI_ASUE_certificate_file",
	eap_configure_type_string,
	false);

/**
 *  This is the ASUE's ECC private key file. It must be in DER format.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_WAPI_ASUE_private_key_file,
	"WAPI_ASUE_private_key_file",
	eap_configure_type_string,
	false);


/**
 *  This is the AE's ECC certificate file. It must be in DER format.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_WAPI_AE_certificate_file,
	"WAPI_AE_certificate_file",
	eap_configure_type_string,
	false);

/**
 *  This is the AE's ECC private key file. It must be in DER format.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_WAPI_AE_private_key_file,
	"WAPI_AE_private_key_file",
	eap_configure_type_string,
	false);


/**
 *  This is the ASU's ECC certificate file. It must be in DER format.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_WAPI_ASU_certificate_file,
	"WAPI_ASU_certificate_file",
	eap_configure_type_string,
	false);

/**
 *  This is the ASU's ECC private key file. It must be in DER format.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_WAPI_ASU_private_key_file,
	"WAPI_ASU_private_key_file",
	eap_configure_type_string,
	false);

/**
 *  This u32_t data configuration option is the timeout of the PAC store key.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAP_FAST_PAC_store_key_timeout_ms,
	"EAP_FAST_PAC_store_key_timeout_ms",
	eap_configure_type_u32_t,
	false);

//----------------------------------------------------------------------------

enum wapi_pem_read_state_e
{
	wapi_pem_read_state_header,
	wapi_pem_read_state_data,
	wapi_pem_read_state_end,
};

enum wapi_pem_data_type_e
{
	wapi_pem_data_type_none,
	wapi_pem_data_type_certificate,
	wapi_pem_data_type_private_key,
};

EAP_CONFIGURATION_FIELD(
	wapi_pem_certificate_begin,
	"-----BEGIN CERTIFICATE-----",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	wapi_pem_certificate_end,
	"-----END CERTIFICATE-----",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	wapi_pem_ec_private_key_begin,
	"-----BEGIN EC PRIVATE KEY-----",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	wapi_pem_ec_private_key_end,
	"-----END EC PRIVATE KEY-----",
	eap_configure_type_string,
	false);

//----------------------------------------------------------------------------

class abs_eap_am_tools_c;
class ec_am_base_algorithms_c;
class ec_am_base_certificate_store_c;


class EAP_EXPORT ec_certificate_store_c
: public abs_eap_base_timer_c
, public ec_base_certificate_store_c
, public abs_ec_am_algorithms_c
, public abs_ec_am_certificate_store_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	abs_ec_certificate_store_c * const m_partner;

	ec_am_base_algorithms_c * m_ec_algorithms;

	ec_am_base_certificate_store_c * const m_am_certificate_store;

	eap_am_network_id_c m_receive_network_id;

	bool m_master_key_changed;
	eap_variable_data_c m_PAC_store_master_key;

	eap_variable_data_c m_PAC_store_password;

	eap_variable_data_c m_PAC_store_device_seed;

	/// This object includes pending asyncronous actions or it may be empty.
	eap_array_c<ec_cs_completion_c> m_completion_queue;

	ec_cs_pending_operation_e m_pending_operation;

	eap_variable_data_c m_queried_issuer_ID;

	eap_variable_data_c m_imported_certificate_wapi_id;
	eap_variable_data_c m_imported_certificate_file_data;
	eap_variable_data_c m_imported_certificate_filename;

	eap_variable_data_c m_imported_certificate_data;
	eap_variable_data_c m_imported_private_key_data;

	eap_status_e m_ec_cs_completion_status;

	eap_variable_data_c m_ae_certificate;

	eap_variable_data_c m_selected_ca_id;
	eap_variable_data_c m_selected_client_id;

	eap_array_c<ec_cs_data_c> m_broken_cs_data_list;

	eap_array_c<ec_cs_data_c> m_ca_asu_id_list;
	bool m_read_ca_asu_id_list;

	eap_array_c<ec_cs_data_c> m_client_asu_id_list;
	bool m_read_client_asu_id_list;

	eap_array_c<ec_cs_data_c> m_ca_certificates;
	eap_array_c<ec_cs_data_c> m_client_certificates;
	eap_array_c<ec_cs_data_c> m_client_private_keys;

	eap_variable_data_c m_peer_identity;
	eap_variable_data_c m_signature;

	eap_variable_data_c m_hash_of_message;
	eap_variable_data_c m_id_of_own_certificate;


	eap_variable_data_c m_dummy_test_asu_certificate;

	eap_variable_data_c m_dummy_test_asu_private_key;

	eap_variable_data_c m_dummy_test_peer_certificate;

	eap_variable_data_c m_dummy_test_own_certificate;

	eap_variable_data_c m_dummy_test_own_private_key;



	bool m_is_client;

	bool m_is_valid;

	bool m_shutdown_was_called;

	bool m_reference_counter_read;
	bool m_reference_counter_changed;
	u32_t m_reference_counter;

	u32_t m_PAC_store_key_timeout_ms;

	bool m_already_in_completion_action_check;

	bool m_pending_read_ec_cs_data;

	bool m_complete_start_certificate_import;

	bool m_certificate_store_initialized;

	bool m_allow_use_of_ae_certificate;


	eap_status_e create_unique_reference(
		ec_cs_data_c * const out_reference);

	eap_status_e cancel_operations();

#if defined(USE_WAPI_CORE_SERVER) || !defined(WAPI_USE_CERTIFICATE_STORE)
	eap_status_e read_test_certificate(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);
#endif //#if defined(USE_WAPI_CORE_SERVER) || !defined(WAPI_USE_CERTIFICATE_STORE)

	eap_status_e compare_id_and_certificate(
		const eap_variable_data_c * const ID,
		const eap_variable_data_c * const certificate);

	eap_status_e compare_issuer_name_of_id_and_certificate(
		const eap_variable_data_c * const issuer_ID,
		const eap_variable_data_c * const certificate);

	eap_status_e compare_issuer_common_name_and_certificate(
		const eap_variable_data_c * const certificate,
		const eap_variable_data_c * const subject_common_name);

	eap_status_e convert_PEM_to_DER(
		const wapi_pem_data_type_e key_type,
		const eap_variable_data_c * const pem_data,
		eap_array_c<ec_cs_data_c> * const der_data);

	eap_status_e read_PEM_data_line(
		const eap_variable_data_c * const in_imported_certificate_file_data,
		u32_t * const offset,
		eap_variable_data_c * const line);

	eap_status_e parse_PEM_file_data(
		const eap_variable_data_c * const in_imported_certificate_file_data,
		eap_array_c<ec_cs_data_c> * const der_data);

	eap_status_e read_certificate_wapi_identity(
		const eap_variable_data_c * const certificate,
		eap_variable_data_c * const certificate_wapi_identity);

	eap_status_e copy_certificate_wapi_identities(
		EAP_TEMPLATE_CONST eap_array_c<ec_cs_data_c> * const certificates_id_list,
		eap_array_c<eap_variable_data_c> * const wapi_identities_list);

	eap_status_e read_certificate_type(
		const eap_variable_data_c * const imported_certificate_file_data,
		ec_cs_data_type_e * const data_type);

	eap_status_e read_certificate(
		const ec_cs_pending_operation_e pending_operation,
		const ec_cs_data_type_e certificate_type,
		const eap_variable_data_c * certificate_reference);

	eap_status_e read_both_certificate_lists(
		const ec_cs_pending_operation_e pending_operation);

	eap_status_e read_ca_certificate_list(
		const ec_cs_pending_operation_e pending_operation);

	eap_status_e read_client_certificate_list(
		const ec_cs_pending_operation_e pending_operation);

	eap_status_e save_to_broken_cs_data_list(
		const ec_cs_data_c * const ref_and_data);

	eap_status_e save_to_ec_cs_list(
		eap_array_c<ec_cs_data_c> * const ec_cs_list,
		const ec_cs_data_c * const ref_and_data);

	eap_status_e save_ec_cs_data(
		EAP_TEMPLATE_CONST eap_array_c<ec_cs_data_c> * const in_references_and_data_blocks);

	eap_status_e add_imported_certificate(
		const ec_cs_data_type_e certificate_type,
		const eap_variable_data_c * const in_imported_certificate_wapi_id,
		const eap_variable_data_c * const in_imported_certificate_file_data,
		const eap_variable_data_c * const in_imported_certificate_filename,
		eap_array_c<ec_cs_data_c> * const out_asu_id_list,
		eap_array_c<ec_cs_data_c> * const out_certificates,
		ec_cs_variable_data_c * const out_certificate_reference);

	eap_status_e add_imported_private_key(
		const ec_cs_data_type_e private_key_type,
		const eap_variable_data_c * const in_imported_private_key_file_data,
		const eap_variable_data_c * const in_imported_private_key_filename,
		const ec_cs_variable_data_c * const in_certificate_reference,
		eap_array_c<ec_cs_data_c> * const out_private_keys);

	eap_status_e read_certificate_reference(
		const ec_cs_data_c * const reference_tlv,
		eap_variable_data_c * const certificate_reference);

	eap_status_e internal_create_signature_with_private_key();

	eap_status_e internal_select_certificate_with_identity(
		const eap_variable_data_c * const queried_issuer_ID);

	eap_status_e internal_select_own_certificate_with_issuer_name();

	eap_status_e internal_select_certificate();

	eap_status_e add_asu_id_list(
		EAP_TEMPLATE_CONST eap_array_c<ec_cs_data_c> * const asu_id_list,
		eap_array_c<ec_cs_data_c> * const data_references);

	eap_status_e save_data_to_permanent_store();

	eap_status_e internal_complete_add_imported_certificate_file();

	eap_status_e query_PAC_store_password(
		const ec_cs_pending_operation_e in_pending_operation);

	eap_status_e add_password_qyery(
		eap_array_c<ec_cs_data_c> * const in_references);


	//--------------------------------------------------

	eap_status_e are_pending_queries_completed();

	void set_pending_operation(const ec_cs_pending_operation_e operation);

	eap_status_e completion_action_add(
		ec_cs_completion_e action);

	eap_status_e completion_action_push(
		ec_cs_completion_e action);

	eap_status_e completion_action_pop();

	eap_status_e completion_action_clenup();

	void completion_action_trace();

	eap_status_e completion_action_check();

	//--------------------------------------------------

	void send_error_notification(const eap_status_e error);

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the ec_certificate_store_c class does nothing.
	 */
	EAP_FUNC_IMPORT virtual ~ec_certificate_store_c();

	/**
	 * The constructor of the ec_certificate_store_c class simply initializes the attributes.
	 */
	EAP_FUNC_IMPORT ec_certificate_store_c(
		abs_eap_am_tools_c * const tools,
		abs_ec_certificate_store_c * const partner,
		ec_am_base_certificate_store_c * const am_certificate_store,
		const bool is_client_when_true);


	EAP_FUNC_IMPORT bool get_is_valid() const;


	EAP_FUNC_IMPORT eap_status_e configure();

	EAP_FUNC_IMPORT eap_status_e shutdown();

	EAP_FUNC_IMPORT eap_status_e timer_expired(const u32_t id, void *data);

	EAP_FUNC_IMPORT eap_status_e timer_delete_data(const u32_t id, void *data);

	/**
	 * Function initializes the certificate store.
	 * This function is completed by complete_initialize_certificate_store() function call.
	 */
	EAP_FUNC_IMPORT eap_status_e initialize_certificate_store();

	EAP_FUNC_IMPORT eap_status_e query_asu_id();

	EAP_FUNC_IMPORT eap_status_e get_own_certificate();

	EAP_FUNC_IMPORT eap_status_e set_ae_certificate(
		const eap_variable_data_c * const ae_certificate);

	EAP_FUNC_IMPORT eap_status_e select_certificate(
		const eap_variable_data_c * const issuer_ID);

	EAP_FUNC_IMPORT eap_status_e create_signature_with_private_key(
		const eap_variable_data_c * const hash_of_message,
		const eap_variable_data_c * const id_of_certificate);

	EAP_FUNC_IMPORT eap_status_e verify_signature_with_public_key(
		const eap_variable_data_c * const peer_identity,
		const eap_variable_data_c * const hash_of_message,
		const eap_variable_data_c * const signature,
		const bool allow_use_of_ae_certificate);

	EAP_FUNC_IMPORT eap_status_e read_id_of_certificate(
		const eap_variable_data_c * const certificate);

	EAP_FUNC_IMPORT eap_status_e create_ecdh_temporary_keys();

	EAP_FUNC_IMPORT eap_status_e create_ecdh(
		const eap_variable_data_c * const own_private_key_d,
		const eap_variable_data_c * const peer_public_key_x,
		const eap_variable_data_c * const peer_public_key_y);

	// This is documented in abs_eap_base_type_c::read_configure().
	EAP_FUNC_IMPORT virtual eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	// This is documented in abs_ec_algorithms_c::complete_create_signature_with_private_key().
	EAP_FUNC_IMPORT eap_status_e complete_create_signature_with_private_key(
		const eap_variable_data_c * const signature,
		const eap_status_e signature_status);

	// This is documented in abs_ec_algorithms_c::complete_verify_signature_with_public_key().
	EAP_FUNC_IMPORT eap_status_e complete_verify_signature_with_public_key(
		const eap_status_e verification_status);

	// This is documented in abs_ec_algorithms_c::complete_create_ecdh_temporary_keys().
	EAP_FUNC_IMPORT eap_status_e complete_create_ecdh_temporary_keys(
		const eap_variable_data_c * const private_key_d,
		const eap_variable_data_c * const public_key_x,
		const eap_variable_data_c * const public_key_y);

	// This is documented in abs_ec_algorithms_c::complete_create_ecdh().
	EAP_FUNC_IMPORT eap_status_e complete_create_ecdh(
		const eap_variable_data_c * const K_AB_x4,
		const eap_variable_data_c * const K_AB_y4);

	// This is documented in abs_ec_am_certificate_store_c::complete_initialize_certificate_store().
	EAP_FUNC_IMPORT eap_status_e complete_initialize_certificate_store(
		const wapi_completion_operation_e completion_operation);

	// This is documented in abs_ec_am_certificate_store_c::remove_cached_certificate_store_data().
	EAP_FUNC_IMPORT eap_status_e remove_cached_certificate_store_data();

	// This is documented in abs_ec_am_certificate_store_c::add_imported_certificate_file().
	EAP_FUNC_IMPORT eap_status_e add_imported_certificate_file(
		const eap_variable_data_c * const in_imported_certificate_file_data,
		const eap_variable_data_c * const in_imported_certificate_filename);

	// This is documented in abs_ec_am_certificate_store_c::complete_read_certificate_store_data().
	EAP_FUNC_IMPORT eap_status_e complete_read_certificate_store_data(
		const eap_status_e in_completion_status,
		const ec_cs_pending_operation_e in_pending_operation,
		EAP_TEMPLATE_CONST eap_array_c<ec_cs_data_c> * const in_references_and_data_blocks);
	
	// This is documented in abs_ec_am_certificate_store_c::complete_write_certificate_store_data().
	EAP_FUNC_IMPORT eap_status_e complete_write_certificate_store_data(
		const eap_status_e in_completion_status,
		const ec_cs_pending_operation_e in_pending_operation);

	// This is documented in abs_ec_am_certificate_store_c::query_certificate_list().
	EAP_FUNC_IMPORT eap_status_e query_certificate_list();

	EAP_FUNC_IMPORT eap_status_e start_certificate_import();

	EAP_FUNC_IMPORT eap_status_e set_receive_network_id(const eap_am_network_id_c * const receive_network_id);

	//--------------------------------------------------
}; // ec_certificate_store_c

//----------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

#endif //#if !defined(_EC_CERTIFICATE_STORE_H_)


// End.
