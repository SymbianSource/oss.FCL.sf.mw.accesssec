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
* %version: 49 %
*/

#if !defined(_EAP_PROCESS_TLV_MESSAGE_DATA_H_)
#define _EAP_PROCESS_TLV_MESSAGE_DATA_H_

#include "eap_am_types.h"
#include "eap_tools.h"
#include "eap_array.h"
#include "eap_tlv_message_data.h"
#include "eap_expanded_type.h"
#include "eapol_rsna_key_header.h"
#include "eap_method_settings.h"
#include "eap_file_config.h"

#if defined(USE_EAP_SIMPLE_CONFIG)
#include "simple_config_types.h"
#include "simple_config_credential.h"
#include "simple_config_payloads.h"
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_PROCESS_TLV_MESSAGE_DATA_H)
	#define EAP_CLASS_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H 
	#define EAP_FUNC_EXPORT_EAP_PROCESS_TLV_MESSAGE_DATA_H 
	#define EAP_C_FUNC_EXPORT_EAP_PROCESS_TLV_MESSAGE_DATA_H 
#elif defined(EAP_EXPORT_EAP_PROCESS_TLV_MESSAGE_DATA_H)
	#define EAP_CLASS_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_PROCESS_TLV_MESSAGE_DATA_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_PROCESS_TLV_MESSAGE_DATA_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_PROCESS_TLV_MESSAGE_DATA_H 
	#define EAP_C_FUNC_EXPORT_EAP_PROCESS_TLV_MESSAGE_DATA_H 
#endif
// End: added by script change_export_macros.sh.

enum eap_tlv_message_type_e
{
	eap_tlv_message_type_none                                 = 0,
	eap_tlv_message_type_array                                = 1,
	eap_tlv_message_type_boolean                              = 2,
	eap_tlv_message_type_eap_protocol_layer                   = 3,
	eap_tlv_message_type_eap_state_notification               = 4,
	eap_tlv_message_type_eap_status                           = 5,
	eap_tlv_message_type_eap_type                             = 6,
	eap_tlv_message_type_eapol_key_802_11_authentication_mode = 7,
	eap_tlv_message_type_eapol_key_authentication_type        = 8,
	eap_tlv_message_type_eapol_key_type                       = 9,
	eap_tlv_message_type_eapol_tkip_mic_failure_type          = 10,
	eap_tlv_message_type_eapol_wlan_authentication_state      = 11,
	eap_tlv_message_type_error                                = 12,
	eap_tlv_message_type_function                             = 13,
	eap_tlv_message_type_network_id                           = 14,
	eap_tlv_message_type_network_key                          = 15,
	eap_tlv_message_type_protected_setup_credential           = 16,
	eap_tlv_message_type_RSNA_cipher                          = 17,
	eap_tlv_message_type_session_key                          = 18,
	eap_tlv_message_type_u8_t                                 = 19,
	eap_tlv_message_type_u16_t                                = 20,
	eap_tlv_message_type_u32_t                                = 21,
	eap_tlv_message_type_u64_t                                = 22,
	eap_tlv_message_type_variable_data                        = 23,
	eap_tlv_message_type_eap_method_settings                  = 24,
	eap_tlv_message_type_eap_certificate_entry                = 25,
	eap_tlv_message_type_i8_t                                 = 26,
	eap_tlv_message_type_i16_t                                = 27,
	eap_tlv_message_type_i32_t                                = 28,
	eap_tlv_message_type_configuration_option                 = 29,
};


enum eap_tlv_message_type_function_e
{
	eap_tlv_message_type_function_none                                            = 0,
	eap_tlv_message_type_function_check_pmksa_cache                               = 1,
	eap_tlv_message_type_function_start_authentication                            = 2,
	eap_tlv_message_type_function_complete_association                            = 3,
	eap_tlv_message_type_function_disassociation                                  = 4,
	eap_tlv_message_type_function_start_preauthentication                         = 5,
	eap_tlv_message_type_function_start_reassociation                             = 6,
	eap_tlv_message_type_function_complete_reassociation                          = 7,
	eap_tlv_message_type_function_start_WPXM_reassociation                        = 8,
	eap_tlv_message_type_function_complete_WPXM_reassociation                     = 9,
	eap_tlv_message_type_function_packet_process                                  = 10,
	eap_tlv_message_type_function_tkip_mic_failure                                = 11,
	eap_tlv_message_type_function_eap_acknowledge                                 = 12,
	eap_tlv_message_type_function_update_header_offset                            = 13,
	eap_tlv_message_type_function_complete_check_pmksa_cache                      = 14,
	eap_tlv_message_type_function_packet_send                                     = 15,
	eap_tlv_message_type_function_associate                                       = 16,
	eap_tlv_message_type_function_disassociate                                    = 17,
	eap_tlv_message_type_function_packet_data_session_key                         = 18,
	eap_tlv_message_type_function_state_notification                              = 19,
	eap_tlv_message_type_function_reassociate                                     = 20,
	eap_tlv_message_type_function_update_wlan_database_reference_values           = 21,
	eap_tlv_message_type_function_complete_start_WPXM_reassociation               = 22,
	eap_tlv_message_type_function_new_protected_setup_credentials                 = 23,
	eap_tlv_message_type_function_create_eap_session                              = 24,
	eap_tlv_message_type_function_remove_eap_session                              = 25,
	eap_tlv_message_type_function_send_eap_identity_request                       = 26,
	eap_tlv_message_type_function_packet_data_crypto_keys                         = 27, // EAP Master session Key.
	eap_tlv_message_type_function_restart_authentication                          = 28,
	eap_tlv_message_type_function_create_state                                    = 29,
	eap_tlv_message_type_function_remove_bksa_from_cache                          = 30,
	eap_tlv_message_type_function_association                                     = 31,
	eap_tlv_message_type_function_set_eap_database_reference_values               = 32,
	eap_tlv_message_type_function_eap_mtu                                         = 33,
	eap_tlv_message_type_function_get_802_11_authentication_mode                  = 34,
	eap_tlv_message_type_function_complete_get_802_11_authentication_mode         = 35,
	eap_tlv_message_type_function_complete_remove_eap_session                     = 36,
	eap_tlv_message_type_function_complete_disassociation                         = 37,
	eap_tlv_message_type_function_last_function                                   = 38, // Keep this the last on this set.

	eap_tlv_message_type_function_plugin_get_configuration                        = 1000,
	eap_tlv_message_type_function_plugin_set_configuration                        = 1001,
	eap_tlv_message_type_function_plugin_copy_configuration                       = 1002,
	eap_tlv_message_type_function_plugin_delete_configuration                     = 1003,
	eap_tlv_message_type_function_plugin_set_index                                = 1004,
	eap_tlv_message_type_function_plugin_get_type_info                            = 1005,
	eap_tlv_message_type_function_plugin_invoke_ui                                = 1006,
	eap_tlv_message_type_function_plugin_complete_get_configuration               = 1007,
	eap_tlv_message_type_function_plugin_complete_set_configuration               = 1008,
	eap_tlv_message_type_function_plugin_complete_delete_configuration            = 1009,
	eap_tlv_message_type_function_plugin_complete_copy_configuration              = 1010,
	eap_tlv_message_type_function_plugin_complete_set_index                       = 1011,
	eap_tlv_message_type_function_plugin_complete_get_type_info                   = 1012,
	eap_tlv_message_type_function_plugin_complete_invoke_ui                       = 1013,
	eap_tlv_message_type_function_plugin_last_function                            = 1014, // Keep this the last on this set.

	eap_tlv_message_type_function_general_settings_set_eap_methods                  = 2000,
	eap_tlv_message_type_function_general_settings_get_eap_methods                  = 2001,
	eap_tlv_message_type_function_general_settings_get_certificate_lists            = 2002,
	eap_tlv_message_type_function_general_settings_delete_all_eap_settings          = 2003,
	eap_tlv_message_type_function_general_settings_copy_all_eap_settings            = 2004,
	eap_tlv_message_type_function_general_settings_complete_set_eap_methods         = 2005,
	eap_tlv_message_type_function_general_settings_complete_get_eap_methods         = 2006,
	eap_tlv_message_type_function_general_settings_complete_get_certificate_lists   = 2007,
	eap_tlv_message_type_function_general_settings_complete_delete_all_eap_settings = 2008,
	eap_tlv_message_type_function_general_settings_complete_copy_all_eap_settings   = 2009,
	eap_tlv_message_type_function_general_settings_last_function                    = 2010, // Keep this the last on this set.

	eap_tlv_message_type_function_pac_store_open_pac_store            = 3000,
	eap_tlv_message_type_function_pac_store_create_device_seed            = 3001,
	eap_tlv_message_type_function_pac_store_is_master_key_present   = 3002,
	eap_tlv_message_type_function_pac_store_is_master_key_and_password_matching   = 3003,
	eap_tlv_message_type_function_pac_store_create_and_save_master_key   = 3004,
	eap_tlv_message_type_function_pac_store_compare_pac_store_password   = 3005,
	eap_tlv_message_type_function_pac_store_is_pacstore_password_present   = 3006,
	eap_tlv_message_type_function_pac_store_set_pac_store_password   = 3007,
	eap_tlv_message_type_function_pac_store_destroy_pac_store            = 3008,
	eap_tlv_message_type_function_pac_store_complete_open_pac_store            = 3009,
	eap_tlv_message_type_function_pac_store_complete_create_device_seed            = 3010,
	eap_tlv_message_type_function_pac_store_complete_is_master_key_present   = 3011,
	eap_tlv_message_type_function_pac_store_complete_is_master_key_and_password_matching   = 3012,
	eap_tlv_message_type_function_pac_store_complete_create_and_save_master_key   = 3013,
	eap_tlv_message_type_function_pac_store_complete_compare_pac_store_password   = 3014,
	eap_tlv_message_type_function_pac_store_complete_is_pacstore_password_present   = 3015,
	eap_tlv_message_type_function_pac_store_complete_set_pac_store_password   = 3016,
	eap_tlv_message_type_function_pac_store_complete_destroy_pac_store            = 3017,
	eap_tlv_message_type_function_pac_store_last_function              = 3018, // Keep this the last on this set.

	eap_tlv_message_type_function_wapi_settings_get_all_certificate_labels              = 4000,
	eap_tlv_message_type_function_wapi_settings_reset_certificate_store                 = 4001,
    eap_tlv_message_type_function_wapi_settings_get_configuration                       = 4002,
    eap_tlv_message_type_function_wapi_settings_set_configuration                       = 4003,
    eap_tlv_message_type_function_wapi_settings_set_ca_cert                             = 4004,
    eap_tlv_message_type_function_wapi_settings_set_user_cert                           = 4005,
    eap_tlv_message_type_function_wapi_settings_delete_configuration                    = 4006,
    eap_tlv_message_type_function_wapi_settings_complete_get_all_certificate_labels     = 4007,
    eap_tlv_message_type_function_wapi_settings_complete_reset_certificate_store        = 4008,
    eap_tlv_message_type_function_wapi_settings_complete_get_configuration              = 4009,
    eap_tlv_message_type_function_wapi_settings_complete_set_configuration              = 4010,
    eap_tlv_message_type_function_wapi_settings_complete_set_ca_cert                    = 4011,
    eap_tlv_message_type_function_wapi_settings_complete_set_user_cert                  = 4012,
    eap_tlv_message_type_function_wapi_settings_complete_delete_configuration           = 4013,
    eap_tlv_message_type_function_wapi_settings_complete_last_function                  = 4014, // Keep this the last on this set.


	eap_tlv_message_type_function_illegal_value, // Keep this the last value.
};


enum eap_message_payload_index_e
{
	eap_message_payload_index_function        = 0,
	eap_message_payload_index_first_parameter = 1,
};


/** @file */

class eap_variable_data_c;
class eap_am_network_id_c;
class eap_buf_chain_wr_c;
class eapol_session_key_c;
class abs_eap_state_notification_c;
class eap_state_notification_c;
class network_key_and_index_c;

//----------------------------------------------------------------------------


/// This class defines functions to add and parse message data composed
/// of Attribute-Value Pairs (See eap_tlv_header_c) to/from eap_tlv_message_data_c object.
class EAP_CLASS_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_process_tlv_message_data_c
: public eap_tlv_message_data_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	bool m_is_valid;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the eap_process_tlv_message_data_c class does nothing.
	 */
	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H virtual ~eap_process_tlv_message_data_c();

	/**
	 * The constructor of the eap_process_tlv_message_data_c class simply initializes the attributes.
	 */
	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_process_tlv_message_data_c(
		abs_eap_am_tools_c * const tools);

	/**
	 * This function should increase reference count.
	 */
	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H void object_increase_reference_count();

	/**
	 * This function should first decrease reference count
	 * and second return the remaining reference count.
	 * Reference count must not be decreased when it is zero.
	 */
	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H u32_t object_decrease_reference_count();

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H bool get_is_valid();

	//- - - - - - - - - - - - - - - - - - - - - - - - - 

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H u32_t get_payload_size(
		const eap_variable_data_c * const data) const;

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H u32_t get_payload_size(
		const eap_am_network_id_c * const network_id) const;

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H u32_t get_payload_size(
		const abs_eap_state_notification_c * const state) const;

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H u32_t get_payload_size(
		const eapol_session_key_c * const session_key) const;

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H u32_t get_payload_size(
		EAP_TEMPLATE_CONST eap_array_c<u16_t> * const ushort_array) const;

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H u32_t get_payload_size(
		const eap_certificate_entry_c * const cert) const;

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H u32_t get_payload_size(
		EAP_TEMPLATE_CONST eap_array_c<eap_certificate_entry_c> * const cert_array) const;

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H u32_t get_payload_size(
		const eap_method_settings_c * const internal_settings) const;

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H u32_t get_payload_size(
		EAP_TEMPLATE_CONST eap_array_c<eap_type_value_e> * const eap_type_array) const;

#if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H u32_t get_payload_size(
		const network_key_and_index_c * const key) const;

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H u32_t get_payload_size(
		const eap_array_c<network_key_and_index_c> * const network_keys) const;

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H u32_t get_payload_size(
		const simple_config_credential_c * const credential) const;

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H u32_t get_payload_size(
		EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array) const;

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H u32_t get_payload_size(
		const eap_variable_data_c * const selector,
		const eap_config_value_c * const configuration_option) const;

	//- - - - - - - - - - - - - - - - - - - - - - - - - 

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_structured_parameter_header(
		const eap_tlv_message_type_e type,
		const u32_t length);


	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const eap_tlv_message_type_e type,
		const u32_t integer);


	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const u64_t long_integer);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const u32_t integer);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const u16_t integer);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const u8_t byte_integer);


	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const i32_t integer);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const i16_t integer);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const i8_t byte_integer);


	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const bool boolean);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const eap_status_e status);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const eapol_key_authentication_type_e authentication_type);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const eapol_key_802_11_authentication_mode_e mode);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const eap_tlv_message_type_function_e function);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const eap_variable_data_c * const variable_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const eap_am_network_id_c * const network_id);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const eap_buf_chain_wr_c * const packet_buffer);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const eapol_session_key_c * const session_key);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const abs_eap_state_notification_c * const state);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const eap_type_value_e eap_type);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const eap_general_header_base_c * const packet_data,
		const u32_t packet_length);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const eap_method_settings_c * const internal_settings);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const eap_certificate_entry_c * const internal_settings);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<u16_t> * const ushort_array);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_certificate_entry_c> * const cert_array);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_type_value_e> * const eap_type_array);

#if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array);
	
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e add_parameter_data(
		const eap_variable_data_c * const selector,
		const eap_config_value_c * const configuration_option);

	//- - - - - - - - - - - - - - - - - - - - - - - - - 

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const integer_header,
		u64_t * const value);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const integer_header,
		u32_t * const value);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const integer_header,
		u16_t * const value);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const integer_header,
		u8_t * const value);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const integer_header,
		i32_t * const value);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const integer_header,
		i16_t * const value);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const integer_header,
		i8_t * const value);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const function_header,
		eap_tlv_message_type_function_e * const function);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const network_id_header,
		eap_am_network_id_c * const new_network_id);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const variable_data_header,
		eap_variable_data_c * const variable_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const session_key_header,
		eapol_session_key_c * const session_key);
	
	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const state_header,
		eap_state_notification_c * * const state);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const eap_type_header,
		eap_type_value_e * const eap_type);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const settings_header,
		eap_method_settings_c * const settings);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const settings_header,
		eap_certificate_entry_c * const settings);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const settings_header,
		eap_array_c<u16_t> * const settings);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const settings_header,
		eap_array_c<eap_type_value_e> * const settings);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const settings_header,
		eap_array_c<eap_certificate_entry_c> * const settings);

#if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const network_key_header,
		network_key_and_index_c * const network_key);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const network_keys_array_header,
		eap_array_c<network_key_and_index_c> * const network_keys_array);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const credential_array_header,
		eap_array_c<simple_config_credential_c> * const credential_array);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e get_parameter_data(
		const eap_tlv_header_c * const credential_header,
		simple_config_credential_c * const credential);

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

	//- - - - - - - - - - - - - - - - - - - - - - - - - 

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		eap_am_network_id_c * const network_id);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		eap_variable_data_c * const variable_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		const eap_tlv_message_type_e type,
		eap_status_e * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		eap_array_c<eap_am_network_id_c> * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		eap_state_notification_c * * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		eapol_RSNA_key_header_c::eapol_RSNA_cipher_e * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		bool * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		eap_type_value_e * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		eapol_key_authentication_type_e * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		eapol_session_key_c * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		eap_tlv_message_type_function_e * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		eapol_key_802_11_authentication_mode_e * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		eapol_RSNA_key_header_c::eapol_tkip_mic_failure_type_e * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		eapol_wlan_authentication_state_e * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		u64_t * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		u32_t * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		u16_t * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		u8_t * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		i32_t * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		i16_t * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		i8_t * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		eap_method_settings_c * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		eap_array_c<u16_t> * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		eap_array_c<eap_certificate_entry_c> * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		eap_array_c<eap_type_value_e> * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		eap_certificate_entry_c::eap_certificate_type_e * const out_data);

#if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		simple_config_Authentication_Type_e * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		simple_config_Encryption_Type_e * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		eap_array_c<simple_config_credential_c> * const out_data);

	EAP_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H eap_status_e read_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
		const u32_t parameter_index,
		eap_array_c<network_key_and_index_c> * const out_data);

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

	//- - - - - - - - - - - - - - - - - - - - - - - - - 

	EAP_C_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H static eap_const_string get_type_string(const eap_tlv_message_type_e type);

	EAP_C_FUNC_VISIBILITY_EAP_PROCESS_TLV_MESSAGE_DATA_H static eap_const_string get_function_string(const eap_tlv_message_type_function_e function);

	// 
	//--------------------------------------------------
}; // class eap_process_tlv_message_data_c


//--------------------------------------------------

#endif //#if !defined(_EAP_PROCESS_TLV_MESSAGE_DATA_H_)


// End.
