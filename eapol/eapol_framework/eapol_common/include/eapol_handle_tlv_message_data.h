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




#if !defined(_EAP_CREATE_TLV_MESSAGE_DATA_H_)
#define _EAP_CREATE_TLV_MESSAGE_DATA_H_

#include "eap_am_types.h"
#include "eap_tools.h"
#include "eap_array.h"
#include "eap_tlv_message_data.h"
#include "eap_expanded_type.h"


enum eapol_tlv_message_type_e
{
	eapol_tlv_message_type_none                                 = 0,
	eapol_tlv_message_type_array                                = 1,
	eapol_tlv_message_type_boolean                              = 2,
	eapol_tlv_message_type_eap_protocol_layer                   = 3,
	eapol_tlv_message_type_eap_state_notification               = 4,
	eapol_tlv_message_type_eap_status                           = 5,
	eapol_tlv_message_type_eap_type                             = 6,
	eapol_tlv_message_type_eapol_key_802_11_authentication_mode = 7,
	eapol_tlv_message_type_eapol_key_authentication_type        = 8,
	eapol_tlv_message_type_eapol_key_type                       = 9,
	eapol_tlv_message_type_eapol_tkip_mic_failure_type          = 10,
	eapol_tlv_message_type_eapol_wlan_authentication_state      = 11,
	eapol_tlv_message_type_error                                = 12,
	eapol_tlv_message_type_function                             = 13,
	eapol_tlv_message_type_network_id                           = 14,
	eapol_tlv_message_type_network_key                          = 15,
	eapol_tlv_message_type_protected_setup_credential           = 16,
	eapol_tlv_message_type_RSNA_cipher                          = 17,
	eapol_tlv_message_type_session_key                          = 18,
	eapol_tlv_message_type_u8_t                                 = 19,
	eapol_tlv_message_type_u16_t                                = 20,
	eapol_tlv_message_type_u32_t                                = 21,
	eapol_tlv_message_type_u64_t                                = 22,
	eapol_tlv_message_type_variable_data                        = 23,
};


enum eapol_tlv_message_type_function_e
{
	eapol_tlv_message_type_function_none                                        = 0,
	eapol_tlv_message_type_function_check_pmksa_cache                           = 1,
	eapol_tlv_message_type_function_start_authentication                        = 2,
	eapol_tlv_message_type_function_complete_association                        = 3,
	eapol_tlv_message_type_function_disassociation                              = 4,
	eapol_tlv_message_type_function_start_preauthentication                     = 5,
	eapol_tlv_message_type_function_start_reassociation                         = 6,
	eapol_tlv_message_type_function_complete_reassociation                      = 7,
	eapol_tlv_message_type_function_start_WPXM_reassociation                    = 8,
	eapol_tlv_message_type_function_complete_WPXM_reassociation                 = 9,
	eapol_tlv_message_type_function_packet_process                              = 10,
	eapol_tlv_message_type_function_tkip_mic_failure                            = 11,
	eapol_tlv_message_type_function_eap_acknowledge                             = 12,
	eapol_tlv_message_type_function_update_header_offset                        = 13,
	eapol_tlv_message_type_function_complete_check_pmksa_cache                  = 14,
	eapol_tlv_message_type_function_packet_send                                 = 15,
	eapol_tlv_message_type_function_associate                                   = 16,
	eapol_tlv_message_type_function_disassociate                                = 17,
	eapol_tlv_message_type_function_packet_data_session_key                     = 18,
	eapol_tlv_message_type_function_state_notification                          = 19,
	eapol_tlv_message_type_function_reassociate                                 = 20,
	eapol_tlv_message_type_function_update_wlan_database_reference_values       = 21,
	eapol_tlv_message_type_function_complete_start_WPXM_reassociation           = 22,
	eapol_tlv_message_type_function_new_protected_setup_credentials             = 23,
	eapol_tlv_message_type_function_illegal_value, // Keep this the last value.
};


enum eapol_message_payload_index_e
{
	eapol_message_payload_index_function        = 0,
	eapol_message_payload_index_first_parameter = 1,
};


/** @file */

class eap_variable_data_c;
class eap_am_network_id_c;
class eap_buf_chain_wr_c;
class eapol_session_key_c;
class abs_eap_state_notification_c;
class eap_state_notification_c;
class network_key_and_index_c;
class simple_config_credential_c;

//----------------------------------------------------------------------------


/// This class defines functions to add and parse message data composed
/// of Attribute-Value Pairs (See eap_tlv_header_c) to/from eap_tlv_message_data_c object.
class EAP_EXPORT eapol_handle_tlv_message_data_c
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
	 * The destructor of the eapol_handle_tlv_message_data_c class does nothing.
	 */
	EAP_FUNC_IMPORT virtual ~eapol_handle_tlv_message_data_c();

	/**
	 * The constructor of the eapol_handle_tlv_message_data_c class simply initializes the attributes.
	 */
	EAP_FUNC_IMPORT eapol_handle_tlv_message_data_c(
		abs_eap_am_tools_c * const tools);

	/**
	 * This function should increase reference count.
	 */
	EAP_FUNC_IMPORT void object_increase_reference_count();

	/**
	 * This function should first decrease reference count
	 * and second return the remaining reference count.
	 * Reference count must not be decreased when it is zero.
	 */
	EAP_FUNC_IMPORT u32_t object_decrease_reference_count();

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	EAP_FUNC_IMPORT bool get_is_valid();

	//- - - - - - - - - - - - - - - - - - - - - - - - - 

	EAP_FUNC_IMPORT u32_t get_payload_size(
		const eap_am_network_id_c * const network_id) const;

	EAP_FUNC_IMPORT u32_t get_payload_size(
		const abs_eap_state_notification_c * const state) const;

	EAP_FUNC_IMPORT u32_t get_payload_size(
		const eapol_session_key_c * const session_key) const;

#if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_IMPORT u32_t get_payload_size(
		network_key_and_index_c * key) const;

	EAP_FUNC_IMPORT u32_t get_payload_size(
		EAP_TEMPLATE_CONST eap_array_c<network_key_and_index_c> * network_keys) const;

	EAP_FUNC_IMPORT u32_t get_payload_size(
		simple_config_credential_c * const credential) const;

	EAP_FUNC_IMPORT u32_t get_payload_size(
		EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array) const;

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

	//- - - - - - - - - - - - - - - - - - - - - - - - - 

	EAP_FUNC_IMPORT eap_status_e add_structured_parameter_header(
		const eapol_tlv_message_type_e type,
		const u32_t length);


	EAP_FUNC_IMPORT eap_status_e add_parameter_data(
		const eapol_tlv_message_type_e type,
		const u32_t integer);

	EAP_FUNC_IMPORT eap_status_e add_parameter_data(
		const u64_t long_integer);

	EAP_FUNC_IMPORT eap_status_e add_parameter_data(
		const u32_t integer);

	EAP_FUNC_IMPORT eap_status_e add_parameter_data(
		const u16_t integer);

	EAP_FUNC_IMPORT eap_status_e add_parameter_data(
		const u8_t byte_integer);

	EAP_FUNC_IMPORT eap_status_e add_parameter_data(
		const bool boolean);

	EAP_FUNC_IMPORT eap_status_e add_parameter_data(
		const eap_status_e status);

	EAP_FUNC_IMPORT eap_status_e add_parameter_data(
		const eapol_tlv_message_type_function_e function);

	EAP_FUNC_IMPORT eap_status_e add_parameter_data(
		const eap_variable_data_c * const variable_data);

	EAP_FUNC_IMPORT eap_status_e add_parameter_data(
		const eap_am_network_id_c * const network_id);

	EAP_FUNC_IMPORT eap_status_e add_parameter_data(
		const eap_buf_chain_wr_c * const packet_buffer);

	EAP_FUNC_IMPORT eap_status_e add_parameter_data(
		const eapol_session_key_c * const session_key);

	EAP_FUNC_IMPORT eap_status_e add_parameter_data(
		const abs_eap_state_notification_c * const state);

	EAP_FUNC_IMPORT eap_status_e add_parameter_data(
		const eap_type_value_e eap_type);

	EAP_FUNC_IMPORT eap_status_e add_parameter_data(
		const eap_general_header_base_c * const packet_data);
	
	EAP_FUNC_IMPORT eap_status_e get_parameter_data(
		const eap_tlv_header_c * const credential_header,
		simple_config_credential_c * const credential);

#if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_IMPORT eap_status_e add_parameter_data(
		EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array);
	
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

	//- - - - - - - - - - - - - - - - - - - - - - - - - 

	EAP_FUNC_IMPORT eap_status_e get_parameter_data(
		const eap_tlv_header_c * const integer_header,
		u64_t * const value);

	EAP_FUNC_IMPORT eap_status_e get_parameter_data(
		const eap_tlv_header_c * const integer_header,
		u32_t * const value);

	EAP_FUNC_IMPORT eap_status_e get_parameter_data(
		const eap_tlv_header_c * const integer_header,
		u16_t * const value);

	EAP_FUNC_IMPORT eap_status_e get_parameter_data(
		const eap_tlv_header_c * const integer_header,
		u8_t * const value);

	EAP_FUNC_IMPORT eap_status_e get_parameter_data(
		const eap_tlv_header_c * const function_header,
		eapol_tlv_message_type_function_e * const function);

	EAP_FUNC_IMPORT eap_status_e get_parameter_data(
		const eap_tlv_header_c * const network_id_header,
		eap_am_network_id_c * const new_network_id);

	EAP_FUNC_IMPORT eap_status_e get_parameter_data(
		const eap_tlv_header_c * const variable_data_header,
		eap_variable_data_c * const variable_data);

	EAP_FUNC_IMPORT eap_status_e get_parameter_data(
		const eap_tlv_header_c * const session_key_header,
		eapol_session_key_c * const session_key);
	
	EAP_FUNC_IMPORT eap_status_e get_parameter_data(
		const eap_tlv_header_c * const state_header,
		eap_state_notification_c * * const state);

	EAP_FUNC_IMPORT eap_status_e get_parameter_data(
		const eap_tlv_header_c * const eap_type_header,
		eap_type_value_e * const eap_type);

#if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_IMPORT eap_status_e get_parameter_data(
		const eap_tlv_header_c * const network_key_header,
		network_key_and_index_c * const network_key);

	EAP_FUNC_IMPORT eap_status_e get_parameter_data(
		const eap_tlv_header_c * const network_keys_array_header,
		eap_array_c<network_key_and_index_c> * const network_keys_array);

	EAP_FUNC_IMPORT eap_status_e get_parameter_data(
		const eap_tlv_header_c * const credential_array_header,
		eap_array_c<simple_config_credential_c> * const credential_array);

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

	//- - - - - - - - - - - - - - - - - - - - - - - - - 

	EAP_FUNC_IMPORT eap_const_string get_type_string(const eapol_tlv_message_type_e type);

	EAP_FUNC_IMPORT eap_const_string get_function_string(const eapol_tlv_message_type_function_e function);

	// 
	//--------------------------------------------------
}; // class eapol_handle_tlv_message_data_c


//--------------------------------------------------

#endif //#if !defined(_EAP_CREATE_TLV_MESSAGE_DATA_H_)


// End.
