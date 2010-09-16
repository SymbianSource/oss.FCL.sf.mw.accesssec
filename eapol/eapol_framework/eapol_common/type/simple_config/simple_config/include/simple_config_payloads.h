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
* Description:  Defines payloads of protected setup message.
*
*/

/*
* %version: 24.1.3 %
*/

#if !defined(_SIMPLE_CONFIG_PAYLOADS_H_)
#define _SIMPLE_CONFIG_PAYLOADS_H_

#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_SIMPLE_CONFIG_PAYLOADS_H)
	#define EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H 
	#define EAP_C_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H 
	#define EAP_FUNC_EXPORT_SIMPLE_CONFIG_PAYLOADS_H 
	#define EAP_C_FUNC_EXPORT_SIMPLE_CONFIG_PAYLOADS_H 
#elif defined(EAP_EXPORT_SIMPLE_CONFIG_PAYLOADS_H)
	#define EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_SIMPLE_CONFIG_PAYLOADS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_SIMPLE_CONFIG_PAYLOADS_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_SIMPLE_CONFIG_PAYLOADS_H 
	#define EAP_C_FUNC_EXPORT_SIMPLE_CONFIG_PAYLOADS_H 
#endif
// End: added by script change_export_macros.sh.
#include "simple_config_tlv_header.h"
#include "simple_config_attribute_type.h"
#include "eap_core_map.h"
#include "eap_array.h"

class simple_config_message_c;
class crypto_hmac_c;

class EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H simple_config_variable_data_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	eap_variable_data_c m_data;

	simple_config_tlv_header_c m_header;

	/// This is pointer to the next payload that have same attribute type.
	/// This link is used when multiple instances of the same attribute types are included to a message.
	simple_config_variable_data_c * m_next_payload_with_same_attribute_type;

	bool m_is_mandatory;

	bool m_is_valid;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H virtual ~simple_config_variable_data_c();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H simple_config_variable_data_c(abs_eap_am_tools_c * const tools);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H bool get_is_valid() const;

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_status_e set_copy_of_buffer(
		const simple_config_Attribute_Type_e current_payload_code,
		const bool is_mandatory,
		const void * const buffer,
		const u32_t buffer_length);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_status_e add_data(
		const void * const buffer,
		const u32_t buffer_length);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H u32_t get_data_length() const;

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H u8_t * get_data(const u32_t data_length) const;

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H simple_config_tlv_header_c * get_header();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_variable_data_c * get_full_attribute_buffer();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H simple_config_Attribute_Type_e get_attribute_type() const;

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H bool get_is_mandatory() const;

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H void set_attribute_type(const simple_config_Attribute_Type_e type);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H void add_next_payload_with_same_attribute_type(simple_config_variable_data_c * const attribute);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H void set_next_payload_with_same_attribute_type(simple_config_variable_data_c * attribute);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H simple_config_variable_data_c * get_next_payload_with_same_attribute_type();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H simple_config_variable_data_c * copy() const;

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H void object_increase_reference_count();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_status_e check_header() const;

	//--------------------------------------------------
}; // class simple_config_variable_data_c


//--------------------------------------------------


// 
class EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H simple_config_payloads_c
: public abs_eap_core_map_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	/// This stores the simple_config_variable_data_c objects using eap_variable_data selector.
	eap_core_map_c<simple_config_variable_data_c, abs_eap_core_map_c, eap_variable_data_c> m_payload_map;

	/// This stores the same simple_config_variable_data_c objects to array.
	/// This is to speed the sequential check of all payloads.
	eap_array_c<simple_config_variable_data_c> m_read_payloads;

	/// This index is used when payloads are retrieved in order.
	u32_t m_payload_index;

	bool m_is_valid;

	eap_status_e verify_padding(
		const u8_t * const possible_padding,
		const u32_t possible_padding_length);

	eap_status_e get_attribute_data(
		const simple_config_Attribute_Type_e copied_attribute_type,
		void * const data,
		const u32_t data_length) const;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H virtual ~simple_config_payloads_c();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H simple_config_payloads_c(
		abs_eap_am_tools_c * const tools);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H simple_config_variable_data_c * get_attribute_pointer(
		const simple_config_Attribute_Type_e current_payload,
		u32_t index) const;

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H simple_config_variable_data_c * get_attribute_pointer(
		const simple_config_Attribute_Type_e current_payload) const;


	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H u32_t get_attribute_count() const;

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H simple_config_variable_data_c * get_attribute(const u32_t attribute_index) const;

	/**
	 * This function adds new_payload object to payloads.
	 * NOTE the data is NOT copied.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_status_e add_attribute(
		simple_config_variable_data_c *new_payload);

	/**
	 * This function copies the selected attribute from source to payloads.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_status_e copy_attribute(
		const simple_config_payloads_c * const source,
		const simple_config_Attribute_Type_e attribute);

	/**
	 * This function copies the attribute data to payloads.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_status_e copy_attribute_data(
		const simple_config_Attribute_Type_e current_payload,
		const bool is_mandatory,
		const void * const data,
		const u32_t data_length);

	/**
	 *	Function retrieves data of attribute type to data object.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_status_e get_attribute_data(
		const simple_config_Attribute_Type_e copied_attribute_type,
		eap_variable_data_c * const data) const;

	/**
	 *	Function retrieves data of attribute type to data object.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_status_e get_attribute_data(
		const simple_config_Attribute_Type_e copied_attribute_type,
		u8_t * const data) const;

	/**
	 *	Function retrieves data of attribute type to data object.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_status_e get_attribute_data(
		const simple_config_Attribute_Type_e copied_attribute_type,
		u16_t * const data) const;

	/**
	 *	Function retrieves data of attribute type to data object.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_status_e get_attribute_data(
		const simple_config_Attribute_Type_e copied_attribute_type,
		u32_t * const data) const;

	/**
	 *	Function retrieves data of attribute type to data object.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_status_e get_attribute_data(
		const simple_config_Attribute_Type_e copied_attribute_type,
		u64_t * const data) const;

	/**
	 * This function parses the payloads starting from specified payload (p_payload).
	 * Function parses all payloads from the buffer.
	 * Payloads are stored to member variables.
	 * @return If the length of the buffer and sum of the length of all payloads does not match
	 * function returns eap_status_header_corrupted.
	 * Also error is returned when illegal payload attribute is recognised.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_status_e parse_simple_config_payloads(
		void * const message_buffer, ///< This is the start of the message buffer.
		u32_t * const buffer_length, ///< This is the length of the buffer. This must match with the length of all payloads.
		u32_t * const padding_length ///< Length of possible padding is set to this variable.
		);

	/**
	 * This function parses each payload attributes.
	 * @return If payload attribute is illegal function returns eap_status_header_corrupted.
	 * If payload attribute is unknown function returns eap_status_unsupported_payload.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_status_e parse_generic_payload(
		const simple_config_Attribute_Type_e current_payload, ///< This is the type of current payload attribute.
		const simple_config_tlv_header_c * const payload ///< This is the current parsed payload.
		);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_status_e check_payloads_existense(
		const simple_config_Attribute_Type_e * const needed_payloads,
		const u32_t count_of_needed_payloads) const;

	/**
	 * This function checks all mandatory AVPs are used.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_status_e check_mandatory_payloads(
		EAP_TEMPLATE_CONST eap_array_c<simple_config_Attribute_Type_e> * const used_payloads) const;

	/**
	 * This function checks all required AVPs are received.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_status_e check_payloads_existense(
		EAP_TEMPLATE_CONST eap_array_c<simple_config_Attribute_Type_e> * const needed_payloads) const;

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H bool get_is_valid() const;

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_status_e create_simple_config_message(
		simple_config_message_c * const new_simple_config_message_data,
		const bool add_payloads) const;

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_status_e add_payloads_to_simple_config_authenticator(
		crypto_hmac_c * const hmac_sha_256,
		const bool include_authenticator_attribute) const;

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H eap_status_e reset();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_PAYLOADS_H simple_config_payloads_c * copy() const;

	//--------------------------------------------------
}; // class simple_config_payloads_c


#endif //#if !defined(_SIMPLE_CONFIG_PAYLOADS_H_)

//--------------------------------------------------



// End.
