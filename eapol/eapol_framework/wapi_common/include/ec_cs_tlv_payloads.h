/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/ec_cs_tlv_payloads.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 9 % << Don't touch! Updated by Synergy at check-out.
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



#if !defined(_EC_CS_TLV_PAYLOADS_H_)
#define _EC_CS_TLV_PAYLOADS_H_

#if defined(USE_WAPI_CORE)

#include "eap_variable_data.h"
#include "eap_am_export.h"
#include "ec_cs_tlv_header.h"
#include "eap_core_map.h"
#include "eap_array.h"

class ec_cs_tlv_message_c;
class crypto_hmac_c;


class EAP_EXPORT ec_cs_variable_data_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	eap_variable_data_c m_data;

	ec_cs_tlv_header_c m_header;

	/// This is pointer to the next payload that have same tlv type.
	/// This link is used when multiple instances of the same tlv types are included to a message.
	ec_cs_variable_data_c * m_next_payload_with_same_tlv_type;

	bool m_is_valid;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	EAP_FUNC_IMPORT virtual ~ec_cs_variable_data_c();

	EAP_FUNC_IMPORT ec_cs_variable_data_c(abs_eap_am_tools_c * const tools);

	EAP_FUNC_IMPORT bool get_is_valid() const;

	EAP_FUNC_IMPORT bool get_is_valid_data() const;

	EAP_FUNC_IMPORT eap_status_e reset();

	EAP_FUNC_IMPORT eap_status_e set_copy_of_buffer(
		const ec_cs_tlv_type_e current_payload_code,
		const void * const buffer,
		const u32_t buffer_length);

	EAP_FUNC_IMPORT eap_status_e set_copy_of_buffer(
		const ec_cs_variable_data_c * const source);

	EAP_FUNC_IMPORT eap_status_e set_copy_of_buffer(
		const void * const buffer,
		const u32_t buffer_length);

	EAP_FUNC_IMPORT eap_status_e init_header(
		const ec_cs_tlv_type_e current_payload,
		const u32_t default_buffer_length);

	EAP_FUNC_IMPORT eap_status_e add_data(
		const void * const buffer,
		const u32_t buffer_length);

	EAP_FUNC_IMPORT eap_status_e add_data(
		const ec_cs_variable_data_c * const data);

	EAP_FUNC_IMPORT u32_t get_data_length() const;

	EAP_FUNC_IMPORT u8_t * get_data(const u32_t data_length) const;

	EAP_FUNC_IMPORT u8_t * get_data_offset(const u32_t offset, const u32_t data_length) const;

	EAP_FUNC_IMPORT const ec_cs_tlv_header_c * get_header() const;

	EAP_FUNC_IMPORT const eap_variable_data_c * get_full_tlv_buffer() const;

	EAP_FUNC_IMPORT eap_variable_data_c * get_writable_full_tlv_buffer();

	EAP_FUNC_IMPORT ec_cs_tlv_type_e get_type() const;

	EAP_FUNC_IMPORT void set_type(const ec_cs_tlv_type_e type);

	EAP_FUNC_IMPORT void add_next_payload_with_same_tlv_type(ec_cs_variable_data_c * const tlv);

	EAP_FUNC_IMPORT void set_next_payload_with_same_tlv_type(ec_cs_variable_data_c * tlv);

	EAP_FUNC_IMPORT ec_cs_variable_data_c * get_next_payload_with_same_tlv_type() const;

	EAP_FUNC_IMPORT ec_cs_variable_data_c * copy() const;

	EAP_FUNC_IMPORT void object_increase_reference_count();

	EAP_FUNC_IMPORT eap_status_e check_header() const;

	EAP_FUNC_IMPORT i32_t compare(const ec_cs_variable_data_c * right) const;

	//--------------------------------------------------
}; // class ec_cs_variable_data_c


//--------------------------------------------------


// 
class EAP_EXPORT ec_cs_tlv_payloads_c
: public abs_eap_core_map_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	/// This stores the ec_cs_variable_data_c objects using eap_variable_data selector.
	eap_core_map_c<ec_cs_variable_data_c, abs_eap_core_map_c, eap_variable_data_c> m_payload_map;

	/// This stores the same ec_cs_variable_data_c objects to array.
	/// This is to speed the sequential check of all payloads.
	eap_array_c<ec_cs_variable_data_c> m_read_payloads;

	/// This index is used when payloads are retrieved in order.
	u32_t m_payload_index;

	bool m_is_client;

	bool m_is_valid;

	eap_status_e verify_padding(
		const u8_t * const possible_padding,
		const u32_t possible_padding_length);

	eap_status_e get_tlv_data(
		const ec_cs_tlv_type_e copied_tlv_type,
		void * const data,
		const u32_t data_length) const;

	/**
	 * This function parses each payload tlvs.
	 * @return If payload tlv is illegal function returns eap_status_header_corrupted.
	 * If payload tlv is unknown function returns eap_status_unsupported_payload.
	 */
	EAP_FUNC_IMPORT eap_status_e parse_generic_payload(
		const ec_cs_tlv_type_e current_payload, ///< This is the type of current payload tlv.
		const ec_cs_tlv_header_c * const payload ///< This is the current parsed payload.
		);

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	EAP_FUNC_IMPORT virtual ~ec_cs_tlv_payloads_c();

	EAP_FUNC_IMPORT ec_cs_tlv_payloads_c(
		abs_eap_am_tools_c * const tools,
		const bool true_when_is_client);

	EAP_FUNC_IMPORT ec_cs_variable_data_c * get_tlv_pointer(
		const ec_cs_tlv_type_e current_payload,
		u32_t index) const;

	EAP_FUNC_IMPORT ec_cs_variable_data_c * get_tlv_pointer(
		const ec_cs_tlv_type_e current_payload) const;


	EAP_FUNC_IMPORT u32_t get_tlv_count() const;

	EAP_FUNC_IMPORT ec_cs_variable_data_c * get_tlv(const u32_t tlv_index) const;

	/**
	 * This function adds new_payload object to payloads.
	 * NOTE the data is NOT copied.
	 */
	EAP_FUNC_IMPORT eap_status_e add_tlv(
		ec_cs_variable_data_c *new_payload);

	/**
	 * This function copies the selected tlv from source to payloads.
	 */
	EAP_FUNC_IMPORT eap_status_e copy_tlv(
		const ec_cs_tlv_payloads_c * const source,
		const ec_cs_tlv_type_e tlv);

	/**
	 * This function copies the tlv data to payloads.
	 */
	EAP_FUNC_IMPORT eap_status_e copy_tlv_data(
		const ec_cs_tlv_type_e current_payload,
		const void * const data,
		const u32_t data_length);

	/**
	 * This function parses the payloads starting from specified payload (p_payload).
	 * Function parses all payloads from the buffer.
	 * Payloads are stored to member variables.
	 * @return If the length of the buffer and sum of the length of all payloads does not match
	 * function returns eap_status_header_corrupted.
	 * Also error is returned when illegal payload tlv is recognised.
	 */
	EAP_FUNC_IMPORT eap_status_e parse_ec_cs_payloads(
		void * const message_buffer, ///< This is the start of the message buffer.
		u32_t * const buffer_length, ///< This is the length of the buffer. This must match with the length of all payloads.
		u32_t * const padding_length ///< Length of possible padding is set to this variable.
		);

	EAP_FUNC_IMPORT eap_status_e check_payloads_existense(
		const ec_cs_tlv_type_e * const needed_payloads,
		const u32_t count_of_needed_payloads) const;

	/**
	 * This function checks all required AVPs are received.
	 */
	EAP_FUNC_IMPORT eap_status_e check_payloads_existense(
		EAP_TEMPLATE_CONST eap_array_c<ec_cs_tlv_type_e> * const needed_payloads) const;

	EAP_FUNC_IMPORT bool get_is_valid() const;

	EAP_FUNC_IMPORT eap_status_e create_ec_cs_tlv_message(
		ec_cs_tlv_message_c * const new_ec_cs_tlv_message_data,
		const bool add_payloads) const;

	EAP_FUNC_IMPORT eap_status_e reset();

	EAP_FUNC_IMPORT ec_cs_tlv_payloads_c * copy() const;

	//--------------------------------------------------
}; // class ec_cs_tlv_payloads_c

#endif //#if defined(USE_WAPI_CORE)

#endif //#if !defined(_EC_CS_TLV_PAYLOADS_H_)

//--------------------------------------------------

// End.
