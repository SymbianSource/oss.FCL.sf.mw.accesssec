/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/wai_variable_data.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 15 % << Don't touch! Updated by Synergy at check-out.
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



#if !defined(_WAI_VARIABLE_DATA_H_)
#define _WAI_VARIABLE_DATA_H_

#if defined(USE_WAPI_CORE)

#include "eap_variable_data.h"
#include "eap_am_export.h"
#include "wai_tlv_header.h"
#include "ec_cs_tlv_header.h"
#include "eap_core_map.h"
#include "wai_protocol_packet_header.h"
#include "wapi_strings.h"

class wai_message_c;
class crypto_hmac_c;


class EAP_EXPORT wai_variable_data_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	eap_variable_data_c m_data; ///< This is used for all payloads.

	wai_tlv_header_c m_wai_tlv_header; ///< This is used for payloads with 8-bit type and 16-bit length fields.

	ec_cs_tlv_header_c m_ec_cs_tlv_header; ///< This is used for payloads with 16-bit type and 16-bit length fields.

	/// This tells which payload this is and what type the payload is.
	wai_payload_type_e m_payload_type;

	/// This is pointer to the next payload that have same tlv type.
	/// This link is used when multiple instances of the same tlv types are included to a message.
	wai_variable_data_c * m_next_payload_with_same_tlv_type;

	bool m_is_valid;

	eap_status_e set_header_buffer(
		const wai_payload_type_e current_payload,
		const bool write_header);

	eap_status_e set_header_buffer(
		const wai_payload_type_e current_payload,
		const bool write_header,
		const u32_t data_length);

	wai_payload_type_size_e get_type_class(const wai_payload_type_e current_payload) const;

	u32_t get_header_length(
		const wai_payload_type_e current_payload) const;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	EAP_FUNC_IMPORT virtual ~wai_variable_data_c();

	EAP_FUNC_IMPORT wai_variable_data_c(abs_eap_am_tools_c * const tools);

	EAP_FUNC_IMPORT bool get_is_valid() const;

	EAP_FUNC_IMPORT bool get_is_valid_data() const;

	EAP_FUNC_IMPORT eap_status_e reset();

	EAP_FUNC_IMPORT eap_status_e create(
		const wai_payload_type_e current_payload,
		const void * const buffer, // Buffer includes only data.
		const u32_t buffer_length); // Buffer_length includes only data.

	EAP_FUNC_IMPORT eap_status_e create(
		const wai_payload_type_e current_payload,
		const eap_variable_data_c * const buffer); // Buffer includes only data.

	EAP_FUNC_IMPORT eap_status_e set_buffer(
		const wai_payload_type_e current_payload,
		const void * const buffer, // Buffer includes the header and data.
		const u32_t buffer_length); // Buffer_length includes header and data.


	EAP_FUNC_IMPORT eap_status_e set_copy_of_buffer(
		const wai_payload_type_e current_payload,
		const void * const buffer, // Buffer includes the header and data.
		const u32_t buffer_length); // Buffer_length includes header and data.

	EAP_FUNC_IMPORT eap_status_e set_copy_of_buffer(
		const wai_payload_type_e current_payload,
		const eap_variable_data_c * const buffer); // Buffer includes the header and data.

	EAP_FUNC_IMPORT eap_status_e set_copy_of_buffer(
		const wai_variable_data_c * const source); // Buffer includes the header and data.

	EAP_FUNC_IMPORT eap_status_e init_header(
		const wai_payload_type_e current_payload,
		const u32_t default_buffer_length);


	EAP_FUNC_IMPORT eap_status_e add_data(
		const wai_payload_type_e new_payload,
		const eap_variable_data_c * const buffer);

	EAP_FUNC_IMPORT eap_status_e add_data(
		const wai_payload_type_e new_payload,
		const void * const buffer,
		const u32_t buffer_length);

	EAP_FUNC_IMPORT eap_status_e add_data(
		const wai_variable_data_c * const data);


	EAP_FUNC_IMPORT wai_payload_type_size_e get_type_class() const;

	EAP_FUNC_IMPORT u32_t get_data_length() const;

	EAP_FUNC_IMPORT u32_t get_type_data_length() const;

	EAP_FUNC_IMPORT u32_t get_type_header_length() const;

	EAP_FUNC_IMPORT u8_t * get_type_data_offset(
		const u32_t offset,
		const u32_t data_length) const;

	EAP_FUNC_IMPORT u8_t * get_type_data(
		const u32_t data_length) const;

	EAP_FUNC_IMPORT u8_t * get_data(const u32_t data_length) const;

	EAP_FUNC_IMPORT u8_t * get_data_offset(const u32_t offset, const u32_t data_length) const;

	EAP_FUNC_IMPORT const wai_tlv_header_c * get_wai_tlv_header() const;

	EAP_FUNC_IMPORT const ec_cs_tlv_header_c * get_ec_cs_tlv_header() const;

	EAP_FUNC_IMPORT const eap_variable_data_c * get_full_tlv_buffer() const;

	EAP_FUNC_IMPORT eap_variable_data_c * get_writable_full_tlv_buffer();

	EAP_FUNC_IMPORT wai_payload_type_e get_payload_type() const;

	EAP_FUNC_IMPORT wai_variable_data_c * get_next_payload_with_same_tlv_type() const;


	EAP_FUNC_IMPORT eap_status_e set_payload_type(const wai_payload_type_e payload_type);

	EAP_FUNC_IMPORT void add_next_payload_with_same_tlv_type(wai_variable_data_c * const tlv);

	EAP_FUNC_IMPORT void set_next_payload_with_same_tlv_type(wai_variable_data_c * tlv);

	EAP_FUNC_IMPORT wai_variable_data_c * copy() const;

	EAP_FUNC_IMPORT void object_increase_reference_count();

	EAP_FUNC_IMPORT eap_status_e check_header() const;

	EAP_FUNC_IMPORT i32_t compare(const wai_variable_data_c * right) const;


	EAP_FUNC_IMPORT static wai_payload_type_e convert_to_wai_payload_type(const wai_tlv_type_e tlv_type);

	EAP_FUNC_IMPORT static wai_tlv_type_e convert_to_wai_tlv_type(const wai_payload_type_e payload_type);

	EAP_FUNC_IMPORT static wai_certificate_identifier_e convert_to_wai_certificate_identifier(const wai_payload_type_e payload_type);

	EAP_FUNC_IMPORT static ec_cs_tlv_type_e convert_to_ec_cs_tlv_type(const wai_payload_type_e payload_type);


	EAP_FUNC_IMPORT eap_const_string get_wai_payload_type_string() const;

	/// Function traces wai_tlv_header_c type and data.
	static void wai_variable_data_trace(
		abs_eap_am_tools_c * const tools,
		eap_format_string prefix,
		const wai_variable_data_c * const wai_data,
		const bool when_true_is_client);


	//--------------------------------------------------
}; // class wai_variable_data_c

//--------------------------------------------------


#define WAI_VARIABLE_DATA_TRACE(tools, prefix, wai_data, when_true_is_client) { wai_variable_data_c::wai_variable_data_trace(tools, prefix, wai_data, when_true_is_client); }

//--------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

#endif //#if !defined(_WAI_VARIABLE_DATA_H_)

//--------------------------------------------------

// End.
