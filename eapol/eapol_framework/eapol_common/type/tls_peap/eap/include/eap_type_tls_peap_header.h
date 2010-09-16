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

#if !defined(_EAP_TLS_PEAP_HEADER_H_)
#define _EAP_TLS_PEAP_HEADER_H_

#include "eap_tools.h"
#include "eap_header.h"
#include "tls_peap_types.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TYPE_TLS_PEAP_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H 
	#define EAP_FUNC_EXPORT_EAP_TYPE_TLS_PEAP_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_TLS_PEAP_HEADER_H 
#elif defined(EAP_EXPORT_EAP_TYPE_TLS_PEAP_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_TLS_PEAP_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_TLS_PEAP_HEADER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_TLS_PEAP_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_TLS_PEAP_HEADER_H 
#endif
// End: added by script change_export_macros.sh.


/** @file */

const u32_t TLS_PEAP_FIRST_SEQUENCE = 1u;
const u8_t TLS_PEAP_NAI_AT_BYTE = '@';


//----------------------------------------------------------------------------


/// This class defines header of TLS_PEAP EAP-type.
/**
 * Here is a figure of header of TLS_PEAP EAP-type.
 * Subtype-Data is m_length-sizeof(eap_tls_peap_header_c) data octets that follows eap_tls_peap_header_c.
 * @code
 *  EAP/TLS-header:
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Code      |   Identifier  |            Length             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Type      |     Flags     |      TLS Message Length       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     TLS Message Length        |       TLS Data...
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  PEAP-header:
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |   Identifier  |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |   Flags   |Ver|      TLS Message Length opt.  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     TLS Message Length  opt.  |       TLS Data...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * @endcode
 *
 */
class EAP_CLASS_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H eap_tls_peap_header_c
: public eap_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	enum message_fields
	{
		TLS_MESSAGE_LENGTH_FIELD_SIZE = 4u,
	};

	enum bit_shifts
	{
		m_flag_shift_reserved = 0x02,
		m_flag_shift_version = 0x00,
	};

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	enum delta_offsets
	{
		m_flag_delta_offset = 0ul,
		m_tls_length_delta_offset = m_flag_delta_offset+sizeof(u8_t),
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	enum bit_masks
	{
		m_flag_mask_tls_length_included = 0x80,
		m_flag_mask_more_fragments = 0x40,
		m_flag_mask_start = 0x20,
		m_flag_mask_reserved = 0x1c,
		m_flag_mask_version = 0x03,
	};


	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H virtual ~eap_tls_peap_header_c();

	// 
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H eap_tls_peap_header_c(
		abs_eap_am_tools_c * const tools,
		u8_t * const header_begin,
		const u32_t header_buffer_length);

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H eap_code_value_e get_eap_code() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H u8_t get_eap_identifier() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H u16_t get_eap_length() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H eap_type_value_e get_eap_type() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H u16_t get_data_length() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H u32_t get_tls_min_header_length() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H static u32_t get_tls_max_header_length();

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H u32_t get_header_length() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H u32_t get_tls_flags_offset() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H u32_t get_tls_length_offset() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H u32_t get_start_offset_of_data() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H u8_t * get_data_offset(
		abs_eap_am_tools_c * const m_am_tools,
		const u32_t offset,
		const u32_t contignuous_bytes) const;


	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H u8_t * get_data(
		abs_eap_am_tools_c * const m_am_tools,
		const u32_t contignuous_bytes) const;


	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H u8_t * get_tls_flags() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H bool get_tls_flag_bit(
		const u32_t mask) const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H u8_t get_tls_flag_value(
		const u32_t mask,
		const u32_t shift) const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H bool get_flag_tls_length_included() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H bool get_flag_more_fragments() const;
	
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H bool get_flag_start() const;
	
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H u8_t get_flag_reserved() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H u8_t get_flag_version() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H eap_status_e get_tls_message_length(
		u32_t * const tls_length) const;


	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H eap_status_e check_header(
		abs_eap_am_tools_c * const tools,
		const eap_type_value_e required_eap_type,
		const bool is_client_when_true,
		const peap_version_e peap_version,
		const bool check_peap_version_when_true) const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H eap_const_string get_code_string() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H eap_const_string get_eap_type_string() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H void set_eap_code(const eap_code_value_e p_code);

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H void set_eap_identifier(const u8_t p_identifier);

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H void set_eap_length(
		const u16_t p_length,
		const bool expanded_type_when_true);

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H void set_eap_type(
		const eap_type_value_e p_type,
		const bool expanded_type_when_true);


	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H void set_tls_flag_value(
		const u8_t value,
		const u32_t mask,
		const u32_t shift) const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H void set_tls_flag_bit(const bool flag, u32_t mask) const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H void set_flag_reserved(const u8_t reserved);

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H void set_flag_version(const u8_t version);

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H void set_flag_tls_length_included(const bool tls_length_included);

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H void set_flag_more_fragments(const bool more_fragments);

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H void set_flag_start(const bool start);


	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H void set_data_length(
		const u32_t p_data_length,
		const bool expanded_type_when_true);

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H void set_tls_message_length(const u32_t tls_length);


	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_HEADER_H void reset_header(
		abs_eap_am_tools_c * const m_am_tools,
		const eap_type_value_e required_eap_type,
		const u32_t buffer_length,
		const peap_version_e peap_version,
		const bool expanded_type_when_true);

	// 
	//--------------------------------------------------
}; // class eap_tls_peap_header_c


//--------------------------------------------------

#endif //#if !defined(_EAP_TLS_PEAP_HEADER_H_)



// End.
