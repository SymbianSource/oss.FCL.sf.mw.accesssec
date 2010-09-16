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
* %version: 3.1.2 %
*/

#if !defined(_GSMSIM_HEADER_H_)
#define _GSMSIM_HEADER_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TYPE_GSMSIM_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H 
	#define EAP_FUNC_EXPORT_EAP_TYPE_GSMSIM_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_GSMSIM_HEADER_H 
#elif defined(EAP_EXPORT_EAP_TYPE_GSMSIM_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_GSMSIM_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_GSMSIM_HEADER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_GSMSIM_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_GSMSIM_HEADER_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_tools.h"
#include "eap_header.h"
#include "eap_type_gsmsim_types.h"

/** @file */

const u32_t TRACE_FLAGS_GSMSIM_ERROR = eap_am_tools_c::eap_trace_mask_error;


//----------------------------------------------------------------------------


/// This class defines the attribute payload header of GSMSIM EAP-type.
/**
 * Here is a figure of attribute payload header of GSMSIM EAP-type.
 * Attribute payload data is (m_length*4)-sizeof(gsmsim_payload_AT_header_c)
 * data octets that follows gsmsim_payload_AT_header_c.
 * @code
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Type         |    Length     |    Value ...                  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Attribute payload data ...
 *  +-+-+-+-+-+-+-+-+-+-+-
 * @endcode
 *
 */
class EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H gsmsim_payload_AT_header_c
: public eap_general_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	enum offsets
	{
		m_type_offset = 0ul,
		m_length_offset = m_type_offset+sizeof(u8_t),
		m_reserved_offset = m_length_offset+sizeof(u8_t),
		m_data_offset = m_reserved_offset+sizeof(u16_t),
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H virtual ~gsmsim_payload_AT_header_c();

	// 
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H gsmsim_payload_AT_header_c(
		abs_eap_am_tools_c * const tools,
		void * const header_buffer,
		const u32_t header_buffer_length);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H gsmsim_payload_AT_type_e get_current_payload() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H u16_t get_payload_length() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H u16_t get_reserved() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H u32_t get_data_length() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H static u16_t get_header_length();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H static u16_t get_max_payload_data_length();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H u8_t * get_data(const u32_t contignuous_bytes) const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H u8_t * get_data_offset(const u32_t offset, const u32_t contignuous_bytes) const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H u8_t * get_next_header() const;

	// Mostly this is zero.
	// With some attributes this is used for special purposes.
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H void set_reserved(const u16_t reserved);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H void set_current_payload(const gsmsim_payload_AT_type_e p_current_payload);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H void set_data_length(const u16_t p_data_length);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H void reset_header(const u16_t data_length);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H static eap_const_string get_payload_AT_string(const gsmsim_payload_AT_type_e payload_type);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H eap_const_string get_payload_AT_string() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H eap_status_e check_header() const;

	// 
	//--------------------------------------------------
}; // class gsmsim_payload_AT_header_c



//----------------------------------------------------------------------------


/// This class defines header of GSMSIM EAP-type.
/**
 * Here is a figure of header of GSMSIM EAP-type.
 * Subtype-Data is m_length-sizeof(gsmsim_header_c) data octets that follows gsmsim_header_c.
 * @code
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Code      |  Identifier   |            Length             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Type=18      |    Subtype    |         Reserved = 0          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Subtype-Data...
 *  +-+-+-+-+-+-+-+-+-+-+-
 * @endcode
 *
 */
class EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H gsmsim_header_c
: public eap_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	enum delta_offsets
	{
		m_subtype_delta_offset = 0ul, // This is offset from the end of the type field. NOTE type field could be extented 8 bytes in length.
		m_reserved_delta_offset = m_subtype_delta_offset+sizeof(u8_t),
		m_data_delta_offset = m_reserved_delta_offset+sizeof(u16_t),
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H virtual ~gsmsim_header_c();

	// 
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H gsmsim_header_c(
		abs_eap_am_tools_c * const tools,
		u8_t * const header_buffer,
		const u32_t header_buffer_length);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H gsmsim_subtype_e get_subtype() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H u16_t get_data_length() const;

	/// This returns the length of EAP-header, EAP-type, subtype and reserved fields.
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H u32_t get_header_length() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H u32_t get_sub_type_offset() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H u8_t * get_data_offset(const u32_t offset, const u32_t contignuous_bytes) const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H u8_t * get_data(const u32_t contignuous_bytes) const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H u16_t get_reserved() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H eap_status_e check_header() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H eap_const_string get_subtype_string() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H eap_const_string get_code_string() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H eap_const_string get_eap_type_string() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H void set_reserved(const u16_t reserved);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H void set_subtype(const gsmsim_subtype_e p_subtype);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H void set_data_length(
		const u32_t p_data_length,
		const bool expanded_type_when_true);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_HEADER_H void reset_header(
		const u32_t buffer_length,
		const bool expanded_type_when_true);

	// 
	//--------------------------------------------------
}; // class gsmsim_header_c

//--------------------------------------------------

/// Macro traces payload type and data.
#define EAP_GSMSIM_TRACE_PAYLOAD(prefix, payload) \
	{ \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("%s (0x%08x): current payload 0x%04x=%s, data length 0x%04x.\n"), \
			prefix, (payload)->get_header_buffer((payload)->get_payload_length()), (payload)->get_current_payload(), \
			(payload)->get_payload_AT_string(), (payload)->get_data_length())); \
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, (EAPL("payload"), \
			(payload)->get_header_buffer((payload)->get_payload_length()), \
			(payload)->get_payload_length())); \
	}

//--------------------------------------------------

#endif //#if !defined(_GSMSIM_HEADER_H_)



// End.
