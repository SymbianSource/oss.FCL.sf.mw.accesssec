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




#if !defined(_EAP_RADIUS_PAYLOAD_HEADER_H_)
#define _EAP_RADIUS_PAYLOAD_HEADER_H_

#include "eap_tools.h"
#include "eap_header.h"
#include "eap_radius_types.h"
#include "eap_diameter_avp_code.h"

/** @file */

const u32_t TRACE_FLAGS_RADIUS_ERROR = eap_am_tools_c::eap_trace_mask_error;


const u32_t EAP_RADIUS_VENDOR_ID_LENGTH = 4ul*sizeof(u8_t);

const u32_t EAP_RADIUS_VENDOR_ID_MS = 311ul;

const u32_t EAP_RADIUS_MS_MPPE_KEY_LENGTH     = 32u;
const u32_t EAP_RADIUS_MS_MPPE_KEY_DATA_LENGTH = 50ul;

//----------------------------------------------------------------------------


/// This class defines the attribute payload header of RADIUS EAP-type.
/**
 * Here is a figure of attribute payload header of RADIUS EAP-type.
 * Attribute payload data is (m_length)-sizeof(eap_radius_attribute_header_c)
 * data octets that follows eap_radius_attribute_header_c.
 * @code
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Type         |    Length     |    Value ...                   
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * @endcode
 *
 */
class EAP_EXPORT eap_radius_attribute_header_c
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
		m_data_offset = m_length_offset+sizeof(u8_t),
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	EAP_FUNC_IMPORT virtual ~eap_radius_attribute_header_c();

	// 
	EAP_FUNC_IMPORT eap_radius_attribute_header_c(
		abs_eap_am_tools_c * const tools,
		void * const header_buffer,
		const u32_t header_buffer_length);

	EAP_FUNC_IMPORT eap_diameter_avp_code_c get_current_payload() const;

	EAP_FUNC_IMPORT u16_t get_length() const;

	EAP_FUNC_IMPORT u32_t get_data_length() const;

	EAP_FUNC_IMPORT static u16_t get_header_length();

	EAP_FUNC_IMPORT static u16_t get_max_attribute_data_length();

	EAP_FUNC_IMPORT u8_t * get_data_offset(const u32_t offset, const u32_t contignuous_bytes) const;

	EAP_FUNC_IMPORT u8_t * get_next_header() const;


	EAP_FUNC_IMPORT void set_current_payload(const eap_diameter_avp_code_c p_current_payload);

	EAP_FUNC_IMPORT void set_data_length(const u16_t p_data_length);

	EAP_FUNC_IMPORT void reset_header(const u16_t data_length);

	EAP_FUNC_IMPORT eap_const_string get_payload_type_string() const;

	EAP_FUNC_IMPORT eap_status_e check_header() const;

	// 
	//--------------------------------------------------
}; // class eap_radius_attribute_header_c


//--------------------------------------------------

/// Macro traces payload type and data.
#define EAP_RADIUS_TRACE_PAYLOAD(prefix, payload) \
	{ \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("%s (0x%08x): current payload 0x%08x=%s, data length 0x%04x.\n"), \
			prefix, \
			(payload)->get_header_buffer((payload)->get_length()), \
			(payload)->get_current_payload().get_vendor_code(), \
			(payload)->get_payload_type_string(), \
			(payload)->get_data_length())); \
		EAP_TRACE_DATA_DEBUG(m_am_tools, \
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("payload"), \
			(payload)->get_header_buffer((payload)->get_length()), \
			(payload)->get_length())); \
	}

//--------------------------------------------------

#endif //#if !defined(_EAP_RADIUS_PAYLOAD_HEADER_H_)



// End.
