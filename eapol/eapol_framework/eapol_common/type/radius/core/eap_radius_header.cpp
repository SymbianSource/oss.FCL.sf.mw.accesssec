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

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 105 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_radius_header.h"
#include "eap_radius_header_string.h"

//--------------------------------------------------

EAP_FUNC_EXPORT eap_radius_header_base_c::~eap_radius_header_base_c()
{
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_radius_header_base_c::eap_radius_header_base_c(
	abs_eap_am_tools_c * const tools,
	void * const header_begin,
	const u32_t header_buffer_length)
	: eap_general_header_base_c(tools, header_begin, header_buffer_length)
	, m_am_tools(tools)
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_radius_header_base_c::get_header_length()
{
	return m_attributes_offset;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_radius_code_value_e eap_radius_header_base_c::get_code() const
{
	const u8_t * const code_data = get_header_offset(m_code_offset, sizeof(u8_t));
	if (code_data != 0)
	{
		return static_cast<eap_radius_code_value_e>(*code_data);
	}
	else
	{
		return eap_radius_code_none;
	}
}

/// This function returns the authenticator field of RADIUS-header.
EAP_FUNC_EXPORT u8_t * eap_radius_header_base_c::get_authenticator() const
{
	u8_t * authenticator = get_header_offset(
		m_authenticator_offset,
		get_authenticator_length());
	if (authenticator != 0)
	{
		return authenticator;
	}
	else
	{
		return 0;
	}
}

/// This function returns the length of the authenticator field of RADIUS-header.
EAP_FUNC_EXPORT u32_t eap_radius_header_base_c::get_authenticator_length() const
{
	return EAP_RADIUS_AUTHENTICATOR_LENGTH*sizeof(u8_t);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t eap_radius_header_base_c::get_identifier() const
{
	const u8_t * const identifier_data = get_header_offset(m_identifier_offset, sizeof(u8_t));
	if (identifier_data != 0)
	{
		return *identifier_data;
	}
	else
	{
		return 0xff;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT u16_t eap_radius_header_base_c::get_length() const
{
	const u8_t * const length_data = get_header_offset(m_length_offset, sizeof(u16_t));
	if (length_data != 0)
	{
		return static_cast<u16_t>(static_cast<u16_t>(length_data[0]) << 8
								  | static_cast<u16_t>(length_data[1]));		
	}
	else
	{
		return 0ul;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT u16_t eap_radius_header_base_c::get_data_length() const
{
	u32_t length = get_length();
	if (length >= get_header_length())
	{
		return static_cast<u16_t>(length-get_header_length());		
	}
	else
	{
		return 0ul;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * eap_radius_header_base_c::get_data_offset(
	const u32_t p_offset, const u32_t p_continuous_bytes) const
{
	if (get_length() >= static_cast<u16_t>(get_header_length()+p_offset+p_continuous_bytes))
	{
		u8_t * const data_begin = get_header_offset(m_attributes_offset, sizeof(u8_t));
		if (data_begin == 0)
		{
			return 0;
		}
		return &(data_begin[p_offset]);
	}
	else
	{
		return 0;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_radius_header_base_c::set_code(const eap_radius_code_value_e p_code)
{
	u8_t * const code_data = get_header_offset(m_code_offset, sizeof(u8_t));
	EAP_ASSERT(code_data != 0);

	*code_data = static_cast<u8_t>(p_code);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_radius_header_base_c::set_identifier(const u8_t p_identifier)
{
	u8_t * const identifier_data = get_header_offset(m_identifier_offset, sizeof(u8_t));
	EAP_ASSERT(identifier_data != 0);

	*identifier_data = p_identifier;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_radius_header_base_c::set_length(const u16_t p_length)
{
	u8_t * const length_data = get_header_offset(m_length_offset, sizeof(u16_t));
	EAP_ASSERT(length_data != 0);

	length_data[0] = static_cast<u8_t>((p_length & 0xff00) >> 8);
	length_data[1] = static_cast<u8_t>(p_length & 0x00ff);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_radius_header_base_c::set_data_length(const u16_t data_length)
{
	u16_t length = static_cast<u16_t>(data_length+get_header_length());

	u8_t * const length_data = get_header_offset(m_length_offset, sizeof(u16_t));
	EAP_ASSERT(length_data != 0);

	length_data[0] = static_cast<u8_t>((length & 0xff00) >> 8);
	length_data[1] = static_cast<u8_t>(length & 0x00ff);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_radius_header_base_c::get_code_string() const
{
	return eap_radius_header_string_c::get_code_string(get_code());
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_radius_header_base_c::check_header() const
{
	eap_status_e status = eap_status_process_general_error;

	if (get_code() > eap_radius_code_maximum_supported
		|| eap_radius_code_maximum_supported < get_code())
	{
		status = eap_status_illegal_eap_code;

		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: eap_header_c::check_header(), illegal code field 0x%02x, eap_status_e %d\n"),
			 get_code(),
			 status));
	}
	else
	{
		status = eap_status_ok;
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

/// This function resets the RADIUS-header.
/// The buffer_length parameter is the length of the RADISU-header and the following attribute data buffer.
EAP_FUNC_EXPORT void eap_radius_header_base_c::reset_header(u16_t buffer_length)
{
	set_code(eap_radius_code_none);
	set_identifier(0u);
	set_length(buffer_length);
}

//--------------------------------------------------



// End.
