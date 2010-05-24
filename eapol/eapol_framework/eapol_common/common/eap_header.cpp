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
	#define EAP_FILE_NUMBER_ENUM 26 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_header.h"
#include "eap_header_string.h"


//--------------------------------------------------

EAP_FUNC_EXPORT eap_header_base_c::~eap_header_base_c()
{
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_header_base_c::eap_header_base_c(
	abs_eap_am_tools_c * const tools,
	void * const header_begin,
	const u32_t header_buffer_length)
	: eap_general_header_base_c(tools, header_begin, header_buffer_length)
	, m_am_tools(tools)
{
	EAP_ASSERT(sizeof(eap_expanded_type_c) == sizeof(eap_static_expanded_type_c));
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_header_base_c::get_header_length()
{
	return m_type_offset;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_header_base_c::get_ietf_type_field_length()
{
	return eap_expanded_type_c::m_ietf_type_size;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_header_base_c::get_expanded_type_field_length()
{
	return eap_expanded_type_c::m_eap_expanded_type_size;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_header_base_c::get_expanded_ietf_type_offset()
{
	return m_exp_ietf_type_offset;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_header_base_c::get_expanded_vendor_id_offset()
{
	return m_exp_vendor_id_offset;
}


//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_header_base_c::get_expanded_vendor_type_offset()
{
	return m_exp_vendor_type_offset;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_header_base_c::get_type_data_start_offset(
	const bool expanded_type_when_true)
{
	u32_t type_field_length(get_ietf_type_field_length());

	if (expanded_type_when_true == true)
	{
		type_field_length = get_expanded_type_field_length();
	}

	return get_header_length() + type_field_length;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_code_value_e eap_header_base_c::get_code() const
{
	const u8_t * const code_data = get_header_offset(m_code_offset, sizeof(u8_t));
	if (code_data != 0)
	{
		return static_cast<eap_code_value_e>(*code_data);
	}
	else
	{
		return eap_code_none;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t eap_header_base_c::get_identifier() const
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

EAP_FUNC_EXPORT u16_t eap_header_base_c::get_length() const
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

EAP_FUNC_EXPORT eap_type_ietf_values_e eap_header_base_c::get_ietf_type() const
{
	const u8_t * const ietf_type_field = get_data(eap_expanded_type_c::m_ietf_type_size);
	if (ietf_type_field == 0)
	{
		return eap_type_none;
	}
	else
	{
		return static_cast<eap_type_ietf_values_e>(*ietf_type_field);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_type_value_e eap_header_base_c::get_type() const
{
	eap_type_value_e type(eap_type_none);

	if (get_length() > static_cast<u16_t>(get_header_length()))
	{
		eap_status_e status = eap_expanded_type_c::read_type(
			m_am_tools,
			0ul,
			get_data(get_data_length()),
			get_data_length(),
			&type);

		EAP_UNREFERENCED_PARAMETER(status);
		(void)EAP_STATUS_RETURN(m_am_tools, status);
	}

	return type;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u16_t eap_header_base_c::get_data_length() const
{
	if (get_length() > static_cast<u16_t>(get_header_length()))
	{
		return static_cast<u16_t>(get_length()-get_header_length());
	}
	return 0u;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_header_base_c::get_type_field_length() const
{
	eap_type_ietf_values_e p_type = get_ietf_type();

	if (eap_expanded_type_c::is_expanded_type(p_type) == true)
	{
		return eap_expanded_type_c::m_eap_expanded_type_size;
	}
	else
	{
		return eap_expanded_type_c::m_ietf_type_size;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT u16_t eap_header_base_c::get_type_data_length() const
{
	u32_t type_field_length(get_type_field_length());

	if (get_length() > static_cast<u16_t>(get_header_length()+type_field_length))
	{
		return static_cast<u16_t>(get_length()-(get_header_length()+type_field_length));
	}
	return 0u;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * eap_header_base_c::get_data_offset(
	const u32_t p_offset, const u32_t p_continuous_bytes) const
{
	if (get_length() >= static_cast<u16_t>(get_header_length()+p_offset+p_continuous_bytes))
	{
		u8_t * const data_begin = get_header_offset(m_type_offset, sizeof(u8_t));
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

EAP_FUNC_EXPORT u8_t * eap_header_base_c::get_type_data_offset(
	const u32_t p_offset, const u32_t p_continuous_bytes) const
{
	u32_t type_field_length(get_type_field_length());

	u32_t type_data_offset = get_header_length()+type_field_length;

	if (get_length() >= static_cast<u16_t>(type_data_offset+p_offset+p_continuous_bytes))
	{
		u8_t * const data_begin = get_header_offset(type_data_offset, sizeof(u8_t));
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

EAP_FUNC_EXPORT u8_t * eap_header_base_c::get_type_data(
	const u32_t p_continuous_bytes) const
{
	return get_type_data_offset(0u, p_continuous_bytes);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * eap_header_base_c::get_data(
	const u32_t p_continuous_bytes) const
{
	return get_data_offset(0u, p_continuous_bytes);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_header_base_c::set_code(const eap_code_value_e p_code)
{
	u8_t * const code_data = get_header_offset(m_code_offset, sizeof(u8_t));
	EAP_ASSERT(code_data != 0);
	*code_data = static_cast<u8_t>(p_code);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_header_base_c::set_identifier(const u8_t p_identifier)
{
	u8_t * const identifier_data = get_header_offset(m_identifier_offset, sizeof(u8_t));
	EAP_ASSERT(identifier_data != 0);
	*identifier_data = p_identifier;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_header_base_c::set_length(
	const u16_t p_length,
	const bool /* expanded_type_when_true */)
{
	u8_t * const length_data = get_header_offset(m_length_offset, sizeof(u16_t));
	EAP_ASSERT(length_data != 0);
	length_data[0] = static_cast<u8_t>((p_length & 0xff00) >> 8);
	length_data[1] = static_cast<u8_t>(p_length & 0x00ff);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_header_base_c::set_type_data_length(
	const u16_t p_length,
	const bool expanded_type_when_true)
{
	u32_t type_field_length(eap_expanded_type_c::m_ietf_type_size);

	if (expanded_type_when_true == true)
	{
		type_field_length = eap_expanded_type_c::m_eap_expanded_type_size;
	}

	set_length(
		static_cast<u16_t>(p_length+get_header_length()+type_field_length),
		expanded_type_when_true);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_header_base_c::set_type(
	const eap_type_value_e p_type,
	const bool expanded_type_when_true)
{
	return eap_expanded_type_c::write_type(
		m_am_tools,
		0ul,
		get_data(get_data_length()),
		get_data_length(),
		expanded_type_when_true,
		p_type);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_header_base_c::get_code_string() const
{
	return eap_header_string_c::get_eap_code_string(get_code());
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_header_base_c::get_type_string() const
{
	if (get_length() <= get_header_length())
	{
		return EAPL("No EAP-type");
	}

	return eap_header_string_c::get_eap_type_string(get_type());
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_header_base_c::check_header() const
{
	eap_status_e status = eap_status_process_general_error;

	if (get_code() < eap_code_request
		|| eap_code_failure < get_code())
	{
		status = eap_status_illegal_eap_code;

		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: eap_header_c::check_header(), illegal code field 0x%02x, eap_status_e %d\n"),
			 get_code(),
			 status));
	}
	else if ((get_code() == eap_code_request
			|| get_code() == eap_code_response)
		&& get_length() < get_header_length() + sizeof(u8_t))
	{
		// Packet is too short.
		status = eap_status_too_short_message;

		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: eap_header_c::check_header(), code 0x%02x, illegal length field 0x%02x, eap_status_e %d\n"),
			 get_code(),
			 get_length(),
			 status));
	}
	else
	{
		status = eap_status_ok;
	}

	return EAP_STATUS_RETURN_WARNING(m_am_tools, status);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_header_rd_c::~eap_header_rd_c()
{
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_header_rd_c::eap_header_rd_c(
	abs_eap_am_tools_c * const tools,
	u8_t * const header_buffer,
	const u32_t header_buffer_length)
	: eap_header_base_c(tools, header_buffer, header_buffer_length)
	, m_am_tools(tools)
{
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_header_wr_c::~eap_header_wr_c()
{
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_header_wr_c::eap_header_wr_c(
	abs_eap_am_tools_c * const tools,
	u8_t * const header_buffer,
	const u32_t header_buffer_length)
	: eap_header_base_c(tools, header_buffer, header_buffer_length)
	, m_am_tools(tools)
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * eap_header_wr_c::get_type_data(const u32_t p_continuous_bytes) const
{
	return const_cast<u8_t *>(eap_header_base_c::get_type_data(p_continuous_bytes));
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * eap_header_wr_c::get_type_data_offset(
	const u32_t p_offset,
	const u32_t p_continuous_bytes) const
{
	return const_cast<u8_t *>(eap_header_base_c::get_type_data_offset(
		p_offset, p_continuous_bytes));
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_header_wr_c::reset_header(
	const u16_t buffer_length,
	const bool expanded_type_when_true)
{
	set_code(eap_code_none);
	set_identifier(0u);
	set_length(buffer_length, expanded_type_when_true);
}

//--------------------------------------------------



// End.
