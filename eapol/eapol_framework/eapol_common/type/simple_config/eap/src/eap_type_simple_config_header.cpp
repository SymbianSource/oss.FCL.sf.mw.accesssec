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
	#define EAP_FILE_NUMBER_ENUM 591 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#if defined(USE_EAP_SIMPLE_CONFIG)


#include "eap_am_memory.h"
#include "eap_type_simple_config_header.h"
#include "eap_header_string.h"


/** @file */

//--------------------------------------------------

EAP_FUNC_EXPORT eap_simple_config_header_c::~eap_simple_config_header_c()
{
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_simple_config_header_c::eap_simple_config_header_c(
	abs_eap_am_tools_c * const tools,
	u8_t * const header_begin,
	const u32_t header_buffer_length)
	: eap_header_base_c(tools, header_begin, header_buffer_length)
	, m_am_tools(tools)
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_code_value_e eap_simple_config_header_c::get_eap_code() const
{
	return eap_header_base_c::get_code();
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t eap_simple_config_header_c::get_eap_identifier() const
{
	return eap_header_base_c::get_identifier();
}

//--------------------------------------------------

EAP_FUNC_EXPORT u16_t eap_simple_config_header_c::get_eap_length() const
{
	return eap_header_base_c::get_length();
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_type_value_e eap_simple_config_header_c::get_eap_type() const
{
	return eap_header_base_c::get_type();
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_simple_config_header_c::get_sc_op_code_offset() const
{
	return eap_header_base_c::get_header_length() + eap_header_base_c::get_type_field_length() + m_op_code_delta_offset;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_simple_config_header_c::get_sc_flags_offset() const
{
	return eap_header_base_c::get_header_length() + eap_header_base_c::get_type_field_length() + m_flag_delta_offset;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_simple_config_header_c::get_sc_length_offset() const
{
	return eap_header_base_c::get_header_length() + eap_header_base_c::get_type_field_length() + m_data_or_message_length_delta_offset;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_simple_config_header_c::op_code_e eap_simple_config_header_c::get_sc_op_code() const
{
	u32_t op_code_offset(get_sc_op_code_offset());

	u8_t * const op_code = get_header_offset(op_code_offset, sizeof(u8_t));
	if (op_code != 0)
	{
		return static_cast<eap_simple_config_header_c::op_code_e>(*op_code);
	}
	else
	{
		return eap_simple_config_header_c::op_code_none;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_simple_config_header_c::set_sc_op_code(const eap_simple_config_header_c::op_code_e op_code)
{
	u32_t op_code_offset(get_sc_op_code_offset());

	u8_t * const p_op_code = get_header_offset(op_code_offset, sizeof(u8_t));
	if (p_op_code != 0)
	{
		*p_op_code = static_cast<u8_t>(op_code);
	}
	else
	{
		EAP_ASSERT(p_op_code != 0);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT u16_t eap_simple_config_header_c::get_data_length() const
{
	if (get_flag_simple_config_length_included() == true
		&& get_eap_length() > static_cast<u16_t>(get_header_length()))
	{
		return static_cast<u16_t>(get_eap_length()-static_cast<u16_t>(get_header_length()));
	}
	else if (get_flag_simple_config_length_included() == false
			 && get_eap_length() > static_cast<u16_t>(get_header_length()))
	{
		return static_cast<u16_t>(get_eap_length()-static_cast<u16_t>(get_header_length()));
	}
	else
	{
		return 0;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_simple_config_header_c::get_simple_config_min_header_length() const
{
	return eap_header_base_c::get_header_length()
		+ eap_header_base_c::get_type_field_length()
		+ m_data_or_message_length_delta_offset;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_simple_config_header_c::get_simple_config_max_header_length()
{
	return eap_header_base_c::get_header_length()
		+ eap_header_base_c::get_expanded_type_field_length()
		+ m_data_or_message_length_delta_offset
		+ SIMPLE_CONFIG_MESSAGE_LENGTH_FIELD_SIZE;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_simple_config_header_c::get_header_length() const
{
	u32_t length = get_simple_config_min_header_length();

	if (get_flag_simple_config_length_included() == true)
	{
		return length+SIMPLE_CONFIG_MESSAGE_LENGTH_FIELD_SIZE;
	}
	else
	{
		return length;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_simple_config_header_c::get_start_offset_of_data() const
{
	return get_header_length();
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * eap_simple_config_header_c::get_data_offset(
	abs_eap_am_tools_c * const m_am_tools,
	const u32_t offset,
	const u32_t contignuous_bytes) const
{
	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	u32_t data_length = get_data_length(); // Here is removed optional SIMPLE_CONFIG message length.

	if (data_length >= offset+contignuous_bytes)
	{
		// get_header_length() handles optional SIMPLE_CONFIG message length field.
		u32_t offset_of_data = get_start_offset_of_data();
		u8_t * const data = get_header_offset(offset_of_data, offset+contignuous_bytes);
		if (data != 0)
		{
			return data+offset; // Data begins after the header.
		}
		else
		{
			return 0;
		}
	}
	else
	{
		EAP_ASSERT_ALWAYS(get_data_length() > 0u);
	}
	return 0;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * eap_simple_config_header_c::get_data(
	abs_eap_am_tools_c * const m_am_tools,
	const u32_t contignuous_bytes) const
{
	return get_data_offset(m_am_tools, 0u, contignuous_bytes);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * eap_simple_config_header_c::get_simple_config_flags() const
{
	u32_t flag_offset(get_sc_flags_offset());

	return get_header_offset(flag_offset, sizeof(u8_t));
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_simple_config_header_c::get_simple_config_flag_bit(const u32_t mask) const
{
	const u8_t * const flag = get_simple_config_flags();

	if (flag != 0
		&& ((*flag) & mask))
	{
		return true;
	}
	return false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t eap_simple_config_header_c::get_simple_config_flag_value(const u32_t mask, const u32_t shift) const
{
	const u8_t * const flag = get_simple_config_flags();

	if (flag != 0)
	{
		return static_cast<u8_t>(((*flag) & mask) >> shift);
	}
	else
	{
		return 0;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_simple_config_header_c::get_flag_simple_config_length_included() const
{
	return get_simple_config_flag_bit(m_flag_mask_simple_config_length_included);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_simple_config_header_c::get_flag_more_fragments() const
{
	return get_simple_config_flag_bit(m_flag_mask_more_fragments);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t eap_simple_config_header_c::get_flag_reserved() const
{
	return get_simple_config_flag_value(m_flag_mask_reserved, m_flag_shift_reserved);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_simple_config_header_c::get_simple_config_message_length(u32_t * const simple_config_length) const
{
	if (get_flag_simple_config_length_included() == false)
	{
		// SIMPLE_CONFIG data length is NOT included.
		*simple_config_length = 0u;
		return eap_status_ok;
	}
	
	u8_t * const data = get_header_offset(get_sc_length_offset(), sizeof(u32_t));
	if (data != 0)
	{
		u32_t simple_config_message_length =
			eap_read_u32_t_network_order(data, sizeof(u32_t));
		
		*simple_config_length = simple_config_message_length;
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_simple_config_header_c::check_header(
	abs_eap_am_tools_c * const /* tools */,
	const bool is_client_when_true) const
{
	eap_status_e status = eap_status_ok;

	if (get_flag_reserved() != static_cast<u16_t>(0ul))
	{
		status = EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	if (status != eap_status_ok)
	{
		EAP_UNREFERENCED_PARAMETER(is_client_when_true);
		
		// In version negotiation this check will fail.
		// Do not add error traces here.
		eap_status_string_c status_string;
		EAP_UNREFERENCED_PARAMETER(status_string);
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("WARNING: EAP_type_SIMPLE_CONFIG: check_header(): failed, %s, ")
			 EAPL("get_eap_type() 0x%08x, get_op_code() %d, get_flag_reserved() %d, status %s\n"),
			 (is_client_when_true == true) ? "client": "server",
			 convert_eap_type_to_u32_t(get_eap_type()),
			 get_sc_op_code(),
			 get_flag_reserved(),
			 status_string.get_status_string(status)));
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_simple_config_header_c::get_code_string() const
{
	return eap_header_string_c::get_eap_code_string(get_eap_code());
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_simple_config_header_c::get_eap_type_string() const
{
	if (get_eap_length() <= eap_header_base_c::get_header_length())
	{
		return EAPL("No EAP-type");
	}

	return eap_header_string_c::get_eap_type_string(get_eap_type());
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_simple_config_header_c::get_sc_op_code_string() const
{
	const op_code_e op_code(get_sc_op_code());

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(op_code, op_code_none)
	else EAP_IF_RETURN_STRING(op_code, op_code_WSC_Start)
	else EAP_IF_RETURN_STRING(op_code, op_code_WSC_ACK)
	else EAP_IF_RETURN_STRING(op_code, op_code_WSC_NACK)
	else EAP_IF_RETURN_STRING(op_code, op_code_WSC_MSG)
	else EAP_IF_RETURN_STRING(op_code, op_code_WSC_Done)
	else EAP_IF_RETURN_STRING(op_code, op_code_FRAG_ACK)
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(op_code);
		return EAPL("Unknown SIMPLE CONFIG Op-Code");
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_simple_config_header_c::set_eap_code(const eap_code_value_e p_code)
{
	eap_header_base_c::set_code(p_code);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_simple_config_header_c::set_eap_identifier(const u8_t p_identifier)
{
	eap_header_base_c::set_identifier(p_identifier);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_simple_config_header_c::set_eap_length(
	const u16_t p_length,
	const bool expanded_type_when_true)
{
	eap_header_base_c::set_length(
		p_length,
		expanded_type_when_true);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_simple_config_header_c::set_eap_type(
	const eap_type_value_e p_type,
	const bool expanded_type_when_true)
{
	eap_header_base_c::set_type(p_type, expanded_type_when_true);
}


//--------------------------------------------------

EAP_FUNC_EXPORT void eap_simple_config_header_c::set_simple_config_flag_value(const u8_t value, const u32_t mask, const u32_t shift) const
{
	u8_t *flag = get_simple_config_flags();

	if (flag != 0)
	{
		(*flag) = static_cast<u8_t>(((*flag) & ~mask) | ((value << shift) & mask));
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_simple_config_header_c::set_simple_config_flag_bit(const bool flag, u32_t mask) const
{
	u8_t *p_flag = get_simple_config_flags();
	
	if (p_flag != 0)
	{
		if (flag == true)
		{
			(*p_flag) = static_cast<u8_t>((*p_flag) | mask);
		}
		else
		{
			(*p_flag) = static_cast<u8_t>((*p_flag) & ~mask);
		}
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_simple_config_header_c::set_flag_reserved(const u8_t reserved)
{
	set_simple_config_flag_value(reserved, m_flag_mask_reserved, m_flag_shift_reserved);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_simple_config_header_c::set_flag_simple_config_length_included(const bool simple_config_length_included)
{
	set_simple_config_flag_bit(simple_config_length_included, m_flag_mask_simple_config_length_included);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_simple_config_header_c::set_flag_more_fragments(const bool more_fragments)
{
	set_simple_config_flag_bit(more_fragments, m_flag_mask_more_fragments);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_simple_config_header_c::set_data_length(
	const u32_t p_data_length,
	const bool expanded_type_when_true)
{
	EAP_ASSERT_ALWAYS(p_data_length+get_header_length() <= 0xffff);
	
	set_eap_length(
		static_cast<u16_t>(p_data_length+get_header_length()),
		expanded_type_when_true);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_simple_config_header_c::set_simple_config_message_length(const u32_t simple_config_length)
{
	EAP_ASSERT_ALWAYS(get_flag_simple_config_length_included() == true);

	u32_t message_length_offset(get_sc_length_offset());

	u8_t * const data = get_header_offset(message_length_offset, sizeof(u32_t));

	EAP_ASSERT(data != 0);

	data[0] = static_cast<u8_t>((simple_config_length & 0xff000000) >> 24);
	data[1] = static_cast<u8_t>((simple_config_length & 0x00ff0000) >> 16);
	data[2] = static_cast<u8_t>((simple_config_length & 0x0000ff00) >> 8);
	data[3] = static_cast<u8_t>((simple_config_length & 0x000000ff) >> 0);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_simple_config_header_c::reset_header(
	abs_eap_am_tools_c * const m_am_tools,
	const u32_t buffer_length,
	const bool expanded_type_when_true)
{
	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	eap_header_base_c::set_length(
		static_cast<u16_t>(buffer_length),
		expanded_type_when_true);

	set_eap_code(eap_code_none);

	set_eap_type(
		eap_type_none,
		true);

	set_flag_simple_config_length_included(false);
	set_flag_more_fragments(false);
	set_sc_op_code(op_code_none);
	
	set_flag_reserved(0u);
		
	set_eap_identifier(0u);
}

//--------------------------------------------------

#endif //#if defined(USE_EAP_SIMPLE_CONFIG)

// End.
