/*
* Copyright (c) 2008 Nokia Corporation and/or its subsidiary(-ies).
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
* %version: 32.1.5 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 761 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include "asn1_der_type.h"
#include "eap_automatic_variable.h"

//--------------------------------------------------

EAP_FUNC_EXPORT asn1_der_type_c::~asn1_der_type_c()
{
	delete m_sub_types;
	m_sub_types = 0;
}

//--------------------------------------------------

EAP_FUNC_EXPORT asn1_der_type_c::asn1_der_type_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_is_valid(false)
	, m_index(0u)
	, m_count_of_sub_types(0u)
	, m_recursion(0ul)
	, m_input_data_length(0ul)
	, m_input_data(0)
	, m_used_octets(0ul)
	, m_offset_of_length_field(0ul)
	, m_offset_of_contents_field(0ul)
	, m_parent_type(0)
	, m_sub_types(0)
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool asn1_der_type_c::get_is_valid() const
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t asn1_der_type_c::get_index() const
{
	return m_index;
}

//--------------------------------------------------

u32_t asn1_der_type_c::get_input_data_length() const
{
	return m_input_data_length;
}

//--------------------------------------------------

const u8_t * asn1_der_type_c::get_input_data() const
{
	return m_input_data;
}

//--------------------------------------------------

u16_t asn1_der_type_c::get_recursion() const
{
	return m_recursion;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string asn1_der_type_c::get_class_string() const
{

#if defined(USE_EAP_DEBUG_TRACE)

	asn1_class_e asn1_class = get_class();

	if (asn1_class == asn1_class_universal)
	{
		return("U");
	}
	else if (asn1_class == asn1_class_application)
	{
		return("A");
	}
	else if (asn1_class == asn1_class_context_specific)
	{
		return("C");
	}
	else if (asn1_class == asn1_class_private)
	{
		return("P");
	}
	else
#endif //#if defined(USE_EAP_DEBUG_TRACE)
	{
		return("<Unknown Class>");
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string asn1_der_type_c::get_pc_string() const
{

#if defined(USE_EAP_DEBUG_TRACE)

	asn1_pc_e pc = get_pc();

	if (pc == asn1_pc_primitive)
	{
		return("P");
	}
	else if (pc == asn1_pc_constructed)
	{
		return("C");
	}
	else
#endif //#if defined(USE_EAP_DEBUG_TRACE)
	{
		return("<Unknown PC>");
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string asn1_der_type_c::get_tag_string() const
{

#if defined(USE_EAP_DEBUG_TRACE)

	asn1_class_e asn1_class = get_class();
	asn1_tag_e tag = get_tag();

	if (asn1_class == asn1_class_context_specific)
	{
		static const eap_char context[][4] = { "[0]", "[1]", "[2]", "[3]", "[4]", "[5]", "[6]", "[7]", "[8]", "[9]", };
		if (tag < (sizeof(context)/sizeof(context[0])))
		{
			return context[tag];
		}
		else
		{
			return("<Too big context>");
		}
	}
	else
	{
		EAP_IF_RETURN_STRING(tag, asn1_tag_end_of_content)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_boolean)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_integer)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_bit_string)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_octet_string)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_null)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_object_identifier)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_object_descriptor)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_external)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_real)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_enumerated)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_empedded_pdv)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_utf8_string)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_relative_oid)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_unknown_14)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_unknown_15)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_sequence)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_set)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_numeric_string)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_printable_string)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_t61_string)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_videotex_string)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_ia5_string)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_utc_time)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_unknown_24)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_graphic_string)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_visible_string)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_general_string)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_universal_string)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_character_string)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_bmp_string)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_extented)
		else EAP_IF_RETURN_STRING(tag, asn1_tag_none)
		else
		{
			return("<Unknown Tag>");
		}
	}

#else

	return("<Unknown Tag>");

#endif //#if defined(USE_EAP_DEBUG_TRACE)

}

//--------------------------------------------------

#if defined(USE_EAP_DEBUG_TRACE)

eap_status_e asn1_der_type_c::debug_create_prefix(const u32_t recursion, u8_t * const prefix, const u32_t max_prefix, u32_t * const prefix_length)
{
	if (prefix == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u32_t offset(0ul);

	for (u32_t ind = 0ul; ind < recursion; ++ind)
	{
		offset += m_am_tools->snprintf(
			&prefix[offset],
			max_prefix - offset,
			"  |\0");

		if (max_prefix <= offset)
		{
			break;
		}
	}

	if (max_prefix > offset)
	{
		prefix[offset] = 0;
	}

	*prefix_length = offset;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif //#if defined(USE_EAP_DEBUG_TRACE)

//--------------------------------------------------

#if defined(USE_EAP_DEBUG_TRACE)

eap_status_e asn1_der_type_c::debug_header(eap_variable_data_c * const debug_buffer)
{
	if (debug_buffer == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u32_t max_data_length(m_recursion * SIZE_OF_ONE_OCTET_STRING + m_offset_of_contents_field * SIZE_OF_ONE_OCTET_STRING);

	if (max_data_length > debug_buffer->get_buffer_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = debug_buffer->set_data_length(max_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t ind(0ul);
	u32_t offset(0ul);

	u8_t * const prefix = reinterpret_cast<u8_t *>(debug_buffer->get_data(max_data_length));

	if (prefix == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = debug_create_prefix(m_recursion, prefix, max_data_length, &offset);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	for (ind = 0ul; ind < m_offset_of_length_field && ind < m_input_data_length; ++ind)
	{
		offset += m_am_tools->snprintf(
			debug_buffer->get_data_offset(offset, debug_buffer->get_data_length() - offset),
			debug_buffer->get_data_length() - offset,
			"%02x \0",
			m_input_data[ind]);
	}

	for (ind = m_offset_of_length_field; ind < m_offset_of_contents_field && ind < m_input_data_length; ++ind)
	{
		offset += m_am_tools->snprintf(
			debug_buffer->get_data_offset(offset, debug_buffer->get_data_length() - offset),
			debug_buffer->get_data_length() - offset,
			"%02x \0",
			m_input_data[ind]);
	}

	status = debug_buffer->add_end_null();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_const_string tag_string = 0;
	eap_char buffer[MAX_STACK_BUFFER];

	if (get_class() == asn1_class_application)
	{
		m_am_tools->snprintf(
			reinterpret_cast<u8_t *>(buffer),
			MAX_STACK_BUFFER,
			"Application[%d]\0",
			get_tag());

		tag_string = buffer;
	}
	else if (get_class() == asn1_class_context_specific)
	{
		m_am_tools->snprintf(
			reinterpret_cast<u8_t *>(buffer),
			MAX_STACK_BUFFER,
			"[%d]\0",
			get_tag());

		tag_string = buffer;
	}
	else
	{
		tag_string = get_tag_string();
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s # %s, %s, %s, length=0x%x=%d, this=0x%08x, index=%d\n"),
			debug_buffer->get_data(max_data_length),
			get_class_string(),
			get_pc_string(),
			tag_string,
			get_content_length(),
			get_content_length(),
			this,
			m_index));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_DEBUG_TRACE)

//--------------------------------------------------

#if defined(USE_EAP_DEBUG_TRACE)

eap_status_e asn1_der_type_c::debug_content(eap_variable_data_c * const debug_buffer)
{
	if (debug_buffer == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_process_general_error);

	if (get_tag() == asn1_tag_object_identifier)
	{
		status = debug_object_identifier(debug_buffer);
	}
	else
	{
		status = debug_data(debug_buffer);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_DEBUG_TRACE)

//--------------------------------------------------

#if defined(USE_EAP_DEBUG_TRACE)

eap_status_e asn1_der_type_c::debug_data(eap_variable_data_c * const debug_buffer)
{
	if (debug_buffer == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u32_t max_prefix_length((m_recursion + 1ul) * SIZE_OF_ONE_OCTET_STRING + COUNT_OF_OCTETS * SIZE_OF_ONE_OCTET_STRING + 1ul);
	const u32_t ascii_length(COUNT_OF_OCTETS + 5ul);

	if ((max_prefix_length + ascii_length) > debug_buffer->get_buffer_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = debug_buffer->set_data_length(max_prefix_length + ascii_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u8_t * const prefix = reinterpret_cast<u8_t *>(debug_buffer->get_data(max_prefix_length));
	u8_t * const ascii = reinterpret_cast<u8_t *>(debug_buffer->get_data_offset(max_prefix_length, ascii_length));

	if (prefix == 0 || ascii == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t ind(0ul);
	u32_t offset(0ul);

	status = debug_create_prefix(m_recursion + 1u, prefix, max_prefix_length, &offset);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t init_indentation_offset = offset;
	u32_t type_data_size = get_header_length() + get_content_length();
	u32_t data_ind(0ul);
	u32_t ascii_ind(0ul);
	u8_t octet(0);

	for (ind = m_offset_of_contents_field; ind < type_data_size && ind < m_input_data_length; ++ind)
	{
		offset += m_am_tools->snprintf(
			&prefix[offset],
			max_prefix_length - offset,
			"%02x \0",
			m_input_data[ind]);

		octet = m_input_data[ind];

		if (octet < 0x20 || 0x7e < octet)
		{
			octet = '.';
		}

		m_am_tools->snprintf(
			&ascii[ascii_ind],
			ascii_length - ascii_ind,
			"%c\0",
			octet);

		++data_ind;
		++ascii_ind;

		if ((ascii_ind % COUNT_OF_OCTETS) == 0)
		{
			prefix[offset] = 0;
			ascii[ascii_ind] = 0;

			offset = init_indentation_offset;
			ascii_ind = 0ul;

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s |%s|\n"),
					prefix,
					ascii));
		}
	} // for()

	u32_t remainder(ascii_ind % COUNT_OF_OCTETS);

	if (remainder > 0ul)
	{
		for (; ascii_ind < COUNT_OF_OCTETS; ++ascii_ind)
		{
			offset += m_am_tools->snprintf(
				&prefix[offset],
				max_prefix_length - offset,
				"   \0");

			m_am_tools->snprintf(
				&ascii[ascii_ind],
				ascii_length - ascii_ind,
				" \0");
		} // for()

		prefix[offset] = 0;
		ascii[ascii_ind] = 0;

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("%s |%s|\n"),
				prefix,
				ascii));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_DEBUG_TRACE)

//--------------------------------------------------

#if defined(USE_EAP_DEBUG_TRACE)

eap_status_e asn1_der_type_c::debug_object_identifier(eap_variable_data_c * const debug_buffer)
{
	if (debug_buffer == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = debug_buffer->set_data_length(debug_buffer->get_buffer_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const u32_t recursion(m_recursion + 1u);
	const u32_t max_prefix_length(recursion * SIZE_OF_ONE_OCTET_STRING + 1ul);

	if (debug_buffer->get_buffer_length() < (max_prefix_length + 2ul))
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	const u32_t max_data_output_length((debug_buffer->get_buffer_length() - (max_prefix_length + 2ul))/2ul);
	const u32_t max_plain_output_length(max_data_output_length);

	u32_t prefix_length(0ul);

	u8_t * const prefix = debug_buffer->get_data();
	if (prefix == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	status = debug_create_prefix(recursion, prefix, max_prefix_length, &prefix_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u8_t * const data_output = debug_buffer->get_data_offset(max_prefix_length, max_data_output_length);
	if (data_output == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	data_output[max_data_output_length-1ul] = 0;

	u8_t * const plain_output = debug_buffer->get_data_offset(max_prefix_length + max_data_output_length, max_plain_output_length);
	if (plain_output == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	plain_output[max_plain_output_length - 1ul] = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	const u32_t length = get_content_length();
	
	if (length == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("# ERROR: invalid %s, length=%d\n"),
				get_tag_string(),
				length));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
	}

	const u8_t * const oid_data = get_content();

	if (oid_data == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("# ERROR: invalid %s, length=%d\n"),
				get_tag_string(),
				length));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
	}

	u32_t offset(0ul);
	u8_t oid_octet = oid_data[offset];
	u32_t oid1 = oid_octet / 40;
	u32_t oid2 = (oid_octet - oid1*40);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s%02x # = %d = 40 * %d + %d => %d.%d\n"),
		prefix,
		oid_octet,
		oid_octet,
		oid1,
		oid2,
		oid1,
		oid2));

	++offset;

	while(offset < length)
	{
		u32_t oid_length(0ul);
		u32_t data_output_offset(0ul);
		u32_t plain_output_offset(0ul);
		u32_t ind(0ul);

		for (ind = offset; ind < length; ++ind)
		{
			u8_t oid_octet = oid_data[ind];
			++oid_length;
			if ((oid_octet & OID_HIGH_BIT) == 0)
			{
				break;
			}
		} // for()

		u32_t power = oid_length - 1ul;
		u32_t oid_value(0ul);

		for (ind = offset; ind < (offset+oid_length); ++ind)
		{
			u8_t oid_octet = oid_data[ind];

			data_output_offset += m_am_tools->snprintf(
				&data_output[data_output_offset],
				max_data_output_length - data_output_offset,
				"%02x \0",
				oid_octet);

			u8_t oid = static_cast<u8_t>(oid_octet & (~OID_HIGH_BIT));

			if (ind > offset)
			{
				plain_output_offset += m_am_tools->snprintf(
					&plain_output[plain_output_offset],
					max_data_output_length - plain_output_offset,
					" + \0");
			}

			if (power > 1ul)
			{
				plain_output_offset += m_am_tools->snprintf(
					&plain_output[plain_output_offset],
					max_data_output_length - plain_output_offset,
					"0x%02x * 128 ^ %d\0",
					oid,
					power);
			}
			else if (power > 0ul)
			{
				plain_output_offset += m_am_tools->snprintf(
					&plain_output[plain_output_offset],
					max_data_output_length - plain_output_offset,
					"0x%02x * 128\0",
					oid);
			}
			else
			{
				plain_output_offset += m_am_tools->snprintf(
					&plain_output[plain_output_offset],
					max_data_output_length - plain_output_offset,
					"0x%02x\0",
					oid);
			}

			oid_value = (oid_value << 7) + oid;

			--power;
		} // for()

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("%s%s # %s = %d\n"),
			prefix,
			data_output,
			plain_output,
			oid_value));

		offset += oid_length;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_DEBUG_TRACE)

//--------------------------------------------------

eap_status_e asn1_der_type_c::initialize(
	const u32_t length,
	const u8_t * const data,
	const u16_t recursion,
	const u32_t index,
	eap_variable_data_c * const debug_buffer)
{
	EAP_UNREFERENCED_PARAMETER(debug_buffer);
	if (index > 0xffff)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	m_index = static_cast<u16_t>(index);

	m_recursion = recursion;

	m_input_data_length = length;

	if (m_input_data_length == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
	}

	m_input_data = data;

	if (m_input_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	m_offset_of_length_field = get_offset_of_length_field();

	if (m_offset_of_length_field > m_input_data_length
		|| m_offset_of_length_field == 0)
	{
		ASN1_DEBUG_HEADER(this, debug_buffer);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
	}

	m_offset_of_contents_field = get_offset_of_contents_field();

	if (m_offset_of_contents_field > m_input_data_length
		|| m_offset_of_contents_field == 0)
	{
		ASN1_DEBUG_HEADER(this, debug_buffer);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
	}

	if ((m_offset_of_contents_field + get_content_length()) > m_input_data_length)
	{
		ASN1_DEBUG_HEADER(this, debug_buffer);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
	}

	u32_t data_length = get_header_length() + get_content_length();

	if (m_input_data_length >= data_length)
	{
		m_input_data_length = data_length;
	}
	else
	{
		ASN1_DEBUG_HEADER(this, debug_buffer);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
	}

	add_used_octets(get_header_length());

	ASN1_DEBUG_HEADER(this, debug_buffer);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT asn1_der_type_c::asn1_class_e asn1_der_type_c::get_class() const
{
	if (m_input_data == 0)
	{
		return asn1_der_type_c::asn1_class_none;
	}

	return static_cast<asn1_der_type_c::asn1_class_e>(m_input_data[0] & asn1_identifier_mask_class);
}

//--------------------------------------------------

EAP_FUNC_EXPORT asn1_der_type_c::asn1_pc_e asn1_der_type_c::get_pc() const
{
	if (m_input_data == 0)
	{
		return asn1_der_type_c::asn1_pc_none;
	}

	return static_cast<asn1_der_type_c::asn1_pc_e>(m_input_data[0] & asn1_identifier_mask_pc);
}

//--------------------------------------------------

EAP_FUNC_EXPORT asn1_der_type_c::asn1_tag_e asn1_der_type_c::get_tag() const
{
	if (m_input_data == 0)
	{
		return asn1_der_type_c::asn1_tag_none;
	}

	asn1_der_type_c::asn1_tag_e tag = static_cast<asn1_der_type_c::asn1_tag_e>(m_input_data[0] & asn1_identifier_mask_tag);

	if (m_offset_of_length_field == asn1_identifier_const_simple_tag_size
		&& static_cast<asn1_identifier_mask_e>(tag) != asn1_identifier_mask_tag)
	{
		// Simple Tag.
		return tag;
	}
	else if (m_offset_of_length_field > asn1_identifier_const_simple_tag_size)
	{
		return asn1_der_type_c::asn1_tag_extented;
	}
	else
	{
		return asn1_der_type_c::asn1_tag_none;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e asn1_der_type_c::get_extented_tag(const u8_t ** const extented_tag, u32_t * const extented_tag_size) const
{
	if (extented_tag == 0
		|| extented_tag_size == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (get_tag() == asn1_der_type_c::asn1_tag_extented)
	{
		*extented_tag = m_input_data + asn1_identifier_const_simple_tag_size;
		*extented_tag_size = m_offset_of_length_field - asn1_identifier_const_simple_tag_size;
	}
	else
	{
		*extented_tag = m_input_data;
		*extented_tag_size = m_offset_of_length_field;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

u16_t asn1_der_type_c::get_offset_of_length_field()
{
	if (m_input_data == 0)
	{
		return 0ul;
	}

	asn1_der_type_c::asn1_tag_e tag = static_cast<asn1_der_type_c::asn1_tag_e>(m_input_data[0] & asn1_identifier_mask_tag);

	if (static_cast<asn1_identifier_mask_e>(tag) != asn1_identifier_mask_tag)
	{
		// Simple Tag.
		return asn1_identifier_const_simple_tag_size;
	}
	else if (m_input_data_length > asn1_identifier_const_simple_tag_size)
	{
		const u8_t * extented_tag = &(m_input_data[1]);
		if (extented_tag == 0)
		{
			return 0ul;
		}

		const u8_t * const end_byte = &(m_input_data[m_input_data_length]);
		if (end_byte == 0)
		{
			return 0ul;
		}

		while (extented_tag < end_byte)
		{
			if ((extented_tag[0] & static_cast<u8_t>(asn1_high_bit_mask_tag)) == 0)
			{
				return static_cast<u16_t>(extented_tag - m_input_data);
			}

			++extented_tag;
		}
	}

	// Illegal data.
	return 0ul;
}

//--------------------------------------------------

u16_t asn1_der_type_c::get_offset_of_contents_field()
{
	if (m_input_data == 0)
	{
		return 0ul;
	}

	if (m_offset_of_length_field < asn1_identifier_const_simple_tag_size
		|| m_offset_of_length_field > m_input_data_length)
	{
		return 0ul;
	}

	const u8_t length_octet1 = m_input_data[m_offset_of_length_field];

	if ((length_octet1 & static_cast<u8_t>(asn1_high_bit_mask_tag)) == 0)
	{
		// Short Length field.
		return static_cast<u16_t>(m_offset_of_length_field + asn1_identifier_const_short_length_size);
	}
	else if (m_input_data_length > static_cast<u32_t>(m_offset_of_length_field + asn1_identifier_const_short_length_size))
	{
		const u8_t * extented_length = &(m_input_data[m_offset_of_length_field]);
		if (extented_length == 0)
		{
			return 0ul;
		}

		u16_t count_of_length_octets = static_cast<u16_t>((*extented_length) & static_cast<u8_t>(~asn1_high_bit_mask_tag));

		u16_t offset(static_cast<u16_t>(m_offset_of_length_field + asn1_identifier_const_short_length_size + count_of_length_octets));

		if (offset > m_input_data_length)
		{
			// Illegal data.
			return 0ul;
		}

		return offset;
	}

	// Illegal data.
	return 0ul;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t asn1_der_type_c::get_header_length() const
{
	return m_offset_of_contents_field;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t asn1_der_type_c::get_content_length() const
{
	if (m_input_data == 0
		|| m_offset_of_length_field == 0ul
		|| m_offset_of_contents_field == 0ul)
	{
		return 0ul;
	}

	const u8_t * extented_length = &(m_input_data[m_offset_of_length_field]);
	if (extented_length == 0)
	{
		return 0ul;
	}

	if (((*extented_length) & static_cast<u8_t>(asn1_high_bit_mask_tag)) == 0)
	{
		// Short Length field.
		return static_cast<u32_t>(*extented_length);
	}

	u32_t count_of_length_octets = static_cast<u32_t>((*extented_length) & static_cast<u8_t>(~asn1_high_bit_mask_tag));

	if ((m_offset_of_length_field + asn1_identifier_const_short_length_size + count_of_length_octets) > m_input_data_length)
	{
		// Illegal data.
		return 0ul;
	}

	const u8_t * end_byte = &(m_input_data[m_offset_of_contents_field]);
	if (end_byte == 0)
	{
		return 0ul;
	}

	++extented_length;

	if (static_cast<u32_t>(end_byte - extented_length) > sizeof(u32_t))
	{
		// Overflow of length.
		return 0ul;
	}

	u32_t length(0ul);


	while (extented_length < end_byte)
	{
		length = (length << 8) + static_cast<u32_t>(*extented_length);
		++extented_length;
	}

	return length;
}

//--------------------------------------------------

EAP_FUNC_EXPORT const u8_t * asn1_der_type_c::get_content() const
{
	if (m_input_data == 0)
	{
		return 0;
	}

	if (m_offset_of_contents_field > m_input_data_length
		|| m_offset_of_contents_field == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return 0;
	}

	return (&m_input_data[m_offset_of_contents_field]);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t asn1_der_type_c::get_full_data_length() const
{
	return m_input_data_length;
}

//--------------------------------------------------

EAP_FUNC_EXPORT const u8_t * asn1_der_type_c::get_full_data() const
{
	return m_input_data;
}

//--------------------------------------------------

void asn1_der_type_c::set_parent_type(asn1_der_type_c * const parent_type)
{
	m_parent_type = parent_type;
}

//--------------------------------------------------

asn1_der_type_c * asn1_der_type_c::get_parent_type() const
{
	return m_parent_type;
}

//--------------------------------------------------

eap_status_e asn1_der_type_c::add_sub_type(asn1_der_type_c * const sub_type)
{
	if (m_sub_types == 0)
	{
		m_sub_types = new eap_array_c<asn1_der_type_c>(m_am_tools);
		if (m_sub_types == 0)
		{
			delete sub_type;

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}

	sub_type->set_parent_type(this);

	eap_status_e status = m_sub_types->add_object(sub_type, true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT const eap_array_c<asn1_der_type_c> * asn1_der_type_c::get_sub_types() const
{
	return m_sub_types;
}

//--------------------------------------------------

EAP_FUNC_EXPORT const asn1_der_type_c * asn1_der_type_c::get_sub_type(
	const asn1_type_const_c * const asn1_type) const
{
	const asn1_type_object_c * type = asn1_type[0].get_type();

	if (type == 0
		|| type->get_is_valid() == false)
	{
		return 0;
	}

	ASN1_TYPE_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("# asn1_type = 0x%08x, class=%d, tag=%d, index=%d\n"),
		type,
		type->get_asn1_class(),
		type->get_asn1_tag(),
		type->get_index()));

	const asn1_der_type_c * current_type = this;

	ASN1_TYPE_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("### current_type = 0x%08x, class=%d, tag=%d, index=%d\n"),
		current_type,
		current_type->get_class(),
		current_type->get_tag(),
		0));

	if (current_type->get_class() != type->get_asn1_class()
		|| current_type->get_tag() != type->get_asn1_tag())
	{
		ASN1_TYPE_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: ### current_type does not match.\n")));
		return 0;
	}

	++type;

	while (current_type != 0 && type->get_is_valid() == true)
	{
		ASN1_TYPE_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("# asn1_type = 0x%08x, class=%d, tag=%d, index=%d\n"),
			type,
			type->get_asn1_class(),
			type->get_asn1_tag(),
			type->get_index()));

		const eap_array_c<asn1_der_type_c> * sub_type_array = current_type->get_sub_types();
		if (sub_type_array == 0)
		{
			ASN1_TYPE_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: ### No sub-type array.\n")));
			return 0;
		}

		current_type = 0;

		for (u32_t sub_ind = type->get_index(); sub_ind < sub_type_array->get_object_count(); ++sub_ind)
		{
			const asn1_der_type_c * const sub_type = sub_type_array->get_object(sub_ind);
			if (sub_type == 0
				|| sub_type->get_is_valid() == false)
			{
				ASN1_TYPE_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: ### No sub-type.\n")));
				return 0;
			}

			ASN1_TYPE_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("### sub_type = 0x%08x, class=%d, tag=%d, index=%d\n"),
				sub_type,
				sub_type->get_class(),
				sub_type->get_tag(),
				sub_ind));

			if (sub_type->get_class() == type->get_asn1_class()
				&& sub_type->get_tag() == type->get_asn1_tag())
			{
				current_type = sub_type;
				break;
			}
		}

		++type;
	}

	if (current_type == 0)
	{
		ASN1_TYPE_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: ### No match found.\n")));
	}
	else
	{
		ASN1_TYPE_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("### Match found.\n")));

		ASN1_TYPE_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ASN.1 type data"),
			current_type->get_full_data(),
			current_type->get_full_data_length()));
	}

	return current_type;
}

//--------------------------------------------------

EAP_FUNC_EXPORT const asn1_der_type_c * asn1_der_type_c::get_previous_type() const
{
	const asn1_der_type_c * parent = get_parent_type();

	if (parent == 0)
	{
		return 0;
	}

	if (parent->get_sub_types() == 0)
	{
		return 0;
	}

	const u32_t object_count = parent->get_sub_types()->get_object_count();

	if (object_count <= 1ul)
	{
		return 0;
	}

	const u32_t previous_index = get_index() - 1ul;

	if (object_count <= previous_index)
	{
		return 0;
	}

	return parent->get_sub_types()->get_object(previous_index);
}

//--------------------------------------------------

EAP_FUNC_EXPORT const asn1_der_type_c * asn1_der_type_c::get_next_type() const
{
	const asn1_der_type_c * parent = get_parent_type();

	if (parent == 0)
	{
		return 0;
	}

	const u32_t next_index = get_index() + 1ul;

	if (parent->get_sub_types() == 0
		|| parent->get_sub_types()->get_object_count() <= next_index)
	{
		return 0;
	}

	return parent->get_sub_types()->get_object(next_index);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u16_t asn1_der_type_c::get_count_of_sub_types() const
{
	return m_count_of_sub_types;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void asn1_der_type_c::increase_count_of_sub_types()
{
	++m_count_of_sub_types;
}

//--------------------------------------------------

void asn1_der_type_c::add_used_octets(const u32_t used_octets)
{
	m_used_octets += used_octets;
}

//--------------------------------------------------

u32_t asn1_der_type_c::get_used_octets() const
{
	return m_used_octets;
}

//--------------------------------------------------

u32_t asn1_der_type_c::get_unused_data_length() const
{
	return get_input_data_length() - get_used_octets();
}

//--------------------------------------------------

const u8_t * asn1_der_type_c::get_unused_data() const
{
	return get_input_data() + get_used_octets();
}

//--------------------------------------------------

eap_status_e asn1_der_type_c::encode_oid_from_string(eap_const_string oid, const u32_t oid_length, eap_variable_data_c * const buffer) const
{
	if (oid == 0
		|| buffer == 0
		|| buffer->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_process_general_error);

	const eap_char * oid_char = oid;
	const eap_char * end_char = &oid[oid_length];
	u32_t remaining_length(oid_length);
	u32_t first_component(0ul);
	u32_t component_index(0ul);

	status = buffer->set_data_length(0ul);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	while(oid_char < end_char)
	{
		// Search next dot (.).
		const eap_char * dot  = reinterpret_cast<const eap_char *>(m_am_tools->memchr(oid_char, '.', remaining_length));
		if (dot == 0)
		{
			// The last component.
			dot  = reinterpret_cast<const eap_char *>(oid_char + remaining_length);
			if (dot == 0
				|| dot != end_char)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}
		}

		u32_t integer(0ul);

		status = m_am_tools->number_string_to_u32(
			reinterpret_cast<const u8_t *>(oid_char),
			dot - oid_char,
			&integer);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (component_index == 0ul)
		{
			// The first component is encoded with the second component.
			first_component = integer;
		}
		else if (component_index == 1ul)
		{
			if (first_component < 2ul
				&& integer > 39ul)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}
			else if (first_component > 2ul)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			const u32_t oid_value = first_component * 40ul + integer;
			if (oid_value > 0xff)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			const u8_t oid_octet(static_cast<u8_t>(oid_value));

			status = buffer->add_data(&oid_octet, sizeof(oid_octet));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			eap_variable_data_c encoded_data(m_am_tools);
			if (encoded_data.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			const u32_t ENCODE_BASE = 128ul;

			while(integer > 0ul)
			{
				const u8_t oid_octet = static_cast<u8_t>(integer % ENCODE_BASE);

				// Encodes the octets to reverse order.
				status = encoded_data.add_data(&oid_octet, sizeof(oid_octet));
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				integer = integer / ENCODE_BASE;
			} // while()

			for (u32_t ind = encoded_data.get_data_length(); ind > 0ul; --ind)
			{
				// reads the octets on reverse order.
				u8_t * oid_octet = encoded_data.get_data_offset(ind-1ul, sizeof(u8_t));
				if (oid_octet == 0)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
				}

				if (ind > 1ul)
				{
					// All but the last octet have high bit set.
					*oid_octet |= static_cast<u8_t>(asn1_high_bit_mask_tag);
				}

				status = buffer->add_data(oid_octet, sizeof(*oid_octet));
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			} // for()
		}

		remaining_length -= (dot - oid_char) + 1ul;

		oid_char = dot+1ul;

		++component_index;

	} // while()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e asn1_der_type_c::compare_object_identifier(const u8_t * const der_encoded_oid, const u32_t oid_length) const
{
	if (get_tag() != asn1_tag_object_identifier
		|| der_encoded_oid == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u32_t content_length(get_content_length());

	if (content_length != oid_length
		|| m_am_tools->memcmp(
			der_encoded_oid, 
			get_content(), 
			content_length) != 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return eap_status_no_match;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e asn1_der_type_c::compare_object_identifier(eap_const_string oid, const u32_t oid_length) const
{
	if (get_tag() != asn1_tag_object_identifier
		|| oid == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_variable_data_c oid_buffer(m_am_tools);

	if (oid_buffer.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = encode_oid_from_string(oid, oid_length, &oid_buffer);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return compare_object_identifier(oid_buffer.get_data(), oid_buffer.get_data_length());
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e asn1_der_type_c::decode(const eap_variable_data_c * const asn1_der_data)
{
	if (asn1_der_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_variable_data_c * debug_buffer = 0;

#if defined(USE_EAP_DEBUG_TRACE)
	// Buffer is used for debug traces.
	eap_variable_data_c tmp_debug_buffer(m_am_tools);

	{
		eap_status_e status = tmp_debug_buffer.set_buffer_length(MAX_DEBUG_BUFFER);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		debug_buffer = &tmp_debug_buffer;
	}
#endif //	#if defined(USE_EAP_DEBUG_TRACE)


	eap_status_e status = initialize(
		asn1_der_data->get_data_length(),
		asn1_der_data->get_data(),
		0ul,
		0ul,
		debug_buffer);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	asn1_der_type_c * current_type = this;

	if (current_type->get_pc() == asn1_pc_constructed)
	{
		ASN1_TYPE_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("# this = 0x%08x, input_data_length=%d, used_octets=%d\n"),
			 current_type,
			 current_type->get_input_data_length(),
			 current_type->get_used_octets()));

		while (current_type->get_used_octets() != current_type->get_input_data_length())
		{
			asn1_der_type_c * sub_type = new asn1_der_type_c(m_am_tools);

			eap_automatic_variable_c<asn1_der_type_c> automatic_sub_type(m_am_tools, sub_type);

			if (sub_type == 0
				|| sub_type->get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			ASN1_TYPE_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("# this = 0x%08x, unused_data_length=%d, recursion=%d\n"),
				 current_type,
				 current_type->get_unused_data_length(),
				 current_type->get_recursion()));

			status = sub_type->initialize(
				current_type->get_unused_data_length(),
				current_type->get_unused_data(),
				static_cast<u16_t>(current_type->get_recursion() + 1u),
				current_type->get_count_of_sub_types(),
				debug_buffer);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			current_type->increase_count_of_sub_types();

			ASN1_TYPE_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("# this = 0x%08x, used_octets=%d\n"),
				 sub_type,
				 sub_type->get_used_octets()));

			automatic_sub_type.do_not_free_variable();

			status = current_type->add_sub_type(sub_type);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (sub_type->get_pc() == asn1_pc_primitive)
			{
				ASN1_DEBUG_DATA(sub_type, debug_buffer);

				sub_type->add_used_octets(sub_type->get_content_length());

				current_type = sub_type;

				do
				{
					sub_type = current_type;
					current_type = current_type->get_parent_type();
					current_type->add_used_octets(sub_type->get_used_octets());

					ASN1_TYPE_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("# this = 0x%08x, input_data_length=%d, used_octets=%d\n"),
						 current_type,
						 current_type->get_input_data_length(),
						 current_type->get_used_octets()));
				}
				while (current_type->get_used_octets() == current_type->get_input_data_length() && current_type->get_parent_type() != 0);
			}
			else
			{
				current_type = sub_type;
			}

		} // while()
	}
	else
	{
		ASN1_DEBUG_DATA(this, debug_buffer);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

// End.
