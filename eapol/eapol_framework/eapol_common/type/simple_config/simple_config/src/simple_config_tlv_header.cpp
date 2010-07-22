/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  defines header of Attribute-Value Pairs used in protected setup.
*
*/

/*
* %version: 11.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 598 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "simple_config_tlv_header.h"
#include "simple_config_types.h"


/** @file */


/**
 * The destructor of the simple_config_tlv_header_c class does nothing.
 */
simple_config_tlv_header_c::~simple_config_tlv_header_c()
{
}

/**
 * The constructor of the simple_config_tlv_header_c class simply initializes the attributes.
 */
simple_config_tlv_header_c::simple_config_tlv_header_c(
	abs_eap_am_tools_c * const tools)
	: eap_general_header_base_c(tools, 0, 0ul)
	, m_am_tools(tools)
{
}

/**
 * The constructor of the simple_config_tlv_header_c class simply initializes the attributes.
 */
simple_config_tlv_header_c::simple_config_tlv_header_c(
	abs_eap_am_tools_c * const tools,
	void * const header_begin,
	const u32_t header_buffer_length)
	: eap_general_header_base_c(tools, header_begin, header_buffer_length)
	, m_am_tools(tools)
{
}

/**
 * This function returns the TLV type flag.
 */
simple_config_Attribute_Type_e simple_config_tlv_header_c::get_tlv_type() const
{
	const u8_t * const flag_tlv_type_data = get_header_offset(m_tlv_type_offset, sizeof(u16_t));
	if (flag_tlv_type_data != 0)
	{
		return static_cast<simple_config_Attribute_Type_e>(
			(static_cast<u16_t>(flag_tlv_type_data[0] << 8)
			| (static_cast<u16_t>(flag_tlv_type_data[1]))));
	}
	else
	{
		return simple_config_Attribute_Type_None;
	}
}

/**
 * This function returns the data length of TLV.
 */
u32_t simple_config_tlv_header_c::get_length() const
{
	return get_header_length() + get_data_length();
}

/**
 * This function returns the data length of TLV.
 */
u16_t simple_config_tlv_header_c::get_data_length() const
{
	const u8_t * const length_data = get_header_offset(m_length_offset, sizeof(u16_t));
	if (length_data != 0)
	{
		return eap_read_u16_t_network_order(length_data, sizeof(u16_t));
	}
	else
	{
		return 0ul;
	}
}

/**
 * This function returns the header length of TLV.
 */
u32_t simple_config_tlv_header_c::get_header_length()
{
	return m_data_offset;
}

/**
 * This function returns pointer to the offset of data of TLV.
 * @param offset is the offset of queried data in bytes.
 * @param contignuous_bytes is the length of queried data in bytes.
 */
u8_t * simple_config_tlv_header_c::get_data_offset(const u32_t offset, const u32_t contignuous_bytes) const
{
	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	u32_t data_length = get_data_length();

	if (data_length >= offset+contignuous_bytes)
	{
		u8_t * const data = get_header_offset(m_data_offset, offset+contignuous_bytes);
		if (data != 0)
		{
			return &data[offset];
		}
		else
		{
			return 0;
		}
	}
	else
	{
		EAP_ASSERT_ALWAYS(data_length >= offset+contignuous_bytes);
	}
	return 0;
}


/**
 * This function returns pointer to the offset of data of TLV.
 * @param contignuous_bytes is the length of queried data in bytes.
 */
u8_t * simple_config_tlv_header_c::get_data(const u32_t contignuous_bytes) const
{
	return get_data_offset(0ul, contignuous_bytes);
}


/**
 * This function return pointer to the next TLV header in the same buffer.
 */
u8_t * simple_config_tlv_header_c::get_next_header() const
{
	if (get_header_buffer_length() >= 2ul*get_header_length()+get_data_length())
	{
		return get_data_offset(get_data_length(), get_header_length());
	}
	else
	{
		return 0;
	}
}


/**
 * This function checks the header is valid.
 */
eap_status_e simple_config_tlv_header_c::check_header() const
{
	if (get_tlv_type() < simple_config_Attribute_Type_First_Correct_Value
		|| get_tlv_type() > simple_config_Attribute_Type_Last_Correct_Value)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

/**
 * This function returns debug strings of the TLV type.
 */
eap_const_string simple_config_tlv_header_c::get_tlv_type_string() const
{
	eap_simple_config_trace_string_c debug_string;

	return debug_string.get_attribute_type_string(get_tlv_type());
}

/**
 * This function sets the TLV type flag.
 */
void simple_config_tlv_header_c::set_tlv_type(simple_config_Attribute_Type_e type)
{
	u8_t * const flag_tlv_type_data = get_header_offset(m_tlv_type_offset, sizeof(u16_t));
	
	EAP_ASSERT(flag_tlv_type_data != 0);
	
	flag_tlv_type_data[0] = static_cast<u8_t>((type & 0xff00) >> 8);
	flag_tlv_type_data[1] = static_cast<u8_t>(type & 0x00ff);
}

/**
 * This function sets the TLV data length.
 */
void simple_config_tlv_header_c::set_data_length(const u16_t p_length)
{
	u8_t * const length_data = get_header_offset(m_length_offset, sizeof(u16_t));
	
	EAP_ASSERT(length_data != 0);
	
	length_data[0] = static_cast<u8_t>((p_length & 0xff00) >> 8);
	length_data[1] = static_cast<u8_t>((p_length & 0x00ff));
}

/**
 * This function resets the TLV header.
 */
void simple_config_tlv_header_c::reset_header(const u16_t buffer_length)
{
	set_tlv_type(simple_config_Attribute_Type_None);
	set_data_length(buffer_length);
}




// End.
