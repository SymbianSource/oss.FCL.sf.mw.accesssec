/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/ec_cs_tlv_header.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 10 % << Don't touch! Updated by Synergy at check-out.
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
* Template version: 4.1.1
*/

// This is enumeration of WAPI source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 705 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#if defined(USE_WAPI_CORE)

#include "eap_am_memory.h"
#include "ec_cs_tlv_header.h"
#include "ec_cs_strings.h"

/** @file */


/**
 * The destructor of the ec_cs_tlv_header_c class does nothing.
 */
ec_cs_tlv_header_c::~ec_cs_tlv_header_c()
{
}

/**
 * The constructor of the ec_cs_tlv_header_c class simply initializes the attributes.
 */
ec_cs_tlv_header_c::ec_cs_tlv_header_c(
	abs_eap_am_tools_c * const tools,
	void * const header_begin,
	const u32_t header_buffer_length)
	: eap_general_header_base_c(tools, header_begin, header_buffer_length)
	, m_am_tools(tools)
{
}

/**
 * This function returns the TLV Type.
 */
ec_cs_tlv_type_e ec_cs_tlv_header_c::get_type() const
{
	const u8_t * const data = get_header_offset(m_type_offset, m_type_size);
	if (data != 0)
	{
		const u16_t value(eap_read_u16_t_network_order(data, m_type_size));

		EAP_STATIC_ASSERT(m_type_size == sizeof(value));

		return static_cast<ec_cs_tlv_type_e>(value);
	}
	else
	{
		return ec_cs_tlv_type_none;
	}
}

/**
 * This function returns the data length of TLV.
 */
u32_t ec_cs_tlv_header_c::get_data_length() const
{
	const u8_t * const length_data = get_header_offset(m_length_offset, m_length_size);
	if (length_data != 0)
	{
		return static_cast<u32_t>(eap_read_u16_t_network_order(length_data, m_length_size));
	}
	else
	{
		return 0ul;
	}
}

/**
 * This function returns the header length of TLV.
 */
u32_t ec_cs_tlv_header_c::get_header_length()
{
	return m_data_offset;
}

/**
 * This function returns pointer to the offset of data of TLV.
 * @param offset is the offset of queried data in bytes.
 * @param contignuous_bytes is the length of queried data in bytes.
 */
u8_t * ec_cs_tlv_header_c::get_data_offset(const u32_t offset, const u32_t contignuous_bytes) const
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
u8_t * ec_cs_tlv_header_c::get_data(const u32_t contignuous_bytes) const
{
	return get_data_offset(0u, contignuous_bytes);
}


/**
 * This function return pointer to the next TLV header in the same buffer.
 */
u8_t * ec_cs_tlv_header_c::get_next_header() const
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
eap_status_e ec_cs_tlv_header_c::check_header() const
{
	if (get_type() == ec_cs_tlv_type_none)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

/**
 * This function returns debug strings of the TLV type.
 */
eap_const_string ec_cs_tlv_header_c::get_tlv_string(const ec_cs_tlv_type_e type)
{
	return ec_cs_strings_c::get_ec_cs_tlv_header_string(type);
}

/**
 * This function returns debug strings of the TLV type.
 */
eap_const_string ec_cs_tlv_header_c::get_tlv_string() const
{
	const ec_cs_tlv_type_e type = get_type();
	return get_tlv_string(type);
}

/**
 * This function sets the TLV type flag.
 */
eap_status_e ec_cs_tlv_header_c::set_type(const ec_cs_tlv_type_e type)
{
	u8_t * const data = get_header_offset(m_type_offset, m_type_size);
	if (data != 0)
	{
		const u16_t value(static_cast<u16_t>(type));

		EAP_STATIC_ASSERT(m_type_size == sizeof(value));

		return EAP_STATUS_RETURN(m_am_tools, eap_write_u16_t_network_order(
			data,
			sizeof(value),
			value));
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

/**
 * This function sets the TLV data length.
 */
eap_status_e ec_cs_tlv_header_c::set_data_length(const u32_t p_length)
{
	u8_t * const data = get_header_offset(m_length_offset, m_length_size);
	if (data != 0)
	{
		const u16_t value(static_cast<u16_t>(p_length));

		EAP_STATIC_ASSERT(m_length_offset == sizeof(value));

		return EAP_STATUS_RETURN(m_am_tools, eap_write_u16_t_network_order(
			data,
			sizeof(value),
			value));
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

/**
 * This function resets the TLV header.
 */
eap_status_e ec_cs_tlv_header_c::reset_header()
{
	eap_status_e status = set_type(ec_cs_tlv_type_none);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_data_length(0ul);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

/**
 * This function resets the TLV header object.
 */
eap_status_e ec_cs_tlv_header_c::reset()
{
	eap_general_header_base_c::set_header_buffer(0, 0ul);

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//------------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

// End.
