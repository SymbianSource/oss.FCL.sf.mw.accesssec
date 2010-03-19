/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/wai_protocol_packet_header.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 18 % << Don't touch! Updated by Synergy at check-out.
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
	#define EAP_FILE_NUMBER_ENUM 702 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#if defined(USE_WAPI_CORE)

#include "eap_am_memory.h"
#include "wai_protocol_packet_header.h"

/** @file */


/**
 * The destructor of the wai_protocol_packet_header_c class does nothing.
 */
wai_protocol_packet_header_c::~wai_protocol_packet_header_c()
{
}

/**
 * The constructor of the wai_protocol_packet_header_c class.
 */
wai_protocol_packet_header_c::wai_protocol_packet_header_c(
	abs_eap_am_tools_c * const tools)
	: eap_general_header_base_c(tools, 0, 0)
	, m_am_tools(tools)
{
}

/**
 * The constructor of the wai_protocol_packet_header_c class simply initializes the attributes.
 */
wai_protocol_packet_header_c::wai_protocol_packet_header_c(
	abs_eap_am_tools_c * const tools,
	void * const header_begin,
	const u32_t header_buffer_length)
	: eap_general_header_base_c(tools, header_begin, header_buffer_length)
	, m_am_tools(tools)
{
}

/**
 * This function sets the header buffer.
 */
eap_status_e wai_protocol_packet_header_c::set_header_buffer(
	void * const header_begin,
	const u32_t header_buffer_length)
{
	eap_general_header_base_c::set_header_buffer(reinterpret_cast<u8_t *>(header_begin), header_buffer_length);

	if (get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("wai_protocol_packet_header_c::set_header_buffer(): packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

/**
 * This function returns the Version value.
 */
wai_protocol_version_e wai_protocol_packet_header_c::get_version() const
{
	const u8_t * const data = get_header_offset(m_version_offset, m_version_size);
	if (data != 0)
	{
		u16_t value = eap_read_u16_t_network_order(
			data, m_version_size);

		EAP_STATIC_ASSERT(m_version_size == sizeof(value));

		return static_cast<wai_protocol_version_e>(value);
	}

	return wai_protocol_version_none;
}

/**
 * This function returns the Type value.
 */
wai_protocol_type_e wai_protocol_packet_header_c::get_type() const
{
	const u8_t * const data = get_header_offset(m_type_offset, m_type_size);
	if (data != 0)
	{
		EAP_STATIC_ASSERT(m_type_size == sizeof(*data));

		return static_cast<wai_protocol_type_e>(*data);
	}

	return wai_protocol_type_none;
}

/**
 * This function returns the Subtype value.
 */
wai_protocol_subtype_e wai_protocol_packet_header_c::get_subtype() const
{
	const u8_t * const data = get_header_offset(m_subtype_offset, m_subtype_size);
	if (data != 0)
	{
		EAP_STATIC_ASSERT(m_subtype_size == sizeof(*data));

		return static_cast<wai_protocol_subtype_e>(*data);
	}

	return wai_protocol_subtype_none;
}

/**
 * This function returns the Reserved value.
 */
u16_t wai_protocol_packet_header_c::get_reserved() const
{
	const u8_t * const data = get_header_offset(m_reserved_offset, m_reserved_size);
	if (data != 0)
	{
		u16_t value = eap_read_u16_t_network_order(
			data, m_reserved_size);

		EAP_STATIC_ASSERT(m_reserved_size == sizeof(value));

		return value;
	}

	return 0xffff;
}

/**
 * This function returns the Length value.
 */
u32_t wai_protocol_packet_header_c::get_length() const
{
	const u8_t * const data = get_header_offset(m_length_offset, m_length_size);
	if (data != 0)
	{
		u16_t value = eap_read_u16_t_network_order(
			data, m_length_size);

		EAP_STATIC_ASSERT(m_length_size == sizeof(value));

		return value;
	}

	return 0u;
}

/**
 * This function returns the Packet sequence number value.
 */
u16_t wai_protocol_packet_header_c::get_packet_sequence_number() const
{
	const u8_t * const data = get_header_offset(m_packet_sequence_number_offset, m_packet_sequence_number_size);
	if (data != 0)
	{
		u16_t value = eap_read_u16_t_network_order(
			data, m_packet_sequence_number_size);

		EAP_STATIC_ASSERT(m_packet_sequence_number_size == sizeof(value));

		return value;
	}

	return 0u;
}

/**
 * This function returns the Fragment sequence number value.
 */
u8_t wai_protocol_packet_header_c::get_fragment_sequence_number() const
{
	const u8_t * const data = get_header_offset(m_fragment_sequence_number_offset, m_fragment_sequence_number_size);
	if (data != 0)
	{
		EAP_STATIC_ASSERT(m_fragment_sequence_number_size == sizeof(*data));

		return (*data);
	}

	return 0xff;
}

/**
 * This function returns the Flag value.
 */
u8_t wai_protocol_packet_header_c::get_flag() const
{
	const u8_t * const data = get_header_offset(m_flag_offset, m_flag_size);
	if (data != 0)
	{
		EAP_STATIC_ASSERT(m_flag_size == sizeof(*data));

		return (*data);
	}

	return 0xff;
}

/**
 * This function returns the header length of WAI protocol packet.
 */
u32_t wai_protocol_packet_header_c::get_header_length()
{
	return m_data_offset;
}

/**
 * This function returns the data length of WAI protocol packet.
 */
u32_t wai_protocol_packet_header_c::get_data_length() const
{
	u32_t length = get_length();

	if (length >= get_header_length())
	{
		return (length - get_header_length());
	}
	else
	{
		return 0ul;
	}
}

/**
 * This function returns pointer to the offset of data of WAI protocol packet.
 * @param offset is the offset of queried data in bytes.
 * @param contignuous_bytes is the length of queried data in bytes.
 */
u8_t * wai_protocol_packet_header_c::get_data_offset(const u32_t offset, const u32_t contignuous_bytes) const
{
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
 * This function returns pointer to the begin of data of WAI protocol packet.
 * @param contignuous_bytes is the length of queried data in bytes.
 */
u8_t * wai_protocol_packet_header_c::get_data(const u32_t contignuous_bytes) const
{
	return get_data_offset(0u, contignuous_bytes);
}

/**
 * This function checks the header is valid.
 */
eap_status_e wai_protocol_packet_header_c::check_header() const
{
	if (get_version() != wai_protocol_version_1)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	else if (get_reserved() != 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	else if (get_length() < get_header_length())
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	else if (get_length() > get_header_buffer_length())
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

/**
 * This function sets the Version value.
 */
eap_status_e wai_protocol_packet_header_c::set_version(const wai_protocol_version_e version)
{
	const u16_t value = static_cast<u16_t>(version);

	u8_t * const data = get_header_offset(m_version_offset, m_version_size);
	if (data != 0)
	{
		EAP_STATIC_ASSERT(m_version_size == sizeof(value));

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
 * This function sets the Type value.
 */
eap_status_e wai_protocol_packet_header_c::set_type(const wai_protocol_type_e type)
{
	const u8_t value = static_cast<u8_t>(type);

	u8_t * const data = get_header_offset(m_type_offset, m_type_size);
	if (data != 0)
	{
		EAP_STATIC_ASSERT(m_type_size == sizeof(*data));

		*data = value;
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

/**
 * This function sets the Subype value.
 */
eap_status_e wai_protocol_packet_header_c::set_subtype(const wai_protocol_subtype_e subtype)
{
	const u8_t value = static_cast<u8_t>(subtype);

	u8_t * const data = get_header_offset(m_subtype_offset, m_subtype_size);
	if (data != 0)
	{
		EAP_STATIC_ASSERT(m_subtype_size == sizeof(*data));

		*data = value;
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

/**
 * This function sets the Reserved value.
 */
eap_status_e wai_protocol_packet_header_c::set_reserved(const u16_t reserved)
{
	u8_t * const data = get_header_offset(m_reserved_offset, m_reserved_size);
	if (data != 0)
	{
		EAP_STATIC_ASSERT(m_version_size == sizeof(reserved));

		return EAP_STATUS_RETURN(m_am_tools, eap_write_u16_t_network_order(
			data,
			sizeof(reserved),
			reserved));
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

/**
 * This function sets the Length value.
 */
eap_status_e wai_protocol_packet_header_c::set_length(const u32_t length)
{
	u8_t * const data = get_header_offset(m_length_offset, m_length_size);
	if (data != 0
		&& length <= 0xffff)
	{
		const u16_t value = static_cast<u16_t>(length);

		EAP_STATIC_ASSERT(m_length_size == sizeof(value));

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
 * This function sets the Packet sequence number value.
 */
eap_status_e wai_protocol_packet_header_c::set_packet_sequence_number(const u16_t packet_sequence_number)
{
	u8_t * const data = get_header_offset(m_packet_sequence_number_offset, m_packet_sequence_number_size);
	if (data != 0)
	{
		EAP_STATIC_ASSERT(m_packet_sequence_number_size == sizeof(packet_sequence_number));

		return EAP_STATUS_RETURN(m_am_tools, eap_write_u16_t_network_order(
			data,
			sizeof(packet_sequence_number),
			packet_sequence_number));
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

/**
 * This function sets the Fragment sequence number value.
 */
eap_status_e wai_protocol_packet_header_c::set_fragment_sequence_number(const u8_t fragment_sequence_number)
{
	u8_t * const data = get_header_offset(m_fragment_sequence_number_offset, m_fragment_sequence_number_size);
	if (data != 0)
	{
		EAP_STATIC_ASSERT(m_fragment_sequence_number_size == sizeof(fragment_sequence_number));

		*data = fragment_sequence_number;
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

/**
 * This function sets the Subype value.
 */
eap_status_e wai_protocol_packet_header_c::set_flag(const u8_t flag)
{
	u8_t * const data = get_header_offset(m_flag_offset, m_flag_size);
	if (data != 0)
	{
		EAP_STATIC_ASSERT(m_flag_size == sizeof(flag));

		*data = flag;
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

/**
 * This function resets the WAI protocol packet header.
 */
eap_status_e wai_protocol_packet_header_c::reset_header()
{
	eap_status_e status = set_version(wai_protocol_version_1);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_type(wai_protocol_type_wai);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	status = set_subtype(wai_protocol_subtype_none);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	status = set_reserved(0u);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_length(get_header_length());
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_packet_sequence_number(WAI_FIRST_SEQUENCE_NUMBER);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_fragment_sequence_number(WAI_FIRST_FRAGMENT_NUMBER);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_flag(0u);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//------------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

// End.
