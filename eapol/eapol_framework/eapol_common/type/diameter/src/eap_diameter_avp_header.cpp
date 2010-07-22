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
	#define EAP_FILE_NUMBER_ENUM 73 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_diameter_avp_header.h"

/** @file */

//-----------------------------------------------------------------------------

/**
 * This function returns length of the required padding.
 */
u32_t eap_diameter_avp_header_c::get_padding_length() const
{
	// NOTE AVP is padded always to multiple of 4 octets.
	u32_t avp_length = get_length();
	u32_t remainder = avp_length % 4ul;
	if (remainder != 0ul)
	{
		return 4ul - remainder;
	}
	else
	{
		return 0;
	}
}

//-----------------------------------------------------------------------------

/**
 * The destructor of the eap_diameter_avp_header_c class does nothing.
 */
eap_diameter_avp_header_c::~eap_diameter_avp_header_c()
{
}

//-----------------------------------------------------------------------------

/**
 * The constructor of the eap_diameter_avp_header_c class simply initializes the attributes.
 */
eap_diameter_avp_header_c::eap_diameter_avp_header_c(
	abs_eap_am_tools_c * const tools,
	void * const header_begin,
	const u32_t header_buffer_length)
	: eap_general_header_base_c(tools, header_begin, header_buffer_length)
	, m_am_tools(tools)
{
}

//-----------------------------------------------------------------------------

/**
 * This function returns the AVP Code.
 */
eap_diameter_avp_code_c eap_diameter_avp_header_c::get_avp_code() const
{
	const u8_t * const code_data = get_header_offset(m_avp_code_offset, sizeof(u32_t));
	if (code_data  != 0)
	{
		const u32_t avp_code = eap_read_u32_t_network_order(code_data, sizeof(u32_t));

		eap_diameter_vendor_id_e vendor_id(eap_diameter_vendor_id_of_ietf);

		if (get_avp_flag_vendor_specific() == true)
		{
			// We have vendor specific AVP code.
			// This reads the vendor ID.
			const u8_t * const vendor_id_data = get_header_offset(m_vendor_id_or_data_offset, sizeof(u32_t));
			if (vendor_id_data  != 0)
			{
				vendor_id = static_cast<eap_diameter_vendor_id_e>(eap_read_u32_t_network_order(vendor_id_data, sizeof(u32_t)));
			}
			else
			{
				return eap_diameter_avp_code_none;
			}
		}

		eap_diameter_avp_code_c vendor_specific_code(vendor_id, avp_code);

		return vendor_specific_code;
	}
	else
	{
		return eap_diameter_avp_code_none;
	}
}

//-----------------------------------------------------------------------------

/**
 * This function returns the AVP vendor specific flag.
 */
bool eap_diameter_avp_header_c::get_avp_flag_vendor_specific() const
{
	const u8_t * const flags = get_header_offset(m_flags_offset, sizeof(u8_t));
	if (flags != 0)
	{
		if (((*flags) & m_flag_mask_vendor_specific_avp) != 0)
		{
			return true;
		}
	}
	return false;
}

//-----------------------------------------------------------------------------

/**
 * This function returns the AVP mandatory flag.
 */
bool eap_diameter_avp_header_c::get_avp_flag_mandatory_avp() const
{
	const u8_t * const flags = get_header_offset(m_flags_offset, sizeof(u8_t));
	if (flags != 0)
	{
		if (((*flags) & m_flag_mask_mandatory_avp) != 0)
		{
			return true;
		}
	}
	return false;
}

//-----------------------------------------------------------------------------

/**
 * This function returns the AVP reserved flags.
 */
u8_t eap_diameter_avp_header_c::get_avp_flags_reserved() const
{
	const u8_t * const flags = get_header_offset(m_flags_offset, sizeof(u8_t));
	if (flags != 0)
	{
		return static_cast<u8_t>((*flags) & m_flag_mask_reserved_avp);
	}
	
	return 0xff;
}

//-----------------------------------------------------------------------------

/**
 * This function returns the length of AVP (header+data).
 */
u32_t eap_diameter_avp_header_c::get_length() const
{
	return get_header_length() + get_data_length();
}

//-----------------------------------------------------------------------------

/**
 * This function returns the length of AVP data.
 */
u32_t eap_diameter_avp_header_c::get_data_length() const
{
	const u8_t * const length_data = get_header_offset(m_length_offset, 3ul*sizeof(u8_t));
	if (length_data != 0)
	{
		u32_t header_and_data_length = eap_read_u24_t_network_order(length_data, 3ul*sizeof(u8_t));
		if (header_and_data_length > get_header_length())
		{
			return header_and_data_length - get_header_length();
		}
	}
	return 0ul;
}

//-----------------------------------------------------------------------------

/**
 * This function returns the header length of AVP.
 */
u32_t eap_diameter_avp_header_c::get_header_length(const bool include_vendor_specific)
{
	if (include_vendor_specific == true)
	{
		return m_data_with_vendor_id_offset;
	}
	else
	{
		return m_vendor_id_or_data_offset;
	}
}

//-----------------------------------------------------------------------------

/**
 * This function returns the header length of AVP.
 */
u32_t eap_diameter_avp_header_c::get_header_length() const
{
	return get_header_length(get_avp_flag_vendor_specific());
}

//-----------------------------------------------------------------------------

/**
 * This function returns pointer to the offset of data of AVP.
 * @param offset is the offset of queried data in bytes.
 * @param contignuous_bytes is the length of queried data in bytes.
 */
u8_t * eap_diameter_avp_header_c::get_data_offset(const u32_t offset, const u32_t contignuous_bytes) const
{
	u32_t data_length = get_header_buffer_length() - get_header_length();

	if (data_length >= offset+contignuous_bytes)
	{
		u8_t * data = 0;
		
		if (get_avp_flag_vendor_specific() == true)
		{
			data = get_header_offset(m_data_with_vendor_id_offset, offset+contignuous_bytes);
		}
		else
		{
			data = get_header_offset(m_vendor_id_or_data_offset, offset+contignuous_bytes);
		}
		
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

//-----------------------------------------------------------------------------

/**
 * This function returns pointer to the offset of data of AVP.
 * @param contignuous_bytes is the length of queried data in bytes.
 */
u8_t * eap_diameter_avp_header_c::get_data(const u32_t contignuous_bytes) const
{
	return get_data_offset(0u, contignuous_bytes);
}

//-----------------------------------------------------------------------------

/**
 * This function return pointer to the next AVP header in the same buffer.
 */
u8_t * eap_diameter_avp_header_c::get_next_header() const
{
	// NOTE AVP is padded always to multiple of 4 octets.
	u32_t data_length = get_header_buffer_length() - get_header_length();
	u32_t avp_data_length = get_data_length();
	u32_t padding_length = get_padding_length();
	u32_t required_length = avp_data_length+padding_length+EAP_DIAMETER_AVP_MINIMUM_HEADER_LENGTH;
	
	if (data_length >= required_length)
	{
		return get_data_offset(avp_data_length+padding_length, EAP_DIAMETER_AVP_MINIMUM_HEADER_LENGTH);
	}
	else
	{
		return 0;
	}
}

//-----------------------------------------------------------------------------

/**
 * This function checks the header is valid.
 */
eap_status_e eap_diameter_avp_header_c::check_header() const
{
	if (get_avp_code() != eap_diameter_avp_code_eap_message)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	else if (get_avp_flags_reserved() != 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	else if (get_avp_flag_vendor_specific() == true
			 && get_header_buffer_length() < m_data_with_vendor_id_offset)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
	}
	else if (get_avp_flag_vendor_specific() == false
			 && get_header_buffer_length() < m_vendor_id_or_data_offset)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
	}
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//-----------------------------------------------------------------------------

/**
 * This function returns debug strings of the AVP Code.
 */
eap_const_string eap_diameter_avp_header_c::get_avp_code_string() const
{

#if defined(USE_EAP_TRACE_STRINGS)
	const eap_diameter_avp_code_c code = get_avp_code();

	EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_none)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_user_name)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_user_password)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_chap_password)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_nas_ip_address)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_nas_port)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_service_type)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_framed_protocol)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_framed_ip_address)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_framed_ip_netmask)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_framed_routing)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_filter_id)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_framed_mtu)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_framed_compression)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_login_ip_host)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_login_service)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_login_tcp_port)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_reply_message)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_callback_number)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_callback_id)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_framed_route)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_framed_ipx_network)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_state)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_class)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_vendor_specific)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_session_timeout)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_idle_timeout)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_termination_action)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_called_station_id)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_calling_station_id)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_nas_identifier)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_proxy_state)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_login_lat_service)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_login_lat_node)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_login_lat_group)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_framed_appletalk_link)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_framed_appletalk_network)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_framed_appletalk_zone)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_chap_challenge)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_nas_port_type)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_port_limit)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_login_lat_port)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_eap_message)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_message_authenticator)
	else EAP_IF_RETURN_STRING(code, eap_diameter_avp_code_eap_message)
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	else EAP_IF_RETURN_STRING(code, eap_diameter_vendor_code_of_microsoft_ms_chap_error.get_code())
	else EAP_IF_RETURN_STRING(code, eap_diameter_vendor_code_of_microsoft_ms_chap_nt_enc_pw.get_code())
	else EAP_IF_RETURN_STRING(code, eap_diameter_vendor_code_of_microsoft_ms_chap_challenge.get_code())
	else EAP_IF_RETURN_STRING(code, eap_diameter_vendor_code_of_microsoft_ms_chap2_response.get_code())
	else EAP_IF_RETURN_STRING(code, eap_diameter_vendor_code_of_microsoft_ms_chap2_success.get_code())
	else EAP_IF_RETURN_STRING(code, eap_diameter_vendor_code_of_microsoft_ms_chap2_cpw.get_code())
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown AVP code");
	}
}

//-----------------------------------------------------------------------------

/**
 * This function sets the AVP Code.
 */
eap_status_e eap_diameter_avp_header_c::set_avp_code(const eap_diameter_avp_code_c code)
{
	eap_status_e status(eap_status_process_general_error);

	{
		u8_t * const code_data = get_header_offset(m_avp_code_offset, sizeof(u32_t));
		
		if (code_data == 0)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = eap_write_u32_t_network_order(
				code_data,
				sizeof(u32_t),
				code.get_vendor_code());
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (code.get_vendor_id() != eap_diameter_vendor_id_of_ietf)
	{
		// We have vendor specific AVP code.
		// This writes the vendor ID.

		status = set_avp_flag_vendor_specific(true);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		u8_t * const vendor_id_data = get_header_offset(m_vendor_id_or_data_offset, sizeof(u32_t));
		
		if (vendor_id_data == 0)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = eap_write_u32_t_network_order(
				vendor_id_data,
				sizeof(u32_t),
				code.get_vendor_id());
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-----------------------------------------------------------------------------

/**
 * This function sets the AVP vendor specific flag.
 */
eap_status_e eap_diameter_avp_header_c::set_avp_flag_vendor_specific(
	const bool vendor_specific)
{
	u8_t * const flags = get_header_offset(m_flags_offset, sizeof(u8_t));
	if (flags != 0)
	{
		if (vendor_specific == true)
		{
			*flags = static_cast<u8_t>((*flags) | m_flag_mask_vendor_specific_avp);
		}
		else
		{
			*flags = static_cast<u8_t>((*flags) & ~m_flag_mask_vendor_specific_avp);
		}
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	
	return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
}

//-----------------------------------------------------------------------------

/**
 * This function sets the AVP mandatory flag.
 */
eap_status_e eap_diameter_avp_header_c::set_avp_flag_mandatory_avp(const bool mandatory)
{
	u8_t * const flags = get_header_offset(m_flags_offset, sizeof(u8_t));
	if (flags != 0)
	{
		if (mandatory == true)
		{
			*flags = static_cast<u8_t>((*flags) | m_flag_mask_mandatory_avp);
		}
		else
		{
			*flags = static_cast<u8_t>((*flags) & ~m_flag_mask_mandatory_avp);
		}
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	
	return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
}

//-----------------------------------------------------------------------------

/**
 * This function sets the AVP mandatory flag.
 */
eap_status_e eap_diameter_avp_header_c::set_avp_flags_reserved()
{
	u8_t * const flags = get_header_offset(m_flags_offset, sizeof(u8_t));
	if (flags != 0)
	{
		*flags = static_cast<u8_t>(((*flags) & ~m_flag_mask_reserved_avp) | 0ul);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	
	return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
}

//-----------------------------------------------------------------------------

/**
 * This function sets the AVP data length.
 */
eap_status_e eap_diameter_avp_header_c::set_data_length(const u32_t p_length)
{
	u8_t * const length_data = get_header_offset(m_length_offset, 3ul*sizeof(u8_t));
	if (length_data != 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			eap_write_u24_t_network_order(
				length_data,
				3ul*sizeof(u8_t),
				p_length));
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
}

//-----------------------------------------------------------------------------

/**
 * This function resets the AVP header.
 */
eap_status_e eap_diameter_avp_header_c::reset_header(const u16_t data_length)
{
	eap_status_e status = set_avp_code(eap_diameter_avp_code_none);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	status = set_avp_flag_vendor_specific(false);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	status = set_avp_flag_mandatory_avp(false);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	status = set_avp_flags_reserved();
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_data_length(data_length);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-----------------------------------------------------------------------------
// End.
