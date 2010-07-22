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
	#define EAP_FILE_NUMBER_ENUM 102 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_radius_attribute_header.h"
#include "eap_header_string.h"


/** @file */


// 
EAP_FUNC_EXPORT eap_radius_attribute_header_c::~eap_radius_attribute_header_c()
{
}

// 
EAP_FUNC_EXPORT eap_radius_attribute_header_c::eap_radius_attribute_header_c(
	abs_eap_am_tools_c * const tools,
	void * const header_buffer,
	const u32_t header_buffer_length)
	: eap_general_header_base_c(tools, header_buffer, header_buffer_length)
	  , m_am_tools(tools)
{
}

EAP_FUNC_EXPORT eap_diameter_avp_code_c eap_radius_attribute_header_c::get_current_payload() const
{
	const u8_t * const payload_data = get_header_offset(m_type_offset, sizeof(u8_t));
	if (payload_data != 0)
	{
		eap_diameter_avp_code_c avp_code(static_cast<eap_diameter_avp_code_of_ietf_e>(*payload_data));
		return avp_code;
	}
	else
	{
		return eap_diameter_avp_code_none;
	}
}

EAP_FUNC_EXPORT u16_t eap_radius_attribute_header_c::get_length() const
{
	const u8_t * const length_data = get_header_offset(m_length_offset, sizeof(u8_t));
	if (length_data != 0)
	{
		return static_cast<u16_t>(*length_data);
	}
	else
	{
		return 0ul;
	}
}

EAP_FUNC_EXPORT u32_t eap_radius_attribute_header_c::get_data_length() const
{
	if (get_length() > get_header_length())
		return static_cast<u32_t>(get_length()-get_header_length());
	else
		return 0;
}

EAP_FUNC_EXPORT u16_t eap_radius_attribute_header_c::get_header_length()
{
	return m_data_offset;
}

EAP_FUNC_EXPORT u16_t eap_radius_attribute_header_c::get_max_attribute_data_length()
{
	return static_cast<u16_t>((0xff & (~0)) - get_header_length());
}

EAP_FUNC_EXPORT u8_t * eap_radius_attribute_header_c::get_data_offset(const u32_t offset, const u32_t contignuous_bytes) const
{
	u32_t data_length = get_header_buffer_length() - get_header_length();

	if (data_length >= offset+contignuous_bytes
		&& contignuous_bytes > 0)
	{
		u8_t * const data = get_header_offset(m_data_offset, contignuous_bytes);
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
		EAP_ASSERT(
			data_length >= offset+contignuous_bytes
			&& contignuous_bytes > 0);
	}
	return 0;
}

EAP_FUNC_EXPORT u8_t * eap_radius_attribute_header_c::get_next_header() const
{
	if (get_header_buffer_length() >= get_data_length()+2ul*get_header_length())
	{
		return get_data_offset(get_data_length(), get_header_length());
	}
	else
	{
		return 0;
	}
}

EAP_FUNC_EXPORT void eap_radius_attribute_header_c::set_current_payload(
	const eap_diameter_avp_code_c p_current_payload)
{
	u8_t * const payload_type = get_header_offset(m_type_offset, sizeof(u8_t));

	EAP_ASSERT(payload_type != 0);
	
	*payload_type = static_cast<u8_t>(p_current_payload.get_vendor_code());
}

EAP_FUNC_EXPORT void eap_radius_attribute_header_c::set_data_length(const u16_t p_data_length)
{
	u32_t total_length = p_data_length+eap_radius_attribute_header_c::get_header_length();

	u8_t * const length_data = get_header_offset(m_length_offset, sizeof(u8_t));
	
	EAP_ASSERT(length_data != 0);
	
	*length_data = static_cast<u8_t>(total_length);
}

EAP_FUNC_EXPORT void eap_radius_attribute_header_c::reset_header(const u16_t data_length)
{
	set_current_payload(eap_diameter_avp_code_none);
	set_data_length(data_length);
}

EAP_FUNC_EXPORT eap_const_string eap_radius_attribute_header_c::get_payload_type_string() const
{

#if defined(USE_EAP_TRACE_STRINGS)
	const eap_diameter_avp_code_c payload_type = get_current_payload();

	EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_none)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_user_name)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_user_password)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_chap_password)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_nas_ip_address)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_nas_port)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_service_type)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_framed_protocol)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_framed_ip_address)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_framed_ip_netmask)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_framed_routing)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_filter_id)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_framed_mtu)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_framed_compression)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_login_ip_host)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_login_service)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_login_tcp_port)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_reply_message)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_callback_number)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_callback_id)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_framed_route)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_framed_ipx_network)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_state)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_class)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_vendor_specific)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_session_timeout)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_idle_timeout)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_termination_action)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_called_station_id)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_calling_station_id)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_nas_identifier)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_proxy_state)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_login_lat_service)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_login_lat_node)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_login_lat_group)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_framed_appletalk_link)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_framed_appletalk_network)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_framed_appletalk_zone)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_chap_challenge)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_nas_port_type)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_port_limit)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_login_lat_port)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_eap_message)
	else EAP_IF_RETURN_STRING(payload_type, eap_diameter_avp_code_message_authenticator)
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown RADIUS payload AT");
	}
}

EAP_FUNC_EXPORT eap_status_e eap_radius_attribute_header_c::check_header() const
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

// End.
