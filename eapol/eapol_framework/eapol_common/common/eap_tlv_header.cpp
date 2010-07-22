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
	#define EAP_FILE_NUMBER_ENUM 39 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tlv_header.h"

/** @file */

//--------------------------------------------------

EAP_FUNC_EXPORT eap_tlv_header_c::~eap_tlv_header_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_tlv_header_c::eap_tlv_header_c(
	abs_eap_am_tools_c * const tools,
	void * const header_begin,
	const u32_t header_buffer_length)
	: eap_general_header_base_c(tools, header_begin, header_buffer_length)
	, m_am_tools(tools)
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_tlv_type_t eap_tlv_header_c::get_type() const
{
	const u8_t * const tlv_type_data = get_header_offset(m_type_offset, sizeof(u32_t));
	if (tlv_type_data != 0)
	{
		return static_cast<eap_tlv_type_t>(eap_read_u32_t_network_order(tlv_type_data, sizeof(u32_t)));
	}
	else
	{
		return eap_tlv_type_none;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_tlv_header_c::get_value_length() const
{
	const u8_t * const tlv_length_data = get_header_offset(m_length_offset, sizeof(u32_t));
	if (tlv_length_data != 0)
	{
		return eap_read_u32_t_network_order(tlv_length_data, sizeof(u32_t));
	}
	else
	{
		return 0ul;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_tlv_header_c::get_header_length()
{
	return m_data_offset;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * eap_tlv_header_c::get_value_offset(const u32_t offset, const u32_t contignuous_bytes) const
{
	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	u32_t data_length = get_value_length();

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


//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * eap_tlv_header_c::get_value(const u32_t contignuous_bytes) const
{
	return get_value_offset(0u, contignuous_bytes);
}


//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_tlv_header_c::check_header() const
{
	if ((get_header_length() + get_value_length()) > get_header_buffer_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_tlv_header_c::set_type(const eap_tlv_type_t type)
{
	if (type == eap_tlv_type_none)
	{
		EAP_ASSERT(type != eap_tlv_type_none);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_type);
	}

	u8_t * const type_data = get_header_offset(m_type_offset, sizeof(u32_t));

	if (type_data == 0)
	{
		EAP_ASSERT(type_data != 0);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	eap_write_u32_t_network_order(type_data, sizeof(u32_t), type);

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_tlv_header_c::set_value_length(const u32_t value_length)
{
	if (get_header_length() + value_length > get_header_buffer_length())
	{
		EAP_ASSERT(get_header_length() + value_length <= get_header_buffer_length());
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_long_message);
	}

	u8_t * const length_data = get_header_offset(m_length_offset, sizeof(u32_t));

	if (length_data == 0)
	{
		EAP_ASSERT(length_data != 0);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	eap_write_u32_t_network_order(length_data, sizeof(u32_t), value_length);

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_tlv_header_c::reset_header(
	const eap_tlv_type_t type,
	const u32_t value_length)
{
	eap_status_e status = set_type(type);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_value_length(value_length);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------



// End.
