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
	#define EAP_FILE_NUMBER_ENUM 68 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_tools.h"
#include "eap_header.h"
#include "eap_header_string.h"
#include "eap_type_aka_header.h"

/** @file */


// 
EAP_FUNC_EXPORT aka_payload_AT_header_c::~aka_payload_AT_header_c()
{
}

// 
EAP_FUNC_EXPORT aka_payload_AT_header_c::aka_payload_AT_header_c(
	abs_eap_am_tools_c * const tools,
	void * const header_buffer,
	const u32_t header_buffer_length)
	: eap_general_header_base_c(tools, header_buffer, header_buffer_length)
	, m_am_tools(tools)
{
}

EAP_FUNC_EXPORT aka_payload_AT_type_e aka_payload_AT_header_c::get_current_payload() const
{
	const u8_t * const payload_data = get_header_offset(m_type_offset, sizeof(u8_t));
	if (payload_data != 0)
	{
		return static_cast<aka_payload_AT_type_e>(*payload_data);
	}
	else
	{
		return aka_payload_NONE;
	}
}

EAP_FUNC_EXPORT u16_t aka_payload_AT_header_c::get_payload_length() const
{
	const u8_t * const length_data = get_header_offset(m_length_offset, sizeof(u8_t));
	if (length_data != 0)
	{
		return static_cast<u16_t>(*length_data * 4u);
	}
	else
	{
		return 0ul;
	}
}

EAP_FUNC_EXPORT u16_t aka_payload_AT_header_c::get_reserved() const
{
	const u8_t * const reserved = get_header_offset(m_reserved_offset, sizeof(u16_t));
	if (reserved != 0)
	{
		return eap_read_u16_t_network_order(reserved, sizeof(u16_t));
	}
	else
	{
		// this is illegal reserved field value.
		return 0xffff;
	}
}

EAP_FUNC_EXPORT u8_t * aka_payload_AT_header_c::get_reserved_pointer(const u32_t contignuous_bytes) const
{
	const u32_t required_data_bytes = contignuous_bytes - 2ul;

	if (get_data_length() >= required_data_bytes
		&& required_data_bytes > 0)
	{
		u8_t * const reserved = get_header_offset(m_reserved_offset, contignuous_bytes);
		return reserved;
	}
	else
	{
		EAP_ASSERT(
			get_data_length() >= required_data_bytes
			&& required_data_bytes > 0);
	}
	return 0;
}

EAP_FUNC_EXPORT u32_t aka_payload_AT_header_c::get_data_length() const
{
	if (get_payload_length() > get_header_length())
		return static_cast<u32_t>(get_payload_length()-get_header_length());
	else
		return 0;
}

EAP_FUNC_EXPORT u16_t aka_payload_AT_header_c::get_header_length()
{
	return m_data_offset;
}

EAP_FUNC_EXPORT u16_t aka_payload_AT_header_c::get_max_payload_data_length()
{
	return static_cast<u16_t>((0xff*4u-get_header_length()));
}

EAP_FUNC_EXPORT u8_t * aka_payload_AT_header_c::get_data(const u32_t contignuous_bytes) const
{
	if (get_data_length() >= contignuous_bytes
		&& contignuous_bytes > 0)
	{
		return get_header_offset(m_data_offset, contignuous_bytes); // Data begins after the header.
	}
	else
	{
		EAP_ASSERT(
			get_data_length() >= contignuous_bytes
			&& contignuous_bytes > 0);
	}
	return 0;
}

EAP_FUNC_EXPORT u8_t * aka_payload_AT_header_c::get_data_offset(const u32_t offset, const u32_t contignuous_bytes) const
{
	if (get_header_buffer_length()-get_header_length() >= offset+contignuous_bytes
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
			get_data_length() >= offset+contignuous_bytes
			&& contignuous_bytes > 0);
	}
	return 0;
}

EAP_FUNC_EXPORT u8_t * aka_payload_AT_header_c::get_next_header() const
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

// Mostly this is zero.
// With some attributes this is used for special purposes.
EAP_FUNC_EXPORT void aka_payload_AT_header_c::set_reserved(const u16_t reserved)
{
	u8_t *reserved_data = get_header_offset(m_reserved_offset, sizeof(u16_t));

	EAP_ASSERT(reserved_data != 0);
	
	reserved_data[0] = static_cast<u8_t>(((reserved & 0xff00) >> 8));
	reserved_data[1] = static_cast<u8_t>((reserved & 0x00ff));
}

EAP_FUNC_EXPORT void aka_payload_AT_header_c::set_current_payload(const aka_payload_AT_type_e p_current_payload)
{
	EAP_ASSERT_ALWAYS(p_current_payload == static_cast<aka_payload_AT_type_e>(static_cast<u8_t>(p_current_payload)));

	u8_t * const payload_type = get_header_offset(m_type_offset, sizeof(u8_t));

	EAP_ASSERT(payload_type != 0);

	*payload_type = static_cast<u8_t>(p_current_payload);
}

EAP_FUNC_EXPORT void aka_payload_AT_header_c::set_data_length(const u16_t p_data_length)
{
	u32_t total_length = p_data_length+aka_payload_AT_header_c::get_header_length();
	u32_t remaider = total_length % 4u;

	EAP_ASSERT(remaider == 0);
	EAP_ASSERT((total_length / 4u) <= 0xff);

	EAP_UNREFERENCED_PARAMETER(remaider);

	u8_t * const length_data = get_header_offset(m_length_offset, sizeof(u8_t));

	EAP_ASSERT(length_data != 0);

	*length_data = static_cast<u8_t>(total_length/4u);
}

EAP_FUNC_EXPORT void aka_payload_AT_header_c::reset_header(const u16_t data_length)
{
	set_reserved(0u);
	set_current_payload(aka_payload_NONE);
	set_data_length(data_length);
}

EAP_FUNC_EXPORT eap_const_string aka_payload_AT_header_c::get_payload_AT_string(const aka_payload_AT_type_e payload_type)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(payload_type, aka_payload_NONE)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_RAND)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_AUTN)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_RES)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_AUTS)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_PADDING)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_PERMANENT_ID_REQ)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_MAC)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_NOTIFICATION)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_ANY_ID_REQ)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_IDENTITY)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_FULLAUTH_ID_REQ)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_COUNTER)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_COUNTER_TOO_SMALL)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_NONCE_S)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_CLIENT_ERROR_CODE)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_IV)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_ENCR_DATA)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_NEXT_PSEUDONYM)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_NEXT_REAUTH_ID)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_RESULT_IND)
	else EAP_IF_RETURN_STRING(payload_type, aka_payload_AT_CHECKCODE)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(payload_type);
		return EAPL("Unknown AKA payload AT");
	}
}

EAP_FUNC_EXPORT eap_const_string aka_payload_AT_header_c::get_payload_AT_string() const
{
	return get_payload_AT_string(get_current_payload());
}

EAP_FUNC_EXPORT eap_status_e aka_payload_AT_header_c::check_header() const
{
	if (get_reserved() != 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------


// 
EAP_FUNC_EXPORT aka_header_c::~aka_header_c()
{
}

// 
EAP_FUNC_EXPORT aka_header_c::aka_header_c(
	abs_eap_am_tools_c * const tools,
	u8_t * const header_buffer,
	const u32_t header_buffer_length)
	: eap_header_base_c(tools, header_buffer, header_buffer_length)
	, m_am_tools(tools)
{
}

EAP_FUNC_EXPORT aka_subtype_e aka_header_c::get_subtype() const
{
	u32_t subtype_offset(get_sub_type_offset());

	const u8_t * const subtype_data = get_header_offset(subtype_offset, sizeof(u8_t));
	if (subtype_data != 0)
	{
		return static_cast<aka_subtype_e>(*subtype_data);
	}
	else
	{
		return aka_subtype_NONE;
	}
}

EAP_FUNC_EXPORT u16_t aka_header_c::get_data_length() const
{
	if (get_length() > static_cast<u16_t>(get_header_length()))
	{
		return static_cast<u16_t>(get_length()-static_cast<u16_t>(get_header_length()));
	}
	else
	{
		return 0;
	}
}

EAP_FUNC_EXPORT u32_t aka_header_c::get_sub_type_offset() const
{
	return eap_header_base_c::get_header_length() + eap_header_base_c::get_type_field_length() + m_subtype_delta_offset;
}

EAP_FUNC_EXPORT u32_t aka_header_c::get_header_length() const
{
	return get_sub_type_offset() + m_data_delta_offset;
}

EAP_FUNC_EXPORT u8_t * aka_header_c::get_data_offset(const u32_t offset, const u32_t contignuous_bytes) const
{
	u32_t data_length = get_data_length();

	if (data_length >= offset+contignuous_bytes
		&& contignuous_bytes > 0u)
	{
		return (get_header_offset(get_header_length(), contignuous_bytes)+offset); // Data begins after the header.
	}
	else
	{
		EAP_ASSERT(get_data_length() > 0u);
	}
	return 0;
}


EAP_FUNC_EXPORT u8_t * aka_header_c::get_data(const u32_t contignuous_bytes) const
{
	return get_data_offset(0u, contignuous_bytes);
}


EAP_FUNC_EXPORT u16_t aka_header_c::get_reserved() const
{
	u32_t reserved_offset(get_sub_type_offset()+m_reserved_delta_offset);

	u8_t * const reserved_data = get_header_offset(reserved_offset, sizeof(u16_t));
	if (reserved_data != 0)
	{
		return eap_read_u16_t_network_order(reserved_data, sizeof(u16_t));
	}
	else
	{
		// This is illegal reserved data value.
		return 0xffff;
	}
}


EAP_FUNC_EXPORT eap_status_e aka_header_c::check_header() const
{
	if (get_type() != eap_type_aka)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	else if (get_reserved() != static_cast<u16_t>(0ul))
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

EAP_FUNC_EXPORT eap_const_string aka_header_c::get_subtype_string() const
{

#if defined(USE_EAP_TRACE_STRINGS)
	const aka_subtype_e packet_type = get_subtype();

	EAP_IF_RETURN_STRING(packet_type, aka_subtype_NONE)
	else EAP_IF_RETURN_STRING(packet_type, aka_subtype_Synchronization_Failure)
	else EAP_IF_RETURN_STRING(packet_type, aka_subtype_Authentication_Reject)
	else EAP_IF_RETURN_STRING(packet_type, aka_subtype_Identity)
	else EAP_IF_RETURN_STRING(packet_type, aka_subtype_Challenge)
	else EAP_IF_RETURN_STRING(packet_type, aka_subtype_Notification)
	else EAP_IF_RETURN_STRING(packet_type, aka_subtype_Re_authentication)
	else EAP_IF_RETURN_STRING(packet_type, aka_subtype_Client_Error)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown AKA-type");
	}
}

EAP_FUNC_EXPORT eap_const_string aka_header_c::get_code_string() const
{
	return eap_header_string_c::get_eap_code_string(get_code());
}

EAP_FUNC_EXPORT eap_const_string aka_header_c::get_eap_type_string() const
{
	if (get_length() <= eap_header_base_c::get_header_length())
	{
		return EAPL("No EAP-type");
	}

	return eap_header_string_c::get_eap_type_string(get_type());
}

EAP_FUNC_EXPORT void aka_header_c::set_reserved(const u16_t reserved)
{
	u32_t reserved_offset(get_sub_type_offset()+m_reserved_delta_offset);
	u8_t *reserved_data = get_header_offset(reserved_offset, sizeof(u16_t));

	EAP_ASSERT(reserved_data != 0);

	reserved_data[0] = static_cast<u8_t>((reserved & 0xff00) >> 8);
	reserved_data[1] = static_cast<u8_t>(reserved & 0x00ff);
}

EAP_FUNC_EXPORT void aka_header_c::set_subtype(const aka_subtype_e p_subtype)
{
	u32_t subtype_offset(get_sub_type_offset());
	u8_t * const subtype_data = get_header_offset(subtype_offset, sizeof(u8_t));

	EAP_ASSERT(subtype_data != 0);

	*subtype_data = static_cast<u8_t>(p_subtype);
}

EAP_FUNC_EXPORT void aka_header_c::set_data_length(
	const u32_t p_data_length,
	const bool expanded_type_when_true)
{
	EAP_ASSERT_ALWAYS(p_data_length+get_header_length() <= 0xffff);

	set_length(
		static_cast<u16_t>(p_data_length+get_header_length()),
		expanded_type_when_true);
}

EAP_FUNC_EXPORT void aka_header_c::reset_header(
	const u32_t buffer_length,
	const bool expanded_type_when_true)
{
	eap_header_base_c::set_length(
		static_cast<u16_t>(buffer_length),
		expanded_type_when_true);

	set_code(eap_code_none);

	set_identifier(0u);

	set_type(
		eap_type_aka,
		expanded_type_when_true); // AKA = 18

	set_subtype(aka_subtype_NONE);
	set_reserved(0u);
}

//--------------------------------------------------



// End.
