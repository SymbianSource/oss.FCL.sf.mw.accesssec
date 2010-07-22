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
	#define EAP_FILE_NUMBER_ENUM 54 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eapol_rsna_key_data_header.h"


//------------------------------------------------------

// 
eapol_rsna_key_data_header_c::~eapol_rsna_key_data_header_c()
{
}

//------------------------------------------------------

// 
eapol_rsna_key_data_header_c::eapol_rsna_key_data_header_c(
	abs_eap_am_tools_c * const tools,
	const bool is_RSNA_when_true,
	const bool is_WPXM_when_true,
	void * const header_begin,
	const u32_t header_buffer_length)
	: eap_general_header_base_c(tools, header_begin, header_buffer_length)
	, m_am_tools(tools)
	, m_is_RSNA_when_true(is_RSNA_when_true)
	, m_is_WPXM_when_true(is_WPXM_when_true)
{
}

//------------------------------------------------------

// 
eapol_RSNA_key_descriptor_type_e eapol_rsna_key_data_header_c::get_descriptor_type() const
{
	const u8_t * const data = get_header_offset(m_offset_type, EAPOL_RSNA_KEY_DATA_TYPE_FIELD_SIZE);
	if (data != 0)
	{
		return static_cast<eapol_RSNA_key_descriptor_type_e>(*data);
	}
	else
	{
		return eapol_RSNA_key_data_type_none;
	}
}

//------------------------------------------------------

// 
u32_t eapol_rsna_key_data_header_c::get_header_and_body_length() const
{
	return get_length() + 2ul;
}

//------------------------------------------------------

// 
u8_t eapol_rsna_key_data_header_c::get_length() const
{
	const u8_t * const data = get_header_offset(m_offset_length, EAPOL_RSNA_KEY_DATA_LENGTH_FIELD_SIZE);
	if (data != 0)
	{
		return *data;
	}
	else
	{
		return 0ul;
	}
}

//------------------------------------------------------

// 
u32_t eapol_rsna_key_data_header_c::get_oui() const
{
	const u8_t * const data = get_header_offset(m_offset_oui, EAPOL_RSNA_KEY_DATA_OUI_FIELD_SIZE);
	if (data != 0)
	{
		return eap_read_u24_t_network_order(data, EAPOL_RSNA_KEY_DATA_OUI_FIELD_SIZE);
	}
	else
	{
		return 0ul;
	}
}

//------------------------------------------------------

// 
eapol_RSNA_key_payload_type_e eapol_rsna_key_data_header_c::get_payload_type() const
{
	const u8_t * const data = get_header_offset(m_offset_key_data_payload_type, EAPOL_RSNA_KEY_PAYLOAD_TYPE_FIELD_SIZE);
	if (data != 0)
	{
		return static_cast<eapol_RSNA_key_payload_type_e>(*data);
	}
	else
	{
		return eapol_RSNA_key_payload_type_none;
	}
}

//------------------------------------------------------

// 
u32_t eapol_rsna_key_data_header_c::get_key_data_payload_length() const
{
	const u32_t length = get_length();
	if (length >= EAPOL_RSNA_KEY_DATA_LENGTH_FIELD_MINIMUM_SIZE)
	{
		return length - EAPOL_RSNA_KEY_DATA_LENGTH_FIELD_MINIMUM_SIZE;
	}
	else
	{
		return 0ul;
	}
}

//------------------------------------------------------

// 
u8_t * eapol_rsna_key_data_header_c::get_key_data_payload_offset(const u32_t offset, const u32_t contignuous_bytes) const
{
	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	u32_t payload_length = get_key_data_payload_length();

	if (payload_length >= offset+contignuous_bytes)
	{
		// This is pointer to the offset of the Data.
		u8_t * const data = get_header_offset(m_offset_key_data_payload, offset+contignuous_bytes);
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
		EAP_ASSERT_ALWAYS(payload_length >= offset+contignuous_bytes);
	}
	return 0;
}

//------------------------------------------------------

// 
u8_t * eapol_rsna_key_data_header_c::get_key_data_payload(const u32_t contignuous_bytes) const
{
	return get_key_data_payload_offset(0u, contignuous_bytes);
}

//------------------------------------------------------

// 
u8_t * eapol_rsna_key_data_header_c::get_next_header() const
{
	if (get_header_buffer_length() >= get_key_data_payload_length()+get_header_length())
	{
		// NOTE get_key_data_payload_offset(get_key_data_payload_length(), get_header_length())
		// cannot be used here.
		u8_t * const data = get_header_offset(
			m_offset_key_data_payload,
			get_key_data_payload_length()+get_header_length());
		if (data != 0)
		{
			return &data[get_key_data_payload_length()];
		}
		else
		{
			return 0;
		}
	}
	else
	{
		return 0;
	}
}

//------------------------------------------------------

// 
u16_t eapol_rsna_key_data_header_c::get_header_length()
{
	return m_offset_key_data_payload;
}

//------------------------------------------------------

// 
eap_status_e eapol_rsna_key_data_header_c::set_type(const eapol_RSNA_key_descriptor_type_e type)
{
	u8_t * const data = get_header_offset(m_offset_type, EAPOL_RSNA_KEY_DATA_TYPE_FIELD_SIZE);
	if (data != 0)
	{
		*data = static_cast<u8_t>(type);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

// 
eap_status_e eapol_rsna_key_data_header_c::set_length(const u8_t length)
{
	u8_t * const data = get_header_offset(m_offset_length, EAPOL_RSNA_KEY_DATA_LENGTH_FIELD_SIZE);
	if (data != 0)
	{
		*data = static_cast<u8_t>(length);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

// 
eap_status_e eapol_rsna_key_data_header_c::set_oui(const u32_t oui)
{
	u8_t * const data = get_header_offset(m_offset_oui, EAPOL_RSNA_KEY_DATA_OUI_FIELD_SIZE);
	if (data != 0)
	{
		return eap_write_u24_t_network_order(data, EAPOL_RSNA_KEY_DATA_OUI_FIELD_SIZE, oui);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

// 
eap_status_e eapol_rsna_key_data_header_c::set_payload_type(const eapol_RSNA_key_payload_type_e type)
{
	u8_t * const data = get_header_offset(m_offset_key_data_payload_type, EAPOL_RSNA_KEY_PAYLOAD_TYPE_FIELD_SIZE);
	if (data != 0)
	{
		*data = static_cast<u8_t>(type);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

// 
eap_status_e eapol_rsna_key_data_header_c::check_header() const
{
	if (m_is_WPXM_when_true == true)
	{
		// OK, WPXM could use either RSN IE or WPA IE.
	}
	else if (m_is_RSNA_when_true == true)
	{
		// RSNA
		if (get_descriptor_type() == eapol_RSNA_key_data_type_RSN_IE)
		{
			// OK
		}
		else if (get_descriptor_type() == eapol_RSNA_key_data_type_RSN_key_data)
		{
			if (get_length() < EAPOL_RSNA_KEY_DATA_LENGTH_FIELD_MINIMUM_SIZE)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eapol_oui);
			}
		}
	}
	else
	{
		// WPA
		if (get_descriptor_type() != eapol_RSNA_key_data_type_WPA_IE)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eapol_type);
		}
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//------------------------------------------------------

// 
eap_status_e eapol_rsna_key_data_header_c::reset_header()
{
	eap_status_e status(eap_status_process_general_error);

	if (m_is_RSNA_when_true == true
		|| m_is_WPXM_when_true == true)
	{
		// RSNA or WPXM
		status = set_type(eapol_RSNA_key_data_type_RSN_key_data);
	}
	else
	{
		// WPA
		status = set_type(eapol_RSNA_key_data_type_WPA_IE);
	}

	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_length(EAPOL_RSNA_KEY_DATA_LENGTH_FIELD_MINIMUM_SIZE);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_oui(eapol_RSNA_key_data_oui_IEEE);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_payload_type(eapol_RSNA_key_payload_type_none);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//------------------------------------------------------

// 
eap_const_string eapol_rsna_key_data_header_c::get_descriptor_type_string() const
{

#if defined(USE_EAP_TRACE_STRINGS)
	const eapol_RSNA_key_descriptor_type_e type = get_descriptor_type();
#endif // #if defined(USE_EAP_TRACE_STRINGS)

	if (m_is_RSNA_when_true == true
		|| m_is_WPXM_when_true == true)
	{
#if defined(USE_EAP_TRACE_STRINGS)
		EAP_IF_RETURN_STRING(type, eapol_RSNA_key_data_type_RSN_IE)
		else EAP_IF_RETURN_STRING(type, eapol_RSNA_key_data_type_RSN_key_data)
		else EAP_IF_RETURN_STRING(type, eapol_RSNA_key_data_type_none)
		else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
		{
			return EAPL("Unknown EAPOL Descriptor type");
		}
	}
	else
	{
#if defined(USE_EAP_TRACE_STRINGS)
		EAP_IF_RETURN_STRING(type, eapol_RSNA_key_data_type_WPA_IE)
		else EAP_IF_RETURN_STRING(type, eapol_RSNA_key_data_type_none)
		else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
		{
			return EAPL("Unknown EAPOL Descriptor type");
		}
	}
}

//------------------------------------------------------

// 
eap_const_string eapol_rsna_key_data_header_c::get_payload_type_string() const
{

#if defined(USE_EAP_TRACE_STRINGS)
	const eapol_RSNA_key_payload_type_e type = get_payload_type();

	EAP_IF_RETURN_STRING(type, eapol_RSNA_key_payload_type_reserved)
	else EAP_IF_RETURN_STRING(type, eapol_RSNA_key_payload_type_group_key_and_id)
	else EAP_IF_RETURN_STRING(type, eapol_RSNA_key_payload_type_sta_key)
	else EAP_IF_RETURN_STRING(type, eapol_RSNA_key_payload_type_pmkid)
	else EAP_IF_RETURN_STRING(type, eapol_RSNA_key_payload_type_none)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown EAPOL Key Data type");
	}
}

//------------------------------------------------------



// End.
