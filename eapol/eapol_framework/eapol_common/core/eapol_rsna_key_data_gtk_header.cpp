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
	#define EAP_FILE_NUMBER_ENUM 53 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eapol_rsna_key_data_gtk_header.h"


//------------------------------------------------------

// 
eapol_rsna_key_data_gtk_header_c::~eapol_rsna_key_data_gtk_header_c()
{
}

//------------------------------------------------------

// 
eapol_rsna_key_data_gtk_header_c::eapol_rsna_key_data_gtk_header_c(
	abs_eap_am_tools_c * const tools,
	void * const header_begin,
	const u32_t header_buffer_length)
	: eap_general_header_base_c(tools, header_begin, header_buffer_length)
	, m_am_tools(tools)
{
}

//------------------------------------------------------

// 
u8_t eapol_rsna_key_data_gtk_header_c::get_key_index() const
{
	const u8_t * const data = get_header_offset(m_offset_flags, EAPOL_RSNA_KEY_DATA_FLAGS_FIELD_SIZE);
	if (data != 0)
	{
		return static_cast<u8_t>(((*data) & EAPOL_RSNA_KEY_DATA_GTK_INDEX_MASK) >> EAPOL_RSNA_KEY_DATA_GTK_INDEX_SHIFT);
	}
	else
	{
		return EAPOL_RSNA_KEY_DATA_INVALID_GTK_INDEX;
	}
}

//------------------------------------------------------

// 
bool eapol_rsna_key_data_gtk_header_c::get_tx_bit() const
{
	const u8_t * const data = get_header_offset(m_offset_flags, EAPOL_RSNA_KEY_DATA_FLAGS_FIELD_SIZE);
	if (data != 0)
	{
		u8_t flag = static_cast<u8_t>(((*data) & EAPOL_RSNA_KEY_DATA_TX_MASK) >> EAPOL_RSNA_KEY_DATA_TX_SHIFT);
		if (flag != 0)
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	else
	{
		return false;
	}
}

//------------------------------------------------------

// 
u8_t * eapol_rsna_key_data_gtk_header_c::get_gtk_offset(const u32_t offset, const u32_t contignuous_bytes) const
{
	u32_t GTK_buffer_length = get_header_buffer_length() - get_header_length();

	if (GTK_buffer_length >= offset+contignuous_bytes)
	{
		// This is pointer to the offset of the Data.
		u8_t * const data = get_header_offset(m_offset_gtk, offset+contignuous_bytes);
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
		EAP_ASSERT_ALWAYS(GTK_buffer_length >= offset+contignuous_bytes);
	}
	return 0;
}

//------------------------------------------------------

// 
u8_t * eapol_rsna_key_data_gtk_header_c::get_gtk(const u32_t contignuous_bytes) const
{
	return get_gtk_offset(0u, contignuous_bytes);
}

//------------------------------------------------------

// 
u16_t eapol_rsna_key_data_gtk_header_c::get_header_length()
{
	return m_offset_gtk;
}

//------------------------------------------------------

// 
eap_status_e eapol_rsna_key_data_gtk_header_c::set_key_index(const u32_t index)
{
	u8_t * const data = get_header_offset(m_offset_flags, EAPOL_RSNA_KEY_DATA_FLAGS_FIELD_SIZE);
	if (data != 0)
	{
		*data = static_cast<u8_t>(((*data) && ~EAPOL_RSNA_KEY_DATA_GTK_INDEX_MASK)
								  | ((index <<EAPOL_RSNA_KEY_DATA_GTK_INDEX_SHIFT) & EAPOL_RSNA_KEY_DATA_GTK_INDEX_MASK));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

// 
eap_status_e eapol_rsna_key_data_gtk_header_c::set_tx(const bool tx)
{
	u8_t * const data = get_header_offset(m_offset_flags, EAPOL_RSNA_KEY_DATA_FLAGS_FIELD_SIZE);
	if (data != 0)
	{
		*data = static_cast<u8_t>(((*data) && ~EAPOL_RSNA_KEY_DATA_TX_MASK)
								  | ((tx <<EAPOL_RSNA_KEY_DATA_TX_SHIFT) & EAPOL_RSNA_KEY_DATA_TX_MASK));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

// 
eap_status_e eapol_rsna_key_data_gtk_header_c::set_reserved_flag(const u32_t index)
{
	u8_t * const data = get_header_offset(m_offset_flags, EAPOL_RSNA_KEY_DATA_FLAGS_FIELD_SIZE);
	if (data != 0)
	{
		*data = static_cast<u8_t>(((*data) && ~EAPOL_RSNA_KEY_DATA_RESERVED_MASK)
								  | ((index <<EAPOL_RSNA_KEY_DATA_RESERVED_SHIFT) & EAPOL_RSNA_KEY_DATA_RESERVED_MASK));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

// 
eap_status_e eapol_rsna_key_data_gtk_header_c::set_reserved_field(const u32_t reserved)
{
	u8_t * const data = get_header_offset(m_offset_reserved, EAPOL_RSNA_KEY_DATA_RESERVED_FIELD_SIZE);
	if (data != 0)
	{
		*data = static_cast<u8_t>(reserved);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

// 
eap_status_e eapol_rsna_key_data_gtk_header_c::check_header() const
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//------------------------------------------------------

// 
eap_status_e eapol_rsna_key_data_gtk_header_c::reset_header()
{
	eap_status_e status(eap_status_process_general_error);

	m_am_tools->memset(
		get_header_buffer(get_header_buffer_length()),
		0ul,
		get_header_buffer_length());

	status = set_key_index(0ul);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_tx(false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_reserved_flag(0ul);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_reserved_field(0ul);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//------------------------------------------------------



// End.
