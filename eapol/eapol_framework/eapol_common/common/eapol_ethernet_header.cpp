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
	#define EAP_FILE_NUMBER_ENUM 32 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eapol_ethernet_header.h"


//--------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_ethernet_header_base_c::~eapol_ethernet_header_base_c()
{
}

// 
EAP_FUNC_EXPORT eapol_ethernet_header_base_c::eapol_ethernet_header_base_c(
	abs_eap_am_tools_c * const tools,
	void * const header_buffer,
	const u32_t header_buffer_length)
	: eap_general_header_base_c(tools, header_buffer, header_buffer_length)
	, m_am_tools(tools)
{
}

EAP_FUNC_EXPORT u8_t * eapol_ethernet_header_base_c::get_destination() const
{
	return (get_header_offset(m_destination_offset, EAPOL_ETHERNET_ADDRESS_LENGTH));
}

EAP_FUNC_EXPORT u8_t * eapol_ethernet_header_base_c::get_source() const
{
	return (get_header_offset(m_source_offset, EAPOL_ETHERNET_ADDRESS_LENGTH));
}

EAP_FUNC_EXPORT u32_t eapol_ethernet_header_base_c::get_destination_length() const
{
	return EAPOL_ETHERNET_ADDRESS_LENGTH;
}

EAP_FUNC_EXPORT u32_t eapol_ethernet_header_base_c::get_source_length() const
{
	return EAPOL_ETHERNET_ADDRESS_LENGTH;
}

EAP_FUNC_EXPORT u16_t eapol_ethernet_header_base_c::get_type() const
{
	const u8_t * const type_data = get_header_offset(m_type_offset, sizeof(u16_t));
	if (type_data != 0)
	{
		return eap_read_u16_t_network_order(type_data, sizeof(u16_t));
	}
	else
	{
		return 0;
	}
}

EAP_FUNC_EXPORT u8_t * eapol_ethernet_header_base_c::get_data(const u32_t data_length) const
{
	return get_header_offset(m_data_offset, data_length);
}

EAP_FUNC_EXPORT u32_t eapol_ethernet_header_base_c::get_data_length() const
{
	return get_header_buffer_length()-get_header_length();
}

EAP_FUNC_EXPORT u16_t eapol_ethernet_header_base_c::get_header_length()
{
	return m_data_offset;
}

EAP_FUNC_EXPORT void eapol_ethernet_header_base_c::set_type(const eapol_ethernet_type_e type)
{
	u8_t * const type_data = get_header_offset(m_type_offset, sizeof(u16_t));
	EAP_ASSERT(type_data != 0);
	type_data[0] = static_cast<u8_t>((type & 0xff00) >> 8);
	type_data[1] = static_cast<u8_t>(type & 0x00ff);
}

EAP_FUNC_EXPORT eap_status_e eapol_ethernet_header_base_c::check_header() const
{
	if (get_type() != eapol_ethernet_type_pae
		&& get_type() != eapol_ethernet_type_preauthentication)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_ethernet_header_rd_c::~eapol_ethernet_header_rd_c()
{
}

// 
EAP_FUNC_EXPORT eapol_ethernet_header_rd_c::eapol_ethernet_header_rd_c(
	abs_eap_am_tools_c * const tools,
	const u8_t * const header_buffer,
	const u32_t header_buffer_length)
	: eapol_ethernet_header_base_c(tools, const_cast<u8_t *>(header_buffer), header_buffer_length)
	, m_am_tools(tools)
{
}

EAP_FUNC_EXPORT u8_t * eapol_ethernet_header_rd_c::get_eapol_header() const
{
	return eapol_ethernet_header_base_c::get_data(eapol_header_base_c::get_header_length());
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_ethernet_header_wr_c::~eapol_ethernet_header_wr_c()
{
}

// 
EAP_FUNC_EXPORT eapol_ethernet_header_wr_c::eapol_ethernet_header_wr_c(
	abs_eap_am_tools_c * const tools,
	const u8_t * const header_buffer,
	const u32_t header_buffer_length)
	: eapol_ethernet_header_base_c(tools, const_cast<u8_t *>(header_buffer), header_buffer_length)
	, m_am_tools(tools)
{
}

EAP_FUNC_EXPORT u8_t * eapol_ethernet_header_wr_c::get_eapol_header() const
{
	return eapol_ethernet_header_base_c::get_data(eapol_header_base_c::get_header_length());
}

EAP_FUNC_EXPORT u8_t * eapol_ethernet_header_wr_c::get_destination()
{
	return eapol_ethernet_header_base_c::get_destination();
}

EAP_FUNC_EXPORT u8_t * eapol_ethernet_header_wr_c::get_source()
{
	return eapol_ethernet_header_base_c::get_source();
}

EAP_FUNC_EXPORT void eapol_ethernet_header_wr_c::reset_header(const eapol_ethernet_type_e type, const u16_t buffer_length)
{
	EAP_UNREFERENCED_PARAMETER(buffer_length); // <-- in release version
	m_am_tools->memset(get_destination(), 0, EAPOL_ETHERNET_ADDRESS_LENGTH);
	m_am_tools->memset(get_source(), 0, EAPOL_ETHERNET_ADDRESS_LENGTH);
	
	set_type(type);
	
	EAP_ASSERT(buffer_length >= get_header_length()+eapol_header_wr_c::get_header_length());
}

//--------------------------------------------------



// End.
