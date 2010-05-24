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
	#define EAP_FILE_NUMBER_ENUM 33 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eapol_header.h"


//--------------------------------------------------

//
EAP_FUNC_EXPORT eapol_header_base_c::~eapol_header_base_c()
{
}

// 
EAP_FUNC_EXPORT eapol_header_base_c::eapol_header_base_c(
	abs_eap_am_tools_c * const tools,
	void * const header_buffer,
	const u32_t header_buffer_length)
	: eap_general_header_base_c(tools, header_buffer, header_buffer_length)
	, m_am_tools(tools)
{
}

EAP_FUNC_EXPORT eapol_protocol_version_e eapol_header_base_c::get_version() const
{
	const u8_t * const version_data = get_header_offset(m_version_offset, sizeof(u8_t));
	if (version_data != 0)
	{
		return static_cast<eapol_protocol_version_e>(*version_data);
	}
	else
	{
		return eapol_protocol_version_none;
	}
}

EAP_FUNC_EXPORT eapol_packet_type_e eapol_header_base_c::get_packet_type() const
{
	const u8_t * const type_data = get_header_offset(m_packet_type_offset, sizeof(u8_t));
	if (type_data != 0)
	{
		return static_cast<eapol_packet_type_e>(*type_data);
	}
	else
	{
		return eapol_packet_type_no_type;
	}
}

EAP_FUNC_EXPORT u16_t eapol_header_base_c::get_data_length() const
{
	const u8_t * const length_data = get_header_offset(m_data_length_offset, sizeof(u16_t));
	if (length_data != 0)
	{
		return eap_read_u16_t_network_order(length_data, sizeof(u16_t));
	}
	else
	{
		return 0ul;
	}
}

EAP_FUNC_EXPORT u32_t eapol_header_base_c::get_header_length()
{
	return m_data_offset;
}

EAP_FUNC_EXPORT u8_t * eapol_header_base_c::get_data(const u32_t data_length) const
{
	return get_header_offset(m_data_offset, data_length); // Data begins after the header.
}

EAP_FUNC_EXPORT void eapol_header_base_c::set_version(const eapol_protocol_version_e p_version)
{
	u8_t * const version_data = get_header_offset(m_version_offset, sizeof(u8_t));
	EAP_ASSERT(version_data != 0);
	*version_data = static_cast<u8_t>(p_version);
}

EAP_FUNC_EXPORT void eapol_header_base_c::set_packet_type(const eapol_packet_type_e p_packet_type)
{
	u8_t * const type_data = get_header_offset(m_packet_type_offset, sizeof(u8_t));
	EAP_ASSERT(type_data != 0);
	*type_data = static_cast<u8_t>(p_packet_type);
}

EAP_FUNC_EXPORT void eapol_header_base_c::set_data_length(const u16_t p_data_length)
{
	u8_t * const data_length = get_header_offset(m_data_length_offset, sizeof(u16_t));
	EAP_ASSERT(data_length != 0);
	data_length[0] = static_cast<u8_t>((p_data_length & 0xff00) >> 8);
	data_length[1] = static_cast<u8_t>(p_data_length & 0x00ff);
}

EAP_FUNC_EXPORT eap_const_string eapol_header_base_c::get_type_string() const
{

#if defined(USE_EAP_TRACE_STRINGS)
	eapol_packet_type_e type = get_packet_type();

	EAP_IF_RETURN_STRING(type, eapol_packet_type_eap)
	else EAP_IF_RETURN_STRING(type, eapol_packet_type_start)
	else EAP_IF_RETURN_STRING(type, eapol_packet_type_logoff)
	else EAP_IF_RETURN_STRING(type, eapol_packet_type_key)
	else EAP_IF_RETURN_STRING(type, eapol_packet_type_enc_asf_alert)
	else EAP_IF_RETURN_STRING(type, eapol_packet_type_SAE_KE)
	else EAP_IF_RETURN_STRING(type, eapol_packet_type_SAE_EAP)
	else EAP_IF_RETURN_STRING(type, eapol_packet_type_SAE_START)
	else EAP_IF_RETURN_STRING(type, eapol_packet_type_SAE_LOGOFF)
	else EAP_IF_RETURN_STRING(type, eapol_packet_type_no_type)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown EAPOL-type");
	}
}

EAP_FUNC_EXPORT eap_status_e eapol_header_base_c::check_header() const
{
	eap_status_e status = eap_status_process_general_error;

	if (get_version() == eapol_protocol_version_none)
	{
		status = eap_status_wrong_eapol_version;

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: eapol_header_base_c::check_header(), illegal version field 0x%02x, at least 0x%02x was expected, eap_status_e %d\n"),
			 get_version(),
			 eapol_protocol_version_none+1,
			 status));
	}
	else if (/* get_packet_type() < eapol_packet_type_eap // This is always false.
				|| */
		eapol_packet_type_SAE_LOGOFF < get_packet_type())
	{
		status = eap_status_wrong_eapol_type;

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: eapol_header_base_c::check_header(), illegal type field 0x%02x, eap_status_e %d\n"),
			 get_packet_type(), status));
	}
	else
	{
		status = eap_status_ok;
	}
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_header_rd_c::~eapol_header_rd_c()
{
}

// 
EAP_FUNC_EXPORT eapol_header_rd_c::eapol_header_rd_c(
	abs_eap_am_tools_c * const tools,
	u8_t * const header_buffer,
	const u32_t header_buffer_length)
	: eapol_header_base_c(tools, header_buffer, header_buffer_length)
	, m_am_tools(tools)
{
}

EAP_FUNC_EXPORT u8_t * eapol_header_rd_c::get_eap_header() const
{
	return get_data(eap_header_base_c::get_header_length());
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_header_wr_c::~eapol_header_wr_c()
{
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_header_wr_c::eapol_header_wr_c(
	abs_eap_am_tools_c * const tools,
	u8_t * const header_buffer,
	const u32_t header_buffer_length)
	: eapol_header_base_c(tools, header_buffer, header_buffer_length)
	, m_am_tools(tools)
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * eapol_header_wr_c::get_eap_header()
{
	return get_data(eap_header_base_c::get_header_length());
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eapol_header_wr_c::reset_header(u16_t buffer_length)
{
	set_version(eapol_protocol_version_none);
	set_packet_type(eapol_packet_type_eap);
	EAP_ASSERT(buffer_length >= get_header_length());
	set_data_length(static_cast<u16_t>(buffer_length-get_header_length()));
}

//--------------------------------------------------



// End.
