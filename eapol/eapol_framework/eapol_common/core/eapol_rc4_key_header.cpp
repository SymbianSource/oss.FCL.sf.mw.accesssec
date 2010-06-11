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
	#define EAP_FILE_NUMBER_ENUM 52 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eapol_rc4_key_header.h"


//------------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_RC4_key_header_c::~eapol_RC4_key_header_c()
{
}

//------------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_RC4_key_header_c::eapol_RC4_key_header_c(
	abs_eap_am_tools_c * const tools,
	void * const header_begin,
	const u32_t header_buffer_length)
	: eap_general_header_base_c(tools, header_begin, header_buffer_length)
	, m_am_tools(tools)
{
}

//------------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_protocol_version_e eapol_RC4_key_header_c::get_eapol_protocol_version() const
{
	const u8_t * const data = get_header_offset(m_offset_eapol_version, sizeof(u8_t));
	if (data != 0)
	{
		return static_cast<eapol_protocol_version_e>(*data);
	}
	else
	{
		return eapol_protocol_version_none;
	}
}

//------------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_packet_type_e eapol_RC4_key_header_c::get_eapol_packet_type() const
{
	const u8_t * const data = get_header_offset(m_offset_eapol_type, sizeof(u8_t));
	if (data != 0)
	{
		return static_cast<eapol_packet_type_e>(*data);
	}
	else
	{
		return eapol_packet_type_no_type;
	}
}

//------------------------------------------------------

// 
EAP_FUNC_EXPORT u16_t eapol_RC4_key_header_c::get_eapol_packet_body_length() const
{
	const u8_t * const data = get_header_offset(m_offset_eapol_packet_body_length, sizeof(u16_t));
	if (data != 0)
	{
		return eap_read_u16_t_network_order(data, sizeof(u16_t));
	}
	else
	{
		return 0ul;
	}
}

//------------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_key_descriptor_type_e eapol_RC4_key_header_c::get_key_descriptor_type() const
{
	const u8_t * const data = get_header_offset(m_offset_key_descriptor_type, sizeof(u8_t));
	if (data != 0)
	{
		return static_cast<eapol_key_descriptor_type_e>(*data);
	}
	else
	{
		return eapol_key_descriptor_type_none;
	}
}

//------------------------------------------------------

// 
EAP_FUNC_EXPORT u16_t eapol_RC4_key_header_c::get_key_length() const
{
	const u8_t * const data = get_header_offset(m_offset_key_length, sizeof(u16_t));
	if (data != 0)
	{
		return eap_read_u16_t_network_order(data, sizeof(u16_t));
	}
	else
	{
		return 0ul;
	}
}	

//------------------------------------------------------

// 
EAP_FUNC_EXPORT u8_t *eapol_RC4_key_header_c::get_replay_counter()
{
	u8_t * const data = get_header_offset(m_offset_replay_counter, EAPOL_RC4_KEY_REPLAY_COUNTER_LENGTH);
	return data;
}

//------------------------------------------------------

// 
EAP_FUNC_EXPORT u8_t *eapol_RC4_key_header_c::get_key_IV()
{
	u8_t * const data = get_header_offset(m_offset_key_IV, EAPOL_RC4_KEY_IV_LENGTH);
	return data;
}

//------------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_RC4_key_flags_e eapol_RC4_key_header_c::get_key_flag() const
{
	const u8_t * const data = get_header_offset(m_offset_key_index, sizeof(u8_t));
	if (data != 0)
	{
		return static_cast<eapol_RC4_key_flags_e>((((*data) & m_flag_mask_key_flag) >> m_flag_shift_key_flag));
	}
	else
	{
		return eapol_RC4_key_flag_none;
	}
}

//------------------------------------------------------

// 
EAP_FUNC_EXPORT u8_t eapol_RC4_key_header_c::get_key_index() const
{
	const u8_t * const data = get_header_offset(m_offset_key_index, sizeof(u8_t));
	if (data != 0)
	{
		return static_cast<u8_t>(((*data) & ~m_flag_mask_key_flag));
	}
	else
	{
		// This is illegal index.
		return 0xff;
	}
}

//------------------------------------------------------

// 
EAP_FUNC_EXPORT u8_t *eapol_RC4_key_header_c::get_key_signature() const
{
	u8_t * const data = get_header_offset(m_offset_key_signature, EAPOL_RC4_KEY_SIGNATURE_LENGTH);
	return data;
}

//------------------------------------------------------

// 
EAP_FUNC_EXPORT u16_t eapol_RC4_key_header_c::get_header_length()
{
	return m_offset_data;
}

//------------------------------------------------------

// 
EAP_FUNC_EXPORT u8_t * eapol_RC4_key_header_c::get_key() const
{
	if (get_eapol_packet_body_length() > SIZE_OF_EMPTY_EAPOL_RC4_KEY_BODY)
	{
		u8_t * const data = get_header_offset(
			m_offset_data, 
			get_header_buffer_length() - SIZE_OF_EMPTY_EAPOL_RC4_KEY_FRAME);
		return data; // Data begins after the header.
	}
	return 0;
}

//------------------------------------------------------
//------------------------------------------------------
//------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_RC4_key_header_c::set_eapol_protocol_version(eapol_protocol_version_e version)
{
	u8_t * const data = get_header_offset(m_offset_eapol_version, sizeof(u8_t));
	if (data != 0)
	{
		*data = static_cast<u8_t>(version);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_RC4_key_header_c::set_eapol_packet_type(eapol_packet_type_e type)
{
	u8_t * const data = get_header_offset(m_offset_eapol_type, sizeof(u8_t));
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

EAP_FUNC_EXPORT eap_status_e eapol_RC4_key_header_c::set_eapol_packet_body_length(u16_t eapol_length)
{
	if (eapol_length - eapol_header_base_c::get_header_length() > eapol_RC4_key_header_c::EAPOL_RC4_EAPOL_KEY_MAXIMUM_SIZE)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_long_message);
	}

	u8_t * const data = get_header_offset(m_offset_eapol_packet_body_length, sizeof(u16_t));
	if (data != 0)
	{
		const u16_t eapol_length_u16_t = static_cast<u16_t>(eapol_length);
		return eap_write_u16_t_network_order(data, sizeof(u16_t), eapol_length_u16_t);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_RC4_key_header_c::set_key_descriptor_type(eapol_key_descriptor_type_e eapol_key_descriptor_type)
{
	u8_t * const data = get_header_offset(m_offset_key_descriptor_type, sizeof(u8_t));
	if (data != 0)
	{
		*data = static_cast<u8_t>(eapol_key_descriptor_type);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_RC4_key_header_c::set_key_length(u16_t length)
{
	u8_t * const data = get_header_offset(m_offset_key_length, sizeof(u16_t));
	if (data != 0)
	{
		return eap_write_u16_t_network_order(data, sizeof(u16_t), length);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_RC4_key_header_c::set_key_flag(eapol_RC4_key_flags_e flags)
{
	u8_t * const data = get_header_offset(m_offset_key_index, sizeof(u8_t));
	if (data != 0)
	{
		*data = static_cast<u8_t>(((*data) & ~m_flag_mask_key_flag)
								  | static_cast<u8_t>((flags << m_flag_shift_key_flag) & m_flag_mask_key_flag));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_RC4_key_header_c::set_key_index(u8_t index)
{
	u8_t * const data = get_header_offset(m_offset_key_index, sizeof(u8_t));
	if (data != 0)
	{
		*data = static_cast<u8_t>(((*data) & m_flag_mask_key_flag)
								  | static_cast<u8_t>((index & ~m_flag_mask_key_flag)));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}


//------------------------------------------------------
//------------------------------------------------------
//------------------------------------------------------

// 
EAP_FUNC_EXPORT void eapol_RC4_key_header_c::zero_key_signature(
	abs_eap_am_tools_c * const m_am_tools
	)
{
	u8_t * const signature = get_key_signature();
	m_am_tools->memset(signature, 0, EAPOL_RC4_KEY_SIGNATURE_LENGTH);
}

//------------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eapol_RC4_key_header_c::check_header() const
{
	if (get_eapol_protocol_version() == eapol_protocol_version_none)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eapol_version);
	}
	else if (get_eapol_packet_type() > eapol_packet_type_enc_asf_alert)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eapol_type);
	}
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}
	
//------------------------------------------------------
//------------------------------------------------------
//------------------------------------------------------



// End.
