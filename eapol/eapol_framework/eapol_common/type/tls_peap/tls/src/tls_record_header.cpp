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
	#define EAP_FILE_NUMBER_ENUM 136 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "tls_record_header.h"

/** @file */


/// Destructor does nothing.
tls_record_header_c::~tls_record_header_c()
{
}

/// Constructor initializes the class.
tls_record_header_c::tls_record_header_c(
	abs_eap_am_tools_c * const tools,
	void * const header_buffer,
	const u32_t header_buffer_length)
	: eap_general_header_base_c(tools, header_buffer, header_buffer_length)
	, m_am_tools(tools)
{
}

/// This function returns protocol of the TLS-record.
tls_record_protocol_e tls_record_header_c::get_protocol() const
{
	const u8_t * const protocol_data = get_header_offset(m_protocol_offset, sizeof(u8_t));
	if (protocol_data != 0)
	{
		return static_cast<tls_record_protocol_e>(*protocol_data);
	}
	else
	{
		return tls_record_protocol_none;
	}
}

/// This function returns version of the TLS-record.
tls_version_e tls_record_header_c::get_version() const
{
	const u8_t * const version_data = get_header_offset(m_version_offset, sizeof(u16_t));
	if (version_data != 0)
	{
		return static_cast<tls_version_e>(eap_read_u16_t_network_order(version_data, sizeof(u16_t)));
	}
	else
	{
		return tls_version_illegal;
	}
}

/// This function returns data length of the TLS-record.
/// The length (in bytes) of the following TLSPlaintext.fragment (TLS-record data). The length should not exceed 2^14.
u16_t tls_record_header_c::get_data_length() const
{
	const u8_t * const length_data = get_header_offset(m_length_offset, sizeof(u16_t));
	if (length_data != 0)
	{
		return eap_read_u16_t_network_order(length_data, sizeof(u16_t));
	}
	else
	{
		return 0ul;
	}
}

/// This function returns header length of the TLS-record. This includes only protocol, version and length fiels.
u32_t tls_record_header_c::get_header_length()
{
	return m_data_offset;
}

/// This function returns pointer to offset of the TLS-record data.
/// @param offset is the offset of queried data in bytes.
/// @param contignuous_bytes is the length of queried data in bytes.
u8_t * tls_record_header_c::get_data_offset(const u32_t offset, const u32_t contignuous_bytes) const
{
	u32_t data_length = get_data_length(); // Here is removed optional TLS message length.
	
	if (data_length >= offset+contignuous_bytes)
	{
		u8_t * const data_begin = get_header_offset(m_data_offset, sizeof(u8_t));
		if (data_begin == 0)
		{
			return 0;
		}
		return &(data_begin[offset]);
	}
	else
	{
		return 0;
	}
}


/// This function returns pointer to begin of the TLS-record data.
/// @param contignuous_bytes is the length of queried data in bytes.
u8_t * tls_record_header_c::get_data(const u32_t contignuous_bytes) const
{
	return get_data_offset(0u, contignuous_bytes);
}


/// This function returns debug strings of the TLS-protocol values.
eap_const_string tls_record_header_c::get_tls_protocol_string(const tls_record_protocol_e protocol)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(protocol, tls_record_protocol_none)
	else EAP_IF_RETURN_STRING(protocol, tls_record_protocol_change_cipher_spec)
	else EAP_IF_RETURN_STRING(protocol, tls_record_protocol_alert)
	else EAP_IF_RETURN_STRING(protocol, tls_record_protocol_handshake)
	else EAP_IF_RETURN_STRING(protocol, tls_record_protocol_application_data)
	else
#else
	EAP_UNREFERENCED_PARAMETER(protocol);
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown TLS record protocol");
	}
}

/// This function returns debug strings of the TLS-protocol values.
eap_const_string tls_record_header_c::get_tls_protocol_string() const
{
	const tls_record_protocol_e protocol = get_protocol();
	return get_tls_protocol_string(protocol);
}


/// This function sets the protocol of TLS-record.
void tls_record_header_c::set_protocol(tls_record_protocol_e protocol)
{
	u8_t * const protocol_data = get_header_offset(m_protocol_offset, sizeof(u8_t));
	EAP_ASSERT(protocol_data != 0);
	*protocol_data = static_cast<u8_t>(protocol);
}

/// This function sets the version of the TLS-record.
void tls_record_header_c::set_version(tls_version_e version)
{
	u8_t * const version_data = get_header_offset(m_version_offset, sizeof(u16_t));
	EAP_ASSERT(version_data != 0);
	version_data[0] = static_cast<u8_t>((version & 0xff00) >> 8);
	version_data[1] = static_cast<u8_t>(version & 0x00ff);
}

/// This function sets the data length of the TLS-record.
void tls_record_header_c::set_data_length(const u16_t p_length)
{
	u8_t * const length_data = get_header_offset(m_length_offset, sizeof(u16_t));
	EAP_ASSERT(length_data != 0);
	length_data[0] = static_cast<u8_t>((p_length & 0xff00) >> 8);
	length_data[1] = static_cast<u8_t>(p_length & 0x00ff);
}

/// This function resets the TLS-record header.
void tls_record_header_c::reset_header(
	const u16_t buffer_length,
	const tls_version_e version)
{
	set_protocol(tls_record_protocol_none);
	set_version(version);
	set_data_length(buffer_length);
}

/// This function checks the header is valid.
eap_status_e tls_record_header_c::check_header() const
{
	if (get_protocol() > tls_record_protocol_application_data
		|| get_protocol() < tls_record_protocol_change_cipher_spec)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	else if (get_version() != tls_version_3_1)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_no_matching_protocol_version);
	}
	
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}




// End.
