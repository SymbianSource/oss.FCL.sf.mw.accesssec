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
	#define EAP_FILE_NUMBER_ENUM 129 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "tls_handshake_header.h"


/** @file */


/**
 * Destructor does nothing.
 */
tls_handshake_header_c::~tls_handshake_header_c()
{
}

/**
 * Constructor initializes class.
 */
tls_handshake_header_c::tls_handshake_header_c(
	abs_eap_am_tools_c * const tools,
	void * const header_buffer,
	const u32_t header_buffer_length)
	: eap_general_header_base_c(tools, header_buffer, header_buffer_length)
	, m_am_tools(tools)
{
}

/**
 * This function returns TLS-handshake type.
 */
tls_handshake_type_e tls_handshake_header_c::get_handshake_type() const
{
	const u8_t * const type_data = get_header_offset(m_type_offset, sizeof(u8_t));
	if (type_data != 0)
	{
		return static_cast<tls_handshake_type_e>(*type_data);
	}
	else
	{
		return tls_handshake_type_none;
	}
}

/**
 * This function returns data length of TLS-handshake message.
 * Length is measured in bytes and it does not include m_handshake_type, m_length_high,
 * m_length_middle and m_length_low fields, only the length of the following handshake message.
 */
u32_t tls_handshake_header_c::get_data_length() const
{
	// Note the lenght is 24-bit value.
	const u8_t * const length_data = get_header_offset(m_length_offset, 3ul*sizeof(u8_t));
	if (length_data != 0)
	{
		return eap_read_u24_t_network_order(length_data, 3ul*sizeof(u8_t));
	}
	else
	{
		return 0ul;
	}
}

/**
 * This function returns maximum data length of TLS-handshake message.
 */
u32_t tls_handshake_header_c::get_max_data_length()
{
	return m_max_data_length;
}

/**
 * This function returns header length of TLS-handshake message.
 */
u32_t tls_handshake_header_c::get_header_length()
{
	return m_data_offset;
}

/**
 * This function returns pointer to the offset of data of TLS-handshake message.
 */
u8_t * tls_handshake_header_c::get_data_offset(
	const u32_t offset,
	const u32_t contignuous_bytes) const
{
	u32_t data_length = get_data_length(); // Here is included TLS handshake message length.
	
	if (data_length >= offset+contignuous_bytes
		&& contignuous_bytes > 0u)
	{
		u8_t * const data = get_header_offset(m_data_offset, offset);
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
		return 0;
	}
}

/**
 * This function returns pointer to data of TLS-handshake message.
 */
u8_t * tls_handshake_header_c::get_data(const u32_t contignuous_bytes) const
{
	return get_data_offset(0u, contignuous_bytes);
}


/**
 * This function returns debug string of TLS-handshake type.
 */
eap_const_string tls_handshake_header_c::get_tls_handshake_string(
	const tls_handshake_type_e type)
{
	
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(type, tls_handshake_type_hello_request)
	else EAP_IF_RETURN_STRING(type, tls_handshake_type_client_hello)
	else EAP_IF_RETURN_STRING(type, tls_handshake_type_server_hello)
	else EAP_IF_RETURN_STRING(type, tls_handshake_type_certificate)
	else EAP_IF_RETURN_STRING(type, tls_handshake_type_server_key_exchange)
	else EAP_IF_RETURN_STRING(type, tls_handshake_type_certificate_request)
	else EAP_IF_RETURN_STRING(type, tls_handshake_type_server_hello_done)
	else EAP_IF_RETURN_STRING(type, tls_handshake_type_certificate_verify)
	else EAP_IF_RETURN_STRING(type, tls_handshake_type_client_key_exchange)
	else EAP_IF_RETURN_STRING(type, tls_handshake_type_finished)
#if defined(USE_EAP_TLS_SESSION_TICKET)
	else EAP_IF_RETURN_STRING(type, tls_handshake_type_new_session_ticket)
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
	else EAP_IF_RETURN_STRING(type, tls_handshake_type_none)
	else
#else
EAP_UNREFERENCED_PARAMETER(type);	
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown TLS handshake type");
	}
}

/**
 * This function returns debug string of TLS-handshake type.
 */
eap_const_string tls_handshake_header_c::get_tls_handshake_string() const
{
	const tls_handshake_type_e type = get_handshake_type();

	return get_tls_handshake_string(type);
}

/**
 * This function sets the TLS-handshake type.
 */
void tls_handshake_header_c::set_handshake_type(tls_handshake_type_e handshake_type)
{
	u8_t * const type_data = get_header_offset(m_type_offset, sizeof(u8_t));

	EAP_ASSERT(type_data != 0);

	*type_data = static_cast<u8_t>(handshake_type);
}

/**
 * This function sets the length of data of the TLS-handshake type.
 */
void tls_handshake_header_c::set_data_length(const u32_t p_length)
{
	u8_t * const length_data = get_header_offset(m_length_offset, 3ul*sizeof(u8_t));

	EAP_ASSERT(length_data != 0);
	
	length_data[0] = static_cast<u8_t>((p_length & 0x00ff0000) >> 16);
	length_data[1] = static_cast<u8_t>((p_length & 0x0000ff00) >> 8);
	length_data[2] = static_cast<u8_t>((p_length & 0x000000ff) >> 0);
}

/**
 * This function resets the header of the TLS-handshake type.
 */
void tls_handshake_header_c::reset_header(
	const u32_t data_length)
{
	set_handshake_type(tls_handshake_type_none);
	set_data_length(data_length);
}

/**
 * This function checks header of TLS-handshake message.
 */
eap_status_e tls_handshake_header_c::check_header() const
{
	if (get_handshake_type() != tls_handshake_type_hello_request
		&& get_handshake_type() != tls_handshake_type_client_hello
		&& get_handshake_type() != tls_handshake_type_server_hello
		&& get_handshake_type() != tls_handshake_type_certificate
		&& get_handshake_type() != tls_handshake_type_server_key_exchange
		&& get_handshake_type() != tls_handshake_type_certificate_request
		&& get_handshake_type() != tls_handshake_type_server_hello_done
		&& get_handshake_type() != tls_handshake_type_certificate_verify
		&& get_handshake_type() != tls_handshake_type_client_key_exchange
		&& get_handshake_type() != tls_handshake_type_finished
#if defined(USE_EAP_TLS_SESSION_TICKET)
		&& get_handshake_type() != tls_handshake_type_new_session_ticket
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
		)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

/**
 * This function checks header of TLS-handshake message
 * is required type.
 */
eap_status_e tls_handshake_header_c::check_header(
	const tls_handshake_type_e required_type,
	const bool /*is_client_when_true*/) const
{
	switch(get_handshake_type())
	{
	case tls_handshake_type_hello_request:
	case tls_handshake_type_client_hello:
	case tls_handshake_type_server_hello:
	case tls_handshake_type_certificate:
	case tls_handshake_type_server_key_exchange:
	case tls_handshake_type_certificate_request:
	case tls_handshake_type_server_hello_done:
	case tls_handshake_type_certificate_verify:
	case tls_handshake_type_client_key_exchange:
	case tls_handshake_type_finished:
#if defined(USE_EAP_TLS_SESSION_TICKET)
	case tls_handshake_type_new_session_ticket:
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
		if (get_handshake_type() == required_type)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
		else
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	default:
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
}




// End.
