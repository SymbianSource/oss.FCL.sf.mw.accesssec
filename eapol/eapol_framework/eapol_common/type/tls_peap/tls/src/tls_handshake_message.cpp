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
	#define EAP_FILE_NUMBER_ENUM 130 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_tools.h"
#include "eap_array.h"
#include "eap_array_algorithms.h"
#include "tls_handshake_message.h"
#include "tls_record_header.h"
#include "eap_crypto_api.h"
#include "eap_automatic_variable.h"

/** @file */

//--------------------------------------------------

EAP_FUNC_EXPORT tls_handshake_message_c::~tls_handshake_message_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_handshake_message_c::tls_handshake_message_c(
	abs_eap_am_tools_c * const tools,
	abs_tls_message_hash_c * const message_hash,
	const bool is_client)
: m_am_tools(tools)
, m_message_hash(message_hash)
, m_tls_handshake_message_buffer(tools)
, m_unix_time(tools)
, m_random_value(tools)
, m_session_id(tools)
, m_cipher_suites(tools)
, m_compression_methods(tools)
#if defined(USE_EAP_TLS_SESSION_TICKET)
, m_tls_extensions(tools)
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
, m_certificate_chain(tools)
, m_certificate_authorities(tools)
, m_certificate_types(tools)
, m_encrypted_premaster_secret(tools)
, m_public_dhe_key(tools)
, m_dhe_prime(tools)
, m_dhe_group_generator(tools)
, m_signed_message_hash(tools)
, m_finished_data(tools)
, m_selected_cipher_suite(tls_cipher_suites_none)
, m_selected_compression_method(tls_compression_method_none)
, m_handshake_type(tls_handshake_type_none)
, m_is_analysed(false)
, m_is_valid(false)
, m_is_client(is_client)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_handshake_message_c::set_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_is_valid = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_handshake_message_c::get_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_handshake_message_c::set_is_analysed()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_is_analysed = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_handshake_message_c::get_is_analysed()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_analysed;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::set_handshake_type(tls_handshake_type_e type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_handshake_type = type;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::set_handshake_header_copy(
	const tls_handshake_header_c * const tls_handshake_header)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_handshake_type = tls_handshake_header->get_handshake_type();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_handshake_type_e tls_handshake_message_c::get_handshake_type() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_handshake_type;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::set_cipher_suites(
	EAP_TEMPLATE_CONST eap_array_c<u16_t> * const cipher_suites)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_cipher_suites.reset();

	eap_status_e status = copy_simple<u16_t>(
		cipher_suites,
		&m_cipher_suites,
		m_am_tools,
		false);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT EAP_TEMPLATE_CONST eap_array_c<u16_t> * tls_handshake_message_c::get_cipher_suites() EAP_TEMPLATE_CONST
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_cipher_suites;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::set_compression_methods(
	EAP_TEMPLATE_CONST eap_array_c<u8_t> * const compression_methods)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = copy_simple<u8_t>(
		compression_methods,
		&m_compression_methods,
		m_am_tools,
		false);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT EAP_TEMPLATE_CONST eap_array_c<u8_t> * tls_handshake_message_c::get_compression_methods() EAP_TEMPLATE_CONST
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_compression_methods;
}

//--------------------------------------------------

#if defined(USE_EAP_TLS_SESSION_TICKET)

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::set_tls_extensions(
	EAP_TEMPLATE_CONST eap_array_c<tls_extension_c> * const tls_extensionss)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = copy<tls_extension_c>(
		tls_extensionss,
		&m_tls_extensions,
		m_am_tools,
		false);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)

//--------------------------------------------------

#if defined(USE_EAP_TLS_SESSION_TICKET)

EAP_FUNC_EXPORT EAP_TEMPLATE_CONST eap_array_c<tls_extension_c> * tls_handshake_message_c::get_tls_extensions() EAP_TEMPLATE_CONST
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_tls_extensions;
}

#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::set_random_value(
	const eap_variable_data_c * const random_value)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_random_value.set_copy_of_buffer(random_value);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT const eap_variable_data_c * tls_handshake_message_c::get_random_value() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_random_value;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::set_session_id(
	const eap_variable_data_c * const session_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_session_id.set_copy_of_buffer(session_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT const eap_variable_data_c * tls_handshake_message_c::get_session_id() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_session_id;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::set_certificate_chain(
	EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_chain)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = copy<eap_variable_data_c>(
		certificate_chain,
		&m_certificate_chain,
		m_am_tools,
		false);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * tls_handshake_message_c::get_certificate_chain() EAP_TEMPLATE_CONST
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_certificate_chain;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::set_certificate_authorities(
	EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_authorities)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = copy<eap_variable_data_c>(
		certificate_authorities,
		&m_certificate_authorities,
		m_am_tools,
		false);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * tls_handshake_message_c::get_certificate_authorities() EAP_TEMPLATE_CONST
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_certificate_authorities;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::set_certificate_types(
	EAP_TEMPLATE_CONST eap_array_c<u8_t> * const certificate_types)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = copy_simple<u8_t>(
		certificate_types,
		&m_certificate_types,
		m_am_tools,
		false);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT EAP_TEMPLATE_CONST eap_array_c<u8_t> * tls_handshake_message_c::get_certificate_types() EAP_TEMPLATE_CONST
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_certificate_types;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::set_selected_cipher_suite(const tls_cipher_suites_e selected_cipher_suite)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_selected_cipher_suite = selected_cipher_suite;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

EAP_FUNC_EXPORT tls_cipher_suites_e tls_handshake_message_c::get_selected_cipher_suite() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_selected_cipher_suite;
}

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::set_selected_compression_method(const tls_compression_method_e selected_compression_method)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_selected_compression_method = selected_compression_method;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

EAP_FUNC_EXPORT tls_compression_method_e tls_handshake_message_c::get_selected_compression_method() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_selected_compression_method;
}

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::set_public_dhe_key(const eap_variable_data_c * const public_dhe_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_public_dhe_key.set_copy_of_buffer(public_dhe_key);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT const eap_variable_data_c * tls_handshake_message_c::get_public_dhe_key() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_public_dhe_key;
}

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::set_encrypted_premaster_secret(const eap_variable_data_c * const encrypted_premaster_secret)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_encrypted_premaster_secret.set_copy_of_buffer(encrypted_premaster_secret);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT const eap_variable_data_c * tls_handshake_message_c::get_encrypted_premaster_secret() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_encrypted_premaster_secret;
}

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::set_dhe_prime(const eap_variable_data_c * const dhe_prime)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_dhe_prime.set_copy_of_buffer(dhe_prime);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT const eap_variable_data_c * tls_handshake_message_c::get_dhe_prime() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_dhe_prime;
}

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::set_dhe_group_generator(const eap_variable_data_c * const dhe_group_generator)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_dhe_group_generator.set_copy_of_buffer(dhe_group_generator);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT const eap_variable_data_c * tls_handshake_message_c::get_dhe_group_generator() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_dhe_group_generator;
}

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::set_signed_message_hash(const eap_variable_data_c * const signed_message_hash)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_signed_message_hash.set_copy_of_buffer(signed_message_hash);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT const eap_variable_data_c * tls_handshake_message_c::get_signed_message_hash() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_signed_message_hash;
}

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::set_finished_data(const eap_variable_data_c * const finished_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_finished_data.set_copy_of_buffer(finished_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT const eap_variable_data_c * tls_handshake_message_c::get_finished_data() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_finished_data;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::u16_t_to_network_order(
	u16_t * const value,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	*value = eap_htons(*value);

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}


//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::create_message_data()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_ok;

	m_tls_handshake_message_buffer.reset();
	status = m_tls_handshake_message_buffer.set_buffer_length(TLS_PEAP_DEFAULT_RECORD_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const u32_t offset_of_tmp_tls_handshake_header = m_tls_handshake_message_buffer.get_data_length();

	m_tls_handshake_message_buffer.set_data_length(
		m_tls_handshake_message_buffer.get_data_length() + tls_handshake_header_c::get_header_length());

	tls_handshake_header_c tmp_tls_handshake_header_on_tls_message_buffer(
		m_am_tools,
		m_tls_handshake_message_buffer.get_data_offset(
		offset_of_tmp_tls_handshake_header, tls_handshake_header_c::get_header_length()),
		tls_handshake_header_c::get_header_length());

	if (tmp_tls_handshake_header_on_tls_message_buffer.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_long_message);
	}

	tmp_tls_handshake_header_on_tls_message_buffer.reset_header(0ul);
	tmp_tls_handshake_header_on_tls_message_buffer.set_handshake_type(get_handshake_type());

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: data_function: tls_handshake_message_c::create_message_data(): %s\n"),
		(m_is_client == true ? "client": "server"),
		tmp_tls_handshake_header_on_tls_message_buffer.get_tls_handshake_string()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS-handshake tls_handshake_header"),
		 tmp_tls_handshake_header_on_tls_message_buffer.get_header_buffer(
			 tls_handshake_header_c::get_header_length()),
		 tls_handshake_header_c::get_header_length()));

	const u32_t handshake_data_length_start = m_tls_handshake_message_buffer.get_data_length();

	if (tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_client_hello
		|| tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_server_hello)
	{
		u16_t version = eap_htons(tls_version_3_1);

		status = m_tls_handshake_message_buffer.add_data(
			&version,
			sizeof(version));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake version"),
			&version,
			sizeof(version)));
	}

	if (tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_client_hello
		|| tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_server_hello)
	{
		if (m_random_value.get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
		else
		{
			status = m_tls_handshake_message_buffer.add_data(
				m_random_value.get_data(m_random_value.get_data_length()),
				m_random_value.get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake random"),
				m_random_value.get_data(m_random_value.get_data_length()),
				m_random_value.get_data_length()));
		}
	}

	if (tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_client_hello
		|| tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_server_hello)
	{
		u8_t session_id_length = 0ul;

		if (m_session_id.get_is_valid_data() == true
			&& m_session_id.get_data_length() > 0ul)
		{
			session_id_length = static_cast<u8_t>(m_session_id.get_data_length());
		}

		status = m_tls_handshake_message_buffer.add_data(
			&session_id_length,
			sizeof(session_id_length));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake session_id_length"),
			&session_id_length,
			sizeof(session_id_length)));

		if (m_session_id.get_is_valid_data() == true
			&& m_session_id.get_data_length() > 0ul)
		{
			status = m_tls_handshake_message_buffer.add_data(
				m_session_id.get_data(m_session_id.get_data_length()),
				m_session_id.get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake session_id"),
				m_session_id.get_data(m_session_id.get_data_length()),
				m_session_id.get_data_length()));
		}
	}

	if (tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_client_hello)
	{
		u16_t data_size = static_cast<u16_t>(m_cipher_suites.get_object_count() * sizeof(u16_t));
		u16_t data_size_network_order = eap_htons(data_size);

		status = m_tls_handshake_message_buffer.add_data(
			&data_size_network_order,
			sizeof(data_size_network_order));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake cipher_suite_length"),
			&data_size_network_order,
			sizeof(data_size_network_order)));

		if (m_cipher_suites.get_object_count() > 0ul)
		{
			// Copy cipher suites and change them to network order.
			eap_array_c<u16_t> * const tmp_cipher_suites = new eap_array_c<u16_t>(m_am_tools);

			eap_automatic_variable_c<eap_array_c<u16_t> > automatic_tmp_cipher_suites(m_am_tools, tmp_cipher_suites);

			if (tmp_cipher_suites == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = copy_simple<u16_t>(
				&m_cipher_suites,
				tmp_cipher_suites,
				m_am_tools,
				false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = for_each<u16_t>(tmp_cipher_suites, u16_t_to_network_order, m_am_tools, false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = add_simple_data(tmp_cipher_suites, &m_tls_handshake_message_buffer, m_am_tools);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	if (tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_server_hello)
	{
		u16_t selected_cipher_suite_network_order = eap_htons(static_cast<u8_t>(m_selected_cipher_suite));

		status = m_tls_handshake_message_buffer.add_data(
			&selected_cipher_suite_network_order,
			sizeof(selected_cipher_suite_network_order));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake selected_cipher_suite"),
			&selected_cipher_suite_network_order,
			sizeof(selected_cipher_suite_network_order)));

		u8_t selected_compression_method_network_order = static_cast<u8_t>(m_selected_compression_method);

		status = m_tls_handshake_message_buffer.add_data(
			&selected_compression_method_network_order,
			sizeof(selected_compression_method_network_order));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake selected_compression_method"),
			&selected_compression_method_network_order,
			sizeof(selected_compression_method_network_order)));
	}

	if (tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_client_hello)
	{
		u8_t data_size = static_cast<u8_t>(m_compression_methods.get_object_count() * sizeof(u8_t));

		status = m_tls_handshake_message_buffer.add_data(
			&data_size,
			sizeof(data_size));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS-handshake compression_methods length"),
			&data_size,
			sizeof(data_size)));

		if (m_compression_methods.get_object_count() > 0ul)
		{
			status = add_simple_data(&m_compression_methods, &m_tls_handshake_message_buffer, m_am_tools);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}


#if defined(USE_EAP_TLS_SESSION_TICKET)

	if (m_tls_extensions.get_object_count() > 0
		&& (tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_client_hello
			|| tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_server_hello))
	{
		u32_t data_size(0ul);
		u32_t ind(0ul);
		
		for (ind = 0ul; ind < m_tls_extensions.get_object_count(); ++ind)
		{
			const tls_extension_c * const extension = m_tls_extensions.get_object(ind);
			if (extension == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			// Session ticket is always empty in ServerHello message.
			const bool add_extension_data =
				((extension->get_type() == tls_extension_type_session_ticket
					&& tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_server_hello))
				== false;

			// Extension list is formatted as:
			// 0                   1                   2                   3   
			//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
			//                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//                                 | extension list length         |
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// | extension 1 type              | extension 1 data length       |
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// | extension 1 data ...
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// | extension 2 type              | extension 2 data length       |
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// | extension 2 data ...
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

			data_size += 2 * sizeof(u16_t);

			if (add_extension_data == true)
			{
				data_size += extension->get_data_length();
			}

		} // for()


		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS-handshake extensions list length = %d\n"),
			data_size));

		if (data_size > 0x0000ffff)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		u8_t data_size_array[2];
		data_size_array[0] = static_cast<u8_t>((data_size & 0x0000ff00) >> 8);
		data_size_array[1] = static_cast<u8_t>(data_size & 0x000000ff);

		status = m_tls_handshake_message_buffer.add_data(
			&data_size_array,
			sizeof(data_size_array));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		for (ind = 0ul; ind < m_tls_extensions.get_object_count(); ++ind)
		{
			const tls_extension_c * const extension = m_tls_extensions.get_object(ind);
			if (extension == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			// Session ticket is always empty in ServerHello message.
			const bool add_extension_data =
				((extension->get_type() == tls_extension_type_session_ticket
					&& tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_server_hello))
				== false;

			tls_extension_type_e type = extension->get_type();
			u16_t network_order_type(eap_htons(type));

			status = m_tls_handshake_message_buffer.add_data(
				&network_order_type,
				sizeof(network_order_type));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}


			if (add_extension_data == true)
			{
				data_size = extension->get_data_length();
			}
			else
			{
				data_size = 0ul;
			}

			data_size_array[0] = static_cast<u8_t>((data_size & 0x0000ff00) >> 8);
			data_size_array[1] = static_cast<u8_t>(data_size & 0x000000ff);

			status = m_tls_handshake_message_buffer.add_data(
				&data_size_array,
				sizeof(data_size_array));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS-handshake extension type = %s, length = %d\n"),
				extension->get_type_string(extension->get_type()),
				data_size));

			if (add_extension_data == true)
			{
				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("TLS-handshake extension data"),
					extension->get_data(),
					extension->get_data_length()));

				status = m_tls_handshake_message_buffer.add_data(
					extension);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		} // for()
	}

#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)


	if (tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_certificate)
	{
		u32_t data_size = 0ul;
		u32_t ind = 0ul;

		for (ind = 0ul; ind < m_certificate_chain.get_object_count(); ind++)
		{
			const eap_variable_data_c * const certificate =  m_certificate_chain.get_object(ind);
			if (certificate == 0
				|| certificate->get_is_valid_data() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			// Data size includes certificate length field and certificate data.
			data_size += (3ul + certificate->get_data_length());
		}

		if (data_size > 0x00ffffff)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		u8_t data_size_array[3];
		data_size_array[0] = static_cast<u8_t>((data_size & 0x00ff0000) >> 16);
		data_size_array[1] = static_cast<u8_t>((data_size & 0x0000ff00) >> 8);
		data_size_array[2] = static_cast<u8_t>(data_size & 0x000000ff);

		status = m_tls_handshake_message_buffer.add_data(
			data_size_array,
			sizeof(data_size_array));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake certificate_chain length"),
			data_size_array,
			sizeof(data_size_array)));


		for (ind = 0ul; ind < m_certificate_chain.get_object_count(); ind++)
		{
			const eap_variable_data_c * const certificate =  m_certificate_chain.get_object(ind);
			if (certificate == 0
				|| certificate->get_is_valid_data() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			data_size = certificate->get_data_length();
			u8_t data_size_array[3];
			data_size_array[0] = static_cast<u8_t>((data_size & 0x00ff0000) >> 16);
			data_size_array[1] = static_cast<u8_t>((data_size & 0x0000ff00) >> 8);
			data_size_array[2] = static_cast<u8_t>(data_size & 0x000000ff);
			
			status = m_tls_handshake_message_buffer.add_data(
				data_size_array,
				sizeof(data_size_array));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake certificate length"),
				data_size_array,
				sizeof(data_size_array)));

			status = m_tls_handshake_message_buffer.add_data(
				certificate->get_data(certificate->get_data_length()),
				certificate->get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake certificate"),
				certificate->get_data(certificate->get_data_length()),
				certificate->get_data_length()));
		}
	}


	if (tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_server_key_exchange)
	{
		if (m_dhe_prime.get_is_valid_data() == true)
		{
			u16_t dhe_prime_length_network_order = eap_htons(static_cast<u16_t>(m_dhe_prime.get_data_length()));

			status = m_tls_handshake_message_buffer.add_data(
				&dhe_prime_length_network_order,
				sizeof(dhe_prime_length_network_order));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake dhe_prime_length"),
				&dhe_prime_length_network_order,
				sizeof(dhe_prime_length_network_order)));

			status = m_tls_handshake_message_buffer.add_data(
				m_dhe_prime.get_data(m_dhe_prime.get_data_length()),
				m_dhe_prime.get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake dhe_prime"),
				m_dhe_prime.get_data(m_dhe_prime.get_data_length()),
				m_dhe_prime.get_data_length()));
		}
		else if (m_dhe_group_generator.get_is_valid_data() == true
			|| m_public_dhe_key.get_is_valid_data() == true
			|| m_signed_message_hash.get_is_valid_data() == true)
		{
			// all parameters m_dhe_prime, m_dhe_group_generator and m_public_dhe_key are needed.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		if (m_dhe_group_generator.get_is_valid_data() == true)
		{
			u16_t dhe_group_generator_length_network_order = eap_htons(static_cast<u16_t>(m_dhe_group_generator.get_data_length()));

			status = m_tls_handshake_message_buffer.add_data(
				&dhe_group_generator_length_network_order,
				sizeof(dhe_group_generator_length_network_order));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake dhe_group_generator_length"),
				&dhe_group_generator_length_network_order,
				sizeof(dhe_group_generator_length_network_order)));

			status = m_tls_handshake_message_buffer.add_data(
				m_dhe_group_generator.get_data(m_dhe_group_generator.get_data_length()),
				m_dhe_group_generator.get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake dhe_group_generator"),
				m_dhe_group_generator.get_data(m_dhe_group_generator.get_data_length()),
				m_dhe_group_generator.get_data_length()));
		}
		else if (m_dhe_prime.get_is_valid_data() == true
			|| m_public_dhe_key.get_is_valid_data() == true
			|| m_signed_message_hash.get_is_valid_data() == true)
		{
			// all parameters m_dhe_prime, m_dhe_group_generator and m_public_dhe_key are needed.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		if (m_public_dhe_key.get_is_valid_data() == true)
		{
			u16_t public_dhe_key_length_network_order = eap_htons(static_cast<u16_t>(m_public_dhe_key.get_data_length()));

			status = m_tls_handshake_message_buffer.add_data(
				&public_dhe_key_length_network_order,
				sizeof(public_dhe_key_length_network_order));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake public_dhe_key_length"),
				&public_dhe_key_length_network_order,
				sizeof(public_dhe_key_length_network_order)));

			status = m_tls_handshake_message_buffer.add_data(
				m_public_dhe_key.get_data(m_public_dhe_key.get_data_length()),
				m_public_dhe_key.get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake public_dhe_key"),
				m_public_dhe_key.get_data(m_public_dhe_key.get_data_length()),
				m_public_dhe_key.get_data_length()));
		}
		else if (m_dhe_prime.get_is_valid_data() == true
			|| m_dhe_group_generator.get_is_valid_data() == true
			|| m_signed_message_hash.get_is_valid_data() == true)
		{
			// all parameters m_dhe_prime, m_dhe_group_generator and m_public_dhe_key are needed.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		if (m_signed_message_hash.get_is_valid_data() == true)
		{
			if (m_signed_message_hash.get_data_length() == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			status = m_tls_handshake_message_buffer.add_data(
				m_signed_message_hash.get_data(m_signed_message_hash.get_data_length()),
				m_signed_message_hash.get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake signed_message_hash"),
				m_signed_message_hash.get_data(m_signed_message_hash.get_data_length()),
				m_signed_message_hash.get_data_length()));
		}
	}


	if (tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_client_key_exchange)
	{
		if (m_encrypted_premaster_secret.get_is_valid_data() == true)
		{
			u16_t length_of_encrypted_premaster_secret_network_order
				= eap_htons(static_cast<u16_t>(m_encrypted_premaster_secret.get_data_length()));

			status = m_tls_handshake_message_buffer.add_data(
				&length_of_encrypted_premaster_secret_network_order,
				sizeof(length_of_encrypted_premaster_secret_network_order));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake encrypted premaster_secret"),
				&length_of_encrypted_premaster_secret_network_order,
				sizeof(length_of_encrypted_premaster_secret_network_order)));

			status = m_tls_handshake_message_buffer.add_data(
				m_encrypted_premaster_secret.get_data(m_encrypted_premaster_secret.get_data_length()),
				m_encrypted_premaster_secret.get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake encrypted premaster_secret"),
				m_encrypted_premaster_secret.get_data(m_encrypted_premaster_secret.get_data_length()),
				m_encrypted_premaster_secret.get_data_length()));
		}
		else if (m_encrypted_premaster_secret.get_is_valid_data() == false
			&& m_public_dhe_key.get_is_valid_data() == false)
		{
			// Either parameters m_encrypted_premaster_secret or m_public_dhe_key is needed.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		if (m_public_dhe_key.get_is_valid_data() == true)
		{
			u16_t length_of_public_dhe_key_length_network_order = eap_htons(static_cast<u16_t>(m_public_dhe_key.get_data_length()));

			status = m_tls_handshake_message_buffer.add_data(
				&length_of_public_dhe_key_length_network_order,
				sizeof(length_of_public_dhe_key_length_network_order));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake public_dhe_key_length"),
				&length_of_public_dhe_key_length_network_order,
				sizeof(length_of_public_dhe_key_length_network_order)));

			status = m_tls_handshake_message_buffer.add_data(
				m_public_dhe_key.get_data(m_public_dhe_key.get_data_length()),
				m_public_dhe_key.get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake public_dhe_key"),
				m_public_dhe_key.get_data(m_public_dhe_key.get_data_length()),
				m_public_dhe_key.get_data_length()));
		}
		else if (m_encrypted_premaster_secret.get_is_valid_data() == false
			&& m_public_dhe_key.get_is_valid_data() == false)
		{
			// Either parameters m_encrypted_premaster_secret or m_public_dhe_key is needed.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}
	}


	if (tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_certificate_request)
	{
		u32_t data_size = m_certificate_types.get_object_count() * sizeof(u8_t);

		if (data_size > 0x000000ff)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		u8_t data_size_u8_t = static_cast<u8_t>(data_size & 0x000000ff);

		status = m_tls_handshake_message_buffer.add_data(
			&data_size_u8_t,
			sizeof(data_size_u8_t));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake certificate_types length"),
			&data_size_u8_t,
			sizeof(data_size_u8_t)));

		if (data_size_u8_t > 0ul)
		{
			status = add_simple_data(&m_certificate_types, &m_tls_handshake_message_buffer, m_am_tools);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	if (tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_certificate_request)
	{
		u32_t data_size = 0ul;
		u32_t ind = 0ul;

		for (ind = 0ul; ind < m_certificate_authorities.get_object_count(); ind++)
		{
			const eap_variable_data_c * const certificate_authority =  m_certificate_authorities.get_object(ind);
			if (certificate_authority == 0
				|| certificate_authority->get_is_valid_data() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}
			data_size += certificate_authority->get_data_length();
		}

		if (data_size > 0x0000ffff)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		u8_t data_size_array[2];
		data_size_array[0] = static_cast<u8_t>((data_size & 0x0000ff00) >> 8);
		data_size_array[1] = static_cast<u8_t>(data_size & 0x000000ff);

		status = m_tls_handshake_message_buffer.add_data(
			data_size_array,
			sizeof(data_size_array));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake certificate_authorities length"),
			data_size_array,
			sizeof(data_size_array)));


		for (ind = 0ul; ind < m_certificate_authorities.get_object_count(); ind++)
		{
			const eap_variable_data_c * const certificate_authority =  m_certificate_authorities.get_object(ind);
			if (certificate_authority == 0
				|| certificate_authority->get_is_valid_data() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			data_size = certificate_authority->get_data_length();
			u8_t data_size_array[2];
			data_size_array[0] = static_cast<u8_t>((data_size & 0x0000ff00) >> 8);
			data_size_array[1] = static_cast<u8_t>(data_size & 0x000000ff);
			
			status = m_tls_handshake_message_buffer.add_data(
				data_size_array,
				sizeof(data_size_array));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake certificate_authority length"),
				data_size_array,
				sizeof(data_size_array)));

			status = m_tls_handshake_message_buffer.add_data(
				certificate_authority->get_data(certificate_authority->get_data_length()),
				certificate_authority->get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake certificate_authority"),
				certificate_authority->get_data(certificate_authority->get_data_length()),
				certificate_authority->get_data_length()));
		}
	}

	if (tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_certificate_verify)
	{
		u16_t length_of_certificate_verify_network_order = eap_htons(static_cast<u16_t>(m_signed_message_hash.get_data_length()));

		status = m_tls_handshake_message_buffer.add_data(
			&length_of_certificate_verify_network_order,
			sizeof(length_of_certificate_verify_network_order));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS-handshake certificate_verify"),
			 &length_of_certificate_verify_network_order,
			 sizeof(length_of_certificate_verify_network_order)));

		status = m_tls_handshake_message_buffer.add_data(
			m_signed_message_hash.get_data(m_signed_message_hash.get_data_length()),
			m_signed_message_hash.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake signed_message_hash"),
			m_signed_message_hash.get_data(m_signed_message_hash.get_data_length()),
			m_signed_message_hash.get_data_length()));

	}

	if (tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_finished)
	{
		eap_variable_data_c signed_message_hash(m_am_tools);

		status = m_message_hash->message_hash_save_finished(m_is_client);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_message_hash->message_hash_create_finished(m_is_client, &signed_message_hash);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_tls_handshake_message_buffer.add_data(
			signed_message_hash.get_data(signed_message_hash.get_data_length()),
			signed_message_hash.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-handshake signed_message_hash"),
			signed_message_hash.get_data(signed_message_hash.get_data_length()),
			signed_message_hash.get_data_length()));

	}


#if defined(USE_EAP_TLS_SESSION_TICKET)

	if (m_tls_extensions.get_object_count() > 0
		&& tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type() == tls_handshake_type_new_session_ticket)
	{
		const tls_extension_c * const p_new_session_ticket = tls_extension_c::get_tls_extension(
			tls_extension_type_session_ticket,
			&m_tls_extensions,
			m_am_tools);

		if (p_new_session_ticket != 0)
		{
			u32_t ticket_lifetime_hint_network_order = eap_htonl(p_new_session_ticket->get_lifetime_hint());

			status = m_tls_handshake_message_buffer.add_data(
				&ticket_lifetime_hint_network_order,
				sizeof(ticket_lifetime_hint_network_order));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			u32_t length_of_opaque_ticket = p_new_session_ticket->get_data_length();
			u16_t length_of_opaque_ticket_network_order = eap_htons(static_cast<u16_t>(length_of_opaque_ticket));

			status = m_tls_handshake_message_buffer.add_data(
				&length_of_opaque_ticket_network_order,
				sizeof(length_of_opaque_ticket_network_order));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (length_of_opaque_ticket > 0ul)
			{
				status = m_tls_handshake_message_buffer.add_data(
					p_new_session_ticket);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
	}

#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (status == eap_status_ok)
	{
		u32_t handshake_data_length = m_tls_handshake_message_buffer.get_data_length() - handshake_data_length_start;

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("handshake length %d bytes.\n"),
			handshake_data_length));

		if (handshake_data_length <= 0x00ffffff)
		{
			// NOTE the address of tmp_tls_handshake_header_on_tls_message_buffer must be queried again.
			// The whole buffer might be allocated from other address.
			tmp_tls_handshake_header_on_tls_message_buffer.set_header_buffer(
				m_tls_handshake_message_buffer.get_data_offset(
					offset_of_tmp_tls_handshake_header,
					tls_handshake_header_c::get_header_length()+handshake_data_length),
				tls_handshake_header_c::get_header_length()+handshake_data_length);
			if (tmp_tls_handshake_header_on_tls_message_buffer.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_too_long_message);
			}
			tmp_tls_handshake_header_on_tls_message_buffer.set_data_length(handshake_data_length);


			switch (tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type())
			{
			case tls_handshake_type_hello_request:
				// This message is NOT included to TLS-message hash.
				break;
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
			{
				status = m_message_hash->message_hash_update(
					false,
					tmp_tls_handshake_header_on_tls_message_buffer.get_handshake_type(),
					tmp_tls_handshake_header_on_tls_message_buffer.get_header_buffer(
						tmp_tls_handshake_header_on_tls_message_buffer.get_header_length()
						+ tmp_tls_handshake_header_on_tls_message_buffer.get_data_length()),
					tmp_tls_handshake_header_on_tls_message_buffer.get_header_length()
					+ tmp_tls_handshake_header_on_tls_message_buffer.get_data_length());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				break;
			}
			default:
				return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
			} // switch()
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_handshake_message_c::add_message_data(
	eap_variable_data_c * const tls_message_buffer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: data_function: tls_handshake_message_c::add_message_data(): %s\n"),
		 (m_is_client == true ? "client": "server"),
		 tls_handshake_header_c::get_tls_handshake_string(get_handshake_type())));

	eap_status_e status = eap_status_ok;

	if (m_tls_handshake_message_buffer.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	status = tls_message_buffer->add_data(
		m_tls_handshake_message_buffer.get_data(m_tls_handshake_message_buffer.get_data_length()),
		m_tls_handshake_message_buffer.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------



// End.
