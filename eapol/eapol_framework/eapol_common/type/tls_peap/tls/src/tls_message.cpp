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
	#define EAP_FILE_NUMBER_ENUM 131 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_array.h"
#include "tls_message.h"
#include "tls_peap_types.h"
#include "eap_automatic_variable.h"

/** @file */


//--------------------------------------------------

EAP_FUNC_EXPORT tls_message_c::~tls_message_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_record_messages.reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_message_c::tls_message_c(
	abs_eap_am_tools_c * const tools,
	abs_tls_message_hash_c * const message_hash,
	abs_tls_apply_cipher_spec_c * const apply_cipher_spec,
	abs_tls_change_cipher_spec_c * change_cipher_spec,
	const bool is_client)
: m_am_tools(tools)
, m_message_hash(message_hash)
, m_apply_cipher_spec(apply_cipher_spec)
, m_change_cipher_spec(change_cipher_spec)
, m_tls_message_data(tools)
, m_received_eap_identifier(0ul)
, m_analyse_index(0ul)
, m_record_messages(tools)
, m_is_client(is_client)
, m_includes_tls_handshake_message(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_message_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_analyse_index = 0ul;
	m_received_eap_identifier = 0ul;
	m_includes_tls_handshake_message = false;

	eap_status_e status = m_record_messages.reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t tls_message_c::get_analyse_index() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_analyse_index;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_message_c::save_analyse_index(const u32_t analyse_index)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_analyse_index = analyse_index;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_message_c::set_tls_message_data(
	eap_variable_data_c * const tls_message_data,
	u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_tls_message_data.set_copy_of_buffer(tls_message_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_received_eap_identifier = received_eap_identifier;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * tls_message_c::get_tls_message_data()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_tls_message_data;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t tls_message_c::get_received_eap_identifier()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_received_eap_identifier;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_message_c::add_record_message(
	tls_record_message_c * const record,
	const bool free_record,
	const bool includes_tls_handshake_message)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_includes_tls_handshake_message == false)
	{
		m_includes_tls_handshake_message = includes_tls_handshake_message;
	}

	eap_status_e status = m_record_messages.add_object(record, free_record);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_message_c::fragment_tls_records(
	tls_record_message_c * const tls_record_message,
	eap_array_c<tls_record_message_c> * const tls_fragments)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_ok;

	// Here we assume data included in tls_record_message does not include TLS-record header.
	// Only data TLS-protocol messages are included. All TLS-protocol messages are same protocol.
	// This function fragments TLS-protocol messages to one or more TLS-record messages.

	u32_t size_of_data = tls_record_message->get_data_length();
	u32_t offset_of_data = 0ul;

	while(size_of_data > 0ul)
	{
		tls_record_message_c * const fragment = new tls_record_message_c(
			m_am_tools, m_message_hash, m_is_client);

		eap_automatic_variable_c<tls_record_message_c>
			automatic_fragment(m_am_tools, fragment);

		if (fragment == 0
			|| fragment->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t fragment_length = size_of_data;
		if (fragment_length > TLS_PEAP_MAX_RECORD_FRAGMENT_LENGTH)
		{
			fragment_length = TLS_PEAP_MAX_RECORD_FRAGMENT_LENGTH;
		}


		// Adds TLS-record header.
		status = fragment->get_record_message_data()->set_buffer_length(tls_record_header_c::get_header_length()+fragment_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		tls_record_header_c tmp_tls_record_header_on_tls_message_buffer(
			m_am_tools,
			fragment->get_record_message_data()->get_buffer(tls_record_header_c::get_header_length()+fragment_length),
			tls_record_header_c::get_header_length()+fragment_length);

		if (tmp_tls_record_header_on_tls_message_buffer.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_long_message);
		}

		// Note this is the length of the TLS-record header.
		fragment->get_record_message_data()->set_data_length(tls_record_header_c::get_header_length());
		fragment->set_protocol(tls_record_message->get_protocol());
		fragment->set_version(tls_record_message->get_version());
		// Note this is the length of the TLS-record header and TLS-record data.
		// The length of the TLS-record data is the length of the fragment.
		fragment->add_data_length(tls_record_header_c::get_header_length()+fragment_length);
		fragment->set_tls_record_header_is_included(true);

		tmp_tls_record_header_on_tls_message_buffer.reset_header(0ul, tls_record_message->get_version());
		tmp_tls_record_header_on_tls_message_buffer.set_protocol(tls_record_message->get_protocol());
		tmp_tls_record_header_on_tls_message_buffer.set_data_length(static_cast<u16_t>(fragment_length));

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TLS: %s: tls_message_c::fragment_tls_records(): %s fragment %d bytes from %d bytes.\n"),
			(m_is_client == true ? "client": "server"),
			tmp_tls_record_header_on_tls_message_buffer.get_tls_protocol_string(),
			 fragment_length,
			 tls_record_message->get_data_length()));

		// Adds TLS-record data, this includes TLS-protocol messages.
		status = fragment->get_record_message_data()->add_data(
			tls_record_message->get_record_message_data()->get_data_offset(
				offset_of_data, fragment_length),
			fragment_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		size_of_data -= fragment_length;
		offset_of_data += fragment_length;

		automatic_fragment.do_not_free_variable();

		status = tls_fragments->add_object(fragment, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	} // while()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_message_c::add_message_data(
	eap_variable_data_c * const tls_message_buffer,
	bool * const includes_tls_handshake_message)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_ok;

	tls_message_buffer->reset();
	status = tls_message_buffer->set_buffer_length(TLS_PEAP_DEFAULT_RECORD_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	for (u32_t ind = 0ul; ind < m_record_messages.get_object_count(); ind++)
	{
		tls_record_message_c * const tls_record_message = m_record_messages.get_object(ind);
		if (tls_record_message == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (tls_record_message->get_record_message_data()->get_is_valid() == false
			|| tls_record_message->get_record_message_data()->get_buffer_length() < TLS_PEAP_DEFAULT_RECORD_LENGTH)
		{
			status = tls_record_message->get_record_message_data()->set_buffer_length(TLS_PEAP_DEFAULT_RECORD_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		tls_record_message->get_record_message_data()->set_data_length(0ul);

		// This function creates data of TLS-protocol message to internal buffer (tls_record_message->get_record_message_data()).
		status = tls_record_message->add_message_data();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		EAP_ASSERT(tls_record_message->get_tls_record_header_is_included() == false);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("TLS-record data"),
			tls_record_message->get_record_message_data()->get_data(
				tls_record_message->get_record_message_data()->get_data_length()),
			tls_record_message->get_record_message_data()->get_data_length()));

		// Fragmentation checks the TLS-record is not too long, data more than 2^14 bytes.
		// It fragments TLS-record to two or more TLS-records.
		// TLS-records could be stored to object of type of eap_array_c<tls_record_message_c>.
		// In a case the TLS-record cannot be fragmented the whole TLS-message must be dropped.
		eap_array_c<tls_record_message_c> tls_fragments(m_am_tools);
		status = fragment_tls_records(
				tls_record_message,
				&tls_fragments);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// After the fragmentation cipher suite can be applied to every fragment.
		for (u32_t ind_frag = 0ul; ind_frag < tls_fragments.get_object_count(); ind_frag++)
		{
			tls_record_message_c * const fragment = tls_fragments.get_object(ind_frag);
			if (fragment == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
			}

			EAP_ASSERT(fragment->get_data_length() == fragment->get_record_message_data()->get_data_length());

			status = m_apply_cipher_spec->apply_send_cipher_suite(fragment->get_record_message_data());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (ind_frag == 0ul)
			{
				if (fragment->get_protocol() == tls_record_protocol_change_cipher_spec)
				{
					// This is the right place to change the send cipher spec.
					status = m_change_cipher_spec->change_cipher_spec(true);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}

			status = tls_message_buffer->add_data(fragment->get_record_message_data());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		} // for()

	} // for()

	*includes_tls_handshake_message = m_includes_tls_handshake_message;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t tls_message_c::get_record_message_count() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_record_messages.get_object_count();
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_record_message_c * tls_message_c::get_record_message(
	const u32_t index) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_record_messages.get_object(index);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_message_c::remove_record_message(
	const u32_t index)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_record_messages.remove_object(index);
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_record_message_c * tls_message_c::get_last_record_message() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_record_messages.get_last_object();
}

//--------------------------------------------------



// End.
