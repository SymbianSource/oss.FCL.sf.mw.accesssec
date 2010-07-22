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
	#define EAP_FILE_NUMBER_ENUM 137 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_tools.h"
#include "eap_array.h"
#include "tls_record_message.h"
#include "eap_automatic_variable.h"


/** @file */

//--------------------------------------------------

EAP_FUNC_EXPORT tls_record_message_c::~tls_record_message_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_record_message_c::tls_record_message_c(
	abs_eap_am_tools_c * const tools,
	abs_tls_message_hash_c * const message_hash,
	const bool is_client)
: m_am_tools(tools)
, m_message_hash(message_hash)
, m_protocol(tls_record_protocol_none)
, m_version(tls_version_illegal)
, m_length(0ul)
, m_tls_record_header_is_included(false)
, m_record_message_data(tools)
, m_analyse_index(0ul)
, m_parsed_record(false)
, m_cipher_suite_applied(false)
, m_handshake_messages(tools)
, m_change_cipher_spec_messages(tools)
, m_alert_messages(tools)
, m_application_data_messages(tools)
, m_is_client(is_client)
, m_is_valid(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_record_message_c::set_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_is_valid = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_record_message_c::get_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t tls_record_message_c::get_analyse_index() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_analyse_index;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_record_message_c::save_analyse_index(const u32_t analyse_index)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_analyse_index = analyse_index;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_record_message_c::get_parsed_record() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_parsed_record;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_record_message_c::set_parsed_record()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_parsed_record = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_record_message_c::get_tls_record_header_is_included() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_tls_record_header_is_included;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_record_message_c::set_tls_record_header_is_included(const bool when_true_tls_record_header_is_included)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_tls_record_header_is_included = when_true_tls_record_header_is_included;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_record_message_c::get_cipher_suite_applied() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_cipher_suite_applied;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_record_message_c::set_cipher_suite_applied()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_cipher_suite_applied = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_message_c::set_protocol(tls_record_protocol_e protocol)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_protocol = protocol;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_message_c::set_version(
	tls_version_e version)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_version = version;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_message_c::set_record_header_copy(
	const tls_record_header_c * const tls_record_header)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_protocol = tls_record_header->get_protocol();
	m_version = tls_record_header->get_version();
	m_length = tls_record_header->get_data_length();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_message_c::set_record_message_data(
		void * const data,
		const u32_t data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_record_message_data.set_buffer(data, data_length, false, true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * tls_record_message_c::get_record_message_data()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_record_message_data;
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_record_protocol_e tls_record_message_c::get_protocol() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_protocol;
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_version_e tls_record_message_c::get_version() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_version;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t tls_record_message_c::get_data_length() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_length;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_message_c::add_data_length(const u32_t data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if ((m_length + data_length) > tls_handshake_header_c::get_max_data_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_long_message);
	}

	m_length += data_length;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_message_c::add_handshake_message(
	tls_handshake_message_c * const handshake_message,
	const bool free_handshake_message)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools, handshake_message);
	if (free_handshake_message == false)
	{
		automatic_tls_handshake_message.do_not_free_variable();
	}

	if (handshake_message == 0
		|| handshake_message->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (get_protocol() != tls_record_protocol_handshake)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_protocol);
	}

	// Note the m_handshake_messages will free handshake_message, in all cases if free_handshake_message == true.
	automatic_tls_handshake_message.do_not_free_variable();

	eap_status_e status = m_handshake_messages.add_object(
		handshake_message,
		free_handshake_message);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_message_c::add_change_cipher_spec_message(
	tls_change_cipher_spec_message_c * const change_cipher_spec_message,
	const bool free_change_cipher_spec_message)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_automatic_variable_c<tls_change_cipher_spec_message_c>
		automatic_tls_handshake_message(m_am_tools, change_cipher_spec_message);
	if (free_change_cipher_spec_message == false)
	{
		automatic_tls_handshake_message.do_not_free_variable();
	}

	if (change_cipher_spec_message == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (get_protocol() != tls_record_protocol_change_cipher_spec)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_protocol);
	}

	// Note the m_change_cipher_spec_messages will free handshake_message, in all cases if free_change_cipher_spec_message == true.
	automatic_tls_handshake_message.do_not_free_variable();

	eap_status_e status = m_change_cipher_spec_messages.add_object(
		change_cipher_spec_message,
		free_change_cipher_spec_message);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_message_c::add_alert_message(
	tls_alert_message_c * const alert_message,
	const bool free_alert_message)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_automatic_variable_c<tls_alert_message_c>
		automatic_tls_handshake_message(m_am_tools, alert_message);
	if (free_alert_message == false)
	{
		automatic_tls_handshake_message.do_not_free_variable();
	}

	if (alert_message == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (get_protocol() != tls_record_protocol_alert)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_protocol);
	}

	// Note the m_alert_messages will free handshake_message, in all cases if free_alert_message == true.
	automatic_tls_handshake_message.do_not_free_variable();

	eap_status_e status = m_alert_messages.add_object(
		alert_message,
		free_alert_message);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_message_c::add_application_data_message(
	tls_application_data_message_c * const application_data_message,
	const bool free_application_data_message)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_automatic_variable_c<tls_application_data_message_c>
		automatic_tls_handshake_message(m_am_tools, application_data_message);
	if (free_application_data_message == false)
	{
		automatic_tls_handshake_message.do_not_free_variable();
	}

	if (application_data_message == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (get_protocol() != tls_record_protocol_application_data)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_protocol);
	}

	// Note the m_application_data_messages will free handshake_message, in all cases if free_application_data_message == true.
	automatic_tls_handshake_message.do_not_free_variable();

	eap_status_e status = m_application_data_messages.add_object(
		application_data_message,
		free_application_data_message);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_message_c::add_message_data()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_not_supported;

	u32_t offset_of_tmp_tls_record_header = m_record_message_data.get_data_length();

	EAP_UNREFERENCED_PARAMETER(offset_of_tmp_tls_record_header); // Not referenced without assert.
	EAP_ASSERT(offset_of_tmp_tls_record_header == 0ul);


	u32_t record_data_length_start = m_record_message_data.get_data_length();


	switch (get_protocol())
	{
	case tls_record_protocol_change_cipher_spec:
		{
			u32_t ind;
			for (ind = 0ul; ind < m_change_cipher_spec_messages.get_object_count(); ind++)
			{
				tls_change_cipher_spec_message_c * const tls_change_cipher_spec_message
					= m_change_cipher_spec_messages.get_object(ind);
				if (tls_change_cipher_spec_message == 0
					|| tls_change_cipher_spec_message->get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = tls_change_cipher_spec_message->add_message_data(&m_record_message_data);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
		break;
	case tls_record_protocol_alert:
		{
			u32_t ind;
			for (ind = 0ul; ind < m_alert_messages.get_object_count(); ind++)
			{
				tls_alert_message_c * const tls_alert_message
					= m_alert_messages.get_object(ind);
				if (tls_alert_message == 0
					|| tls_alert_message->get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = tls_alert_message->add_message_data(&m_record_message_data);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
		break;
	case tls_record_protocol_handshake:
		{
			u32_t ind;
			for (ind = 0ul; ind < m_handshake_messages.get_object_count(); ind++)
			{
				tls_handshake_message_c * const tls_handshake_message = m_handshake_messages.get_object(ind);
				if (tls_handshake_message == 0
					|| tls_handshake_message->get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = tls_handshake_message->add_message_data(&m_record_message_data);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
		break;
	case tls_record_protocol_application_data:
		{
			u32_t ind;
			for (ind = 0ul; ind < m_application_data_messages.get_object_count(); ind++)
			{
				tls_application_data_message_c * const tls_application_data_message = m_application_data_messages.get_object(ind);
				if (tls_application_data_message == 0
					|| tls_application_data_message->get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = tls_application_data_message->add_message_data(&m_record_message_data);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
		break;
	default:
		break;
	} // switch()


	if (status == eap_status_ok)
	{
		u32_t record_data_length = m_record_message_data.get_data_length() - record_data_length_start;

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("record data length %d bytes.\n"),
			record_data_length));

		status = add_data_length(record_data_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t tls_record_message_c::get_handshake_count() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_handshake_messages.get_object_count();
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t tls_record_message_c::get_change_cipher_spec_count() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_change_cipher_spec_messages.get_object_count();
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t tls_record_message_c::get_alert_count() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_alert_messages.get_object_count();
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t tls_record_message_c::get_application_data_count() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_application_data_messages.get_object_count();
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_handshake_message_c * tls_record_message_c::get_handshake(
	const u32_t index) EAP_TEMPLATE_CONST
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_handshake_messages.get_object(index);
}

//--------------------------------------------------

EAP_FUNC_EXPORT const tls_change_cipher_spec_message_c * tls_record_message_c::get_change_cipher_spec(
	const u32_t index) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_change_cipher_spec_messages.get_object(index);
}

//--------------------------------------------------

EAP_FUNC_EXPORT const tls_alert_message_c * tls_record_message_c::get_alert(
	const u32_t index) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_alert_messages.get_object(index);
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_application_data_message_c * tls_record_message_c::get_application_data(
	const u32_t index) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_application_data_messages.get_object(index);
}

//--------------------------------------------------



// End.
