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
* %version: 36 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 48 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_core_server_message_if.h"
#include "eap_crypto_api.h"
#include "eap_state_notification.h"
#include "eap_automatic_variable.h"
#include "eap_network_id_selector.h"
#include "eap_config.h"
#include "eap_buffer.h"
#include "eapol_session_key.h"
#include "eap_master_session_key.h"
#include "eap_am_stack.h"

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_core_server_message_if_c::~eap_core_server_message_if_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_server_message_if_c::~eap_core_server_message_if_c(): this = 0x%08x\n"),
		this));

	EAP_ASSERT(m_shutdown_was_called == true);

	delete m_eap_core;
	delete m_am_stack;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4355 ) // 'this' : used in base member initializer list
#endif

// 
EAP_FUNC_EXPORT eap_core_server_message_if_c::eap_core_server_message_if_c(
	abs_eap_am_tools_c * const tools,
	const bool is_client_when_true,
	const u32_t MTU)
	: m_partner(0)
	, m_eap_core(eap_session_core_base_c::new_eap_session_core_c(tools, this, is_client_when_true, MTU))
	, m_am_stack(new_eap_am_stack_c(tools, is_client_when_true))
	, m_am_tools(tools)
	, m_eap_header_offset(0u)
	, m_MTU(MTU)
	, m_trailer_length(0u)
	, m_error_code(eap_status_ok)
	, m_error_function(eap_tlv_message_type_function_none)
	, m_is_client(is_client_when_true)
	, m_is_valid(false)
	, m_shutdown_was_called(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_server_message_if_c::eap_core_server_message_if_c(): %s, this = 0x%08x => 0x%08x, compiled %s %s.\n"),
		(m_is_client == true) ? "client": "server",
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this),
		__DATE__,
		__TIME__));

	if (m_eap_core != 0
		&& m_eap_core->get_is_valid() == true
		&& m_am_stack != 0
		&& m_am_stack->get_is_valid() == true)
	{
		set_is_valid();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::configure(
	const eap_variable_data_c * const client_configuration)
{
	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eap_core_server_message_if_c::configure()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::configure()");

	eap_status_e status(eap_status_process_general_error);

	m_eap_header_offset = 0ul;
	m_trailer_length = 0ul;

	if (m_am_stack != 0)
	{
		status = m_am_stack->set_partner(
			this
#if defined(USE_EAP_SIMPLE_CONFIG)
			, this
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)
			);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_am_stack->configure(client_configuration);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	
	if (m_eap_core != 0)
	{
		status = m_eap_core->configure();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::shutdown()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eap_core_server_message_if_c::shutdown(), m_shutdown_was_called=%d\n"),
		(m_is_client == true) ? "client": "server",
		m_shutdown_was_called));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::shutdown()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	if (m_shutdown_was_called == true)
	{
		// Shutdown function was called already.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_shutdown_was_called = true;

	if (m_eap_core != 0)
	{
		(void) m_eap_core->shutdown();
	}

	if (m_am_stack != 0)
	{
		(void) m_am_stack->shutdown();
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_core_server_message_if_c::set_partner(abs_eap_am_message_if_c * const partner)
{
	m_partner = partner;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::send_error_message(
	const eap_status_e error_code,
	const eap_tlv_message_type_function_e function)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eap_core_server_message_if_c::send_error_message()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::send_error_message()");

	eap_status_e status(eap_status_ok);

	{
		// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(
			eap_tlv_message_type_error,
			static_cast<u32_t>(error_code));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(function);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::send_message(eap_process_tlv_message_data_c * const message)
{
	// Sends message data composed of Attribute-Value Pairs.

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_server_message_if_c::send_message(): this = 0x%08x => 0x%08x.\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_NEVER,
		(EAPL("eap_core_client_message_if_c::send_message()"),
		message->get_message_data(),
		message->get_message_data_length()));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_client_message_if_c::send_message()");


	{
		eap_status_e send_status = m_partner->send_data(
			message->get_message_data(),
			message->get_message_data_length());
		if (send_status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, send_status);
		}


		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, send_status);
	}

}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::process_message_type_error(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eap_core_server_message_if_c::process_message_type_error()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::process_message_type_error()");

	eap_status_e status(eap_status_ok);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// Error payload is the first in this case.
	status = message_data.read_parameter_data(parameters, eap_message_payload_index_function, eap_tlv_message_type_error, &m_error_code);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Fuction payload is the second in this case.
	status = message_data.read_parameter_data(parameters, eap_message_payload_index_first_parameter, &m_error_function);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::process_message(eap_process_tlv_message_data_c * const message)
{
	// Parses message data composed of Attribute-Value Pairs.

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eap_core_server_message_if_c::process_message()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::process_message()");

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_NEVER,
		(EAPL("eap_core_server_message_if_c::process_message()"),
		message->get_message_data(),
		message->get_message_data_length()));

	eap_array_c<eap_tlv_header_c> parameters(m_am_tools);

	eap_status_e status = message->parse_message_data(&parameters);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

		(void) send_error_message(
			status,
			eap_tlv_message_type_function_none);

		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (parameters.get_object_count() == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

		status = eap_status_illegal_parameter;

		(void) send_error_message(
			status,
			eap_tlv_message_type_function_none);

		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const eap_tlv_header_c * const function_header = parameters.get_object(eap_message_payload_index_function);
	if (function_header == 0
		|| (function_header->get_type() != eap_tlv_message_type_error
			&& function_header->get_type() != eap_tlv_message_type_function))
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

		status = eap_status_illegal_parameter;

		(void) send_error_message(
			status,
			eap_tlv_message_type_function_none);

		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (function_header->get_type() == eap_tlv_message_type_error)
	{
		status = process_message_type_error(&parameters);
	}
	else // function_header->get_type() == eap_tlv_message_type_function
	{
		eap_tlv_message_type_function_e function(eap_tlv_message_type_function_none);

		status = message->get_parameter_data(function_header, &function);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

			(void) send_error_message(
				status,
				eap_tlv_message_type_function_none);

			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_core_server_message_if_c::process_message(): this = 0x%08x, message=%d=%s\n"),
			this,
			function,
			eap_process_tlv_message_data_c::get_function_string(function)));

		switch(function)
		{
		case eap_tlv_message_type_function_create_eap_session:
			status = create_eap_session(&parameters);
			break;
		case eap_tlv_message_type_function_remove_eap_session:
			status = remove_eap_session(&parameters);
			break;
		case eap_tlv_message_type_function_send_eap_identity_request:
			status = send_eap_identity_request(&parameters);
			break;
		case eap_tlv_message_type_function_packet_process:
			status = packet_process(&parameters);
			break;
		case eap_tlv_message_type_function_eap_acknowledge:
			status = eap_acknowledge(&parameters);
			break;
		case eap_tlv_message_type_function_set_eap_database_reference_values:
			status = set_eap_database_reference_values(&parameters);
			break;
		case eap_tlv_message_type_function_eap_mtu:
			status = eap_mtu(&parameters);
			break;
		case eap_tlv_message_type_function_get_802_11_authentication_mode:
			status = get_802_11_authentication_mode(&parameters);
			break;
		default:
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: process_data(): unknown function %d.\n"),
				 function));

			status = eap_status_illegal_parameter;

			EAP_ASSERT_ANYWAY_TOOLS(m_am_tools);
		};

		if (status != eap_status_ok
			&& status != eap_status_success
			&& status != eap_status_pending_request
			&& status != eap_status_completed_request
			&& status != eap_status_drop_packet_quietly)
		{
			(void) send_error_message(
				status,
				function);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/// Function receives the data message from lower layer.
/// Data is formatted to Attribute-Value Pairs.
/// Look at eap_tlv_header_c and eap_tlv_message_data_c.
EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::process_data(const void * const data, const u32_t length)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eap_core_server_message_if_c::process_data()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::process_data()");

	eap_status_e status(eap_status_process_general_error);

	{
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

			status = eap_status_allocation_error;

			(void) send_error_message(
				status,
				eap_tlv_message_type_function_none);

			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.set_message_data(length, data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

			(void) send_error_message(
				status,
				eap_tlv_message_type_function_none);

			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = process_message(&message);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::packet_send(
	const eap_am_network_id_c * const send_network_id,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const u32_t buffer_length)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eap_core_server_message_if_c::packet_send()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::packet_send()");

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);
	EAP_ASSERT(header_offset < sent_packet->get_data_length());
	EAP_ASSERT(data_length <= sent_packet->get_data_length());
	EAP_ASSERT(sent_packet->get_data_length() <= buffer_length);

	eap_status_e status(eap_status_process_general_error);

	if (sent_packet->get_do_length_checks() == true)
	{
		if (header_offset != 0ul)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: packet_send: packet buffer corrupted (header_offset != %d).\n"),
				0ul));
			EAP_ASSERT_ALWAYS(header_offset == 0ul);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}
		else if (header_offset+data_length != sent_packet->get_data_length())
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: packet_send: packet buffer corrupted ")
				 EAPL("(data_length %d != sent_packet->get_data_length() %d).\n"),
				 header_offset+data_length,
				 sent_packet->get_data_length()));
			EAP_ASSERT_ALWAYS(data_length == sent_packet->get_buffer_length());
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}
		else if (header_offset+data_length > buffer_length)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: packet_send: packet buffer corrupted ")
				 EAPL("(header_offset+data_length %d > buffer_length %d).\n"),
				 header_offset+data_length,
				 buffer_length));
			EAP_ASSERT_ALWAYS(header_offset+data_length <= buffer_length);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}
		else if (header_offset+data_length > m_MTU)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: packet_send: packet buffer corrupted ")
				 EAPL("(header_offset+data_length %d > m_MTU %d).\n"),
				 header_offset+data_length,
				 m_MTU));
			EAP_ASSERT_ALWAYS(header_offset+data_length <= m_MTU);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}
	}
	else
	{
		// Always we need at least the EAP header.
		if (sent_packet->get_data_length()
			< eap_header_base_c::get_header_length())
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: packet_send: packet buffer corrupted ")
				 EAPL("(sent_packet->get_data_length() %d < ")
				 EAPL("eap_header_base_c::get_header_length() %d).\n"),
				 sent_packet->get_data_length(),
				 eap_header_base_c::get_header_length()));
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}
	}
	
	{
		// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_packet_send);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(send_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(sent_packet);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
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

//
EAP_FUNC_EXPORT u32_t eap_core_server_message_if_c::get_header_offset(
	u32_t * const MTU,
	u32_t * const trailer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const u32_t offset = 0ul;

	*MTU = m_MTU;
	*trailer_length = m_trailer_length;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return offset;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::load_module(
	const eap_type_value_e type,
	const eap_type_value_e tunneling_type,
	abs_eap_base_type_c * const partner,
	eap_base_type_c ** const eap_type,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_am_stack->load_module(
		type,
		tunneling_type,
		partner,
		eap_type,
		is_client_when_true,
		receive_network_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::unload_module(const eap_type_value_e /* type*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status(eap_status_process_general_error);

	EAP_ASSERT_ANYWAY_TOOLS(m_am_tools);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::packet_data_crypto_keys(
	const eap_am_network_id_c * const send_network_id,
	const eap_master_session_key_c * const master_session_key
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eap_core_server_message_if_c::packet_data_crypto_keys()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::packet_data_crypto_keys()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status(eap_status_process_general_error);

	if (master_session_key == 0
		|| master_session_key->get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: eap_core_server_message_if_c::packet_data_crypto_keys(), invalid key.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_core_server_message_if_c::packet_data_crypto_keys(): master_session_key"), 
		 master_session_key->get_data(),
		 master_session_key->get_data_length()));
	
	{
		// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_packet_data_crypto_keys);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(send_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// This adds only the EAP-type.
		status = message.add_parameter_data(master_session_key->get_eap_type());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// This adds only the eap_variable_data.
		status = message.add_parameter_data(master_session_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
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

//
EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::complete_get_802_11_authentication_mode(
	const eap_status_e completion_status,
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_802_11_authentication_mode_e mode)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eap_core_server_message_if_c::complete_get_802_11_authentication_mode()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::complete_get_802_11_authentication_mode()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status(eap_status_process_general_error);

	{
		// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_complete_get_802_11_authentication_mode);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(completion_status);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(receive_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(mode);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
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

//
EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::complete_remove_eap_session(
	const bool complete_to_lower_layer,
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eap_core_server_message_if_c::complete_remove_eap_session(): complete_to_lower_layer=%s\n"),
		(m_is_client == true) ? "client": "server",
		(complete_to_lower_layer == true) ? "true": "false"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::complete_remove_eap_session()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status(eap_status_process_general_error);

	{
		// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_complete_remove_eap_session);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(complete_to_lower_layer);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(receive_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
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

//
EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = m_am_stack->read_configure(
		field,
		data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::write_configure(
	const eap_configuration_field_c * const /* field */,
	eap_variable_data_c * const /* data */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status(eap_status_process_general_error);

	EAP_ASSERT_ANYWAY_TOOLS(m_am_tools);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_core_server_message_if_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eap_core_server_message_if_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::timer_expired(
	const u32_t id, void *data)
{
	EAP_UNREFERENCED_PARAMETER(id);
	EAP_UNREFERENCED_PARAMETER(data);
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: %s: [0x%08x]->eap_core_server_message_if_c::timer_expired(id 0x%02x, data 0x%08x).\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 id,
		 data));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::timer_expired()");


	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::timer_delete_data(
	const u32_t id, void *data)
{
	EAP_UNREFERENCED_PARAMETER(id);
	EAP_UNREFERENCED_PARAMETER(data);
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: %s: [0x%08x]->eap_core_server_message_if_c::timer_delete_data(id 0x%02x, data 0x%08x).\n"),
		(m_is_client == true) ? "client": "server",
		this, id, data));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::timer_delete_data()");

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_core_server_message_if_c::state_notification(
	const abs_eap_state_notification_c * const state)
{
	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eap_core_server_message_if_c::state_notification()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::state_notification()");

	{
		// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void)EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			return;
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_state_notification);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void)EAP_STATUS_RETURN(m_am_tools, status);
			return;
		}

		status = message.add_parameter_data(state);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void)EAP_STATUS_RETURN(m_am_tools, status);
			return;
		}

		status = send_message(&message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void)EAP_STATUS_RETURN(m_am_tools, status);
			return;
		}
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::asynchronous_init_remove_eap_session(
	const eap_am_network_id_c * const /* send_network_id */)
{
	// eap_core_server_message_if_c object does not support asynchronous_init_remove_eap_session().
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::asynchronous_start_authentication(
	const eap_am_network_id_c * const /* receive_network_id */,
	const bool /* is_client_when_true */)
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::restart_authentication(
	const eap_am_network_id_c * const send_network_id,
	const bool is_client_when_true,
	const bool force_clean_restart,
	const bool from_timer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eap_core_server_message_if_c::restart_authentication()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::restart_authentication()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status(eap_status_process_general_error);

	{
		// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_restart_authentication);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(send_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(is_client_when_true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(force_clean_restart);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(from_timer);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
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

//
EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::set_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id, 
	void * const p_data,
	const u32_t p_time_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = m_am_stack->set_timer(
		p_initializer, 
		p_id, 
		p_data,
		p_time_ms);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::cancel_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status(eap_status_ok);

	if (m_am_stack != 0)
	{
		status = m_am_stack->cancel_timer(
			p_initializer, 
			p_id);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::check_is_valid_eap_type(
	const eap_type_value_e eap_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = m_am_stack->check_is_valid_eap_type(eap_type);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::get_eap_type_list(
	eap_array_c<eap_type_value_e> * const eap_type_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_am_stack->get_eap_type_list(eap_type_list);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/// @see abs_eap_core_c::add_rogue_ap().
EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::add_rogue_ap(
	eap_array_c<eap_rogue_ap_entry_c> & /* rogue_ap_list */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eap_core_server_message_if_c::add_rogue_ap(): Does nothing.\n"),
		 (m_is_client == true) ? "client": "server"));

	eap_status_e status(eap_status_ok);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::set_session_timeout(
	const u32_t /* session_timeout_ms */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

eap_status_e eap_core_server_message_if_c::create_eap_session(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eap_core_server_message_if_c::create_eap_session()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::create_eap_session()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_am_network_id_c receive_network_id(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_eap_core->create_eap_session(
		&receive_network_id ///< source includes remote address, destination includes local address.
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_core_server_message_if_c::remove_eap_session(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eap_core_server_message_if_c::remove_eap_session()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::remove_eap_session()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	bool complete_to_lower_layer(false);

	status = message_data.read_parameter_data(parameters, parameter_index, &complete_to_lower_layer);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_am_network_id_c receive_network_id(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_eap_core->remove_eap_session(
		complete_to_lower_layer,
		&receive_network_id ///< source includes remote address, destination includes local address.
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// This is a new function to synchronize EAP-client and EAP-server.
	eap_status_e completion_status = complete_remove_eap_session(
		complete_to_lower_layer,
		&receive_network_id ///< source includes remote address, destination includes local address.
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, completion_status);
}

//--------------------------------------------------

eap_status_e eap_core_server_message_if_c::send_eap_identity_request(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eap_core_server_message_if_c::send_eap_identity_request()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::send_eap_identity_request()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_am_network_id_c receive_network_id(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_eap_core->send_eap_identity_request(
		&receive_network_id ///< source includes remote address, destination includes local address.
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_core_server_message_if_c::packet_process(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eap_core_server_message_if_c::packet_process()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::packet_process()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_am_network_id_c receive_network_id(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_variable_data_c packet_data_payload(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &packet_data_payload);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_header_wr_c eap(
		m_am_tools,
		packet_data_payload.get_data(),
		packet_data_payload.get_data_length());
	if (eap.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = m_eap_core->packet_process(
		&receive_network_id,
		&eap,
		packet_data_payload.get_data_length()
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::eap_acknowledge(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eap_core_server_message_if_c::eap_acknowledge()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::eap_acknowledge()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_am_network_id_c receive_network_id(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_eap_core->eap_acknowledge(
		&receive_network_id ///< source includes remote address, destination includes local address.
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::eap_mtu(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eap_core_server_message_if_c::eap_mtu()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::eap_mtu()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = message_data.read_parameter_data(parameters, parameter_index, &m_MTU);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::get_802_11_authentication_mode(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eap_core_server_message_if_c::get_802_11_authentication_mode()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::get_802_11_authentication_mode()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_am_network_id_c receive_network_id(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eapol_key_authentication_type_e authentication_type(eapol_key_authentication_type_none);

	status = message_data.read_parameter_data(parameters, parameter_index, &authentication_type);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_variable_data_c SSID(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &SSID);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

    EAP_TRACE_DATA_DEBUG(
        m_am_tools,
        TRACE_FLAGS_DEFAULT,
        (EAPL("new SSID"),
        SSID.get_data(),
        SSID.get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_variable_data_c preshared_key(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &preshared_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

    EAP_TRACE_DATA_DEBUG(
        m_am_tools,
        TRACE_FLAGS_DEFAULT,
        (EAPL("new preshared_key"),
        preshared_key.get_data(),
        preshared_key.get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (authentication_type == eapol_key_authentication_type_WPS)
	{
		// Saves SSID and pre-shared key for WPS to memory store.

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("%s: eap_core_server_message_if_c::get_802_11_authentication_mode(): Saves SSID and pre-shared key for WPS to memory store.\n"),
			 (m_is_client == true) ? "client": "server"));

		eap_variable_data_c memory_store_key(m_am_tools);

		eap_status_e status = memory_store_key.set_copy_of_buffer(
			EAP_WPS_CONFIGURATION_MEMORY_STORE_KEY,
			sizeof(EAP_WPS_CONFIGURATION_MEMORY_STORE_KEY));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = memory_store_key.add_data(
			&m_is_client,
			sizeof(m_is_client));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_network_id_selector_c state_selector(
			m_am_tools,
			&receive_network_id);

		status = memory_store_key.add_data(
			&state_selector);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_tlv_message_data_c tlv_data(m_am_tools);

		status = tlv_data.add_message_data(
			eap_type_protected_setup_stored_preshared_key,
			preshared_key.get_data_length(),
			preshared_key.get_data());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = tlv_data.add_message_data(
			eap_type_protected_setup_stored_ssid,
			SSID.get_data_length(),
			SSID.get_data());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_am_tools->memory_store_remove_data(&memory_store_key);
		if (status != eap_status_ok
			&& status != eap_status_not_found)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_am_tools->memory_store_add_data(
			&memory_store_key,
			&tlv_data,
			eap_type_default_credential_timeout);
		if (status != eap_status_ok)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("eap_core_server_message_if_c::get_802_11_authentication_mode(): cannot store WPS credentials\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_am_stack->get_802_11_authentication_mode(
		&receive_network_id, ///< source includes remote address, destination includes local address.
		authentication_type);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_core_server_message_if_c::set_eap_database_reference_values(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eap_core_server_message_if_c::set_eap_database_reference_values()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::set_eap_database_reference_values()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c reference(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &reference);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_am_stack->set_eap_database_reference_values(
		&reference
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e eap_core_server_message_if_c::save_simple_config_session(
	const simple_config_state_e /* state */,
	EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
	const eap_variable_data_c * const /* new_password */,
	const simple_config_Device_Password_ID_e /* Device_Password_ID */,
	const simple_config_payloads_c * const /* other_configuration */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eap_core_server_message_if_c::save_simple_config_session()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::save_simple_config_session()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Message is formatted as:
	// 0                   1                   2                   3   
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Function                            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 4                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Value = New_protected_setup_credentials    |
	// +#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+ <= start of Array of Protected setup credential
	// |                    Type = Array                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 137                               |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ <= start of Array of Protected setup credential value
	// |                    Type = Protected setup credential          |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 129                               |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Unsigned 8 bit integer              |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 1                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   u8_t value  |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Variable data                       |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 12                                |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Value = SSID string                        |
	// +-+-+-+-                                                 -+-+-+-+
	// |                                                               |
	// +-+-+-+-                                                 -+-+-+-+
	// |                                                               |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Unsigned 16 bit integer             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 2                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   u16_t Authentication type   |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Unsigned 16 bit integer             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 2                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   u16_t Encryption type       |
	// +#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+ <= start of Array of Network key
	// |                    Type = Array                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 66                                |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ <= start of Array of Network key value
	// |                    Type = Network key                         |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 25                                |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Unsigned 8 bit integer              |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 1                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   u8_t value  |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Variable data                       |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 8                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Value = Network key                        |
	// +-+-+-+-                                                 -+-+-+-+
	// |                                                               |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Network key                         |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 25                                |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Unsigned 8 bit integer              |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 1                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   u8_t value  |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Variable data                       |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 8                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Value = Network key                        |
	// +-+-+-+-                                                 -+-+-+-+
	// |                                                               |
	// +#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+ <= end of Array of Network key
	// |                    Type = Variable data                       |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 6                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Value = MAC address                        |
	// +-+-+-+-                        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                               |
	// +#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+                                 <= end of Array of Protected setup credential


	eap_status_e status(eap_status_ok);

	{
		// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_new_protected_setup_credentials);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(credential_array);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

eap_am_message_if_c * eap_am_message_if_c::new_eap_am_server_message_if_c(
	abs_eap_am_tools_c * const tools,
	const bool is_client_when_true,
	const u32_t MTU)
{
	EAP_TRACE_DEBUG(
		tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_server_message_if_c::new_eap_am_server_message_if_c()\n")));

	EAP_TRACE_RETURN_STRING_FLAGS(tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::new_eap_am_server_message_if_c()");

	eap_am_message_if_c * server = new eap_core_server_message_if_c(
		tools,
		is_client_when_true,
		MTU);

	eap_automatic_variable_c<eap_am_message_if_c> automatic_server(
		tools,
		server);

	if (server == 0
		|| server->get_is_valid() == false)
	{
		// ERROR.
		if (server != 0)
		{
			EAP_TRACE_DEBUG(
				tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: calls: eap_am_message_if_c::new_eap_am_server_message_if_c(): server->shutdown(): %s.\n"),
				(is_client_when_true == true) ? "client": "server"));

			server->shutdown();
		}

		return 0;
	}

	automatic_server.do_not_free_variable();

	return server;
}

//--------------------------------------------------
// End.
