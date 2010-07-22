/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  Class creates and reads the messages used in EAP-general settings interface on the server side.
*
*/

/*
* %version: 13 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 744 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_general_settings_server_message_if.h"
#include "eap_crypto_api.h"
#include "eap_state_notification.h"
#include "eap_automatic_variable.h"
#include "eap_network_id_selector.h"
#include "eap_config.h"
#include "eap_am_general_settings.h"

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_general_settings_server_message_if_c::~eap_general_settings_server_message_if_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("eap_general_settings_server_message_if_c::~eap_general_settings_server_message_if_c(): this = 0x%08x\n"),
		this));

	EAP_ASSERT(m_shutdown_was_called == true);

	delete m_am_settings;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4355 ) // 'this' : used in base member initializer list
#endif

// 
EAP_FUNC_EXPORT eap_general_settings_server_message_if_c::eap_general_settings_server_message_if_c(
	abs_eap_am_tools_c * const tools)
	: m_partner(0)
	, m_am_settings(new_eap_am_general_settings_c(tools, this))
	, m_am_tools(tools)
	, m_error_code(eap_status_ok)
	, m_error_function(eap_tlv_message_type_function_none)
	, m_is_valid(false)
	, m_shutdown_was_called(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("eap_general_settings_server_message_if_c::eap_general_settings_server_message_if_c(): %s, this = 0x%08x => 0x%08x, compiled %s %s.\n"),
		(m_is_client == true) ? "client": "server",
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this),
		__DATE__,
		__TIME__));

	if (m_am_settings != 0
		&& m_am_settings->get_is_valid() == true)
	{
		set_is_valid();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_general_settings_server_message_if_c::configure(
	const eap_variable_data_c * const /* client_configuration */)
{
	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("%s: eap_general_settings_server_message_if_c::configure()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_general_settings_server_message_if_c::configure()");

	eap_status_e status(eap_status_process_general_error);

	if (m_am_settings != 0)
	{
		status = m_am_settings->configure();
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
EAP_FUNC_EXPORT eap_status_e eap_general_settings_server_message_if_c::shutdown()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("%s: eap_general_settings_server_message_if_c::shutdown(), m_shutdown_was_called=%d\n"),
		(m_is_client == true) ? "client": "server",
		m_shutdown_was_called));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_general_settings_server_message_if_c::shutdown()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	if (m_shutdown_was_called == true)
	{
		// Shutdown function was called already.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_shutdown_was_called = true;

	if (m_am_settings != 0)
	{
		(void) m_am_settings->shutdown();
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_general_settings_server_message_if_c::set_partner(abs_eap_am_message_if_c * const partner)
{
	m_partner = partner;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_general_settings_server_message_if_c::send_error_message(
	const eap_status_e error_code,
	const eap_tlv_message_type_function_e function)
{
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
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_general_settings_server_message_if_c::send_message(eap_process_tlv_message_data_c * const message)
{
	// Sends message data composed of Attribute-Value Pairs.

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_core_client_message_if_c::send_message()"),
		message->get_message_data(),
		message->get_message_data_length()));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_core_client_message_if_c::send_message()");


	eap_status_e send_status = m_partner->send_data(
		message->get_message_data(),
		message->get_message_data_length());

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, send_status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_general_settings_server_message_if_c::process_message_type_error(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
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

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_general_settings_server_message_if_c::process_message(eap_process_tlv_message_data_c * const message)
{
	// Parses message data composed of Attribute-Value Pairs.

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_general_settings_server_message_if_c::process_message()"),
		message->get_message_data(),
		message->get_message_data_length()));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_general_settings_server_message_if_c::process_message()");

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

		switch(function)
		{
		case eap_tlv_message_type_function_general_settings_set_eap_methods:
			status = set_eap_methods(&parameters);
			break;
		case eap_tlv_message_type_function_general_settings_get_eap_methods:
			status = get_eap_methods(&parameters);
			break;
		case eap_tlv_message_type_function_general_settings_get_certificate_lists:
			status = get_certificate_lists(&parameters);
			break;
		case eap_tlv_message_type_function_general_settings_delete_all_eap_settings:
			status = delete_all_eap_settings(&parameters);
			break;
		case eap_tlv_message_type_function_general_settings_copy_all_eap_settings:
			status = copy_all_eap_settings(&parameters);
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
EAP_FUNC_EXPORT eap_status_e eap_general_settings_server_message_if_c::process_data(const void * const data, const u32_t length)
{
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
EAP_FUNC_EXPORT void eap_general_settings_server_message_if_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eap_general_settings_server_message_if_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_general_settings_server_message_if_c::timer_expired(
	const u32_t id, void *data)
{
	EAP_UNREFERENCED_PARAMETER(id);
	EAP_UNREFERENCED_PARAMETER(data);
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("TIMER: %s: [0x%08x]->eap_general_settings_server_message_if_c::timer_expired(id 0x%02x, data 0x%08x).\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 id,
		 data));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_general_settings_server_message_if_c::timer_expired()");


	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_general_settings_server_message_if_c::timer_delete_data(
	const u32_t id, void *data)
{
	EAP_UNREFERENCED_PARAMETER(id);
	EAP_UNREFERENCED_PARAMETER(data);
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("TIMER: %s: [0x%08x]->eap_general_settings_server_message_if_c::timer_delete_data(id 0x%02x, data 0x%08x).\n"),
		(m_is_client == true) ? "client": "server",
		this, id, data));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_general_settings_server_message_if_c::timer_delete_data()");

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

eap_status_e eap_general_settings_server_message_if_c::set_eap_methods(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("%s: eap_general_settings_server_message_if_c::set_eap_methods()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_general_settings_server_message_if_c::set_eap_methods()");

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

	eap_method_settings_c internal_settings(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &internal_settings);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_am_settings->set_eap_methods(
		&internal_settings
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_general_settings_server_message_if_c::get_eap_methods(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("%s: eap_general_settings_server_message_if_c::get_eap_methods()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_general_settings_server_message_if_c::get_eap_methods()");

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

	eap_method_settings_c internal_settings(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &internal_settings);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_am_settings->get_eap_methods(
		&internal_settings
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_general_settings_server_message_if_c::get_certificate_lists(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("%s: eap_general_settings_server_message_if_c::get_certificate_lists()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_general_settings_server_message_if_c::get_certificate_lists()");

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

	eap_method_settings_c internal_settings(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &internal_settings);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_am_settings->get_certificate_lists(
		&internal_settings
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_general_settings_server_message_if_c::delete_all_eap_settings(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("%s: eap_general_settings_server_message_if_c::get_certificate_lists()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_general_settings_server_message_if_c::delete_all_eap_settings()");

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

	eap_method_settings_c internal_settings(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &internal_settings);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_am_settings->delete_all_eap_settings(
		&internal_settings
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_general_settings_server_message_if_c::copy_all_eap_settings(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("%s: eap_general_settings_server_message_if_c::get_certificate_lists()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_general_settings_server_message_if_c::copy_all_eap_settings()");

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

	eap_method_settings_c internal_settings(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &internal_settings);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_am_settings->copy_all_eap_settings(
		&internal_settings
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_general_settings_server_message_if_c::complete_set_eap_methods(const eap_method_settings_c * const internal_settings)
{
	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("%s: eap_core_server_message_if_c::complete_set_eap_methods()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_core_server_message_if_c::complete_set_eap_methods()");

	{
		// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_general_settings_complete_set_eap_methods);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(internal_settings);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_general_settings_server_message_if_c::complete_get_eap_methods(const eap_method_settings_c * const internal_settings)
{
	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("%s: eap_core_server_message_if_c::complete_get_eap_methods()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_core_server_message_if_c::complete_get_eap_methods()");

	{
		// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_general_settings_complete_get_eap_methods);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(internal_settings);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_general_settings_server_message_if_c::complete_get_certificate_lists(const eap_method_settings_c * const internal_settings)
{
	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("%s: eap_core_server_message_if_c::complete_get_certificate_lists()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_core_server_message_if_c::complete_get_certificate_lists()");

	{
		// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_general_settings_complete_get_certificate_lists);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(internal_settings);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_general_settings_server_message_if_c::complete_delete_all_eap_settings(const eap_method_settings_c * const internal_settings)
{
	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("%s: eap_core_server_message_if_c::complete_delete_all_eap_settings()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_core_server_message_if_c::complete_delete_all_eap_settings()");

	{
		// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_general_settings_complete_delete_all_eap_settings);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(internal_settings);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_general_settings_server_message_if_c::complete_copy_all_eap_settings(const eap_method_settings_c * const internal_settings)
{
	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("%s: eap_core_server_message_if_c::complete_copy_all_eap_settings()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_core_server_message_if_c::complete_copy_all_eap_settings()");

	{
		// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_general_settings_complete_copy_all_eap_settings);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(internal_settings);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------
// End.
