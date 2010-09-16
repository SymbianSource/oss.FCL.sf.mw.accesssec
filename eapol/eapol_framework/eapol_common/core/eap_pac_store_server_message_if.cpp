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
* %version: 16 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 745 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_pac_store_server_message_if.h"
#include "eap_crypto_api.h"
#include "eap_state_notification.h"
#include "eap_automatic_variable.h"
#include "eap_network_id_selector.h"
#include "eap_config.h"
#include "eap_am_pac_store.h"
#include "eap_am_pac_store_symbian.h"

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_pac_store_server_message_if_c::~eap_pac_store_server_message_if_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_server_message_if_c::~eap_pac_store_server_message_if_c(): this = 0x%08x\n"),
		this));

	EAP_ASSERT(m_shutdown_was_called == true);

	if (m_am_client != 0)
		{
		m_am_client->shutdown();
		delete m_am_client;
		}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4355 ) // 'this' : used in base member initializer list
#endif

// 
EAP_FUNC_EXPORT eap_pac_store_server_message_if_c::eap_pac_store_server_message_if_c(
	abs_eap_am_tools_c * const tools)
	: m_partner(0)
	, m_am_client(eap_am_pac_store_symbian_c::new_eap_am_pac_store_symbian_c(tools, this))
	, m_am_tools(tools)
	, m_error_code(eap_status_ok)
	, m_error_function(eap_tlv_message_type_function_none)
	, m_is_valid(false)
	, m_shutdown_was_called(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_server_message_if_c::eap_pac_store_server_message_if_c(): %s, this = 0x%08x => 0x%08x, compiled %s %s.\n"),
		(m_is_client == true) ? "client": "server",
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this),
		__DATE__,
		__TIME__));

	if (m_am_client != 0
		&& m_am_client->get_is_valid() == true)
	{
		set_is_valid();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_pac_store_server_message_if_c::configure(
	const eap_variable_data_c * const /* client_configuration */)
{
	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eap_pac_store_server_message_if_c::configure()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_server_message_if_c::configure()");

	eap_status_e status(eap_status_process_general_error);

	if (m_am_client != 0)
	{
		status = m_am_client->configure();
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
EAP_FUNC_EXPORT eap_status_e eap_pac_store_server_message_if_c::shutdown()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eap_pac_store_server_message_if_c::shutdown(), m_shutdown_was_called=%d\n"),
		(m_is_client == true) ? "client": "server",
		m_shutdown_was_called));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_server_message_if_c::shutdown()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	if (m_shutdown_was_called == true)
	{
		// Shutdown function was called already.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_shutdown_was_called = true;

	if (m_am_client != 0)
	{
		(void) m_am_client->shutdown();
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_pac_store_server_message_if_c::set_partner(abs_eap_am_message_if_c * const partner)
{
	m_partner = partner;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_pac_store_server_message_if_c::send_error_message(
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

EAP_FUNC_EXPORT eap_status_e eap_pac_store_server_message_if_c::send_message(eap_process_tlv_message_data_c * const message)
{
	// Sends message data composed of Attribute-Value Pairs.

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
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

EAP_FUNC_EXPORT eap_status_e eap_pac_store_server_message_if_c::process_message_type_error(
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
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_pac_store_server_message_if_c::process_message(eap_process_tlv_message_data_c * const message)
{
	// Parses message data composed of Attribute-Value Pairs.

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_pac_store_server_message_if_c::process_message()"),
		message->get_message_data(),
		message->get_message_data_length()));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_server_message_if_c::process_message()");

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
			(EAPL("eap_pac_store_server_message_if_c::process_message(): this = 0x%08x, message=%d=%s\n"),
			this,
			function,
			eap_process_tlv_message_data_c::get_function_string(function)));

		switch(function)
		{
		case eap_tlv_message_type_function_pac_store_is_master_key_present:
			status = is_master_key_present(&parameters);
			break;
		case eap_tlv_message_type_function_pac_store_is_master_key_and_password_matching:
			status = is_master_key_and_password_matching(&parameters);
			break;
		case eap_tlv_message_type_function_pac_store_create_and_save_master_key:
			status = create_and_save_master_key(&parameters);
			break;
		case eap_tlv_message_type_function_pac_store_compare_pac_store_password:
			status = compare_pac_store_password(&parameters);
			break;
		case eap_tlv_message_type_function_pac_store_is_pacstore_password_present:
			status = is_pacstore_password_present(&parameters);
			break;
		case eap_tlv_message_type_function_pac_store_set_pac_store_password:
			status = set_pac_store_password(&parameters);
			break;
		case eap_tlv_message_type_function_pac_store_destroy_pac_store:
			status = destroy_pac_store(&parameters);
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
EAP_FUNC_EXPORT eap_status_e eap_pac_store_server_message_if_c::process_data(const void * const data, const u32_t length)
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
EAP_FUNC_EXPORT void eap_pac_store_server_message_if_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eap_pac_store_server_message_if_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_pac_store_server_message_if_c::timer_expired(
	const u32_t id, void *data)
{
	EAP_UNREFERENCED_PARAMETER(id);
	EAP_UNREFERENCED_PARAMETER(data);
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: %s: [0x%08x]->eap_pac_store_server_message_if_c::timer_expired(id 0x%02x, data 0x%08x).\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 id,
		 data));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_server_message_if_c::timer_expired()");


	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_pac_store_server_message_if_c::timer_delete_data(
	const u32_t id, void *data)
{
	EAP_UNREFERENCED_PARAMETER(id);
	EAP_UNREFERENCED_PARAMETER(data);
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: %s: [0x%08x]->eap_pac_store_server_message_if_c::timer_delete_data(id 0x%02x, data 0x%08x).\n"),
		(m_is_client == true) ? "client": "server",
		this, id, data));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_server_message_if_c::timer_delete_data()");

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

eap_status_e eap_pac_store_server_message_if_c::is_master_key_present(EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const /* parameters */)
    {
    EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

    eap_status_e status(eap_status_ok);

    EAP_TRACE_DEBUG(
        m_am_tools, 
        TRACE_FLAGS_DEFAULT, 
        (EAPL("eap_pac_store_server_message_if_c::is_master_key_present(): this = 0x%08x.\n"),
        this));

    EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_server_message_if_c::is_master_key_present()");
 
    status = m_am_client->is_master_key_present();

    return status;
    
    }

//--------------------------------------------------

eap_status_e eap_pac_store_server_message_if_c::is_master_key_and_password_matching(EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
    {
    EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

    eap_status_e status(eap_status_ok);

    EAP_TRACE_DEBUG(
        m_am_tools, 
        TRACE_FLAGS_DEFAULT, 
        (EAPL("eap_pac_store_server_message_if_c::is_master_key_and_password_matching(): this = 0x%08x.\n"),
        this));

    EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_server_message_if_c::is_master_key_and_password_matching()");
 
    u32_t parameter_index(eap_message_payload_index_first_parameter);

    eap_process_tlv_message_data_c message_data(m_am_tools);

    if (message_data.get_is_valid() == false)
    {
        EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
        return EAP_STATUS_RETURN(m_am_tools, status);
    }

    eap_variable_data_c * const password = new eap_variable_data_c(m_am_tools);
    // eap_automatic_variable_c can be used in this block because no functions are leaving here.
    eap_automatic_variable_c<eap_variable_data_c> automatic_password_data(m_am_tools, password);

    if (password == 0)
    {
    EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
    return EAP_STATUS_RETURN(m_am_tools, status);
    }

    status = message_data.read_parameter_data(parameters, parameter_index, password);
    if (status != eap_status_ok)
    {
    EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
    return EAP_STATUS_RETURN(m_am_tools, status);
    }
    status = m_am_client->is_master_key_and_password_matching(password);

    return status;
   
    }

//--------------------------------------------------

eap_status_e eap_pac_store_server_message_if_c::create_and_save_master_key(EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
    {
    EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

    eap_status_e status(eap_status_ok);

    EAP_TRACE_DEBUG(
        m_am_tools, 
        TRACE_FLAGS_DEFAULT, 
        (EAPL("eap_pac_store_server_message_if_c::create_and_save_master_key(): this = 0x%08x.\n"),
        this));

    EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_server_message_if_c::create_and_save_master_key()");

    u32_t parameter_index(eap_message_payload_index_first_parameter);

    eap_process_tlv_message_data_c message_data(m_am_tools);

    if (message_data.get_is_valid() == false)
        {
        EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
        return EAP_STATUS_RETURN(m_am_tools, status);
        }

    eap_variable_data_c * const password = new eap_variable_data_c(m_am_tools);
    // eap_automatic_variable_c can be used in this block because no functions are leaving here.
    eap_automatic_variable_c<eap_variable_data_c> automatic_password_data(m_am_tools, password);

    if (password == 0)
    {
    EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
    return EAP_STATUS_RETURN(m_am_tools, status);
    }

    status = message_data.read_parameter_data(parameters, parameter_index, password);
    if (status != eap_status_ok)
    {
    EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
    return EAP_STATUS_RETURN(m_am_tools, status);
    }
    status = m_am_client->create_and_save_master_key(password);

    return status;
    
    }

//--------------------------------------------------

eap_status_e eap_pac_store_server_message_if_c::is_pacstore_password_present(EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const /* parameters */)
    {
    EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

    eap_status_e status(eap_status_ok);

    EAP_TRACE_DEBUG(
        m_am_tools, 
        TRACE_FLAGS_DEFAULT, 
        (EAPL("eap_pac_store_server_message_if_c::is_pacstore_password_present(): this = 0x%08x.\n"),
        this));

    EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_server_message_if_c::is_pacstore_password_present()");

    eap_process_tlv_message_data_c message_data(m_am_tools);

    if (message_data.get_is_valid() == false)
        {
        EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
        return EAP_STATUS_RETURN(m_am_tools, status);
        }

    status = m_am_client->is_pacstore_password_present();

    return status;
    
    }

//--------------------------------------------------

eap_status_e eap_pac_store_server_message_if_c::compare_pac_store_password(EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
    {
    EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

    eap_status_e status(eap_status_ok);

    EAP_TRACE_DEBUG(
        m_am_tools, 
        TRACE_FLAGS_DEFAULT, 
        (EAPL("eap_pac_store_server_message_if_c::compare_pac_store_password(): this = 0x%08x.\n"),
        this));

    EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_server_message_if_c::compare_pac_store_password()");

    u32_t parameter_index(eap_message_payload_index_first_parameter);

    eap_process_tlv_message_data_c message_data(m_am_tools);

    if (message_data.get_is_valid() == false)
        {
        EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
        return EAP_STATUS_RETURN(m_am_tools, status);
        }

    eap_variable_data_c * const password = new eap_variable_data_c(m_am_tools);
    // eap_automatic_variable_c can be used in this block because no functions are leaving here.
    eap_automatic_variable_c<eap_variable_data_c> automatic_password_data(m_am_tools, password);

    if (password == 0)
    {
    EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
    return EAP_STATUS_RETURN(m_am_tools, status);
    }

    status = message_data.read_parameter_data(parameters, parameter_index, password);
    if (status != eap_status_ok)
    {
    EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
    return EAP_STATUS_RETURN(m_am_tools, status);
    }

    status = m_am_client->compare_pac_store_password(password);

    return status;
    
    }

//--------------------------------------------------

eap_status_e eap_pac_store_server_message_if_c::set_pac_store_password(EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
    {
    EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

    eap_status_e status(eap_status_ok);

    EAP_TRACE_DEBUG(
        m_am_tools, 
        TRACE_FLAGS_DEFAULT, 
        (EAPL("eap_pac_store_server_message_if_c::set_pac_store_password(): this = 0x%08x.\n"),
        this));

    EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_server_message_if_c::set_pac_store_password()");

    u32_t parameter_index(eap_message_payload_index_first_parameter);

    eap_process_tlv_message_data_c message_data(m_am_tools);

    if (message_data.get_is_valid() == false)
        {
        EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
        return EAP_STATUS_RETURN(m_am_tools, status);
        }

    eap_variable_data_c * const password = new eap_variable_data_c(m_am_tools);
    // eap_automatic_variable_c can be used in this block because no functions are leaving here.
    eap_automatic_variable_c<eap_variable_data_c> automatic_password_data(m_am_tools, password);

    if (password == 0)
    {
    EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
    return EAP_STATUS_RETURN(m_am_tools, status);
    }

    status = message_data.read_parameter_data(parameters, parameter_index, password);
    if (status != eap_status_ok)
    {
    EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
    return EAP_STATUS_RETURN(m_am_tools, status);
    }
    status = m_am_client->set_pac_store_password(password);

    return status;
    
    }

//--------------------------------------------------

eap_status_e eap_pac_store_server_message_if_c::destroy_pac_store(EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const /* parameters */)
    {
    EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

    eap_status_e status(eap_status_ok);

    EAP_TRACE_DEBUG(
        m_am_tools, 
        TRACE_FLAGS_DEFAULT, 
        (EAPL("eap_pac_store_server_message_if_c::destroy_pac_store(): this = 0x%08x.\n"),
        this));

    EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_server_message_if_c::destroy_pac_store()");
 
    status = m_am_client->destroy_pac_store();

    return status;
   
    }

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_pac_store_server_message_if_c::complete_is_master_key_present(
        const bool is_present)
    {
    eap_status_e status(eap_status_process_general_error);

    EAP_TRACE_DEBUG(
        m_am_tools, 
        TRACE_FLAGS_DEFAULT, 
        (EAPL("%s: eap_core_server_message_if_c::complete_is_master_key_present()\n"),
         (m_is_client == true) ? "client": "server"));

    EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::complete_is_master_key_present()");

    {
        // Creates message data composed of Attribute-Value Pairs.
        eap_process_tlv_message_data_c message(m_am_tools);

        if (message.get_is_valid() == false)
        {
            EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
            return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
        }

        status = message.add_parameter_data(eap_tlv_message_type_function_pac_store_complete_is_master_key_present);
        if (status != eap_status_ok)
        {
            EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
            return EAP_STATUS_RETURN(m_am_tools, status);
        }

        status = message.add_parameter_data(is_present);
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

EAP_FUNC_EXPORT eap_status_e eap_pac_store_server_message_if_c::complete_is_master_key_and_password_matching(
        const bool is_matching)
    {
    eap_status_e status(eap_status_process_general_error);

    EAP_TRACE_DEBUG(
        m_am_tools, 
        TRACE_FLAGS_DEFAULT, 
        (EAPL("%s: eap_core_server_message_if_c::complete_is_master_key_and_password_matching()\n"),
         (m_is_client == true) ? "client": "server"));

    EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::complete_is_master_key_and_password_matching()");

    {
        // Creates message data composed of Attribute-Value Pairs.
        eap_process_tlv_message_data_c message(m_am_tools);

        if (message.get_is_valid() == false)
        {
            EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
            return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
        }

        status = message.add_parameter_data(eap_tlv_message_type_function_pac_store_complete_is_master_key_and_password_matching);
        if (status != eap_status_ok)
        {
            EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
            return EAP_STATUS_RETURN(m_am_tools, status);
        }

        status = message.add_parameter_data(is_matching);
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

EAP_FUNC_EXPORT eap_status_e eap_pac_store_server_message_if_c::complete_create_and_save_master_key(
        const eap_status_e completion_status)
    {
    eap_status_e status(eap_status_process_general_error);

    EAP_TRACE_DEBUG(
        m_am_tools, 
        TRACE_FLAGS_DEFAULT, 
        (EAPL("%s: eap_core_server_message_if_c::complete_create_and_save_master_key()\n"),
         (m_is_client == true) ? "client": "server"));

    EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::complete_create_and_save_master_key()");

    {
        // Creates message data composed of Attribute-Value Pairs.
        eap_process_tlv_message_data_c message(m_am_tools);

        if (message.get_is_valid() == false)
        {
            EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
            return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
        }

        status = message.add_parameter_data(eap_tlv_message_type_function_pac_store_complete_create_and_save_master_key);
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

EAP_FUNC_EXPORT eap_status_e eap_pac_store_server_message_if_c::complete_is_pacstore_password_present(
        const bool is_present)
    {
    eap_status_e status(eap_status_process_general_error);

    EAP_TRACE_DEBUG(
        m_am_tools, 
        TRACE_FLAGS_DEFAULT, 
        (EAPL("%s: eap_core_server_message_if_c::complete_is_pacstore_password_present()\n"),
         (m_is_client == true) ? "client": "server"));

    EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::complete_is_pacstore_password_present()");

    {
        // Creates message data composed of Attribute-Value Pairs.
        eap_process_tlv_message_data_c message(m_am_tools);

        if (message.get_is_valid() == false)
        {
            EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
            return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
        }

        status = message.add_parameter_data(eap_tlv_message_type_function_pac_store_complete_is_pacstore_password_present);
        if (status != eap_status_ok)
        {
            EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
            return EAP_STATUS_RETURN(m_am_tools, status);
        }

        status = message.add_parameter_data(is_present);
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

EAP_FUNC_EXPORT eap_status_e eap_pac_store_server_message_if_c::complete_compare_pac_store_password(
        const bool is_matching)
    {
    eap_status_e status(eap_status_process_general_error);

    EAP_TRACE_DEBUG(
        m_am_tools, 
        TRACE_FLAGS_DEFAULT, 
        (EAPL("%s: eap_core_server_message_if_c::complete_compare_pac_store_password()\n"),
         (m_is_client == true) ? "client": "server"));

    EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::complete_compare_pac_store_password()");

    {
        // Creates message data composed of Attribute-Value Pairs.
        eap_process_tlv_message_data_c message(m_am_tools);

        if (message.get_is_valid() == false)
        {
            EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
            return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
        }

        status = message.add_parameter_data(eap_tlv_message_type_function_pac_store_complete_compare_pac_store_password);
        if (status != eap_status_ok)
        {
            EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
            return EAP_STATUS_RETURN(m_am_tools, status);
        }

        status = message.add_parameter_data(is_matching);
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

EAP_FUNC_EXPORT eap_status_e eap_pac_store_server_message_if_c::complete_set_pac_store_password(
        const eap_status_e completion_status)
    {
    eap_status_e status(eap_status_process_general_error);

    EAP_TRACE_DEBUG(
        m_am_tools, 
        TRACE_FLAGS_DEFAULT, 
        (EAPL("%s: eap_core_server_message_if_c::complete_set_pac_store_password()\n"),
         (m_is_client == true) ? "client": "server"));

    EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::complete_set_pac_store_password()");

    {
        // Creates message data composed of Attribute-Value Pairs.
        eap_process_tlv_message_data_c message(m_am_tools);

        if (message.get_is_valid() == false)
        {
            EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
            return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
        }

        status = message.add_parameter_data(eap_tlv_message_type_function_pac_store_complete_set_pac_store_password);
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

EAP_FUNC_EXPORT eap_status_e eap_pac_store_server_message_if_c::complete_destroy_pac_store(
    const eap_status_e completion_status)
    {
    eap_status_e status(eap_status_process_general_error);

    EAP_TRACE_DEBUG(
        m_am_tools, 
        TRACE_FLAGS_DEFAULT, 
        (EAPL("%s: eap_core_server_message_if_c::complete_destroy_pac_store()\n"),
         (m_is_client == true) ? "client": "server"));

    EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_core_server_message_if_c::complete_destroy_pac_store()");

    {
        // Creates message data composed of Attribute-Value Pairs.
        eap_process_tlv_message_data_c message(m_am_tools);

        if (message.get_is_valid() == false)
        {
            EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
            return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
        }

        status = message.add_parameter_data(eap_tlv_message_type_function_pac_store_complete_destroy_pac_store);
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

eap_am_pac_store_c* eap_am_pac_store_symbian_c::new_eap_am_pac_store_symbian_c(
        abs_eap_am_tools_c * const tools,
        abs_eap_am_pac_store_c * const partner)
    {
    eap_am_pac_store_c *server =  new eap_am_pac_store_symbian_c(
        tools, partner);

    if (server == 0)
      	{
        EAP_TRACE_DEBUG(
            tools,
            TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
            (EAPL("calls: eap_pac_store_server_message_if_c(): server == 0 !!!:.\n")));
      	}
    else if (server->get_is_valid() == false)
        {
        EAP_TRACE_DEBUG(
            tools,
            TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
            (EAPL("calls: eap_pac_store_server_message_if_c(): server->shutdown():.\n")));
            server->shutdown();
            delete server;
            server = 0;
        }
   
    return server;
    
    }


//--------------------------------------------------
// End.
