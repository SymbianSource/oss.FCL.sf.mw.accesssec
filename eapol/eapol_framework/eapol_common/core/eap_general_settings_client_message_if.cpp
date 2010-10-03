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
* Description:  Class creates and reads the messages used in EAP-general settings interface on the client side.
*
*/

/*
* %version: 14 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 767 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include "eap_am_tools.h"
#include "eap_tools.h"
#include "eap_am_export.h"
#include "eap_am_assert.h"
#include "eap_general_settings_client_message_if.h"
#include "abs_eap_plugin_message.h"
#include "abs_eap_am_message_if.h"
#include "eap_am_message_if.h"
#include "eap_automatic_variable.h"
#include "eap_process_tlv_message_data.h"
#include "eap_method_settings.h"
#include "eap_am_network_id.h"
#include "abs_eap_general_settings_message.h"

//--------------------------------------------------

EAP_FUNC_EXPORT eap_general_settings_client_message_if_c::~eap_general_settings_client_message_if_c()
{
	delete m_client_if;
	m_client_if = 0;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_general_settings_client_message_if_c::eap_general_settings_client_message_if_c(
	abs_eap_am_tools_c * const tools,
	eap_am_message_if_c * const client_if,
	abs_eap_general_settings_message_c * const partner)
: m_am_tools(tools)
, m_client_if(client_if)
, m_partner(partner)
, m_is_valid(false)
, m_error_code(eap_status_ok)
, m_error_function(eap_tlv_message_type_function_none)
{
	if (m_am_tools == 0
		|| m_am_tools->get_is_valid() == false
		|| m_client_if == 0
		|| m_client_if->get_is_valid() == false
		|| m_partner == 0)
	{
		return;
	}

	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_general_settings_client_message_if_c::reset()
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

// This is documented in abs_eap_stack_interface_c::configure().
EAP_FUNC_EXPORT eap_status_e eap_general_settings_client_message_if_c::configure()
{
	eap_status_e status(eap_status_process_general_error);

	if (m_client_if != 0)
	{
		status = m_client_if->configure(0);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// This is documented in abs_eap_stack_interface_c::shutdown().
EAP_FUNC_EXPORT eap_status_e eap_general_settings_client_message_if_c::shutdown()
{
	eap_status_e status(eap_status_process_general_error);

	if (m_client_if != 0)
	{
		status = m_client_if->shutdown();
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// This is documented in abs_eap_stack_interface_c::get_is_valid().
EAP_FUNC_EXPORT bool eap_general_settings_client_message_if_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_general_settings_client_message_if_c::process_message(eap_process_tlv_message_data_c * const message)
{
	// Process message data composed of Attribute-Value Pairs.
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_general_settings_client_message_if_c::process_message(): this = 0x%08x, m_client_if=0x%08x.\n"),
		this,
		m_client_if));


	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_general_settings_client_message_if_c::send_message()");

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_general_settings_client_message_if_c::process_message()"),
		message->get_message_data(),
		message->get_message_data_length()));

	eap_status_e send_status = m_client_if->process_data(
		message->get_message_data(),
		message->get_message_data_length());

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, send_status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_general_settings_client_message_if_c::set_eap_methods(const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_general_settings_client_message_if_c::set_eap_methods(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_general_settings_client_message_if_c::set_eap_methods()");

	{
		// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_general_settings_set_eap_methods);
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

		status = process_message(&message);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_general_settings_client_message_if_c::get_eap_methods(const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_general_settings_client_message_if_c::get_eap_methods(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_general_settings_client_message_if_c::get_eap_methods()");

	{
		// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_general_settings_get_eap_methods);
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

		status = process_message(&message);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_general_settings_client_message_if_c::get_certificate_lists(const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_general_settings_client_message_if_c::get_certificate_lists(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_general_settings_client_message_if_c::get_certificate_lists()");

	{
		// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_general_settings_get_certificate_lists);
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

		status = process_message(&message);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_general_settings_client_message_if_c::delete_all_eap_settings(const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_general_settings_client_message_if_c::delete_all_eap_settings(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_general_settings_client_message_if_c::delete_all_eap_settings()");

	{
		// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_general_settings_delete_all_eap_settings);
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

		status = process_message(&message);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_general_settings_client_message_if_c::copy_all_eap_settings(const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_general_settings_client_message_if_c::copy_all_eap_settings(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_general_settings_client_message_if_c::copy_all_eap_settings()");

	{
		// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_general_settings_copy_all_eap_settings);
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

		status = process_message(&message);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_general_settings_client_message_if_c::complete_set_eap_methods(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_general_settings_client_message_if_c::complete_set_eap_methods(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_general_settings_client_message_if_c::complete_set_eap_methods()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_method_settings_c * const internal_settings = new eap_method_settings_c(m_am_tools);

	eap_automatic_variable_c<eap_method_settings_c> automatic_internal_settings(m_am_tools, internal_settings);

	if (internal_settings == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = message_data.read_parameter_data(parameters, parameter_index, internal_settings);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_partner->complete_set_eap_methods(
		internal_settings->m_completion_status);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_general_settings_client_message_if_c::complete_get_eap_methods(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_general_settings_client_message_if_c::complete_get_eap_methods(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_general_settings_client_message_if_c::complete_get_eap_methods()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_method_settings_c * const internal_settings = new eap_method_settings_c(m_am_tools);

	eap_automatic_variable_c<eap_method_settings_c> automatic_internal_settings(m_am_tools, internal_settings);

	if (internal_settings == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = message_data.read_parameter_data(parameters, parameter_index, internal_settings);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_partner->complete_get_eap_methods(
		internal_settings);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_general_settings_client_message_if_c::complete_get_certificate_lists(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_general_settings_client_message_if_c::complete_get_certificate_lists(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_general_settings_client_message_if_c::complete_get_certificate_lists()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_method_settings_c * const internal_settings = new eap_method_settings_c(m_am_tools);

	eap_automatic_variable_c<eap_method_settings_c> automatic_internal_settings(m_am_tools, internal_settings);

	if (internal_settings == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = message_data.read_parameter_data(parameters, parameter_index, internal_settings);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_partner->complete_get_certificate_lists(
		internal_settings);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_general_settings_client_message_if_c::complete_delete_all_eap_settings(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_general_settings_client_message_if_c::complete_delete_all_eap_settings(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_general_settings_client_message_if_c::complete_delete_all_eap_settings()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_method_settings_c * const internal_settings = new eap_method_settings_c(m_am_tools);

	eap_automatic_variable_c<eap_method_settings_c> automatic_internal_settings(m_am_tools, internal_settings);

	if (internal_settings == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = message_data.read_parameter_data(parameters, parameter_index, internal_settings);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_partner->complete_delete_all_eap_settings(
		internal_settings->m_completion_status);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_general_settings_client_message_if_c::complete_copy_all_eap_settings(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_general_settings_client_message_if_c::complete_copy_all_eap_settings(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_general_settings_client_message_if_c::complete_copy_all_eap_settings()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_method_settings_c * const internal_settings = new eap_method_settings_c(m_am_tools);

	eap_automatic_variable_c<eap_method_settings_c> automatic_internal_settings(m_am_tools, internal_settings);

	if (internal_settings == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = message_data.read_parameter_data(parameters, parameter_index, internal_settings);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_partner->complete_copy_all_eap_settings(
		internal_settings->m_completion_status);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_general_settings_client_message_if_c::process_message_type_error(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_general_settings_client_message_if_c::process_message_type_error(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_general_settings_client_message_if_c::process_message_type_error()");

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

EAP_FUNC_EXPORT eap_status_e eap_general_settings_client_message_if_c::send_data(const void * const data, const u32_t length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_general_settings_client_message_if_c::send_data(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_general_settings_client_message_if_c::send_data()");

	eap_status_e status(eap_status_process_general_error);

	// Parses message data composed of Attribute-Value Pairs.
	eap_process_tlv_message_data_c message(m_am_tools);

	if (message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = message.set_message_data(length, data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_general_settings_client_message_if_c::send_data()"),
		message.get_message_data(),
		message.get_message_data_length()));

	eap_array_c<eap_tlv_header_c> parameters(m_am_tools);

	status = message.parse_message_data(&parameters);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (parameters.get_object_count() == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const function_header = parameters.get_object(eap_message_payload_index_function);
	if (function_header == 0
		|| (function_header->get_type() != eap_tlv_message_type_error
			&& function_header->get_type() != eap_tlv_message_type_function))
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (function_header->get_type() == eap_tlv_message_type_error)
	{
		status = process_message_type_error(&parameters);
	}
	else
	{
		eap_tlv_message_type_function_e function(eap_tlv_message_type_function_none);

		status = message.get_parameter_data(function_header, &function);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_general_settings_client_message_if_c::send_data(): this = 0x%08x, message=%d=%s\n"),
			this,
			function,
			eap_process_tlv_message_data_c::get_function_string(function)));

		switch(function)
		{
		case eap_tlv_message_type_function_general_settings_complete_set_eap_methods:
			status = complete_set_eap_methods(&parameters);
			break;
		case eap_tlv_message_type_function_general_settings_complete_get_eap_methods:
			status = complete_get_eap_methods(&parameters);
			break;
		case eap_tlv_message_type_function_general_settings_complete_get_certificate_lists:
			status = complete_get_certificate_lists(&parameters);
			break;
		case eap_tlv_message_type_function_general_settings_complete_delete_all_eap_settings:
			status = complete_delete_all_eap_settings(&parameters);
			break;
		case eap_tlv_message_type_function_general_settings_complete_copy_all_eap_settings:
			status = complete_copy_all_eap_settings(&parameters);
			break;
		default:
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: send_data(): unknown function %d.\n"),
				 function));

			EAP_ASSERT_ANYWAY_TOOLS(m_am_tools);

			status = eap_status_illegal_parameter;
		};
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------
// End.
