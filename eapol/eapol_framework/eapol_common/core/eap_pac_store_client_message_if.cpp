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
* %version: 13 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 766 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include "eap_am_tools.h"
#include "eap_tools.h"
#include "eap_am_export.h"
#include "eap_am_assert.h"
#include "eap_pac_store_client_message_if.h"
#include "abs_eap_plugin_message.h"
#include "abs_eap_am_message_if.h"
#include "eap_am_message_if.h"
#include "eap_automatic_variable.h"
#include "eap_process_tlv_message_data.h"
#include "eap_method_settings.h"
#include "eap_am_network_id.h"

//--------------------------------------------------

/**
 * The destructor of the eap_core class does nothing special.
 */
EAP_FUNC_EXPORT eap_pac_store_client_message_if_c::~eap_pac_store_client_message_if_c()
{

}

//--------------------------------------------------

/**
 * The constructor initializes member attributes using parameters passed to it.
 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
 * @param partner is back pointer to object which created this object.
 * @param is_client_when_true indicates whether the network entity should act
 * as a client (true) or server (false), in terms of EAP-protocol
 * whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
 */

EAP_FUNC_EXPORT eap_pac_store_client_message_if_c::eap_pac_store_client_message_if_c(
	abs_eap_am_tools_c * const tools,
	eap_am_message_if_c * const client_if,
	abs_eap_pac_store_message_c * const partner)
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

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_client_message_if_c::eap_pac_store_client_message_if_c(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_client_message_if_c::eap_pac_store_client_message_if_c()");

	m_is_valid = true;
}

//--------------------------------------------------

/**
 * This function must reset the state of object to same as 
 * state was after the configure() function call.
 * If object reset succeeds this function must return eap_status_ok.
 * If object reset fails this function must return corresponding error status.
 * @return This function returns the status of reset operation.
 */
EAP_FUNC_EXPORT eap_status_e eap_pac_store_client_message_if_c::reset()
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

// This is documented in abs_eap_stack_interface_c::configure().
EAP_FUNC_EXPORT eap_status_e eap_pac_store_client_message_if_c::configure()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_client_message_if_c::configure(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_client_message_if_c::configure()");

	eap_status_e status = m_client_if->configure(0);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// This is documented in abs_eap_stack_interface_c::shutdown().
EAP_FUNC_EXPORT eap_status_e eap_pac_store_client_message_if_c::shutdown()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_client_message_if_c::shutdown(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_client_message_if_c::shutdown()");

	eap_status_e status = m_client_if->shutdown();

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// This is documented in abs_eap_stack_interface_c::get_is_valid().
EAP_FUNC_EXPORT bool eap_pac_store_client_message_if_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_pac_store_client_message_if_c::process_message(eap_process_tlv_message_data_c * const message)
{
	// Sends message data composed of Attribute-Value Pairs.

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_client_message_if_c::process_message()");

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_pac_store_client_message_if_c::process_message()"),
		message->get_message_data(),
		message->get_message_data_length()));

	{
		eap_status_e send_status = m_client_if->process_data(
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

EAP_FUNC_EXPORT eap_status_e eap_pac_store_client_message_if_c::destroy_pac_store(
		const eap_status_e /* completion_status */)
		{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_client_message_if_c::destroy_pac_store(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_client_message_if_c::destroy_pac_store()");

// Creates message data composed of Attribute-Value Pairs.

	eap_process_tlv_message_data_c message(m_am_tools);

	if (message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = message.add_parameter_data(eap_tlv_message_type_function_pac_store_destroy_pac_store);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = process_message(&message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);

		}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_pac_store_client_message_if_c::is_master_key_present(
		const eap_status_e /* completion_status */)
		{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_client_message_if_c::is_master_key_present(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_client_message_if_c::is_master_key_present()");
			
	eap_process_tlv_message_data_c message(m_am_tools);

	if (message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = message.add_parameter_data(eap_tlv_message_type_function_pac_store_is_master_key_present);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = process_message(&message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
		}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_pac_store_client_message_if_c::is_master_key_and_password_matching(
		const eap_variable_data_c * const pac_store_password
		,const eap_status_e /* completion_status */)
		{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_client_message_if_c::is_master_key_and_password_matching(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_client_message_if_c::is_master_key_and_password_matching()");
			
// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_pac_store_is_master_key_and_password_matching);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(pac_store_password);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = process_message(&message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);

	}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_pac_store_client_message_if_c::create_and_save_master_key(
		const eap_variable_data_c * const pac_store_password
		,const eap_status_e /* completion_status */)
		{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_client_message_if_c::create_and_save_master_key(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_client_message_if_c::create_and_save_master_key()");
			
// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_pac_store_create_and_save_master_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(pac_store_password);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = process_message(&message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);

		}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_pac_store_client_message_if_c::compare_pac_store_password(
		eap_variable_data_c * pac_store_password)
		{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_client_message_if_c::compare_pac_store_password(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_client_message_if_c::compare_pac_store_password()");

// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_pac_store_compare_pac_store_password);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(pac_store_password);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = process_message(&message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
			
		}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_pac_store_client_message_if_c::is_pacstore_password_present()
		{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_client_message_if_c::is_pacstore_password_present(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_client_message_if_c::is_pacstore_password_present()");
			
	eap_process_tlv_message_data_c message(m_am_tools);

	if (message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = message.add_parameter_data(eap_tlv_message_type_function_pac_store_is_pacstore_password_present);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = process_message(&message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
		}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_pac_store_client_message_if_c::set_pac_store_password(
		const eap_variable_data_c * const pac_store_password
		,const eap_status_e /* completion_status */)
		{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_client_message_if_c::set_pac_store_password(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_client_message_if_c::set_pac_store_password()");

// Creates message data composed of Attribute-Value Pairs.
		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_pac_store_set_pac_store_password);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(pac_store_password);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = process_message(&message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
			
		}

//--------------------------------------------------

eap_status_e eap_pac_store_client_message_if_c::complete_is_master_key_present(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_client_message_if_c::complete_is_master_key_present(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_client_message_if_c::complete_is_master_key_present()");

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
	status = m_partner->complete_is_master_key_present(
		false, eap_status_allocation_error);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

  bool is_present = false;
	status = message_data.read_parameter_data(parameters, parameter_index, &is_present);
	if (status != eap_status_ok)
	{
	status = m_partner->complete_is_master_key_present(
		false, status);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_partner->complete_is_master_key_present(is_present, status);
	return status;

}

//--------------------------------------------------

eap_status_e eap_pac_store_client_message_if_c::complete_is_master_key_and_password_matching(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_client_message_if_c::complete_is_master_key_and_password_matching(): this = 0x%08x.\n"),
		this));

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
	status = m_partner->complete_is_master_key_and_password_matching(
		false, eap_status_allocation_error);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	bool is_matching = false;

	status = message_data.read_parameter_data(parameters, parameter_index, &is_matching);
	if (status != eap_status_ok)
	{
	status = m_partner->complete_is_master_key_and_password_matching(
		false, status);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_partner->complete_is_master_key_and_password_matching(is_matching, status);

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_client_message_if_c::complete_is_master_key_and_password_matching()");
  return status;
}

//--------------------------------------------------

eap_status_e eap_pac_store_client_message_if_c::complete_create_and_save_master_key(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_client_message_if_c::complete_create_and_save_master_key(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_client_message_if_c::complete_create_and_save_master_key()");

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
	status = m_partner->complete_create_and_save_master_key(
		eap_status_allocation_error);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

  eap_status_e return_status;
	status = message_data.read_parameter_data(parameters, parameter_index, eap_tlv_message_type_eap_status, &return_status);
	if (status != eap_status_ok)
	{
	status = m_partner->complete_create_and_save_master_key(
		status);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_partner->complete_create_and_save_master_key(return_status);

	return EAP_STATUS_RETURN(m_am_tools, status);

}
//--------------------------------------------------

eap_status_e eap_pac_store_client_message_if_c::complete_is_pacstore_password_present(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_client_message_if_c::complete_is_pacstore_password_present(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_client_message_if_c::complete_is_pacstore_password_present()");

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
	status = m_partner->complete_is_pacstore_password_present(
		false);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

  bool is_present = false;
	status = message_data.read_parameter_data(parameters, parameter_index, &is_present);
	if (status != eap_status_ok)
	{
	status = m_partner->complete_is_pacstore_password_present(
		false);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_partner->complete_is_pacstore_password_present(is_present);
	return status;

}

//--------------------------------------------------

eap_status_e eap_pac_store_client_message_if_c::complete_compare_pac_store_password(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_client_message_if_c::complete_compare_pac_store_password(): this = 0x%08x.\n"),
		this));

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
	status = m_partner->complete_compare_pac_store_password(
		false);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	bool is_matching = false;

	status = message_data.read_parameter_data(parameters, parameter_index, &is_matching);
	if (status != eap_status_ok)
	{
	status = m_partner->complete_compare_pac_store_password(
		false);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_partner->complete_compare_pac_store_password(is_matching);

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_client_message_if_c::complete_compare_pac_store_password()");
  return status;
}

//--------------------------------------------------

eap_status_e eap_pac_store_client_message_if_c::complete_set_pac_store_password(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_client_message_if_c::complete_set_pac_store_password(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_client_message_if_c::complete_set_pac_store_password()");

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
	status = m_partner->complete_set_pac_store_password(
		eap_status_allocation_error);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

  eap_status_e return_status;
	status = message_data.read_parameter_data(parameters, parameter_index, eap_tlv_message_type_eap_status, &return_status);
	if (status != eap_status_ok)
	{
	status = m_partner->complete_set_pac_store_password(
		status);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_partner->complete_set_pac_store_password(
		return_status);

  return status;
}

//--------------------------------------------------
eap_status_e eap_pac_store_client_message_if_c::complete_destroy_pac_store(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_client_message_if_c::complete_destroy_pac_store(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_client_message_if_c::complete_destroy_pac_store()");

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eap_process_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
	status = m_partner->complete_destroy_pac_store(
		eap_status_allocation_error);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

  eap_status_e return_status;
	status = message_data.read_parameter_data(parameters, parameter_index, eap_tlv_message_type_eap_status, &return_status);
	if (status != eap_status_ok)
	{
	status = m_partner->complete_destroy_pac_store(
		status);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	status = m_partner->complete_destroy_pac_store(
		return_status);
		
	return status;	
	

}

//--------------------------------------------------

eap_status_e eap_pac_store_client_message_if_c::process_message_type_error(
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

EAP_FUNC_EXPORT eap_status_e eap_pac_store_client_message_if_c::send_data(const void * const data, const u32_t length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_pac_store_client_message_if_c::send_data(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_pac_store_client_message_if_c::send_data()");

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
		(EAPL("eap_pac_store_client_message_if_c::send_data()"),
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
	else // function_header->get_type() == eap_tlv_message_type_function
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
			(EAPL("eap_pac_store_client_message_if_c::send_data(): this = 0x%08x, message=%d=%s\n"),
			this,
			function,
			eap_process_tlv_message_data_c::get_function_string(function)));

		switch(function)
		{
		case eap_tlv_message_type_function_pac_store_complete_is_master_key_present:
			status = complete_is_master_key_present(&parameters);
			break;
		case eap_tlv_message_type_function_pac_store_complete_is_master_key_and_password_matching:
			status = complete_is_master_key_and_password_matching(&parameters);
			break;
		case eap_tlv_message_type_function_pac_store_complete_create_and_save_master_key:
			status = complete_create_and_save_master_key(&parameters);
			break;
		case eap_tlv_message_type_function_pac_store_complete_compare_pac_store_password:
			status = complete_compare_pac_store_password(&parameters);
			break;
		case eap_tlv_message_type_function_pac_store_complete_is_pacstore_password_present:
			status = complete_is_pacstore_password_present(&parameters);
			break;
		case eap_tlv_message_type_function_pac_store_complete_set_pac_store_password:
			status = complete_set_pac_store_password(&parameters);
			break;
		case eap_tlv_message_type_function_pac_store_complete_destroy_pac_store:
			status = complete_destroy_pac_store(&parameters);
			break;
		default:
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: send_data(): unknown function %d.\n"),
				 function));

			EAP_ASSERT_ANYWAY_TOOLS(m_am_tools);

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		};

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
// End.
