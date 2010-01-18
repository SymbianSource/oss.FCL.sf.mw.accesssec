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
* %version: 31.1.3 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 40 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_automatic_variable.h"
#include "eapol_handle_tlv_message_data.h"
#include "eap_variable_data.h"
#include "eap_am_network_id.h"
#include "eap_buffer.h"
#include "eapol_session_key.h"
#include "abs_eap_state_notification.h"
#include "eap_state_notification.h"

#if defined(USE_EAP_SIMPLE_CONFIG)
#include "simple_config_types.h"
#include "simple_config_credential.h"
#include "simple_config_payloads.h"
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)


/** @file */


//--------------------------------------------------

EAP_FUNC_EXPORT eapol_handle_tlv_message_data_c::~eapol_handle_tlv_message_data_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eapol_handle_tlv_message_data_c::eapol_handle_tlv_message_data_c(
	abs_eap_am_tools_c * const tools)
	: eap_tlv_message_data_c(tools)
	, m_am_tools(tools)
	, m_is_valid(true)
{
}

//-------------------------------------------------------------------

/**
 * This function should increase reference count.
 */
EAP_FUNC_EXPORT void eapol_handle_tlv_message_data_c::object_increase_reference_count()
{
}

//-------------------------------------------------------------------

/**
 * This function should first decrease reference count
 * and second return the remaining reference count.
 * Reference count must not be decreased when it is zero.
 */
EAP_FUNC_EXPORT u32_t eapol_handle_tlv_message_data_c::object_decrease_reference_count()
{
	return 0;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eapol_handle_tlv_message_data_c::get_is_valid()
{
	return m_is_valid && eap_tlv_message_data_c::get_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eapol_handle_tlv_message_data_c::get_payload_size(
	const eap_am_network_id_c * const network_id) const
{
	return
		(3ul * eap_tlv_header_c::get_header_length() // Each attribute have their own header.
		+ network_id->get_source_id()->get_data_length()
		+ network_id->get_destination_id()->get_data_length()
		+ sizeof(network_id->get_type()));
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eapol_handle_tlv_message_data_c::get_payload_size(
	const abs_eap_state_notification_c * const state) const
{
	return
		(7ul * eap_tlv_header_c::get_header_length()) // Each attribute have their own header.
		+ (get_payload_size(state->get_send_network_id())
		+ sizeof(u32_t) // eap_protocol_layer_e
		+ sizeof(state->get_protocol())
		+ eap_expanded_type_c::get_eap_expanded_type_size()
		+ sizeof(state->get_current_state())
		+ sizeof(u32_t) // bool is_client
		+ sizeof(u32_t) // eap_status_e authentication error
		);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eapol_handle_tlv_message_data_c::get_payload_size(
	const eapol_session_key_c * const session_key) const
{
	return
		((5ul * eap_tlv_header_c::get_header_length()) // Each attribute have their own header.
		+ session_key->get_key()->get_data_length()
		+ session_key->get_sequence_number()->get_data_length()
		+ sizeof(u32_t) // const eapol_key_type_e m_key_type
		+ sizeof(session_key->get_key_index())
		+ sizeof(u32_t) // const bool m_key_tx_bit
		);
}

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT u32_t eapol_handle_tlv_message_data_c::get_payload_size(
	network_key_and_index_c * key) const
{
	u32_t size(0ul);

	if (key != 0)
	{
		size += eap_tlv_header_c::get_header_length()
			+ sizeof(key->get_network_key_index()) // Size of Network Key Index
			+ eap_tlv_header_c::get_header_length()
			+ key->get_network_key()->get_data_length() // Size of Network Key
			;
	}

	return (size);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT u32_t eapol_handle_tlv_message_data_c::get_payload_size(
	EAP_TEMPLATE_CONST eap_array_c<network_key_and_index_c> * network_keys) const
{
	u32_t size(0ul);

	for (u32_t ind_network_key = 0ul; ind_network_key < network_keys->get_object_count(); ind_network_key++)
	{
		network_key_and_index_c * const key = network_keys->get_object(ind_network_key);
		if (key != 0)
		{
			size += eap_tlv_header_c::get_header_length() // Size of structure header
				+ get_payload_size(key); // Size of Network Key
		}
	} // for ()

	return (size);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT u32_t eapol_handle_tlv_message_data_c::get_payload_size(
	simple_config_credential_c * const credential) const
{
	u32_t size(0ul);

	if (credential != 0)
	{
		size += eap_tlv_header_c::get_header_length()
			+ sizeof(credential->get_network_index()) // Size of Network Index
			+ eap_tlv_header_c::get_header_length()
			+ credential->get_SSID()->get_data_length() // Size of SSID
			+ eap_tlv_header_c::get_header_length()
			+ sizeof(u16_t) // Size of Authentiction type
			+ eap_tlv_header_c::get_header_length()
			+ sizeof(u16_t) // Size of Encryption type
			;

		size += eap_tlv_header_c::get_header_length() // Size of header of Array
			+ get_payload_size(credential->get_network_keys());

		size += eap_tlv_header_c::get_header_length()
			+ credential->get_MAC_address()->get_data_length() // Size of MAC Address
			;
	}

	return (size);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT u32_t eapol_handle_tlv_message_data_c::get_payload_size(
	EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array) const
{
	u32_t size(0ul);

	for (u32_t ind_credential = 0ul; ind_credential < credential_array->get_object_count(); ind_credential++)
	{
		simple_config_credential_c * const credential = credential_array->get_object(ind_credential);
		if (credential != 0)
		{
			size += eap_tlv_header_c::get_header_length() // Size of structure header
				+ get_payload_size(credential);
		}
	} // for ()

	return (size);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::add_structured_parameter_header(
	const eapol_tlv_message_type_e type,
	const u32_t length)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::add_structured_parameter_header(): type=%s\n"),
		 get_type_string(type)));

	return add_message_header(
		type,
		length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::add_parameter_data(
	const eapol_tlv_message_type_e type,
	const u32_t integer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::add_parameter_data(): type=%s\n"),
		 get_type_string(type)));

	const u32_t network_order_integer(eap_htonl(integer));

	eap_status_e status = add_message_data(
		type,
		sizeof(network_order_integer),
		&network_order_integer);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::add_parameter_data(
	const u64_t long_integer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::add_parameter_data(): type=%s\n"),
		 get_type_string(eapol_tlv_message_type_u64_t)));

	const u64_t network_order_long_integer(eap_htonll(long_integer));

	eap_status_e status = add_message_data(
		eapol_tlv_message_type_u64_t,
		sizeof(network_order_long_integer),
		&network_order_long_integer);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::add_parameter_data(
	const u32_t integer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::add_parameter_data(): type=%s\n"),
		 get_type_string(eapol_tlv_message_type_u32_t)));

	const u32_t network_order_integer(eap_htonl(integer));

	eap_status_e status = add_message_data(
		eapol_tlv_message_type_u32_t,
		sizeof(network_order_integer),
		&network_order_integer);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::add_parameter_data(
	const u16_t short_integer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::add_parameter_data(): type=%s\n"),
		 get_type_string(eapol_tlv_message_type_u16_t)));

	const u16_t network_order_short_integer(eap_htons(short_integer));

	eap_status_e status = add_message_data(
		eapol_tlv_message_type_u16_t,
		sizeof(network_order_short_integer),
		&network_order_short_integer);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::add_parameter_data(
	const u8_t byte_integer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::add_parameter_data(): type=%s\n"),
		 get_type_string(eapol_tlv_message_type_u8_t)));

	eap_status_e status = add_message_data(
		eapol_tlv_message_type_u8_t,
		sizeof(byte_integer),
		&byte_integer);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::add_parameter_data(
	const bool boolean)
{
	const u32_t value((boolean == false) ? 0u: 1u);

	return add_parameter_data(
		eapol_tlv_message_type_boolean,
		value);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::add_parameter_data(
	const eap_status_e status)
{
	const u32_t value(static_cast<u32_t>(status));

	return add_parameter_data(
		eapol_tlv_message_type_eap_status,
		value);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::add_parameter_data(
	const eapol_tlv_message_type_function_e function)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::add_parameter_data(): type=%s, function=%s\n"),
		 get_type_string(eapol_tlv_message_type_function),
		 get_function_string(function)));

	if (function < eapol_tlv_message_type_function_none
		|| function >= eapol_tlv_message_type_function_illegal_value)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u32_t network_order_function(eap_htonl(function));

	eap_status_e status = add_message_data(
		eapol_tlv_message_type_function,
		sizeof(network_order_function),
		&network_order_function);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::add_parameter_data(
	const eap_variable_data_c * const variable_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::add_parameter_data(): type=%s\n"),
		 get_type_string(eapol_tlv_message_type_variable_data)));

	if (variable_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_process_general_error);

	if (variable_data->get_is_valid_data() == false)
	{
		// Empty variable data. Add just the header.
		status = add_structured_parameter_header(
			eapol_tlv_message_type_variable_data,
			0ul);
	}
	else
	{
		status = add_message_data(
			eapol_tlv_message_type_variable_data,
			variable_data->get_data_length(),
			variable_data->get_data());
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::add_parameter_data(
	const eap_am_network_id_c * const network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::add_parameter_data(): type=%s\n"),
		 get_type_string(eapol_tlv_message_type_network_id)));

	if (network_id == 0
		|| network_id->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u32_t size_of_network_id = get_payload_size(network_id);

	eap_status_e status = add_structured_parameter_header(
		eapol_tlv_message_type_network_id,
		size_of_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(
		network_id->get_source_id());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(
		network_id->get_destination_id());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(
		network_id->get_type());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::add_parameter_data(
	const eap_buf_chain_wr_c * const packet_buffer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::add_parameter_data(): type=%s\n"),
		 get_type_string(eapol_tlv_message_type_variable_data)));

	if (packet_buffer == 0
		|| packet_buffer->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = add_message_data(
		eapol_tlv_message_type_variable_data,
		packet_buffer->get_data_length(),
		packet_buffer->get_data(packet_buffer->get_data_length()));

	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::add_parameter_data(
	const eapol_session_key_c * const session_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::add_parameter_data(): type=%s\n"),
		 get_type_string(eapol_tlv_message_type_session_key)));

	if (session_key == 0
		|| session_key->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u32_t size_of_session_key(get_payload_size(session_key));

	eap_status_e status = add_structured_parameter_header(
		eapol_tlv_message_type_session_key,
		size_of_session_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(
		session_key->get_key());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(
		session_key->get_sequence_number());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(
		eapol_tlv_message_type_eapol_key_type,
		static_cast<u32_t>(session_key->get_key_type()));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(session_key->get_key_index());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(session_key->get_key_tx_bit());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::add_parameter_data(
	const abs_eap_state_notification_c * const state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::add_parameter_data(): type=%s\n"),
		 get_type_string(eapol_tlv_message_type_eap_state_notification)));

	if (state == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u32_t size_of_state(get_payload_size(state));

	eap_status_e status = add_structured_parameter_header(
		eapol_tlv_message_type_eap_state_notification,
		size_of_state);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(state->get_send_network_id());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(
		eapol_tlv_message_type_eap_protocol_layer,
		static_cast<u32_t>(state->get_protocol_layer()));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(state->get_protocol());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(state->get_eap_type());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(state->get_current_state());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(state->get_is_client());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(state->get_authentication_error());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::add_parameter_data(
	const eap_type_value_e eap_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::add_parameter_data(): type=%s\n"),
		 get_type_string(eapol_tlv_message_type_eap_type)));

	void * type_buffer = 0;

	eap_status_e status = allocate_message_buffer(
		eapol_tlv_message_type_eap_type,
		eap_expanded_type_c::get_eap_expanded_type_size(),
		&type_buffer);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = eap_expanded_type_c::write_type(
		m_am_tools,
		0ul, ///< Index is from 0 to n. Index 0 is the first EAP type field after base EAP header.
		type_buffer,
		eap_expanded_type_c::get_eap_expanded_type_size(),
		true, ///< True value writes always Extented Type.
		eap_type ///< The EAP type to be written.
		);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_tlv_message_data_c::add_message_data():   type %2d=0x%08x, length %3d=0x%08x\n"),
		 eapol_tlv_message_type_eap_type,
		 eapol_tlv_message_type_eap_type,
		 eap_expanded_type_c::get_eap_expanded_type_size(),
		 eap_expanded_type_c::get_eap_expanded_type_size()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("add_message_data()"),
		type_buffer,
		eap_expanded_type_c::get_eap_expanded_type_size()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::add_parameter_data(
	const eap_general_header_base_c * const packet_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::add_parameter_data(): type=%s\n"),
		 get_type_string(eapol_tlv_message_type_variable_data)));

	if (packet_data == 0
		|| packet_data->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = add_message_data(
		eapol_tlv_message_type_variable_data,
		packet_data->get_header_buffer_length(),
		packet_data->get_header_buffer(packet_data->get_header_buffer_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::add_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::add_parameter_data(): type=%s\n"),
		 get_type_string(eapol_tlv_message_type_protected_setup_credential)));

	if (credential_array == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u32_t size_of_credential_array(get_payload_size(credential_array));

	eap_status_e status = add_structured_parameter_header(
		eapol_tlv_message_type_array,
		size_of_credential_array);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	for (u32_t ind_credential = 0ul; ind_credential < credential_array->get_object_count(); ind_credential++)
	{
		simple_config_credential_c * const credential = credential_array->get_object(ind_credential);
		if (credential != 0)
		{
			const u32_t size_of_credential(get_payload_size(credential));

			eap_status_e status = add_structured_parameter_header(
				eapol_tlv_message_type_protected_setup_credential,
				size_of_credential);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = add_parameter_data(credential->get_network_index());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = add_parameter_data(credential->get_SSID());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = add_parameter_data(static_cast<u16_t>(credential->get_Authentication_Type()));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = add_parameter_data(static_cast<u16_t>(credential->get_Encryption_Type()));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			const u32_t size_of_network_key_array(get_payload_size(credential->get_network_keys()));

			status = add_structured_parameter_header(
				eapol_tlv_message_type_array,
				size_of_network_key_array);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			for (u32_t ind_network_key = 0ul; ind_network_key < credential->get_network_keys()->get_object_count(); ind_network_key++)
			{
				network_key_and_index_c * const network_key = credential->get_network_keys()->get_object(ind_network_key);
				if (network_key != 0)
				{
					const u32_t size_of_network_key(get_payload_size(network_key));

					status = add_structured_parameter_header(
						eapol_tlv_message_type_network_key,
						size_of_network_key);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = add_parameter_data(network_key->get_network_key_index());
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = add_parameter_data(network_key->get_network_key());
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			} // for ()

			status = add_parameter_data(credential->get_MAC_address());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	} // for ()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const integer_header,
	u64_t * const value)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::get_parameter_data(): type=%s\n"),
		 get_type_string(static_cast<eapol_tlv_message_type_e>(integer_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(u64_t *)"),
		integer_header->get_header_buffer(integer_header->get_header_buffer_length()),
		integer_header->get_header_buffer_length()));

	if (static_cast<eapol_tlv_message_type_e>(integer_header->get_type())
		!= eapol_tlv_message_type_u64_t)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	const u8_t * const data = integer_header->get_value(sizeof(u64_t));
	if (data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	*value =
		eap_read_u64_t_network_order(
			data,
			sizeof(u64_t));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const integer_header,
	u32_t * const value)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::get_parameter_data(): type=%s\n"),
		 get_type_string(static_cast<eapol_tlv_message_type_e>(integer_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(u32_t *)"),
		integer_header->get_header_buffer(integer_header->get_header_buffer_length()),
		integer_header->get_header_buffer_length()));

	if (static_cast<eapol_tlv_message_type_e>(integer_header->get_type())
			!= eapol_tlv_message_type_boolean
		&& static_cast<eapol_tlv_message_type_e>(integer_header->get_type())
			!= eapol_tlv_message_type_eap_protocol_layer
		&& static_cast<eapol_tlv_message_type_e>(integer_header->get_type())
			!= eapol_tlv_message_type_eapol_key_802_11_authentication_mode
		&& static_cast<eapol_tlv_message_type_e>(integer_header->get_type())
			!= eapol_tlv_message_type_eapol_key_authentication_type
		&& static_cast<eapol_tlv_message_type_e>(integer_header->get_type())
			!= eapol_tlv_message_type_eapol_key_type
		&& static_cast<eapol_tlv_message_type_e>(integer_header->get_type())
			!= eapol_tlv_message_type_eapol_tkip_mic_failure_type
		&& static_cast<eapol_tlv_message_type_e>(integer_header->get_type())
			!= eapol_tlv_message_type_eapol_wlan_authentication_state
		&& static_cast<eapol_tlv_message_type_e>(integer_header->get_type())
			!= eapol_tlv_message_type_error
		&& static_cast<eapol_tlv_message_type_e>(integer_header->get_type())
			!= eapol_tlv_message_type_function
		&& static_cast<eapol_tlv_message_type_e>(integer_header->get_type())
			!= eapol_tlv_message_type_RSNA_cipher
		&& static_cast<eapol_tlv_message_type_e>(integer_header->get_type())
			!= eapol_tlv_message_type_u32_t
		&& static_cast<eapol_tlv_message_type_e>(integer_header->get_type())
			!= eapol_tlv_message_type_eap_status
			)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	const u8_t * const data = integer_header->get_value(sizeof(u32_t));
	if (data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	*value =
		eap_read_u32_t_network_order(
			data,
			sizeof(u32_t));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const integer_header,
	u16_t * const value)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::get_parameter_data(): type=%s\n"),
		 get_type_string(static_cast<eapol_tlv_message_type_e>(integer_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(u16_t *)"),
		integer_header->get_header_buffer(integer_header->get_header_buffer_length()),
		integer_header->get_header_buffer_length()));

	if (static_cast<eapol_tlv_message_type_e>(integer_header->get_type())
		!= eapol_tlv_message_type_u16_t)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	const u8_t * const data = integer_header->get_value(sizeof(u16_t));
	if (data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	*value =
		eap_read_u16_t_network_order(
			data,
			sizeof(u16_t));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const integer_header,
	u8_t * const value)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::get_parameter_data(): type=%s\n"),
		 get_type_string(static_cast<eapol_tlv_message_type_e>(integer_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(u8_t *)"),
		integer_header->get_header_buffer(integer_header->get_header_buffer_length()),
		integer_header->get_header_buffer_length()));

	if (static_cast<eapol_tlv_message_type_e>(integer_header->get_type())
		!= eapol_tlv_message_type_u8_t)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	const u8_t * const data = integer_header->get_value(sizeof(u8_t));
	if (data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	*value = *data;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const function_header,
	eapol_tlv_message_type_function_e * const function)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::get_parameter_data(): type=%s\n"),
		 get_type_string(static_cast<eapol_tlv_message_type_e>(function_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eapol_tlv_message_type_function_e *)"),
		function_header->get_header_buffer(function_header->get_header_buffer_length()),
		function_header->get_header_buffer_length()));

	if (static_cast<eapol_tlv_message_type_e>(function_header->get_type())
		!= eapol_tlv_message_type_function)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	u32_t host_order(0ul);

	eap_status_e status = get_parameter_data(
		function_header,
		&host_order);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	*function = static_cast<eapol_tlv_message_type_function_e>(host_order);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::get_parameter_data(): type=%s, function=%s\n"),
		 get_type_string(eapol_tlv_message_type_function),
		 get_function_string(*function)
		 ));

	if (*function < eapol_tlv_message_type_function_none
		|| eapol_tlv_message_type_function_illegal_value <= *function)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const network_id_header,
	eap_am_network_id_c * const new_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::get_parameter_data(): type=%s\n"),
		 get_type_string(static_cast<eapol_tlv_message_type_e>(network_id_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eap_am_network_id_c *)"),
		network_id_header->get_header_buffer(network_id_header->get_header_buffer_length()),
		network_id_header->get_header_buffer_length()));

	if (static_cast<eapol_tlv_message_type_e>(network_id_header->get_type())
		!= eapol_tlv_message_type_network_id)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eapol_handle_tlv_message_data_c network_id_data(m_am_tools);

	if (network_id_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = network_id_data.set_message_data(
		network_id_header->get_value_length(),
		network_id_header->get_value(network_id_header->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> network_id_members(m_am_tools);

	status = network_id_data.parse_message_data(&network_id_members);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	u32_t member_index(0ul);

	eap_variable_data_c source_id(
		m_am_tools);

	if (source_id.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		const eap_tlv_header_c * const source_id_header = network_id_members.get_object(member_index);
		if (source_id_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = network_id_data.get_parameter_data(source_id_header, &source_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++member_index;

	eap_variable_data_c destination_id(
		m_am_tools);

	if (destination_id.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		const eap_tlv_header_c * const destination_id_header = network_id_members.get_object(member_index);
		if (destination_id_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = network_id_data.get_parameter_data(destination_id_header, &destination_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++member_index;

	u16_t type_value(0ul);

	{
		const eap_tlv_header_c * const type_header = network_id_members.get_object(member_index);
		if (type_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = network_id_data.get_parameter_data(type_header, &type_value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	status = new_network_id->set_copy_of_am_network_id(
		source_id.get_data(),
		source_id.get_data_length(),
		destination_id.get_data(),
		destination_id.get_data_length(),
		type_value);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const variable_data_header,
	eap_variable_data_c * const variable_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::get_parameter_data(): type=%s\n"),
		 get_type_string(static_cast<eapol_tlv_message_type_e>(variable_data_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eap_variable_data_c *)"),
		variable_data_header->get_header_buffer(variable_data_header->get_header_buffer_length()),
		variable_data_header->get_header_buffer_length()));

	if (static_cast<eapol_tlv_message_type_e>(variable_data_header->get_type())
		!= eapol_tlv_message_type_variable_data)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eap_status_e status = variable_data->set_copy_of_buffer(
		variable_data_header->get_value(variable_data_header->get_value_length()),
		variable_data_header->get_value_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const session_key_header,
		eapol_session_key_c * const session_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::get_parameter_data(): type=%s\n"),
		 get_type_string(static_cast<eapol_tlv_message_type_e>(session_key_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eapol_session_key_c *)"),
		session_key_header->get_header_buffer(session_key_header->get_header_buffer_length()),
		session_key_header->get_header_buffer_length()));

	if (static_cast<eapol_tlv_message_type_e>(session_key_header->get_type())
		!= eapol_tlv_message_type_session_key)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eapol_handle_tlv_message_data_c session_key_data(m_am_tools);

	if (session_key_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = session_key_data.set_message_data(
		session_key_header->get_value_length(),
		session_key_header->get_value(session_key_header->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> session_key_members(m_am_tools);

	status = session_key_data.parse_message_data(&session_key_members);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t member_index(0ul);

	{
		const eap_tlv_header_c * const tmp_session_key_header = session_key_members.get_object(member_index);
		if (tmp_session_key_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eap_variable_data_c key(
			m_am_tools);

		if (key.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = session_key_data.get_parameter_data(tmp_session_key_header, &key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = session_key->set_key(&key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	++member_index;

	{
		const eap_tlv_header_c * const sequence_number_header = session_key_members.get_object(member_index);
		if (sequence_number_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eap_variable_data_c sequence_number(
			m_am_tools);

		if (sequence_number.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = session_key_data.get_parameter_data(sequence_number_header, &sequence_number);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = session_key->set_sequence_number(&sequence_number);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	++member_index;

	{
		const eap_tlv_header_c * const key_type_header = session_key_members.get_object(member_index);
		if (key_type_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		u32_t value(0ul);

		status = session_key_data.get_parameter_data(key_type_header, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		session_key->set_key_type(static_cast<eapol_key_type_e>(value));
	}

	++member_index;

	{
		const eap_tlv_header_c * const key_index_header = session_key_members.get_object(member_index);
		if (key_index_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		u32_t value(0ul);

		status = session_key_data.get_parameter_data(key_index_header, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		session_key->set_key_index(value);
	}

	++member_index;

	{
		const eap_tlv_header_c * const key_tx_bit_header = session_key_members.get_object(member_index);
		if (key_tx_bit_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		u32_t value(0ul);

		status = session_key_data.get_parameter_data(key_tx_bit_header, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		session_key->set_key_tx_bit((value == 0) ? false : true);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const state_header,
	eap_state_notification_c * * const state)

{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::get_parameter_data(): type=%s\n"),
		 get_type_string(static_cast<eapol_tlv_message_type_e>(state_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eap_state_notification_c *)"),
		state_header->get_header_buffer(state_header->get_header_buffer_length()),
		state_header->get_header_buffer_length()));

	if (static_cast<eapol_tlv_message_type_e>(state_header->get_type())
		!= eapol_tlv_message_type_eap_state_notification)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eapol_handle_tlv_message_data_c session_key_data(m_am_tools);

	if (session_key_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = session_key_data.set_message_data(
		state_header->get_value_length(),
		state_header->get_value(state_header->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> session_key_members(m_am_tools);

	status = session_key_data.parse_message_data(&session_key_members);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	u32_t member_index(0ul);

	eap_am_network_id_c send_network_id(m_am_tools);

	{
		const eap_tlv_header_c * const send_network_id_header = session_key_members.get_object(member_index);
		if (send_network_id_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = get_parameter_data(send_network_id_header, &send_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++member_index;

	eap_protocol_layer_e protocol_layer(eap_protocol_layer_none);

	{
		const eap_tlv_header_c * const protocol_layer_header = session_key_members.get_object(member_index);
		if (protocol_layer_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		u32_t value(0ul);

		status = session_key_data.get_parameter_data(protocol_layer_header, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		protocol_layer = static_cast<eap_protocol_layer_e>(value);
	}


	++member_index;

	u32_t protocol(0ul);

	{
		const eap_tlv_header_c * const protocol_header = session_key_members.get_object(member_index);
		if (protocol_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = session_key_data.get_parameter_data(protocol_header, &protocol);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++member_index;

	eap_type_value_e eap_type(eap_type_none);

	{
		const eap_tlv_header_c * const eap_type_header = session_key_members.get_object(member_index);
		if (eap_type_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = session_key_data.get_parameter_data(eap_type_header, &eap_type);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++member_index;

	u32_t current_state(0ul);

	{
		const eap_tlv_header_c * const current_state_header = session_key_members.get_object(member_index);
		if (current_state_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = session_key_data.get_parameter_data(current_state_header, &current_state);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++member_index;

	bool is_client(true);

	{
		const eap_tlv_header_c * const is_client_header = session_key_members.get_object(member_index);
		if (is_client_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		u32_t value(0ul);

		status = session_key_data.get_parameter_data(is_client_header, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		is_client = (value == 0ul) ? false : true;
	}


	++member_index;

	eap_status_e authentication_error(eap_status_ok);

	{
		const eap_tlv_header_c * const authentication_error_header = session_key_members.get_object(member_index);
		if (authentication_error_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		u32_t value(0ul);

		status = session_key_data.get_parameter_data(authentication_error_header, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		authentication_error = static_cast<eap_status_e>(value);
	}


	if (eap_type != eap_type_none)
	{
		*state = new eap_state_notification_c(
			m_am_tools,
			&send_network_id,
			is_client,
			eap_state_notification_eap,
			protocol_layer,
			eap_type,
			current_state,
			current_state,
			0ul,
			false);
	}
	else
	{
		

		*state = new eap_state_notification_c(
			m_am_tools,
			&send_network_id,
			is_client,
			eap_state_notification_generic,
			protocol_layer,
			protocol,
			current_state,
			current_state,
			0ul,
			false);
	}

	if ((*state) == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	(*state)->set_authentication_error(authentication_error);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const eap_type_header,
	eap_type_value_e * const eap_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::get_parameter_data(): type=%s\n"),
		 get_type_string(static_cast<eapol_tlv_message_type_e>(eap_type_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eap_type_value_e *)"),
		eap_type_header->get_header_buffer(eap_type_header->get_header_buffer_length()),
		eap_type_header->get_header_buffer_length()));

	if (static_cast<eapol_tlv_message_type_e>(eap_type_header->get_type())
		!= eapol_tlv_message_type_eap_type)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eap_status_e status = eap_expanded_type_c::read_type(
		m_am_tools,
		0ul,
		eap_type_header->get_value(eap_type_header->get_value_length()),
		eap_type_header->get_value_length(),
		eap_type);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const network_key_header,
	network_key_and_index_c * const network_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::get_parameter_data(): type=%s\n"),
		 get_type_string(static_cast<eapol_tlv_message_type_e>(network_key_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(simple_config_credential_c *)"),
		network_key_header->get_header_buffer(network_key_header->get_header_buffer_length()),
		network_key_header->get_header_buffer_length()));

	if (static_cast<eapol_tlv_message_type_e>(network_key_header->get_type())
		!= eapol_tlv_message_type_network_key)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eapol_handle_tlv_message_data_c credential_data(m_am_tools);

	if (credential_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = credential_data.set_message_data(
		network_key_header->get_value_length(),
		network_key_header->get_value(network_key_header->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> credential_members(m_am_tools);

	status = credential_data.parse_message_data(&credential_members);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t member_index(0ul);

	u8_t network_key_index(0ul);

	{
		const eap_tlv_header_c * const network_key_index_header = credential_members.get_object(member_index);
		if (network_key_index_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = credential_data.get_parameter_data(network_key_index_header, &network_key_index);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	++member_index;

	eap_variable_data_c key(m_am_tools);

	{
		const eap_tlv_header_c * const key_header = credential_members.get_object(member_index);
		if (key_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = credential_data.get_parameter_data(key_header, &key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	++member_index;

	network_key->set_network_key_index(network_key_index);

	status = network_key->get_network_key()->set_copy_of_buffer(&key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const network_keys_array_header,
	eap_array_c<network_key_and_index_c> * const network_keys_array)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::get_parameter_data(): type=%s\n"),
		 get_type_string(static_cast<eapol_tlv_message_type_e>(network_keys_array_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eap_array_c<simple_config_credential_c> *)"),
		network_keys_array_header->get_header_buffer(network_keys_array_header->get_header_buffer_length()),
		network_keys_array_header->get_header_buffer_length()));

	if (static_cast<eapol_tlv_message_type_e>(network_keys_array_header->get_type())
		!= eapol_tlv_message_type_array)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eapol_handle_tlv_message_data_c credential_array_data(m_am_tools);

	if (credential_array_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = credential_array_data.set_message_data(
		network_keys_array_header->get_value_length(),
		network_keys_array_header->get_value(network_keys_array_header->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> credential_array_members(m_am_tools);

	status = credential_array_data.parse_message_data(&credential_array_members);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	for (u32_t ind_member = 0ul; ind_member < credential_array_members.get_object_count(); ind_member++)
	{
		network_key_and_index_c * const network_key = new network_key_and_index_c(m_am_tools);

		eap_automatic_variable_c<network_key_and_index_c> automatic_network_key(m_am_tools, network_key);

		if (network_key == 0
			|| network_key->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		{
			const eap_tlv_header_c * const simple_config_credential_header = credential_array_members.get_object(ind_member);
			if (simple_config_credential_header == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			status = credential_array_data.get_parameter_data(simple_config_credential_header, network_key);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			automatic_network_key.do_not_free_variable();

			status = network_keys_array->add_object(network_key, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	} // for ()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const credential_header,
	simple_config_credential_c * const credential)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::get_parameter_data(): type=%s\n"),
		 get_type_string(static_cast<eapol_tlv_message_type_e>(credential_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(simple_config_credential_c *)"),
		credential_header->get_header_buffer(credential_header->get_header_buffer_length()),
		credential_header->get_header_buffer_length()));

	if (static_cast<eapol_tlv_message_type_e>(credential_header->get_type())
		!= eapol_tlv_message_type_protected_setup_credential)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eapol_handle_tlv_message_data_c credential_data(m_am_tools);

	if (credential_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = credential_data.set_message_data(
		credential_header->get_value_length(),
		credential_header->get_value(credential_header->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> credential_members(m_am_tools);

	status = credential_data.parse_message_data(&credential_members);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t member_index(0ul);

	u8_t network_index(0ul);

	{
		const eap_tlv_header_c * const network_index_header = credential_members.get_object(member_index);
		if (network_index_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = credential_data.get_parameter_data(network_index_header, &network_index);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	++member_index;

	eap_variable_data_c SSID(m_am_tools);

	{
		const eap_tlv_header_c * const SSID_header = credential_members.get_object(member_index);
		if (SSID_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = credential_data.get_parameter_data(SSID_header, &SSID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	++member_index;

	simple_config_Authentication_Type_e authentication_type(simple_config_Authentication_Type_None);

	{
		const eap_tlv_header_c * const authentication_type_header = credential_members.get_object(member_index);
		if (authentication_type_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		u16_t integer_value(0ul);

		status = credential_data.get_parameter_data(authentication_type_header, &integer_value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		authentication_type = static_cast<simple_config_Authentication_Type_e>(integer_value);
	}

	++member_index;

	simple_config_Encryption_Type_e encryption_type(simple_config_Encryption_Type_None);

	{
		const eap_tlv_header_c * const encryption_type_header = credential_members.get_object(member_index);
		if (encryption_type_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		u16_t integer_value(0ul);

		status = credential_data.get_parameter_data(encryption_type_header, &integer_value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		encryption_type = static_cast<simple_config_Encryption_Type_e>(integer_value);
	}

	++member_index;

	 eap_array_c<network_key_and_index_c> network_keys_array(m_am_tools);

	{
		const eap_tlv_header_c * const network_keys_array_header = credential_members.get_object(member_index);
		if (network_keys_array_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = credential_data.get_parameter_data(network_keys_array_header, &network_keys_array);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	++member_index;

	 eap_variable_data_c MAC_address(m_am_tools);

	{
		const eap_tlv_header_c * const MAC_address_header = credential_members.get_object(member_index);
		if (MAC_address_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = credential_data.get_parameter_data(MAC_address_header, &MAC_address);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	++member_index;


	credential->set_network_index(network_index);

	status = credential->get_SSID()->set_copy_of_buffer(&SSID);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	credential->set_Authentication_Type(authentication_type);

	credential->set_Encryption_Type(encryption_type);

	status = copy(
		&network_keys_array,
		credential->get_network_keys(),
		m_am_tools,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = credential->get_MAC_address()->set_copy_of_buffer(&MAC_address);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e eapol_handle_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const credential_array_header,
	eap_array_c<simple_config_credential_c> * const credential_array)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_handle_tlv_message_data_c::get_parameter_data(): type=%s\n"),
		 get_type_string(static_cast<eapol_tlv_message_type_e>(credential_array_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eap_array_c<simple_config_credential_c> *)"),
		credential_array_header->get_header_buffer(credential_array_header->get_header_buffer_length()),
		credential_array_header->get_header_buffer_length()));

	if (static_cast<eapol_tlv_message_type_e>(credential_array_header->get_type())
		!= eapol_tlv_message_type_array)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eapol_handle_tlv_message_data_c credential_array_data(m_am_tools);

	if (credential_array_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = credential_array_data.set_message_data(
		credential_array_header->get_value_length(),
		credential_array_header->get_value(credential_array_header->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> credential_array_members(m_am_tools);

	status = credential_array_data.parse_message_data(&credential_array_members);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	for (u32_t ind_member = 0ul; ind_member < credential_array_members.get_object_count(); ind_member++)
	{
		simple_config_credential_c * const simple_config_credential = new simple_config_credential_c(m_am_tools);

		eap_automatic_variable_c<simple_config_credential_c> automatic_simple_config_credential(m_am_tools, simple_config_credential);

		if (simple_config_credential == 0
			|| simple_config_credential->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		{
			const eap_tlv_header_c * const simple_config_credential_header = credential_array_members.get_object(ind_member);
			if (simple_config_credential_header == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			status = credential_array_data.get_parameter_data(simple_config_credential_header, simple_config_credential);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			automatic_simple_config_credential.do_not_free_variable();

			status = credential_array->add_object(simple_config_credential, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	} // for ()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eapol_handle_tlv_message_data_c::get_type_string(const eapol_tlv_message_type_e type)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_none)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_array)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_boolean)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_eap_protocol_layer)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_eap_state_notification)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_eap_type)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_eapol_key_802_11_authentication_mode)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_eapol_key_authentication_type)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_eapol_key_type)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_eapol_tkip_mic_failure_type)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_eapol_wlan_authentication_state)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_error)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_function)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_network_id)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_RSNA_cipher)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_session_key)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_u8_t)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_u16_t)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_u32_t)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_u64_t)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_variable_data)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_network_key)
	else EAP_IF_RETURN_STRING(type, eapol_tlv_message_type_protected_setup_credential)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(type);

		return EAPL("Unknown EAPOL-TLV message type");
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eapol_handle_tlv_message_data_c::get_function_string(const eapol_tlv_message_type_function_e function)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_none)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_check_pmksa_cache)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_start_authentication)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_complete_association)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_disassociation)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_start_preauthentication)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_start_reassociation)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_complete_reassociation)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_start_WPXM_reassociation)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_complete_WPXM_reassociation)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_packet_process)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_tkip_mic_failure)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_eap_acknowledge)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_update_header_offset)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_complete_check_pmksa_cache)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_packet_send)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_associate)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_disassociate)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_packet_data_session_key)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_state_notification)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_reassociate)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_update_wlan_database_reference_values)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_complete_start_WPXM_reassociation)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_new_protected_setup_credentials)
	else EAP_IF_RETURN_STRING(function, eapol_tlv_message_type_function_illegal_value)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(function);

		return EAPL("Unknown EAPOL-TLV message function");
	}
}

//--------------------------------------------------

// End.
