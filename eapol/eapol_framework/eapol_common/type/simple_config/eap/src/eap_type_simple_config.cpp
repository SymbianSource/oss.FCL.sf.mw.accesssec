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
	#define EAP_FILE_NUMBER_ENUM 590 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#if defined(USE_EAP_SIMPLE_CONFIG)

#include "eap_am_memory.h"
#include "eap_type_simple_config_types.h"
#include "eap_type_simple_config.h"
#include "eap_type_simple_config_header.h"
#include "eap_type_simple_config_state_notification.h"
#include "eap_am_type_simple_config.h"
#include "eap_state_notification.h"
#include "simple_config_tlv_header.h"
#include "simple_config_base_record.h"
#include "eap_config.h"
#include "eap_header_string.h"

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_type_simple_config_c::~eap_type_simple_config_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: function: eap_type_simple_config_c::~eap_type_simple_config_c(): this = 0x%08x => 0x%08x,")
		 EAPL(" m_am_type_simple_config = 0x%08x (validity %d).\n"),
		 (m_is_client == true ? "client": "server"),
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this),
		 m_am_type_simple_config,
		 m_am_type_simple_config->get_is_valid()));

	EAP_ASSERT(m_shutdown_was_called == true);

	if (m_free_simple_config_record == true)
	{
		delete m_simple_config_record;
		m_simple_config_record = 0;
	}

	if (m_free_am_type_simple_config == true)
	{
		delete m_am_type_simple_config;
		m_am_type_simple_config = 0;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_type_simple_config_c::eap_type_simple_config_c(
	abs_eap_am_tools_c * const tools, ///< This is pointer to the tools AM of current platform.
	abs_eap_base_type_c * const partner, ///< This is back pointer to object which created this object.
	eap_am_type_simple_config_c * const am_type_simple_config, ///< This is pointer to adaptation module of EAP-SIMPLE_CONFIG type.
	const bool free_am_type_simple_config,
	simple_config_base_record_c * const simple_config_record, /// This is pointer to SIMPLE_CONFIG implementation.
	const bool free_simple_config_record,
	const bool is_client_when_true, ///< Indicates whether this is client (true) or server (false).
	const eap_type_value_e current_eap_type, ///< This the current EAP-type (SIMPLE_CONFIG or PEAP).
	const eap_am_network_id_c * const receive_network_id)
	: eap_base_type_c(tools, partner)
	  , m_am_tools(tools)
	  , m_am_type_simple_config(am_type_simple_config)
	  , m_simple_config_record(simple_config_record)
	  , m_nai_realm(tools)
	  , m_NAI(tools)
	  , m_send_network_id(tools)
	  , m_simple_config_header_offset(0u)
	  , m_MTU(0u)
	  , m_trailer_length(0u)
	  , m_state(eap_type_simple_config_state_waiting_for_identity_request)
	  , m_saved_previous_state(eap_type_simple_config_state_waiting_for_identity_request)
	  , m_reassembly_state(eap_type_simple_config_reassembly_state_wait_first_message)
	  , m_saved_previous_reassembly_state(eap_type_simple_config_reassembly_state_wait_first_message)
	  , m_simple_config_message_send_offset(0ul)
	  , m_simple_config_message_buffer(tools)
	  , m_first_fragment_eap_identifier(0ul)
	  , m_free_am_type_simple_config(free_am_type_simple_config)
	  , m_free_simple_config_record(free_simple_config_record)
	  , m_is_valid(false)
	  , m_is_client(is_client_when_true)
	  , m_check_identifier_of_eap_identity_response(false)
	  , m_simple_config_test_version(false)
	  , m_check_nai_realm(false)
	  , m_failure_message_received(false)
	  , m_authentication_finished_successfully(false)
	  , m_last_eap_identifier(0ul)
	  , m_shutdown_was_called(false)
	  , m_simple_config_message_type(simple_config_Message_Type_None)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: function: eap_type_simple_config_c::eap_type_simple_config_c(): ")
		 EAPL("this = 0x%08x => 0x%08x, compiled %s %s\n"),
		 (m_is_client == true ? "client": "server"),
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this),
		__DATE__,
		__TIME__));

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		// No need to delete anything here because it is done in destructor.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	if (simple_config_record == 0)
	{
		// No need to delete anything here because it is done in destructor.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}
	m_simple_config_record->set_type_partner(this);

	if (m_am_type_simple_config == 0)
	{
		// Something wrong with AM.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}
	m_am_type_simple_config->set_am_partner(this);


	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(
		m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());

	eap_status_e status = get_send_network_id()->set_copy_of_network_id(
		&send_network_id);
	if (status != eap_status_ok)
	{
		EAP_UNREFERENCED_PARAMETER(current_eap_type);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	if (m_is_client == false)
	{
		// Server waits EAP-Response/Identity.
		m_state = eap_type_simple_config_state_waiting_for_identity_response;
		m_saved_previous_state
			= eap_type_simple_config_state_waiting_for_identity_response;
	}

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_simple_config_c::save_current_state()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_saved_previous_state = m_state;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_simple_config_c::restore_saved_previous_state()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	set_state(m_saved_previous_state);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_simple_config_c::set_state(
	const eap_type_simple_config_state_variable_e state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_type_simple_config_state_variable_e previous_state = m_state;
	EAP_UNREFERENCED_PARAMETER(previous_state); // This is used only for debugging.

	if (m_state != eap_type_simple_config_state_failure)
	{
		m_state = state;
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_type_simple_config_c::set_state(): ")
		 EAPL("%s: Previous state %d=%s, new state %d=%s.\n"),
			(m_is_client == true ? "client": "server"),
			previous_state,
			get_state_string(previous_state),
			m_state,
			get_state_string(m_state)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_type_simple_config_reassembly_state_e eap_type_simple_config_c::get_reassembly_state() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_reassembly_state;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_simple_config_c::set_reassembly_state(
	const eap_type_simple_config_reassembly_state_e state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_reassembly_state = state;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_simple_config_c::save_current_reassembly_state()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_saved_previous_reassembly_state = m_reassembly_state;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_simple_config_c::restore_saved_reassembly_state()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_reassembly_state = m_saved_previous_reassembly_state;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_am_network_id_c * eap_type_simple_config_c::get_send_network_id()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_send_network_id;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_simple_config_c::set_last_eap_identifier(const u8_t last_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_last_eap_identifier = last_eap_identifier;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_type_simple_config_c::set_last_eap_identifier():")
		 EAPL("%s, saved EAP-identifier %d, state %s\n"),
		 (m_is_client == true ? "client": "server"),
		 m_last_eap_identifier,
		 get_state_string()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u8_t eap_type_simple_config_c::get_last_eap_identifier() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_type_simple_config_c::get_last_eap_identifier():")
		 EAPL("%s, saved EAP-identifier %d, state %s\n"),
		 (m_is_client == true ? "client": "server"),
		 m_last_eap_identifier,
		 get_state_string()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_last_eap_identifier;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_const_string eap_type_simple_config_c::get_state_string(
	eap_type_simple_config_state_variable_e state)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(state, eap_type_simple_config_state_waiting_for_identity_request)
	else EAP_IF_RETURN_STRING(state, eap_type_simple_config_state_pending_identity_query)
	else EAP_IF_RETURN_STRING(state, eap_type_simple_config_state_waiting_for_simple_config_start)
	else EAP_IF_RETURN_STRING(state, eap_type_simple_config_state_process_simple_config_start)
	else EAP_IF_RETURN_STRING(state, eap_type_simple_config_state_waiting_for_request)
	else EAP_IF_RETURN_STRING(state, eap_type_simple_config_state_waiting_for_identity_response)
	else EAP_IF_RETURN_STRING(state, eap_type_simple_config_state_waiting_for_response)
	else EAP_IF_RETURN_STRING(state, eap_type_simple_config_state_process_simple_config_message)
	else EAP_IF_RETURN_STRING(state, eap_type_simple_config_state_success)
	else EAP_IF_RETURN_STRING(state, eap_type_simple_config_state_failure)
	else
#else
	EAP_UNREFERENCED_PARAMETER(state);	
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown EAP-SIMPLE_CONFIG state");
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_const_string eap_type_simple_config_c::get_reassembly_state_string(
	eap_type_simple_config_reassembly_state_e state)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(state, eap_type_simple_config_reassembly_state_none)
	else EAP_IF_RETURN_STRING(state, eap_type_simple_config_reassembly_state_wait_first_message)
	else EAP_IF_RETURN_STRING(state, eap_type_simple_config_reassembly_state_wait_last_fragment)
	else EAP_IF_RETURN_STRING(state, eap_type_simple_config_reassembly_state_message_reassembled)
	else
#else
	EAP_UNREFERENCED_PARAMETER(state);		
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown SIMPLE_CONFIG reassembly state");
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_type_simple_config_c::get_state_string() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return get_state_string(m_state);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_type_simple_config_c::get_reassembly_state_string() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return get_reassembly_state_string(m_reassembly_state);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_type_simple_config_c::get_saved_previous_state_string() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return get_state_string(m_saved_previous_state);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_type_simple_config_c::set_failure_message_received()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_failure_message_received = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_type_simple_config_c::unset_failure_message_received()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_failure_message_received = false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_type_simple_config_c::get_failure_message_received() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_failure_message_received;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_type_simple_config_state_variable_e eap_type_simple_config_c::get_state() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_state;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_variable_data_c * eap_type_simple_config_c::get_nai_realm()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_nai_realm;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_variable_data_c * eap_type_simple_config_c::get_NAI()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_NAI;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_simple_config_c::update_buffer_indexes(
	const u32_t maximum_buffer_size,
	const u32_t payload_size,
	u32_t * const buffer_offset,
	u32_t * const buffer_free)
{
	EAP_UNREFERENCED_PARAMETER(maximum_buffer_size);

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT_ALWAYS(*buffer_offset + *buffer_free <= maximum_buffer_size-m_trailer_length);
	EAP_ASSERT_ALWAYS(*buffer_free >= payload_size);
	EAP_ASSERT_ALWAYS(m_simple_config_header_offset+m_MTU == *buffer_offset + *buffer_free);

	*buffer_free -= payload_size;
	*buffer_offset += payload_size;

	EAP_ASSERT_ALWAYS(*buffer_offset + *buffer_free <= maximum_buffer_size-m_trailer_length);
	EAP_ASSERT_ALWAYS(*buffer_offset <= m_simple_config_header_offset+m_MTU);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_simple_config_c::update_payload_indexes(
	const u32_t /*maximum_buffer_size*/,
	const u32_t /*eap_header_size*/,
	const u32_t /*payload_size*/,
	u32_t * const /*data_offset*/,
	u32_t * const /*data_free*/,
	u32_t * const /*buffer_offset*/,
	u32_t * const /*buffer_free*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::parse_identity(
	const u8_t * const identity, ///< This is pointer to received EAP-Identity buffer.
	const u32_t identity_length ///< This is length of received EAP-Identity buffer.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (identity_length < 1u)
	{
		// Anonymous identity.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	const u8_t *at_character = reinterpret_cast<const u8_t *>(
		m_am_tools->memchr(
			identity,
			EAP_SIMPLE_CONFIG_AT_CHARACTER,
			identity_length));
	if (at_character == 0)
	{
		// No realm.
		// This is allowed.
	}

	eap_status_e status = check_NAI(identity, identity_length, at_character);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = eap_status_process_general_error;

	status = get_NAI()->set_copy_of_buffer(identity, identity_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("SIMPLE_CONFIG received EAP-identity NAI"),
		get_NAI()->get_data(get_NAI()->get_data_length()),
		get_NAI()->get_data_length()));

	if (get_NAI()->get_data_length() != EAP_SIMPLE_CONFIG_ENROLLEE_IDENTITY_LENGTH
		|| m_am_tools->memcmp(
			get_NAI()->get_data(),
			EAP_SIMPLE_CONFIG_ENROLLEE_IDENTITY,
			EAP_SIMPLE_CONFIG_ENROLLEE_IDENTITY_LENGTH) != 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::simple_config_packet_send(
	eap_buf_chain_wr_c * const sent_packet,
	const simple_config_Message_Type_e message_type
    )
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_SIMPLE_CONFIG: %s: function: simple_config_packet_send()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status = eap_status_not_supported;
		
	if ((m_is_client == true
			&& get_state() == eap_type_simple_config_state_process_simple_config_start)
		|| get_state() == eap_type_simple_config_state_process_simple_config_message
		|| get_state() == eap_type_simple_config_state_waiting_for_request // This state is needed to send messages from asyncronous completions.
		|| get_state() == eap_type_simple_config_state_waiting_for_response // This state is needed to send messages from asyncronous completions.
		|| get_state() == eap_type_simple_config_state_success // This state is needed to send the WCS_Done message.
		|| get_state() == eap_type_simple_config_state_failure // This state is needed to send failure messages.
		|| (m_is_client == false
			&& get_state() == eap_type_simple_config_state_success)
		)
	{
		status = m_simple_config_message_buffer.set_copy_of_buffer(
			sent_packet->get_data(sent_packet->get_data_length()),
			sent_packet->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// This will start the packet send from begin of the message.
		m_simple_config_message_send_offset = 0ul;
		
		// Save the type of the message for fragmentation
		m_simple_config_message_type = message_type;

		status = eap_simple_config_fragment_send();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_SIMPLE_CONFIG_ERROR,
			(EAPL("ERROR: eap_type_simple_config_c::simple_config_packet_send(): ")
			 EAPL("Cannot send EAP-SIMPLE_CONFIG message in ")
			 EAPL("eap_type_simple_config_state_variable_e %d=%s.\n"),
			get_state(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::packet_send(
	const eap_am_network_id_c * const network_id,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const u32_t buffer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_SIMPLE_CONFIG: %s: function: packet_send()\n"),
		(m_is_client == true ? "client": "server")));

	eap_header_wr_c eap(
		m_am_tools,
		sent_packet->get_data_offset(
			header_offset, data_length),
		data_length);
	if (eap.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	packet_trace(
		EAPL("<-"),
		network_id,
		&eap,
		data_length);

	eap_status_e status = get_type_partner()->packet_send(
		network_id, 
		sent_packet, 
		header_offset, 
		data_length,
		buffer_length
		);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::check_NAI(
	const u8_t * const identity,
	const u32_t identity_length,
	const u8_t * const at_character)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	bool includes_at = false;
	bool includes_dot = false;
	u32_t username_length = 0u;
	u32_t realm_length = 0u;

	for (u32_t ind = 0; ind < identity_length; ind++)
	{
		const u8_t character = identity[ind];

		if (includes_at == false)
		{
			if (character != EAP_SIMPLE_CONFIG_AT_CHARACTER)
			{
				++username_length;
			}
		}
		else
		{
			++realm_length;
		}


		if ('0' <= character && character <= '9')
		{
			// OK.
		}
		else if ('a' <= character && character <= 'z')
		{
			// OK.
		}
		else if ('A' <= character && character <= 'Z')
		{
			// OK.
		}
		else if (character == EAP_SIMPLE_CONFIG_AT_CHARACTER)
		{
			if (includes_at == false)
			{
				includes_at = true;
			}
			else
			{
				// Second at ('@').
				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: Illegal NAI, includes second at \'@\' character."),
					identity,
					identity_length));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_nai);
			}
		}
		else if (character == '.')
		{
			if (includes_at == true)
			{
				// OK.
				includes_dot = true;
			}
			else
			{
				// dot ('.') within username
				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: Illegal NAI, dot \'.\' within username."),
					identity,
					identity_length));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_nai);
			}
		}
		else if (character == '<'
			|| character == '>'
			|| character == '('
			|| character == ')'
			|| character == '['
			|| character == ']'
			|| character == '\\'
			|| character == '.'
			|| character == ','
			|| character == ';'
			|| character == ':'
			|| character == EAP_SIMPLE_CONFIG_AT_CHARACTER
			|| character == ' ' // space
			|| character <= 0x1f // Ctrl
			|| character >= 0x7f) // extented characters
		{
			// Illegal character.
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_SIMPLE_CONFIG_ERROR,
				(EAPL("ERROR: Illegal NAI, includes illegal character 0x%02x=%c.\n"),
				character,
				character));
			EAP_TRACE_DATA_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: Illegal NAI, includes illegal character."),
				identity,
				identity_length));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_nai);
		}
		else
		{
			// All other ascii values are OK.
		}
	}

	// Note the username could be zero length.
	if ((realm_length == 1u && includes_at == true) // one at ('@') is illegal.
		|| (realm_length == 2u && includes_at == true && includes_dot == true)) //  one at ('@') and one dot is illegal.
	{
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Illegal NAI."),
			identity,
			identity_length));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_nai);
	}

	if (m_check_nai_realm == true)
	{
		if (at_character == 0
			&& realm_length == 0
			&& get_nai_realm()->get_data_length() == 0)
		{
			// OK, no realm.
		}
		else if (at_character == 0
			|| realm_length != get_nai_realm()->get_data_length()
			|| m_am_tools->memcmp(
				at_character+1u,
				get_nai_realm()->get_data(get_nai_realm()->get_data_length()),
				get_nai_realm()->get_data_length()) != 0)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("Illegal NAI, realm unknown."),
				identity,
				identity_length));
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("NAI should be"),
				get_nai_realm()->get_data(get_nai_realm()->get_data_length()),
				get_nai_realm()->get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_nai);
		}
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_simple_config_c::packet_trace(
	eap_const_string prefix,
	const eap_am_network_id_c * const /*receive_network_id*/,
	eap_header_wr_c * const eap_packet,
	const u32_t eap_packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_UNREFERENCED_PARAMETER(prefix); // in release
	
	if (eap_packet_length > eap_header_base_c::get_header_length()
		&& eap_packet->get_type() == eap_expanded_type_simple_config.get_type())
	{
		eap_simple_config_header_c * const received_simple_config
			= reinterpret_cast<eap_simple_config_header_c *>(eap_packet);

		const u8_t * const p_simple_config_flags = received_simple_config->get_simple_config_flags();
		u8_t simple_config_flags = 0u;
		EAP_UNREFERENCED_PARAMETER(simple_config_flags); // in release
		if (p_simple_config_flags != 0)
		{
			simple_config_flags = *p_simple_config_flags;
		}

		u32_t simple_config_message_length = 0ul;
		if (received_simple_config->get_simple_config_message_length(&simple_config_message_length) != eap_status_ok)
		{
			simple_config_message_length = 0ul;
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("%s EAP-SIMPLE_CONFIG header %s: code=0x%02x=%s, identifier=0x%02x=%d, ")
			 EAPL("length=0x%04x=%d, ")
			 EAPL("type=0x%08x=%s, OP-Code=0x%02x=%s, SIMPLE_CONFIG-flags=0x%02x %s%s, SIMPLE_CONFIG-length=0x%08x=%d.\n"),
			 prefix,
			 (m_is_client == true) ? "client": "server",
			 received_simple_config->get_code(),
			 received_simple_config->get_code_string(),
			 received_simple_config->get_identifier(),
			 received_simple_config->get_identifier(),
			 received_simple_config->get_length(),
			 received_simple_config->get_length(),
			 convert_eap_type_to_u32_t(received_simple_config->get_type()),
			 received_simple_config->get_eap_type_string(),
			 received_simple_config->get_sc_op_code(),
			 received_simple_config->get_sc_op_code_string(),
			 simple_config_flags,
			 (simple_config_flags & eap_simple_config_header_c::m_flag_mask_simple_config_length_included) ? "L": " ",
			 (simple_config_flags & eap_simple_config_header_c::m_flag_mask_more_fragments) ? "M": " ",
			 simple_config_message_length,
			 simple_config_message_length));
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("%s EAP header %s: code=0x%02x=%s, identifier=0x%02x, length=0x%04x=%d, ")
			 EAPL("type=0x%08x=%s\n"),
			prefix,
			(m_is_client == true) ? "client": "server",
			eap_packet->get_code(),
			eap_packet->get_code_string(),
			eap_packet->get_identifier(),
			eap_packet->get_length(),
			eap_packet->get_length(),
			convert_eap_type_to_u32_t(eap_packet->get_type()),
			eap_packet->get_type_string()));

		EAP_TRACE_DEBUG(
			m_am_tools,
			eap_am_tools_c::eap_trace_mask_eap_messages,
			(EAPL("\n\t%s\n\tcode       = 0x%02x   = %s\n\tidentifier = 0x%02x\n\t")
			 EAPL("length     = 0x%04x = %lu\n\ttype       = 0x%08x   = %s\n"),
			(m_is_client == true) ? "client": "server",
			eap_packet->get_code(),
			eap_packet->get_code_string(),
			eap_packet->get_identifier(),
			eap_packet->get_length(),
			eap_packet->get_length(),
			convert_eap_type_to_u32_t(eap_packet->get_type()),
			eap_packet->get_type_string()));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::finish_successful_authentication()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_SIMPLE_CONFIG: %s: function: finish_successful_authentication()\n"),
		(m_is_client == true ? "client": "server")));

	eap_simple_config_trace_string_c simple_config_trace;
	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("EAP_type_SIMPLE_CONFIG: %s, EAP-type %s EAP-SUCCESS\n"),
		 ((m_is_client == true) ? "client": "server"),
		 eap_header_string_c::get_eap_type_string(eap_expanded_type_simple_config.get_type())));

	set_state(eap_type_simple_config_state_success);

	// Note, authentication is always terminated unsuccessfully.
	// Server will send EAP-Failure always.
	// Client should accept EAP-Failure quietly.
	{
		eap_state_notification_c notification(
			m_am_tools,
			get_send_network_id(),
			m_is_client,
			eap_state_notification_eap,
			eap_protocol_layer_eap,
			eap_expanded_type_simple_config.get_type(),
			eap_state_none,
			eap_state_use_eap_failure_in_termination,
			get_last_eap_identifier(), // Note the EAP-Failure uses the same EAP-Identifier as the last EAP-Request.
			false);
		get_type_partner()->state_notification(&notification);
	}

	eap_state_notification_c notification(
		m_am_tools,
		get_send_network_id(),
		m_is_client,
		eap_state_notification_eap,
		eap_protocol_layer_eap,
		eap_expanded_type_simple_config.get_type(),
		eap_state_none,
		eap_state_authentication_finished_successfully,
		get_last_eap_identifier(), // Note the EAP-Success uses the same EAP-Identifier as the last EAP-Request.
		false);
	get_type_partner()->state_notification(&notification);

	// Indicate EAP-SIMPLE_CONFIG AM authentication finished successfully.
	m_am_type_simple_config->authentication_finished(true, false);

	m_authentication_finished_successfully = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_success);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::send_final_notification()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_SIMPLE_CONFIG: %s: function: send_final_notification()\n"),
		(m_is_client == true ? "client": "server")));

	if (m_is_valid == true 
		&& m_authentication_finished_successfully == false)
	{
		eap_simple_config_trace_string_c simple_config_trace;
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAP_type_SIMPLE_CONFIG: %s, EAP-type %s FAILED\n"),
			 ((m_is_client == true) ? "client": "server"),
			 eap_header_string_c::get_eap_type_string(eap_expanded_type_simple_config.get_type())));

		set_state(eap_type_simple_config_state_failure);

		// Notifies the lower level of unsuccessfull authentication.
		eap_state_notification_c notification(
			m_am_tools,
			get_send_network_id(),
			m_is_client,
			eap_state_notification_eap,
			eap_protocol_layer_eap,
			eap_expanded_type_simple_config.get_type(),
			eap_state_none,
			eap_state_authentication_terminated_unsuccessfully,
			get_last_eap_identifier(),
			false);

		notification.set_authentication_error(eap_status_authentication_failure);

		get_type_partner()->state_notification(&notification);

		// Indicate EAP-SIMPLE_CONFIG AM authentication terminated unsuccessfully.
		m_am_type_simple_config->authentication_finished(false, false);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eap_type_simple_config_c::get_is_client()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_client;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::handle_eap_identity_query(
	const eap_am_network_id_c * const receive_network_id,
	const u8_t eap_identifier,
	const bool use_manual_username,
	const eap_variable_data_c * const manual_username,
	const bool use_manual_realm,
	const eap_variable_data_c * const manual_realm
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;
	eap_variable_data_c local_identity(m_am_tools);

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(
		m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());

	if (use_manual_username == true
		&& manual_username != 0
		&& manual_username->get_is_valid() == true
		&& use_manual_realm == true
		&& manual_realm != 0
		&& manual_realm->get_is_valid() == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_SIMPLE_CONFIG: %s: eap_type_simple_config_c::handle_eap_identity_query(): manual username and manual realm.\n"),
			(m_is_client == true ? "client": "server")));

		// Here manual username could be zero or more bytes in length.
		status = local_identity.set_copy_of_buffer(manual_username);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (manual_realm->get_data_length() > 0ul)
		{
			// When manual realm is one or more bytes in length
			// we add @ and manual realm to the identity.
			u8_t at_char = EAP_SIMPLE_CONFIG_AT_CHARACTER;
			status = local_identity.add_data(&at_char, sizeof(at_char));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			status = local_identity.add_data(manual_realm);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}
	else if (use_manual_username == true
			&& manual_username != 0
			&& manual_username->get_is_valid() == true
			&& use_manual_realm == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_SIMPLE_CONFIG: %s: eap_type_simple_config_c::handle_eap_identity_query(): manual username.\n"),
			(m_is_client == true ? "client": "server")));

		status = local_identity.set_copy_of_buffer(manual_username);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_SIMPLE_CONFIG: %s: eap_type_simple_config_c::handle_eap_identity_query(): no identity.\n"),
			(m_is_client == true ? "client": "server")));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
	}

	status = get_NAI()->set_copy_of_buffer(&local_identity);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_type_simple_config_c::handle_eap_identity_query(): identity"),
		local_identity.get_data(),
		local_identity.get_data_length()));


	status = get_type_partner()->complete_eap_identity_query(
		&send_network_id,
		&local_identity,
		eap_identifier);	
	if (status == eap_status_ok)
	{
		set_state(eap_type_simple_config_state_waiting_for_simple_config_start);
	}
	else
	{
		get_NAI()->reset();
		restore_saved_previous_state();
	}
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::complete_eap_identity_query(
	const eap_am_network_id_c * const receive_network_id,
	const u8_t eap_identifier,
	const eap_status_e completion_status,
	const bool use_manual_username,
	const eap_variable_data_c * const manual_username,
	const bool use_manual_realm,
	const eap_variable_data_c * const manual_realm
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_state == eap_type_simple_config_state_pending_identity_query)
	{
		if (completion_status != eap_status_ok)
		{
			set_state(eap_type_simple_config_state_failure);

			// The completion_status error value is more important
			// than return value of set_session_timeout().
			get_type_partner()->set_session_timeout(0ul);

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, completion_status);
		}

		eap_status_e status = handle_eap_identity_query(
			receive_network_id,
			eap_identifier,
			use_manual_username,
			manual_username,
			use_manual_realm,
			manual_realm);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_SIMPLE_CONFIG_ERROR, 
			(EAPL("ERROR: eap_type_simple_config_c::complete_eap_identity_query(): ")
			 EAPL("Illegal EAP-Identity query completion in ")
			 EAPL("eap_type_simple_config_state_variable_e %d=%s.\n"),
			get_state(),
			get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}
}

//--------------------------------------------------

//
eap_status_e eap_type_simple_config_c::check_received_eap_identifier(
	const eap_header_wr_c * const eap_header)
{
	if (m_is_client == false
		&& eap_header->get_type() == eap_type_identity
		&& eap_header->get_code() == eap_code_response
		&& m_check_identifier_of_eap_identity_response == true
		&& eap_header->get_identifier() != get_last_eap_identifier())
	{
		eap_status_e status(eap_status_unexpected_message);

		eap_status_string_c status_string;
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_SIMPLE_CONFIG_ERROR,
			(EAPL("ERROR: eap_type_simple_config_c::packet_process() failed,")
			 EAPL("status %d=%s, received EAP-type 0x%08x, received EAP-code %d, ")
			 EAPL("received EAP-identifier %d, current EAP-identifier %d, state %s\n"),
			 status,
			 status_string.get_status_string(status),
			 convert_eap_type_to_u32_t(eap_header->get_type()),
			 eap_header->get_code(),
			 eap_header->get_identifier(),
			 get_last_eap_identifier(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (m_is_client == false
			 && eap_header->get_type() == eap_expanded_type_simple_config.get_type()
			 && eap_header->get_identifier() != get_last_eap_identifier())
	{
		eap_status_e status(eap_status_unexpected_message);

		eap_status_string_c status_string;
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_SIMPLE_CONFIG_ERROR,
			(EAPL("ERROR: eap_type_simple_config_c::packet_process() failed,")
			 EAPL("status %d=%s, received EAP-identifier %d, ")
			 EAPL("current EAP-identifier %d, state %s\n"),
			 status,
			 status_string.get_status_string(status),
			 eap_header->get_identifier(),
			 get_last_eap_identifier(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (m_is_client == true
		&& eap_header->get_identifier() == get_last_eap_identifier())
	{
		// Client have received this packet already.
		eap_status_e status(eap_status_drop_packet_quietly);

		eap_status_string_c status_string;
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: eap_type_simple_config_c::packet_process() failed,")
			 EAPL("status %d=%s, drops already received EAP-identifier %d, ")
			 EAPL("current EAP-identifier %d, state %s\n"),
			 status,
			 status_string.get_status_string(status),
			 eap_header->get_identifier(),
			 get_last_eap_identifier(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::packet_process(
	const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
	eap_header_wr_c * const eap_header, ///< This is pointer to EAP header and data.
	const u32_t eap_packet_length ///< This is length of received EAP packet.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_SIMPLE_CONFIG: %s: function: packet_process()\n"),
		(m_is_client == true ? "client": "server")));

	packet_trace(
		EAPL("->"),
		receive_network_id,
		eap_header,
		eap_packet_length);

	if (eap_packet_length < eap_header->get_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_packet_length=0x%04x < eap_header->get_length()=0x%04x.\n"),
			eap_packet_length, eap_header->get_length()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (eap_header->get_length() < eap_header_base_c::get_header_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_SIMPLE_CONFIG_ERROR,
			(EAPL("ERROR: eap_type_simple_config_c::packet_process(): ")
			 EAPL("eap_header->get_length() < eap_header_base_c::get_header_length().\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}


	// NOTE: by disabling these calls throughput increases about 18%.
	// Disabling also decreases random seeds.
	m_am_tools->get_crypto()->add_rand_seed(
		eap_header->get_header_buffer(eap_packet_length),
		eap_packet_length);
	m_am_tools->get_crypto()->add_rand_seed_hw_ticks();

	eap_status_e status = eap_status_process_general_error;

	if ((m_is_client == true
		&& eap_header->get_code() == eap_code_request)
		|| (m_is_client == false
		&& eap_header->get_code() == eap_code_response))
	{
		if (eap_header->get_type() == eap_type_identity
			|| eap_header->get_type() == eap_expanded_type_simple_config.get_type())
		{
			eap_simple_config_header_c simple_config_header(
				m_am_tools,
				eap_header->get_header_buffer(eap_packet_length),
				eap_packet_length);

			if (eap_header->get_type() == eap_type_identity
				&& eap_header->get_code() == eap_code_request)
			{
				// EAP-Request/Identity is handled in eap_core_c.
				status = eap_status_unexpected_message;
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			else if (eap_header->get_type() == eap_type_identity
				&& eap_header->get_code() == eap_code_response
				&& eap_header->get_length() <= eap_header_base_c::get_header_length())
			{
				status = eap_status_header_corrupted;
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			else if (eap_header->get_type() == eap_expanded_type_simple_config.get_type()
				&& eap_header->get_length() < simple_config_header.get_simple_config_min_header_length())
			{
				status = eap_status_header_corrupted;
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			else if (check_received_eap_identifier(eap_header) != eap_status_ok)
			{
				status = eap_status_unexpected_message;
				eap_status_string_c status_string;
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_SIMPLE_CONFIG_ERROR,
					(EAPL("ERROR: eap_type_simple_config_c::packet_process() failed,")
					 EAPL("status %d=%s, received EAP-type 0x%08x, received EAP-code %d, ")
					 EAPL("received EAP-identifier %d, current EAP-identifier %d, state %s\n"),
					 status,
					 status_string.get_status_string(status),
					 convert_eap_type_to_u32_t(eap_header->get_type()),
					 eap_header->get_code(),
					 eap_header->get_identifier(),
					 get_last_eap_identifier(),
					 get_state_string()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			else
			{
				if (m_is_client == true)
				{
					// Client saves the received EAP-Identifier.
					set_last_eap_identifier(eap_header->get_identifier());
				}

				if (eap_header->get_type() == eap_type_identity)
				{
					status = eap_identity_response_packet_process(
						receive_network_id,
						eap_header,
						eap_packet_length);

					if (status != eap_status_ok
						&& status != eap_status_success
						&& status != eap_status_drop_packet_quietly)
					{
						eap_status_string_c status_string;

						EAP_TRACE_ERROR(
							m_am_tools,
							TRACE_FLAGS_SIMPLE_CONFIG_ERROR,
							(EAPL("ERROR: eap_type_simple_config_c::")
							 EAPL("eap_identity_response_packet_process() failed, status %d=%s\n"),
							 status, status_string.get_status_string(status)));
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
					if (status == eap_status_ok)
					{
						EAP_GENERAL_HEADER_SET_ERROR_DETECTED(eap_header, false);

						eap_state_notification_c notification(
							m_am_tools,
							get_send_network_id(),
							m_is_client,
							eap_state_notification_eap,
							eap_protocol_layer_eap,
							eap_expanded_type_simple_config.get_type(),
							eap_state_none,
							eap_state_identity_response_received,
							get_last_eap_identifier(),
							false);
						get_type_partner()->state_notification(&notification);
					}
				}
				else
				{
					status = simple_config_packet_process(
						receive_network_id,
						&simple_config_header,
						eap_packet_length);

					if (status == eap_status_ok)
					{
						EAP_GENERAL_HEADER_SET_ERROR_DETECTED(eap_header, false);
					}

					if (status != eap_status_ok
						&& status != eap_status_success
						&& status != eap_status_pending_request
						&& status != eap_status_drop_packet_quietly)
					{
						eap_status_string_c status_string;

						EAP_TRACE_ERROR(
							m_am_tools,
							TRACE_FLAGS_SIMPLE_CONFIG_ERROR,
							(EAPL("ERROR: eap_type_simple_config_c::simple_config_packet_process() ")
							 EAPL("failed, status %d=%s\n"),
							 status, status_string.get_status_string(status)));
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else if (eap_header->get_type() == eap_type_notification)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("dropped EAP type notification: code=0x%02x, identifier=0x%02x, ")
				 EAPL("length=0x%04x, type=0x%08x\n"),
				 eap_header->get_code(),
				 eap_header->get_identifier(),
				 eap_header->get_length(),
				 convert_eap_type_to_u32_t(eap_header->get_type())));

			status = eap_status_illegal_eap_type;

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("dropped EAP type unknown: code=0x%02x, identifier=0x%02x, ")
				 EAPL("length=0x%04x, type=0x%08x\n"),
				 eap_header->get_code(),
				 eap_header->get_identifier(),
				 eap_header->get_length(),
				 convert_eap_type_to_u32_t(eap_header->get_type())));

			status = eap_status_illegal_eap_type;

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (eap_header->get_code() == eap_code_success
		|| eap_header->get_code() == eap_code_failure)
	{
		// Here we swap the addresses.
		eap_am_network_id_c send_network_id(m_am_tools,
			receive_network_id->get_destination_id(),
			receive_network_id->get_source_id(),
			receive_network_id->get_type());

		if (eap_header->get_code() == eap_code_success)
		{
			if (get_state() == eap_type_simple_config_state_success)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("quietly dropped EAP-Success: code=0x%02x, identifier=0x%02x, ")
					 EAPL("length=0x%04x, state %d=%s, is client %d\n"),
					 eap_header->get_code(),
					 eap_header->get_identifier(),
					 eap_header->get_length(),
					 get_state(),
					 get_state_string(),
					 (m_is_client == true)));
				status = eap_status_drop_packet_quietly;
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("dropped EAP-Success: code=0x%02x, identifier=0x%02x, ")
					 EAPL("length=0x%04x, state %d=%s, is client %d\n"),
					 eap_header->get_code(),
					 eap_header->get_identifier(),
					 eap_header->get_length(),
					 get_state(),
					 get_state_string(),
					 (m_is_client == true)));
				status = eap_status_illegal_eap_code;
			}
		}
		else if (eap_header->get_code() == eap_code_failure)
		{
			// EAP is quite sloppy protocol.
			// Somebody just send a EAP-failure message and authentication is terminated.

			// Save received failure. We do not change our state yet.
			// The real correct EAP message could be received later if this failure was
			// send by nasty attacker.
			set_failure_message_received();
			// We handle the EAP-Request/Failure message after a timeout.

			status = eap_status_ok;
		}
		else
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("dropped EAP code unknown: code=0x%02x, identifier=0x%02x, ")
				 EAPL("length=0x%04x, is client %d\n"),
				 eap_header->get_code(),
				 eap_header->get_identifier(),
				 eap_header->get_length(),
				 (m_is_client == true)));
			status = eap_status_illegal_eap_code;
		}
	}
	else
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("dropped EAP code unknown: code=0x%02x, identifier=0x%02x, ")
			 EAPL("length=0x%04x, is client %d\n"),
			 eap_header->get_code(),
			 eap_header->get_identifier(),
			 eap_header->get_length(),
			 (m_is_client == true)));
		status = eap_status_illegal_eap_code;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::send_sc_frag_ack()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_buf_chain_wr_c eap_fragment_acknowledge_packet(
		eap_write_buffer, 
		m_am_tools, 
		SIMPLE_CONFIG_LOCAL_PACKET_BUFFER_LENGTH);

	if (eap_fragment_acknowledge_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_ASSERT_ALWAYS(SIMPLE_CONFIG_LOCAL_PACKET_BUFFER_LENGTH
					  >= (m_simple_config_header_offset+m_trailer_length));
	u32_t packet_buffer_free = SIMPLE_CONFIG_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_simple_config_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_simple_config_header_offset+m_MTU;
	}

	eap_simple_config_header_c fragment_acknowledge(
		m_am_tools,
		eap_fragment_acknowledge_packet.get_data_offset(
			m_simple_config_header_offset,
			(packet_buffer_free-m_simple_config_header_offset)),
		(packet_buffer_free-m_simple_config_header_offset));

	if (fragment_acknowledge.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	fragment_acknowledge.reset_header(
		m_am_tools,
		static_cast<u16_t>(packet_buffer_free-m_simple_config_header_offset),
		true);

	fragment_acknowledge.set_eap_length(
		static_cast<u16_t>(packet_buffer_free-m_simple_config_header_offset),
		true);

	if (m_is_client == true)
	{
		fragment_acknowledge.set_eap_code(eap_code_response);
		fragment_acknowledge.set_eap_identifier(static_cast<u8_t>(get_last_eap_identifier()));
	}
	else // if (m_is_client == false)
	{
		fragment_acknowledge.set_eap_code(eap_code_request);
		fragment_acknowledge.set_eap_identifier(static_cast<u8_t>(get_last_eap_identifier()+1u));
	}

	fragment_acknowledge.set_eap_type(
		eap_expanded_type_simple_config.get_type(),
		true);

	fragment_acknowledge.set_sc_op_code(eap_simple_config_header_c::op_code_FRAG_ACK);

	u32_t simple_config_data_offset = 0u;

	update_buffer_indexes(
		SIMPLE_CONFIG_LOCAL_PACKET_BUFFER_LENGTH,
		m_simple_config_header_offset+fragment_acknowledge.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	// No payloads.

	fragment_acknowledge.set_data_length(
		simple_config_data_offset,
		true);
	eap_fragment_acknowledge_packet.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_simple_config_header_offset
		+fragment_acknowledge.get_header_length()
		+fragment_acknowledge.get_data_length()
		== packet_buffer_offset);

	eap_status_e status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_is_client == true)
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("    send: EAP-Response/SIMPLE_CONFIG/Acknowledge packet"),
			fragment_acknowledge.get_header_buffer(fragment_acknowledge.get_eap_length()),
			fragment_acknowledge.get_eap_length()));
	}
	else // if (m_is_client == false)
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("    send: EAP-Request/SIMPLE_CONFIG/Acknowledge packet"),
			fragment_acknowledge.get_header_buffer(fragment_acknowledge.get_eap_length()),
			fragment_acknowledge.get_eap_length()));
	}

	status = packet_send(
		get_send_network_id(),
		&eap_fragment_acknowledge_packet,
		m_simple_config_header_offset,
		fragment_acknowledge.get_eap_length(),
		SIMPLE_CONFIG_LOCAL_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
		if (m_is_client == false)
		{
			// Server saves the sent EAP-Identifier.
			set_last_eap_identifier(static_cast<u8_t>(get_last_eap_identifier()+1ul));
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::send_simple_config_start_message(
	const u8_t next_eap_identifier ///< This is EAP-Identifier of next EAP packet.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_buf_chain_wr_c eap_simple_config_start_packet(
		eap_write_buffer, 
		m_am_tools, 
		SIMPLE_CONFIG_LOCAL_PACKET_BUFFER_LENGTH);

	if (eap_simple_config_start_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_ASSERT_ALWAYS(SIMPLE_CONFIG_LOCAL_PACKET_BUFFER_LENGTH
					  >= (m_simple_config_header_offset+m_trailer_length));
	u32_t packet_buffer_free = SIMPLE_CONFIG_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_simple_config_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_simple_config_header_offset+m_MTU;
	}

	eap_simple_config_header_c simple_config_start_packet(
		m_am_tools,
		eap_simple_config_start_packet.get_data_offset(
			m_simple_config_header_offset,
			(packet_buffer_free-m_simple_config_header_offset)),
		(packet_buffer_free-m_simple_config_header_offset));

	if (simple_config_start_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	simple_config_start_packet.reset_header(
		m_am_tools,
		static_cast<u16_t>(packet_buffer_free-m_simple_config_header_offset),
		true);

	simple_config_start_packet.set_flag_simple_config_length_included(false);

	simple_config_start_packet.set_eap_length(
		static_cast<u16_t>(
			packet_buffer_free-m_simple_config_header_offset),
		true);

	simple_config_start_packet.set_eap_code(eap_code_request);
	simple_config_start_packet.set_eap_identifier(next_eap_identifier);
	simple_config_start_packet.set_eap_type(
		eap_expanded_type_simple_config.get_type(),
		true);
	simple_config_start_packet.set_sc_op_code(eap_simple_config_header_c::op_code_WSC_Start);

	update_buffer_indexes(
		SIMPLE_CONFIG_LOCAL_PACKET_BUFFER_LENGTH,
		m_simple_config_header_offset+simple_config_start_packet.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	simple_config_start_packet.set_data_length(
		0ul,
		true);
	eap_simple_config_start_packet.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_simple_config_header_offset+simple_config_start_packet.get_header_length()
		+simple_config_start_packet.get_data_length()
		== packet_buffer_offset);

	eap_status_e status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("    send: EAP-Request/SIMPLE_CONFIG/Start packet"),
		simple_config_start_packet.get_header_buffer(simple_config_start_packet.get_eap_length()),
		simple_config_start_packet.get_eap_length()));

	status = packet_send(
		get_send_network_id(),
		&eap_simple_config_start_packet,
		m_simple_config_header_offset,
		simple_config_start_packet.get_eap_length(),
		SIMPLE_CONFIG_LOCAL_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
		if (m_is_client == false)
		{
			// Server saves the sent EAP-Identifier.
			set_last_eap_identifier(next_eap_identifier);

			set_state(eap_type_simple_config_state_waiting_for_response);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::start_simple_config_authentication(
	const eap_am_network_id_c * const /*receive_network_id*/, ///< This is the network identity of the received EAP packet.
	const eap_variable_data_c * const NAI ///< This is the full NAI of the client.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_simple_config_record->start_simple_config_authentication(NAI);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::eap_simple_config_fragment_send()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_not_supported;

	if (m_simple_config_message_send_offset == 0ul
		&& m_simple_config_message_buffer.get_data_length()
		< simple_config_tlv_header_c::get_header_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_simple_config_fragment_send(): ")
			 EAPL("packet buffer too short, %d bytes.\n"),
			m_simple_config_message_buffer.get_data_length()));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	else if (m_simple_config_message_buffer.get_data_length()
			 < m_simple_config_message_send_offset)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_simple_config_fragment_send(): ")
			 EAPL("packet buffer %d shorter than ")
			 EAPL("m_simple_config_message_send_offset %d.\n"),
			 m_simple_config_message_buffer.get_data_length(),
			 m_simple_config_message_send_offset));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}


	eap_buf_chain_wr_c eap_simple_config_fragment(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (eap_simple_config_fragment.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_ASSERT_ALWAYS(EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH
					  >= (m_simple_config_header_offset+m_trailer_length));
	u32_t packet_buffer_free
		= EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_simple_config_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_simple_config_header_offset+m_MTU;
	}

	u32_t packet_eap_data_free
		= packet_buffer_free
		- m_simple_config_header_offset
		- eap_simple_config_header_c::get_simple_config_max_header_length();

	eap_simple_config_header_c eap_simple_config_packet(
		m_am_tools,
		eap_simple_config_fragment.get_data_offset(
			m_simple_config_header_offset,
			packet_eap_data_free),
		packet_eap_data_free);

	if (eap_simple_config_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	eap_simple_config_packet.reset_header(
		m_am_tools,
		static_cast<u16_t>(packet_eap_data_free),
		true);
	if (m_simple_config_message_send_offset == 0)
	{
		// This is the first fragment.
		eap_simple_config_packet.set_flag_simple_config_length_included(true);
		eap_simple_config_packet.set_simple_config_message_length(
			m_simple_config_message_buffer.get_data_length());
	}

	eap_simple_config_packet.set_eap_length(
		static_cast<u16_t>(packet_eap_data_free),
		true);

	if (m_is_client == true)
	{
		eap_simple_config_packet.set_eap_code(eap_code_response);
		eap_simple_config_packet.set_eap_identifier(get_last_eap_identifier());
	}
	else
	{
		eap_simple_config_packet.set_eap_code(eap_code_request);
		eap_simple_config_packet.set_eap_identifier(
			static_cast<u8_t>(get_last_eap_identifier()+1ul));
	}
	
	// --------------------------------------------------------------------
	
	eap_simple_config_trace_string_c message_string;
	  
    EAP_TRACE_DEBUG(
        m_am_tools,
        TRACE_FLAGS_DEFAULT,
        (EAPL("eap_simple_config_fragment_send: %s: message type: %s\n"),
        (m_is_client == true ? "client": "server"),
        message_string.get_message_type_string(m_simple_config_message_type)));
    
    EAP_UNREFERENCED_PARAMETER(message_string); // for release
	
	// Set Op-Code based on the message type
	if( m_simple_config_message_type == simple_config_Message_Type_None 
	        || m_simple_config_message_type == simple_config_Message_Type_Beacon
	        || m_simple_config_message_type == simple_config_Message_Type_Probe_Request
	        || m_simple_config_message_type == simple_config_Message_Type_Probe_Response
	        || m_simple_config_message_type > simple_config_Message_keep_this_last )
    {
        // Something is wrong
        EAP_TRACE_ERROR(
            m_am_tools,
            TRACE_FLAGS_DEFAULT,
            (EAPL("eap_simple_config_fragment_send: invalid message type, cannot set Op-Code correctly.\n")));
        return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
    }
	else if( m_simple_config_message_type == simple_config_Message_Type_WSC_ACK )
	{
	    eap_simple_config_packet.set_sc_op_code(eap_simple_config_header_c::op_code_WSC_ACK);
	}  
	else if( m_simple_config_message_type == simple_config_Message_Type_WSC_NACK )
	{
	    eap_simple_config_packet.set_sc_op_code(eap_simple_config_header_c::op_code_WSC_NACK);
	}
    else if( m_simple_config_message_type == simple_config_Message_Type_WSC_DONE )
    {
        eap_simple_config_packet.set_sc_op_code(eap_simple_config_header_c::op_code_WSC_Done);  
    }
	else 
	{
	    // In other cases this is a WSC message
	    eap_simple_config_packet.set_sc_op_code(eap_simple_config_header_c::op_code_WSC_MSG);
	}
	
	// --------------------------------------------------------------------
	
	eap_simple_config_packet.set_eap_type(
		eap_expanded_type_simple_config.get_type(),
		true);


	u32_t fragment_length
		= m_MTU
		- eap_simple_config_header_c::get_simple_config_max_header_length();
	u32_t pending_message_length
		= m_simple_config_message_buffer.get_data_length()
		- m_simple_config_message_send_offset;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP-SIMPLE_CONFIG fragment: packet_eap_data_free %d, ")
		 EAPL("fragment_length %d, pending_message_length %d, ")
		 EAPL("EAP-header length %d, buffer length %d\n"),
		 packet_eap_data_free,
		 fragment_length,
		 pending_message_length,
		 eap_simple_config_packet.get_header_length(),
		 eap_simple_config_fragment.get_buffer_length()));

	if (packet_eap_data_free >= pending_message_length)
	{
		// Message data is less than the buffer length,
		// so the fragment is only length of the message data.
		fragment_length = pending_message_length;

		// SIMPLE_CONFIG-message length is not included,
		// because no fragmentation is used.
		eap_simple_config_packet.set_flag_simple_config_length_included(false);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP-SIMPLE_CONFIG fragment: packet_eap_data_free %d, ")
			 EAPL("fragment_length %d, pending_message_length %d, ")
			 EAPL("EAP-header length %d\n"),
			 packet_eap_data_free,
			 fragment_length,
			 pending_message_length,
			 eap_simple_config_packet.get_header_length()));
	}

	if (fragment_length < pending_message_length)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP-SIMPLE_CONFIG fragment: more fragments follow. ")
			 EAPL("fragment_length %d, pending_message_length %d, ")
			 EAPL("EAP-header length %d\n"),
			 fragment_length,
			 pending_message_length,
			 eap_simple_config_packet.get_header_length()));

		if (m_simple_config_message_send_offset == 0)
		{
			// SIMPLE_CONFIG-message length is included,
			eap_simple_config_packet.set_flag_simple_config_length_included(true);
		}

		eap_simple_config_packet.set_flag_more_fragments(true);
	}


	update_buffer_indexes(
		SIMPLE_CONFIG_LOCAL_PACKET_BUFFER_LENGTH,
		m_simple_config_header_offset+eap_simple_config_packet.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	status = eap_simple_config_fragment.set_data_length(packet_buffer_offset);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -
	// Payload is SIMPLE_CONFIG-message fragment.

	status = eap_simple_config_fragment.add_data_to_offset(
		packet_buffer_offset,
		m_simple_config_message_buffer.get_data_offset(
			m_simple_config_message_send_offset, fragment_length),
		fragment_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	update_buffer_indexes(
		SIMPLE_CONFIG_LOCAL_PACKET_BUFFER_LENGTH,
		fragment_length,
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_simple_config_packet.set_data_length(
		fragment_length,
		true);

	status = eap_simple_config_fragment.set_data_length(packet_buffer_offset);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_simple_config_fragment_send(): m_simple_config_header_offset %d ")
		 EAPL("+ eap_simple_config_packet.get_header_length()")
		 EAPL("%d + eap_simple_config_packet.get_data_length() ")
		 EAPL("%d = %d == packet_buffer_offset %d.\n"),
		 m_simple_config_header_offset,
		 eap_simple_config_packet.get_header_length(),
		 eap_simple_config_packet.get_data_length(),
		 (m_simple_config_header_offset
		  + eap_simple_config_packet.get_header_length()
		  + eap_simple_config_packet.get_data_length()),
		 packet_buffer_offset));

	EAP_ASSERT_ALWAYS(
		m_simple_config_header_offset
		+eap_simple_config_packet.get_header_length()
		+eap_simple_config_packet.get_data_length()
		== packet_buffer_offset);

	status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	status = packet_send(
		get_send_network_id(),
		&eap_simple_config_fragment,
		m_simple_config_header_offset,
		eap_simple_config_packet.get_eap_length(),
		SIMPLE_CONFIG_LOCAL_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
		m_simple_config_message_send_offset += fragment_length;

		if (m_is_client == false)
		{
			// Server saves the sent EAP-Identifier.
			set_last_eap_identifier(
				static_cast<u8_t>(get_last_eap_identifier()+1ul));
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::simple_config_message_process(
	const eap_am_network_id_c * const /*receive_network_id*/, ///< This is the network identity of the received EAP packet.
	eap_simple_config_header_c * const received_simple_config, ///< This is pointer to EAP header including EAP-SIMPLE_CONFIG fields.
	const u32_t /*simple_config_packet_length*/ ///< This is length of received EAP-SIMPLE_CONFIG packet.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_simple_config_message_buffer.get_is_valid_data() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("simple_config_message_process: packet buffer invalid.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	if (m_simple_config_message_buffer.get_data_length()
		< simple_config_tlv_header_c::get_header_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("simple_config_message_process: packet buffer too short, %d bytes.\n"),
			m_simple_config_message_buffer.get_data_length()));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	save_current_state();
	set_state(eap_type_simple_config_state_process_simple_config_message);

	eap_status_e status = m_simple_config_record->packet_process(
		&m_simple_config_message_buffer,
		received_simple_config->get_eap_identifier());

	if (status == eap_status_ok)
	{
		// Do nothing.
	}
	else if (status == eap_status_pending_request)
	{
		// Asyncronous operation is pending.
		// Do nothing.
	}
	else if (status == eap_status_success)
	{
		// Authentication OK.
		// Do nothing.
	}
	else if (status == eap_status_drop_packet_quietly)
	{
		// Dropped packet.
		// Do nothing.
	}
	else
	{
		// All other return values are ERROR. Authentication is failed.

		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("%s: simple_config_message_process: Authentication failed.\n"),
			(m_is_client == true) ? "client": "server"));

		restore_saved_previous_state();
		set_state(eap_type_simple_config_state_failure);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::eap_identity_response_packet_process(
	const eap_am_network_id_c * const /*receive_network_id*/, ///< This is the network identity of the received EAP packet.
	eap_header_wr_c * const eap_header, ///< This is pointer to EAP header and data.
	const u32_t eap_packet_length ///< This is length of received EAP packet.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_SIMPLE_CONFIG: %s: function: eap_identity_response_packet_process()\n"),
		(m_is_client == true ? "client": "server")));

	if (eap_header->check_header() != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	else if (eap_header->get_length() > eap_packet_length)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}


	if (m_check_identifier_of_eap_identity_response == true)
	{
		if (m_state == eap_type_simple_config_state_waiting_for_identity_response
			&& eap_header->get_identifier() != get_last_eap_identifier())
		{
			// Wrong EAP-Identifier in this state.
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_SIMPLE_CONFIG_ERROR,
				(EAPL("ERROR: eap_type_simple_config_c::handle_identity_response_message(): ")
				 EAPL("EAP-Identifier 0x%02x is wrong (0x%02x is correct) in ")
				 EAPL("eap_type_simple_config_state_variable_e %d=%s.\n"),
				 eap_header->get_identifier(),
				 get_last_eap_identifier(),
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}
		else if (m_simple_config_test_version == true
			&& m_state == eap_type_simple_config_state_success) // This one is for testing purposes.
		{
			// NOTE here we can not check the EAP-identifier.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: eap_type_simple_config_c::handle_identity_response_message(): ")
				 EAPL("EAP-Identifier 0x%02x is not checked in ")
				 EAPL("eap_type_simple_config_state_variable_e %d=%s.\n"),
				 eap_header->get_identifier(),
				 get_state(),
				 get_state_string()));
		}
	}


	if (m_state == eap_type_simple_config_state_waiting_for_identity_response
		|| (m_simple_config_test_version == true
			// In test version new authentication could start from this state.
			&& m_state == eap_type_simple_config_state_success))
	{
		// EAP-Response/Identity is accepted only as a very first message.

		eap_status_e status = eap_status_process_general_error;

		save_current_state();

		// In test version new authentication could start from this state.
		if (m_simple_config_test_version == true
			&& m_state == eap_type_simple_config_state_success) // This one is for testing purposes.
		{
			// NOTE here we can not check the EAP-identifier.
			set_state(eap_type_simple_config_state_waiting_for_identity_response);
		}

		u8_t next_eap_identifier = static_cast<u8_t>(eap_header->get_identifier()+1u);

		status = parse_identity(
			eap_header->get_type_data(
				eap_header->get_type_data_length()),
			eap_header->get_type_data_length());
		if (status != eap_status_ok)
		{
			restore_saved_previous_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_simple_config_start_message(next_eap_identifier);
		if (status != eap_status_ok)
		{
			restore_saved_previous_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		set_last_eap_identifier(next_eap_identifier);
		set_state(eap_type_simple_config_state_waiting_for_response);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: eap_type_simple_config_c::handle_identity_response_message(): ")
			 EAPL("EAP-Identifier 0x%02x in eap_type_simple_config_state_variable_e %d=%s. ")
			 EAPL("EAP-Response/Identity is accepted only in ")
			 EAPL("eap_type_simple_config_state_waiting_for_identity_response.\n"),
			 eap_header->get_identifier(),
			 get_state(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::simple_config_packet_process(
	const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
	eap_simple_config_header_c * const received_simple_config, ///< This is pointer to EAP header including EAP-SIMPLE_CONFIG fields.
	const u32_t simple_config_packet_length ///< This is length of received EAP-SIMPLE_CONFIG packet.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_SIMPLE_CONFIG: %s: function: simple_config_packet_process()\n"),
		(m_is_client == true ? "client": "server")));

	if (m_simple_config_test_version == true
		&& get_state() == eap_type_simple_config_state_failure)
	{
		// This is for testing.
		if (m_is_client == false
			&& received_simple_config->get_eap_code() == eap_code_response
			&& received_simple_config->get_eap_type() == eap_type_identity)
		{
			set_state(eap_type_simple_config_state_waiting_for_identity_response);
		}
		else if (m_is_client == true
			&& received_simple_config->get_sc_op_code() == eap_simple_config_header_c::op_code_WSC_Start)
		{
			set_state(eap_type_simple_config_state_waiting_for_simple_config_start);
		}
	}

	if (received_simple_config->check_header(
			m_am_tools,
			m_is_client) != eap_status_ok)
	{
		// ERROR: EAP-SIMPLE_CONFIG header is corrupted.
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_SIMPLE_CONFIG_ERROR,
			(EAPL("ERROR: eap_type_simple_config_c::simple_config_packet_process(): ")
			 EAPL("EAP-SIMPLE_CONFIG header is corrupted in ")
			 EAPL("eap_type_simple_config_state_variable_e %d=%s.\n"),
			get_state(),
			get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	else if (received_simple_config->get_eap_length() > simple_config_packet_length)
	{
		// ERROR: EAP-Lenght field value is larger than actual received packet.
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_SIMPLE_CONFIG_ERROR,
			(EAPL("ERROR: eap_type_simple_config_c::simple_config_packet_process(): ")
			 EAPL("EAP-Lenght field %d value is larger than actual received ")
			 EAPL("packet %d in eap_type_simple_config_state_variable_e %d=%s.\n"),
			received_simple_config->get_eap_length(),
			simple_config_packet_length,
			get_state(),
			get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	else if (m_is_client == false
		&& received_simple_config->get_sc_op_code() == eap_simple_config_header_c::op_code_WSC_Start)
	{
		// ERROR: Server cannot receive EAP-SIMPLE_CONFIG Start message.
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_SIMPLE_CONFIG_ERROR,
			(EAPL("ERROR: eap_type_simple_config_c::simple_config_packet_process(): ")
			 EAPL("Server cannot receive EAP-SIMPLE_CONFIG Start message. ")
			 EAPL("eap_type_simple_config_state_variable_e %d=%s.\n"),
			get_state(),
			get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}
	else if (m_is_client == true
		&& (get_state() != eap_type_simple_config_state_waiting_for_request
			&& get_state() != eap_type_simple_config_state_waiting_for_identity_request
			// EAP-SIMPLE_CONFIG could start without EAP-Request/Identity message.
			&& get_state() != eap_type_simple_config_state_waiting_for_simple_config_start
			))
	{
		// ERROR: Client cannot receive EAP-SIMPLE_CONFIG message in other states.
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: eap_type_simple_config_c::simple_config_packet_process(): ")
			 EAPL("Client cannot receive EAP-SIMPLE_CONFIG message in ")
			 EAPL("eap_type_simple_config_state_variable_e %d=%s.\n"),
			get_state(),
			get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	else if (m_is_client == false
		&& get_state() != eap_type_simple_config_state_waiting_for_response
		)
	{
		// WARNING: Server cannot receive EAP-SIMPLE_CONFIG message in other states.
		// This packet is dropped quietly.
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: eap_type_simple_config_c::simple_config_packet_process(): ")
			 EAPL("Server cannot receive EAP-SIMPLE_CONFIG message in ")
			 EAPL("eap_type_simple_config_state_variable_e %d=%s.\n"),
			get_state(),
			get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	else if (received_simple_config->get_sc_op_code() == eap_simple_config_header_c::op_code_WSC_Start
		&& get_state() != eap_type_simple_config_state_waiting_for_simple_config_start
		&& get_state() != eap_type_simple_config_state_waiting_for_identity_request)
		// EAP-SIMPLE_CONFIG could start without EAP-Request/Identity message.
	{
		// ERROR: EAP-SIMPLE_CONFIG Start message is accepted only in
		// eap_type_simple_config_state_waiting_for_simple_config_start.
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_SIMPLE_CONFIG_ERROR,
			(EAPL("ERROR: eap_type_simple_config_c::simple_config_packet_process(): ")
			 EAPL("EAP-SIMPLE_CONFIG Start message is NOT accepted in ")
			 EAPL("eap_type_simple_config_state_variable_e %d=%s.\n"),
			get_state(),
			get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	// EAP-SIMPLE_CONFIG and PEAP fragmentation support:
	// 
	// Flags include the Length included (L), More fragments (M), and EAP-SIMPLE_CONFIG Start (S) bits.
	// 
	// The L flag is set to indicate the presence of the four octet SIMPLE_CONFIG Message
	// Length field, and MUST be set for the first fragment of a fragmented
	// SIMPLE_CONFIG message or set of messages.
	// 
	// The M flag is set on all but the last fragment.
	// 
	// The S flag is set only within the EAP-SIMPLE_CONFIG start message
	// sent from the EAP server to the peer. This differentiates
	// the EAP-SIMPLE_CONFIG Start message from a fragment acknowledgement.
	// 
	// The SIMPLE_CONFIG Message Length field is four octets, and provides
	// the total length of the SIMPLE_CONFIG message or set of messages
	// that is being fragmented. This simplifies buffer allocation.

	eap_status_e status = eap_status_process_general_error;

	save_current_reassembly_state();

	if (get_reassembly_state() == eap_type_simple_config_reassembly_state_wait_first_message)
	{
		if (received_simple_config->get_flag_more_fragments() == true
			&& received_simple_config->get_flag_simple_config_length_included() == false)
		{
			// The first fragmented message must include SIMPLE_CONFIG-length field.
			restore_saved_reassembly_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}


		bool first_fragment = false;
		u32_t simple_config_message_length = 0ul;

		if (received_simple_config->get_flag_simple_config_length_included() == true)
		{
			// This is the first fragment and SIMPLE_CONFIG message length is included.
			// We must allocate buffer for the fragments.

			status = received_simple_config->get_simple_config_message_length(&simple_config_message_length);
			if (status != eap_status_ok)
			{
				restore_saved_reassembly_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			first_fragment = true;
		}
		else if (received_simple_config->get_flag_more_fragments() == false
			&& received_simple_config->get_sc_op_code() != eap_simple_config_header_c::op_code_WSC_Start
			&& received_simple_config->get_data_length() > 0ul)
		{
			// This is the individual message and SIMPLE_CONFIG message length is not included.
			// We must allocate buffer for the message.

			simple_config_message_length = received_simple_config->get_data_length();

			first_fragment = true;
		}


		if (first_fragment == true)
		{
			m_simple_config_message_buffer.reset();

			if (simple_config_message_length > 0ul)
			{
				if (simple_config_message_length > EAP_SIMPLE_CONFIG_MAX_MESSAGE_LENGTH)
				{
					restore_saved_reassembly_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_too_long_message);
				}

				// Next allocate buffer for reassembled SIMPLE_CONFIG-message.
				status = m_simple_config_message_buffer.set_buffer_length(simple_config_message_length);
				if (status != eap_status_ok)
				{
					restore_saved_reassembly_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				// Copy first fragment to the reassembly buffer.
				status = m_simple_config_message_buffer.add_data(
					received_simple_config->get_data(m_am_tools, received_simple_config->get_data_length()),
					received_simple_config->get_data_length());
				if (status != eap_status_ok)
				{
					restore_saved_reassembly_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				m_first_fragment_eap_identifier = received_simple_config->get_eap_identifier();
			}
		}


		if (received_simple_config->get_flag_more_fragments() == true)
		{
			// This is NOT the last fragment.

			// Send fragment acknowledge message.
			status = send_sc_frag_ack();
			if (status != eap_status_ok)
			{
				restore_saved_reassembly_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// Change reassembly state.
			set_reassembly_state(eap_type_simple_config_reassembly_state_wait_last_fragment);
		}
		else
		{
			// This is the last fragment or non fragmented message.
			// Change reassembly state.
			set_reassembly_state(eap_type_simple_config_reassembly_state_message_reassembled);

			if (received_simple_config->get_sc_op_code() == eap_simple_config_header_c::op_code_FRAG_ACK)
			{
				// This is EAP-SIMPLE_CONFIG fragment acknowledge.
				if (m_simple_config_message_buffer.get_is_valid_data() == true
					&& m_simple_config_message_send_offset < m_simple_config_message_buffer.get_data_length())
				{
					// We can send next fragment.

					save_current_state();
					set_state(eap_type_simple_config_state_process_simple_config_message);

					status = eap_simple_config_fragment_send();
					if (status != eap_status_ok)
					{
						restore_saved_previous_state();
						restore_saved_reassembly_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
					
					if (m_is_client == true)
					{
						set_state(eap_type_simple_config_state_waiting_for_request);
					}
					else
					{
						set_state(eap_type_simple_config_state_waiting_for_response);
					}
				}
				else
				{
					// No fragment available. Drop this packet.
					restore_saved_reassembly_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
				}
			}
			else if (received_simple_config->get_sc_op_code() == eap_simple_config_header_c::op_code_WSC_Start)
			{
				if (get_state() == eap_type_simple_config_state_waiting_for_simple_config_start)
				{
					// This is EAP-SIMPLE_CONFIG Start message.
					save_current_state();
					set_state(eap_type_simple_config_state_process_simple_config_start);

					if (get_NAI()->get_is_valid_data() == false)
					{
						status = get_type_partner()->get_saved_eap_identity(get_NAI());
						if (status != eap_status_ok)
						{
							restore_saved_previous_state();
							restore_saved_reassembly_state();
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}

					status = start_simple_config_authentication(receive_network_id, get_NAI());
					if (status == eap_status_pending_request)
					{
						// Do nothing.
					}
					else if (status != eap_status_ok)
					{
						restore_saved_previous_state();
						restore_saved_reassembly_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
					else
					{
						// OK.
						set_reassembly_state(eap_type_simple_config_reassembly_state_wait_first_message);
					}
				}
				else
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_SIMPLE_CONFIG_ERROR,
						(EAPL("ERROR: eap_type_simple_config_c::simple_config_packet_process(): ")
						 EAPL("Cannot receive EAP-SIMPLE_CONFIG message in ")
						 EAPL("eap_type_simple_config_state_variable_e %d=%s, ")
						 EAPL("eap_type_simple_config_reassembly_state_e %d=%s.\n"),
						 get_state(),
						 get_state_string(),
						 get_reassembly_state(),
						 get_reassembly_state_string()));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
				}
			}
			else
			{
				status = received_simple_config->check_header(
					m_am_tools,
					m_is_client);
				if (status != eap_status_ok)
				{
					restore_saved_reassembly_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				// Process the reassembled SIMPLE_CONFIG message.
				status = simple_config_message_process(
					receive_network_id,
					received_simple_config,
					simple_config_packet_length);

				if (status != eap_status_ok
					&& status != eap_status_pending_request
					&& status != eap_status_success)
				{
					restore_saved_reassembly_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}

			set_reassembly_state(eap_type_simple_config_reassembly_state_wait_first_message);
		}
	}
	else if (get_reassembly_state() == eap_type_simple_config_reassembly_state_wait_last_fragment)
	{
		// SIMPLE_CONFIG message length field may or may not be included.

		EAP_ASSERT_ALWAYS(received_simple_config->get_sc_op_code() != eap_simple_config_header_c::op_code_WSC_Start);

		// Concatenate fragment to the reassembly buffer.
		status = m_simple_config_message_buffer.add_data(
			received_simple_config->get_data(m_am_tools, received_simple_config->get_data_length()),
			received_simple_config->get_data_length());
		if (status != eap_status_ok)
		{
			restore_saved_reassembly_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (received_simple_config->get_flag_more_fragments() == true)
		{
			// This is NOT the last fragment.

			// Send fragment acknowledge message.
			status = send_sc_frag_ack();
			if (status != eap_status_ok)
			{
				restore_saved_reassembly_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			// This is the last fragment.
			// Change reassembly state.
			set_reassembly_state(eap_type_simple_config_reassembly_state_message_reassembled);

			// Process the reassembled SIMPLE_CONFIG message.
			status = simple_config_message_process(
				receive_network_id,
				received_simple_config,
				simple_config_packet_length);

			if (status != eap_status_ok
				&& status != eap_status_pending_request
				&& status != eap_status_success)
			{
				restore_saved_reassembly_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			set_reassembly_state(eap_type_simple_config_reassembly_state_wait_first_message);
		}
	}
	else if (get_reassembly_state() == eap_type_simple_config_reassembly_state_message_reassembled)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_SIMPLE_CONFIG_ERROR,
			(EAPL("ERROR: eap_type_simple_config_c::simple_config_packet_process(): ")
			 EAPL("Cannot receive EAP-SIMPLE_CONFIG message in ")
			 EAPL("eap_type_simple_config_state_variable_e %d=%s, ")
			 EAPL("eap_type_simple_config_reassembly_state_e %d=%s.\n"),
			 get_state(),
			 get_state_string(),
			 get_reassembly_state(),
			 get_reassembly_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}
	else
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_SIMPLE_CONFIG_ERROR,
			(EAPL("ERROR: eap_type_simple_config_c::simple_config_packet_process(): ")
			 EAPL("Cannot receive EAP-SIMPLE_CONFIG message in ")
			 EAPL("eap_type_simple_config_state_variable_e %d=%s, ")
			 EAPL("eap_type_simple_config_reassembly_state_e %d=%s.\n"),
			 get_state(),
			 get_state_string(),
			 get_reassembly_state(),
			 get_reassembly_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u32_t eap_type_simple_config_c::get_header_offset(
	u32_t * const MTU,
	u32_t * const trailer_length
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Note, EAP-SIMPLE_CONFIG and PEAP supports fragmentation.
	// Here we could tell the MTU is big enough, the maximum memory buffer size is perfect.

	if (MTU != 0)
	{
		*MTU = EAP_SIMPLE_CONFIG_MAX_MESSAGE_LENGTH;
	}

	if (trailer_length != 0)
	{
		*trailer_length = 0ul;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return 0ul; // This is the header offset of the SIMPLE_CONFIG-record header.
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::timer_expired(
	const u32_t /*id*/, void * /*data*/
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::timer_delete_data(
	const u32_t /*id*/, void * /*data*/
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_simple_config_c::set_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_is_valid = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eap_type_simple_config_c::get_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_valid;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	status = m_am_type_simple_config->configure();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_simple_config_record->configure();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c check_identifier_of_eap_identity_response(m_am_tools);

		status = read_configure(
			cf_str_EAP_SIMPLE_CONFIG_check_identifier_of_eap_identity_response.get_field(),
			&check_identifier_of_eap_identity_response);

		if (status == eap_status_ok
			&& check_identifier_of_eap_identity_response.get_is_valid_data() == true)
		{
			u32_t *flag = reinterpret_cast<u32_t *>(
				check_identifier_of_eap_identity_response.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_check_identifier_of_eap_identity_response = false;
				}
				else
				{
					m_check_identifier_of_eap_identity_response = true;
				}
			}
			else
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_SIMPLE_CONFIG_ERROR,
					(EAPL("ERROR: illegal configuration value %s\n"),
					 cf_str_EAP_SIMPLE_CONFIG_check_identifier_of_eap_identity_response
					 .get_field()->get_field()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c EAP_SIMPLE_CONFIG_check_nai_realm(m_am_tools);

		status = read_configure(
			cf_str_EAP_SIMPLE_CONFIG_check_nai_realm.get_field(),
			&EAP_SIMPLE_CONFIG_check_nai_realm);
		if (status == eap_status_ok
			&& EAP_SIMPLE_CONFIG_check_nai_realm.get_is_valid_data() == true)
		{
			u32_t *check_nai_realm = reinterpret_cast<u32_t *>(
				EAP_SIMPLE_CONFIG_check_nai_realm.get_data(sizeof(u32_t)));
			if (check_nai_realm != 0
				&& *check_nai_realm != 0)
			{
				m_check_nai_realm = true;
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c test_version(m_am_tools);

		status = read_configure(
			cf_str_EAP_SIMPLE_CONFIG_test_version.get_field(),
			&test_version);
		if (status == eap_status_ok
			&& test_version.get_is_valid_data() == true
			&& test_version.get_data_length() == sizeof(u32_t)
			&& test_version.get_data(sizeof(u32_t)) != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(test_version.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_simple_config_test_version = false;
				}
				else
				{
					m_simple_config_test_version = true;
				}
			}
		}
	}

	//----------------------------------------------------------

	m_simple_config_header_offset = get_type_partner()->get_header_offset(
		&m_MTU, &m_trailer_length);

	if (m_simple_config_header_offset+m_MTU+m_trailer_length > SIMPLE_CONFIG_LOCAL_PACKET_BUFFER_LENGTH)
	{
		EAP_ASSERT_ALWAYS(SIMPLE_CONFIG_LOCAL_PACKET_BUFFER_LENGTH
						  >= (m_simple_config_header_offset+m_trailer_length));

		m_MTU = SIMPLE_CONFIG_LOCAL_PACKET_BUFFER_LENGTH
			- (m_simple_config_header_offset+m_trailer_length);
	}

	//----------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: function: eap_type_simple_config_c::shutdown(): this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));

	if (m_shutdown_was_called == true)
	{
		// Shutdown was already called (this prevents looping forever)
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	m_shutdown_was_called = true;

	send_final_notification();
	
	// Here we ignore return value. Both shutdown() calls must be done.
	eap_status_e status = m_simple_config_record->shutdown();

	status = m_am_type_simple_config->shutdown();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// NOTE this will be read from AM of EAP-SIMPLE_CONFIG type.
	eap_status_e status = m_am_type_simple_config->type_configure_read(field, data);
	if (status != eap_status_ok)
	{
		// EAP-SIMPLE_CONFIG AM did not have configuration parameter.
		// Let's try the global configuration.
		status = get_type_partner()->read_configure(field, data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: eap_type_simple_config_c::read_configure(): ")
				 EAPL("unknown configuration parameter"),
				field->get_field(),
				field->get_field_length()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::write_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// NOTE this will be read from AM of EAP-SIMPLE_CONFIG type.
	const eap_status_e status = m_am_type_simple_config->type_configure_write(field, data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_simple_config_c::state_notification(
	const abs_eap_state_notification_c * const state
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (state->get_protocol_layer() == eap_protocol_layer_general)
	{
		// Just forward these notifications to lower layers.

		if (state->get_eap_type() == eap_type_none)
		{
			// NOTE, here we set the EAP-type.
			eap_state_notification_c notification(
				m_am_tools,
				state->get_send_network_id(),
				state->get_is_client(),
				eap_state_notification_eap,
				state->get_protocol_layer(),
				eap_expanded_type_simple_config.get_type(),
				state->get_previous_state(),
				state->get_current_state(),
				state->get_eap_identifier(),
				false);

			notification.set_authentication_error(state->get_authentication_error());

			get_type_partner()->state_notification(&notification);
		}
		else
		{
			get_type_partner()->state_notification(state);
		}

		return;
	}


	if (state->get_protocol_layer() == eap_protocol_layer_eap)
	{
		if (state->get_current_state() == eap_state_authentication_terminated_unsuccessfully)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: %s: eap_type_simple_config_c::state_notification(): ")
				 EAPL("authentication failed: EAP-type 0x%08x\n"),
				 (m_is_client == true ? "client": "server"),
				 convert_eap_type_to_u32_t(eap_expanded_type_simple_config.get_type())));

			// Here we must change the EAP-type of the notification.
			{
				eap_state_notification_c notification(
					m_am_tools,
					state->get_send_network_id(),
					state->get_is_client(),
					eap_state_notification_eap,
					state->get_protocol_layer(),
					eap_expanded_type_simple_config.get_type(),
					state->get_previous_state(),
					eap_state_authentication_terminated_unsuccessfully,
					state->get_eap_identifier(),
					false);

				notification.set_authentication_error(eap_status_authentication_failure);

				get_type_partner()->state_notification(&notification);
			}
		}
		else if (state->get_current_state() == eap_state_authentication_finished_successfully)
		{
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: eap_type_simple_config_c::state_notification(): ")
				 EAPL("authentication EAP-SUCCESS: EAP-type 0x%08x\n"),
				 (m_is_client == true ? "client": "server"),
				 convert_eap_type_to_u32_t(eap_expanded_type_simple_config.get_type())));

			(void) finish_successful_authentication();
		}
	}
	else if (state->get_protocol_layer() == eap_protocol_layer_internal_type)
	{
		eap_simple_config_trace_string_c simple_config_trace;

		if (state->get_current_state() == simple_config_state_failure)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: eap_type_simple_config_c::state_notification(): SIMPLE_CONFIG tunneled ")
				 EAPL("authentication failed: EAP-type 0x%08x\n"),
				 (m_is_client == true ? "client": "server"),
				 convert_eap_type_to_u32_t(eap_expanded_type_simple_config.get_type())));

			set_state(eap_type_simple_config_state_failure);
		}
		else if (state->get_current_state() == simple_config_state_simple_config_success)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: eap_type_simple_config_c::state_notification(): ")
				 EAPL("SIMPLE_CONFIG authentication ")
				 EAPL("EAP-SUCCESS: EAP-type 0x%08x\n"),
				 (m_is_client == true ? "client": "server"),
				 convert_eap_type_to_u32_t(eap_expanded_type_simple_config.get_type())));
		}
		else if (state->get_current_state() == simple_config_state_pending_simple_config_messages_processed)
		{
			if (get_state() == eap_type_simple_config_state_process_simple_config_message
				|| get_state() == eap_type_simple_config_state_process_simple_config_start)
			{
				if (m_is_client == true)
				{
					set_state(eap_type_simple_config_state_waiting_for_request);
				}
				else
				{
					set_state(eap_type_simple_config_state_waiting_for_response);
				}
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::query_eap_identity(
	const bool /* must_be_synchronous */,
	eap_variable_data_c * const identity,
	const eap_am_network_id_c * const receive_network_id,
	const u8_t eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_simple_config_c::query_eap_identity() ")
		 EAPL("in eap_type_simple_config_state_variable_e %d=%s.\n"),
		 get_state(),
		 get_state_string()));

	if (m_simple_config_test_version == true
		&& get_state() == eap_type_simple_config_state_failure)
	{
		// This is for testing.
		if (m_is_client == false)
		{
			set_state(eap_type_simple_config_state_waiting_for_identity_response);
		}
		else if (m_is_client == true)
		{
			set_state(eap_type_simple_config_state_waiting_for_simple_config_start);
		}
	}


	bool use_manual_username(false);
	eap_variable_data_c manual_username(m_am_tools);
	bool use_manual_realm(false);
	eap_variable_data_c manual_realm(m_am_tools);


	if (m_state == eap_type_simple_config_state_waiting_for_identity_request
		|| (m_simple_config_test_version == true // This one is for testing purposes.
			&& m_state == eap_type_simple_config_state_success))
	{
		save_current_state();
		set_state(eap_type_simple_config_state_pending_identity_query);

		eap_status_e status = eap_status_process_general_error;

		status = m_am_type_simple_config->query_eap_identity(
			receive_network_id,
			eap_identifier,
			&use_manual_username,
			&manual_username,
			&use_manual_realm,
			&manual_realm);

		if (status == eap_status_pending_request)
		{
			// This is pending query, that will be completed by complete_eap_identity_query() call.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else if (status == eap_status_completed_request)
		{
			// This is already completed by complete_eap_identity_query() call.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else if (status != eap_status_ok
			&& status != eap_status_success)
		{
			// This is an error case.
			restore_saved_previous_state();

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else
		{
			status = handle_eap_identity_query(
				receive_network_id,
				eap_identifier,
				use_manual_username,
				&manual_username,
				use_manual_realm,
				&manual_realm);
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (m_state == eap_type_simple_config_state_waiting_for_simple_config_start)
	{
		// This is re-transmission request. We do not change our state.
		// Just send EAP-Identity again.
		if (get_NAI()->get_is_valid_data() == true)
		{
			eap_status_e status = identity->set_copy_of_buffer(get_NAI());

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_simple_config_c::query_eap_identity() ")
				 EAPL("returns already obtained NAI in ")
				 EAPL("eap_type_simple_config_state_variable_e %d=%s.\n"),
				 get_state(),
				 get_state_string()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_SIMPLE_CONFIG_ERROR, 
				(EAPL("ERROR: eap_type_simple_config_c::query_eap_identity(): ")
				 EAPL("EAP-Request/Identity cannot be completed, identity (NAI) ")
				 EAPL("is missing. in eap_type_simple_config_state_variable_e %d=%s.\n"),
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
	else if (m_state == eap_type_simple_config_state_pending_identity_query)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_type_simple_config_c::query_eap_identity(): ")
			 EAPL("Already pending EAP-Identity query in ")
			 EAPL("eap_type_simple_config_state_variable_e %d=%s.\n"),
			get_state(),
			get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_pending_request);
	}
	else
	{	
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_SIMPLE_CONFIG_ERROR,
			(EAPL("ERROR: eap_type_simple_config_c::query_eap_identity(): ")
			 EAPL("Illegal EAP-Identity query in eap_type_simple_config_state_variable_e %d=%s.\n"),
			get_state(),
			get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::set_initial_eap_identifier(
	const eap_am_network_id_c * const /*receive_network_id*/,
	const u8_t /*initial_identifier*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::eap_acknowledge(
	const eap_am_network_id_c * const /* receive_network_id */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eap_type_simple_config_c::reset(): this = 0x%08x: %d=%s.\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 get_state(),
		 get_state_string()));

	get_NAI()->reset();

	if (m_is_client == true)
	{
		// Client waits EAP-Request/Identity.
		m_state = eap_type_simple_config_state_waiting_for_identity_request;
		m_saved_previous_state = eap_type_simple_config_state_waiting_for_identity_request;
	}
	else if (m_is_client == false)
	{
		// Server waits EAP-Response/Identity.
		m_state = eap_type_simple_config_state_waiting_for_identity_response;
		m_saved_previous_state = eap_type_simple_config_state_waiting_for_identity_response;
	}

	m_reassembly_state = eap_type_simple_config_reassembly_state_wait_first_message;

	m_saved_previous_reassembly_state = eap_type_simple_config_reassembly_state_wait_first_message;

	m_simple_config_message_send_offset = 0ul;

	m_simple_config_message_buffer.reset();

	eap_status_e status = m_simple_config_record->reset();

	m_failure_message_received = false;
	m_authentication_finished_successfully = false;
	m_last_eap_identifier = 0ul;

	m_first_fragment_eap_identifier = 0ul;

	m_am_type_simple_config->reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::set_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id, 
	void * const p_data,
	const u32_t p_time_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = get_type_partner()->set_timer(
		p_initializer, 
		p_id, 
		p_data,
		p_time_ms);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::cancel_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = get_type_partner()->cancel_timer(
		p_initializer, 
		p_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// This is commented in abs_simple_config_base_application_c.
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::load_module(
	const eap_type_value_e type,
	const eap_type_value_e tunneling_type,
	abs_eap_base_type_c * const partner,
	eap_base_type_c ** const eap_type,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// This call is forwarded to EAPOL AM module because it handles all the 
	// tunneled EAP type handlings for PEAP.
	const eap_status_e status =  get_type_partner()->load_module(
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

// This is commented in abs_simple_config_base_application_c.
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::unload_module(const eap_type_value_e type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// This call is forwarded to EAPOL AM module because it handles all the 
	// tunneled EAP type handlings for PEAP.
	const eap_status_e status = get_type_partner()->unload_module(type);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// This is commented in abs_simple_config_base_application_c.
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::restart_authentication(
	const eap_am_network_id_c * const receive_network_id,
	const bool is_client_when_true,
	const bool /*force_clean_restart*/,
	const bool /*from_timer*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());

	const eap_status_e status = get_type_partner()->restart_authentication(
		&send_network_id,
		is_client_when_true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// This is commented in abs_simple_config_base_application_c.
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::packet_data_crypto_keys(
	const eap_am_network_id_c * const /*send_network_id*/,
	const eap_master_session_key_c * const /*master_session_key*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// NOTE we do NOT forward keys to lower layer.

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

// This is commented in abs_simple_config_base_application_c.
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::check_is_valid_eap_type(
	const eap_type_value_e eap_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// This call is forwarded to SIMPLE_CONFIG AM module because it handles all the 
	// tunneled EAP type handlings for PEAP.
	const eap_status_e status = m_am_type_simple_config->check_is_valid_eap_type(eap_type);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// This is commented in abs_simple_config_base_application_c.
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::get_eap_type_list(
	eap_array_c<eap_type_value_e> * const eap_type_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = m_am_type_simple_config->get_eap_type_list(eap_type_list);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::set_session_timeout(
	const u32_t session_timeout_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = get_type_partner()->set_session_timeout(session_timeout_ms);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_simple_config_c::add_rogue_ap(
	eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = get_type_partner()->add_rogue_ap(rogue_ap_list);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------


#endif //#if defined(USE_EAP_SIMPLE_CONFIG)

// End.
