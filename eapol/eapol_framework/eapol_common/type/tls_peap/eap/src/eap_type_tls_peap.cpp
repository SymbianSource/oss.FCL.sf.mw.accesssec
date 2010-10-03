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
* %version: 91 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 119 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_type_tls_peap_types.h"
#include "eap_type_tls_peap.h"
#include "eap_type_tls_peap_header.h"
#include "eap_type_tls_peap_state_notification.h"
#include "eap_am_type_tls_peap.h"
#include "eap_state_notification.h"
#include "tls_record_header.h"
#include "tls_base_record.h"
#include "eap_config.h"
#include "eap_header_string.h"
#include "eap_automatic_variable.h"

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_type_tls_peap_c::~eap_type_tls_peap_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("this = 0x%08x => 0x%08x, %s: function: eap_type_tls_peap_c::~eap_type_tls_peap_c():,")
		 EAPL(" m_am_type_tls_peap = 0x%08x (validity %d).\n"),
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this),
		 (m_is_client == true ? "client": "server"),
		 m_am_type_tls_peap,
		 m_am_type_tls_peap->get_is_valid()));

	EAP_ASSERT(m_shutdown_was_called == true);

	if (m_free_tls_record == true)
	{
		delete m_tls_record;
		m_tls_record = 0;
	}

	if (m_free_am_type_tls_peap == true)
	{
		delete m_am_type_tls_peap;
		m_am_type_tls_peap = 0;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_type_tls_peap_c::eap_type_tls_peap_c(
	abs_eap_am_tools_c * const tools, ///< This is pointer to the tools AM of current platform.
	abs_eap_base_type_c * const partner, ///< This is back pointer to object which created this object.
	eap_am_type_tls_peap_c * const am_type_tls_peap, ///< This is pointer to adaptation module of TLS/PEAP EAP type.
	const bool free_am_type_tls_peap,
	tls_base_record_c * const tls_record, /// This is pointer to TLS implementation.
	const bool free_tls_record,
	const bool is_client_when_true, ///< Indicates whether this is client (true) or server (false).
	const eap_type_value_e current_eap_type, ///< This the current EAP-type (TLS or PEAP).
	const eap_am_network_id_c * const receive_network_id)
	: eap_base_type_c(tools, partner)
	  , m_am_tools(tools)
	  , m_am_type_tls_peap(am_type_tls_peap)
	  , m_tls_record(tls_record)
	  , m_nai_realm(tools)
	  , m_NAI(tools)
	  , m_current_identity(tools)
	  , m_send_network_id(tools)
	  , m_tls_peap_header_offset(0u)
	  , m_MTU(0u)
	  , m_trailer_length(0u)
	  , m_state(eap_type_tls_peap_state_waiting_for_identity_request)
	  , m_saved_previous_state(eap_type_tls_peap_state_waiting_for_identity_request)
	  , m_reassembly_state(eap_type_tls_peap_reassembly_state_wait_first_message)
	  , m_saved_previous_reassembly_state(eap_type_tls_peap_reassembly_state_wait_first_message)
	  , m_tls_message_send_offset(0ul)
	  , m_tls_message_buffer(tools)
	  , m_master_session_key(tools, current_eap_type)
	  , m_accepted_PEAP_versions(tools)
	  , m_current_eap_type(current_eap_type)
	  , m_configured_peap_version(peap_version_none)
	  , m_current_peap_version(peap_version_none)
	  , m_first_fragment_eap_identifier(0ul)
	  , m_tls_session_type(tls_session_type_none)
	  , m_tunneled_eap_type_active(false)
	  , m_tunneled_eap_type_authentication_state(eap_state_none)
	  , m_free_am_type_tls_peap(free_am_type_tls_peap)
	  , m_free_tls_record(free_tls_record)
	  , m_is_valid(false)
	  , m_is_client(is_client_when_true)
	  , m_wait_eap_success_packet(true)
	  , m_check_identifier_of_eap_identity_response(false)
	  , m_tls_peap_test_version(false)
	  , m_check_nai_realm(false)
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	  , m_tls_use_identity_privacy(false)
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	  , m_failure_message_received(false)
	  , m_authentication_finished_successfully(false)
	  , m_last_eap_identifier(0ul)
	  , m_shutdown_was_called(false)
	  , m_use_tppd_tls_peap(true)
	  , m_use_tppd_peapv1_acknowledge_hack(true)
	  , m_includes_tls_handshake_message(false)
	  , m_use_eap_expanded_type(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("this = 0x%08x => 0x%08x, %s: function: eap_type_tls_peap_c::eap_type_tls_peap_c(): compiled %s %s\n"),
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this),
		 (m_is_client == true ? "client": "server"),
		 __DATE__,
		 __TIME__));
	
	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		// No need to delete anything here because it is done in destructor.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	if (tls_record == 0)
	{
		// No need to delete anything here because it is done in destructor.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}
	m_tls_record->set_type_partner(this);

	if (m_am_type_tls_peap == 0)
	{
		// Something wrong with AM.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}
	m_am_type_tls_peap->set_am_partner(this);


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
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	if (m_is_client == false)
	{
		// Server waits EAP-Response/Identity.
		m_state = eap_type_tls_peap_state_waiting_for_identity_response;
		m_saved_previous_state
			= eap_type_tls_peap_state_waiting_for_identity_response;
	}

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_tls_peap_c::save_current_state()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_saved_previous_state = m_state;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_tls_peap_c::restore_saved_previous_state()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	set_state(m_saved_previous_state);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_tls_peap_c::set_state(
	const eap_type_tls_peap_state_variable_e state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_type_tls_peap_state_variable_e previous_state = m_state;

	if (m_state != eap_type_tls_peap_state_failure)
	{
		m_state = state;
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("this = 0x%08x, %s, %s: eap_type_tls_peap_c::set_state(): ")
		 EAPL(" Previous state %d=%s, new state %d=%s.\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 (get_type_partner()->get_is_tunneled_eap() == true ? "tunneled" : "outer most"),
		 previous_state,
		 get_state_string(previous_state),
		 m_state,
		 get_state_string(m_state)));

	eap_type_tls_peap_state_notification_c notification(
		m_am_tools,
		get_send_network_id(),
		m_is_client,
		eap_state_notification_eap,
		eap_protocol_layer_eap_type,
		m_current_eap_type,
		previous_state,
		state,
		m_last_eap_identifier,
		false);
	get_type_partner()->state_notification(&notification);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_type_tls_peap_reassembly_state_e eap_type_tls_peap_c::get_reassembly_state() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_reassembly_state;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_tls_peap_c::set_reassembly_state(
	const eap_type_tls_peap_reassembly_state_e state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_reassembly_state = state;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_tls_peap_c::save_current_reassembly_state()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_saved_previous_reassembly_state = m_reassembly_state;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_tls_peap_c::restore_saved_reassembly_state()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_reassembly_state = m_saved_previous_reassembly_state;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_am_network_id_c * eap_type_tls_peap_c::get_send_network_id()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_send_network_id;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_tls_peap_c::set_last_eap_identifier(const u8_t last_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_last_eap_identifier = last_eap_identifier;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("this = 0x%08x, %s, %s, eap_type_tls_peap_c::set_last_eap_identifier():")
		 EAPL(" saved EAP-identifier %d, state %s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 (get_type_partner()->get_is_tunneled_eap() == true ? "tunneled" : "outer most"),
		 m_last_eap_identifier,
		 get_state_string()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u8_t eap_type_tls_peap_c::get_last_eap_identifier() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("this = 0x%08x, eap_type_tls_peap_c::get_last_eap_identifier():")
		 EAPL("%s, saved EAP-identifier %d, state %s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 m_last_eap_identifier,
		 get_state_string()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_last_eap_identifier;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_const_string eap_type_tls_peap_c::get_state_string(
	eap_type_tls_peap_state_variable_e state)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(state, eap_type_tls_peap_state_waiting_for_identity_request)
	else EAP_IF_RETURN_STRING(state, eap_type_tls_peap_state_pending_identity_query)
	else EAP_IF_RETURN_STRING(state, eap_type_tls_peap_state_waiting_for_tls_start)
	else EAP_IF_RETURN_STRING(state, eap_type_tls_peap_state_process_tls_start)
	else EAP_IF_RETURN_STRING(state, eap_type_tls_peap_state_waiting_for_request)
	else EAP_IF_RETURN_STRING(state, eap_type_tls_peap_state_waiting_for_success)
	else EAP_IF_RETURN_STRING(state, eap_type_tls_peap_state_tppd_peapv1_waits_eap_success_or_tunneled_packet)
	else EAP_IF_RETURN_STRING(state, eap_type_tls_peap_state_waiting_for_identity_response)
	else EAP_IF_RETURN_STRING(state, eap_type_tls_peap_state_waiting_for_first_response)
	else EAP_IF_RETURN_STRING(state, eap_type_tls_peap_state_waiting_for_response)
	else EAP_IF_RETURN_STRING(state, eap_type_tls_peap_state_waiting_for_empty_response)
	else EAP_IF_RETURN_STRING(state, eap_type_tls_peap_state_process_tls_message)
	else EAP_IF_RETURN_STRING(state, eap_type_tls_peap_state_success)
	else EAP_IF_RETURN_STRING(state, eap_type_tls_peap_state_failure)
	else
#else
EAP_UNREFERENCED_PARAMETER(state);	
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown EAP-TLS/PEAP state");
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_const_string eap_type_tls_peap_c::get_reassembly_state_string(
	eap_type_tls_peap_reassembly_state_e state)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(state, eap_type_tls_peap_reassembly_state_none)
	else EAP_IF_RETURN_STRING(state, eap_type_tls_peap_reassembly_state_wait_first_message)
	else EAP_IF_RETURN_STRING(state, eap_type_tls_peap_reassembly_state_wait_last_fragment)
	else EAP_IF_RETURN_STRING(state, eap_type_tls_peap_reassembly_state_message_reassembled)
	else
#else
EAP_UNREFERENCED_PARAMETER(state);		
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown TLS_PEAP reassembly state");
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_type_tls_peap_c::get_state_string() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return get_state_string(m_state);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_type_tls_peap_c::get_reassembly_state_string() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return get_reassembly_state_string(m_reassembly_state);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_type_tls_peap_c::get_saved_previous_state_string() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return get_state_string(m_saved_previous_state);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_type_tls_peap_c::set_failure_message_received()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_failure_message_received = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_type_tls_peap_c::unset_failure_message_received()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_failure_message_received = false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_type_tls_peap_c::get_failure_message_received() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_failure_message_received;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_type_tls_peap_state_variable_e eap_type_tls_peap_c::get_state() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_state;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::generate_nai(
	eap_variable_data_c * const /*new_nai*/, ///< This is the new generated NAI.
	const eap_variable_data_c * const /*domain*/, ///< This is the domain part of the NAI.
	const eap_variable_data_c * const /*identity*/ ///< This is identity.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::handle_tls_peap_packet(
	const eap_am_network_id_c * const /*receive_network_id*/, ///< This is the network identity of the received EAP packet.
	eap_tls_peap_header_c * const /*tls_peap*/, ///< This is pointer to EAP header including EAP-TLS/PEAP fields.
	const u32_t /*tls_peap_length*/ ///< This is length of received TLS/PEAP EAP packet.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::analyse_tls_peap_packet(
	const eap_am_network_id_c * const /*receive_network_id*/, ///< This is the network identity of the received EAP packet.
	eap_tls_peap_header_c * const /*received_tls_peap*/, ///< This is pointer to EAP header including EAP-TLS/PEAP fields.
	const u32_t /*tls_peap_packet_length*/ ///< This is length of received TLS/PEAP EAP packet.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::parse_tls_peap_payload(
	u32_t * const /*buffer_length*/ ///< This is the length of the buffer. This must match with the length of all payloads.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::check_version_list(
	const u16_t /*version_list_length*/,
	u8_t * /*version_list*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::parse_tls_peap_packet(
	eap_tls_peap_header_c * const /*tls_peap*/, ///< This is pointer to EAP header including EAP-TLS/PEAP fields.
	const u32_t /*tls_peap_packet_length*/ ///< This is length of received TLS/PEAP EAP packet.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_variable_data_c * eap_type_tls_peap_c::get_nai_realm()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_nai_realm;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_variable_data_c * eap_type_tls_peap_c::get_NAI()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_NAI;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_tls_peap_c::update_buffer_indexes(
	const u32_t maximum_buffer_size,
	const u32_t payload_size,
	u32_t * const buffer_offset,
	u32_t * const buffer_free)
{
	EAP_UNREFERENCED_PARAMETER(maximum_buffer_size);

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT_ALWAYS(*buffer_offset + *buffer_free <= maximum_buffer_size-m_trailer_length);
	EAP_ASSERT_ALWAYS(*buffer_free >= payload_size);
	EAP_ASSERT_ALWAYS(m_tls_peap_header_offset+m_MTU == *buffer_offset + *buffer_free);

	*buffer_free -= payload_size;
	*buffer_offset += payload_size;

	EAP_ASSERT_ALWAYS(*buffer_offset + *buffer_free <= maximum_buffer_size-m_trailer_length);
	EAP_ASSERT_ALWAYS(*buffer_offset <= m_tls_peap_header_offset+m_MTU);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_tls_peap_c::update_payload_indexes(
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
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::parse_identity(
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
			EAP_TLS_PEAP_AT_CHARACTER,
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

	u32_t username_length = identity_length;
	if (at_character != 0)
	{
		username_length = static_cast<u32_t>(at_character-identity);
	}

	status = m_current_identity.set_copy_of_buffer(
		identity,
		username_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = get_NAI()->set_copy_of_buffer(identity, identity_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS/PEAP received EAP-identity NAI"),
		get_NAI()->get_data(get_NAI()->get_data_length()),
		get_NAI()->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::handle_identity_response_message(
	eap_header_rd_c * const /*eap_header*/, ///< This is the received EAP-Identity packet, pointer points to the header.
	const u32_t /*tls_peap_packet_length*/ ///< This is length of received TLS/PEAP EAP packet.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::tls_peap_packet_send(
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t /*header_offset*/,
	const u32_t /*data_length*/,
	const u32_t /*buffer_length*/,
	const bool includes_tls_handshake_message)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_TLS_PEAP: %s: function: eap_type_tls_peap_c::tls_peap_packet_send()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status = eap_status_not_supported;

	if ((m_is_client == true
			&& get_state() == eap_type_tls_peap_state_process_tls_start)
		|| get_state() == eap_type_tls_peap_state_process_tls_message
		|| get_state() == eap_type_tls_peap_state_waiting_for_request // This state is needed to send messages from asyncronous completions.
		|| get_state() == eap_type_tls_peap_state_waiting_for_response
		|| get_state() == eap_type_tls_peap_state_failure // This state is needed to send failure messages.
		|| get_state() == eap_type_tls_peap_state_waiting_for_empty_response
		|| get_state() == eap_type_tls_peap_state_waiting_for_success
		|| get_state() == eap_type_tls_peap_state_success
#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
		|| get_state() == eap_type_tls_peap_state_waiting_for_empty_tppd_peap_v1_acknowledge
		|| (m_is_client == true
			&& m_current_eap_type == eap_type_peap
			&& m_current_peap_version == peap_version_1
			&& m_use_tppd_tls_peap == true
			&& m_use_tppd_peapv1_acknowledge_hack == true
			&& (get_tls_session_type() == tls_session_type_original_session_resumption
				|| get_tls_session_type() == tls_session_type_stateless_session_resumption)
			&& (get_state() == eap_type_tls_peap_state_success
				|| get_state() == eap_type_tls_peap_state_tppd_peapv1_waits_eap_success_or_tunneled_packet))
#endif //#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		|| get_state() == eap_type_tls_peap_state_server_waits_ttls_plain_ms_chap_v2_empty_ack
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		)
	{
		status = m_tls_message_buffer.set_copy_of_buffer(
			sent_packet->get_data(sent_packet->get_data_length()),
			sent_packet->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// This will start the packet send from begin of the message.
		m_tls_message_send_offset = 0ul;

		m_includes_tls_handshake_message = includes_tls_handshake_message;

		status = eap_tls_peap_fragment_send();
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
			TRACE_FLAGS_TLS_PEAP_ERROR,
			(EAPL("ERROR: this = 0x%08x, eap_type_tls_peap_c::tls_peap_packet_send(): ")
			 EAPL("Cannot send EAP-TLS/PEAP message in ")
			 EAPL("eap_type_tls_peap_state_variable_e %d=%s.\n"),
			 this,
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
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::packet_send(
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
		(EAPL("EAP_type_TLS_PEAP: %s,  %s: function: eap_type_tls_peap_c::packet_send()\n"),
		(m_is_client == true ? "client": "server"),
		(get_type_partner()->get_is_tunneled_eap() == true ? "tunneled" : "outer most")));

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
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::check_NAI(
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
			if (character != EAP_TLS_PEAP_AT_CHARACTER)
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
		else if (character == EAP_TLS_PEAP_AT_CHARACTER)
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
			|| character == EAP_TLS_PEAP_AT_CHARACTER
			|| character == ' ' // space
			|| character <= 0x1f // Ctrl
			|| character >= 0x7f) // extented characters
		{
			// Illegal character.
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_TLS_PEAP_ERROR,
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
EAP_FUNC_EXPORT void eap_type_tls_peap_c::packet_trace(
	eap_const_string prefix,
	const eap_am_network_id_c * const /*receive_network_id*/,
	eap_header_wr_c * const eap_packet,
	const u32_t eap_packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_UNREFERENCED_PARAMETER(prefix); // in release
	
	if (eap_packet_length > eap_header_base_c::get_header_length()
		&& eap_packet->get_type() == m_current_eap_type)
	{
		eap_tls_peap_header_c * const received_tls_peap
			= reinterpret_cast<eap_tls_peap_header_c *>(eap_packet);

		const u8_t * const p_tls_flags = received_tls_peap->get_tls_flags();
		u8_t tls_flags = 0u;
		EAP_UNREFERENCED_PARAMETER(tls_flags); // in release
		if (p_tls_flags != 0)
		{
			tls_flags = *p_tls_flags;
		}

		u32_t tls_message_length = 0ul;
		if (received_tls_peap->get_tls_message_length(&tls_message_length) != eap_status_ok)
		{
			tls_message_length = 0ul;
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("%s EAP-TLS/PEAP header %s: code=0x%02x=%s, identifier=0x%02x=%d, ")
			 EAPL("length=0x%04x=%d, ")
			 EAPL("type=0x%08x=%s, TLS-flags=0x%02x %s%s%s, TLS-length=0x%08x=%d.\n"),
			 prefix,
			 (m_is_client == true) ? "client": "server",
			 received_tls_peap->get_code(),
			 received_tls_peap->get_code_string(),
			 received_tls_peap->get_identifier(),
			 received_tls_peap->get_identifier(),
			 received_tls_peap->get_length(),
			 received_tls_peap->get_length(),
			 convert_eap_type_to_u32_t(received_tls_peap->get_type()),
			 received_tls_peap->get_eap_type_string(),
			 tls_flags,
			 (tls_flags & eap_tls_peap_header_c::m_flag_mask_tls_length_included) ? "L": " ",
			 (tls_flags & eap_tls_peap_header_c::m_flag_mask_more_fragments) ? "M": " ",
			 (tls_flags & eap_tls_peap_header_c::m_flag_mask_start) ? "S": " ",
			 tls_message_length,
			 tls_message_length));
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
eap_master_session_key_c * eap_type_tls_peap_c::get_master_session_key()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_master_session_key;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::finish_successful_authentication(
	const bool send_tppd_peapv1_empty_acknowledge,
	const bool do_quiet_finish,
	const bool do_send_empty_acknowledge)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(send_tppd_peapv1_empty_acknowledge); // Not used if USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES defined.

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_TLS_PEAP: %s: function: eap_type_tls_peap_c::finish_successful_authentication()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("EAP_type_TLS_PEAP: %s, EAP-type %s EAP-SUCCESS, m_tls_session_type=%d=%s, PEAP version %s\n"),
		 ((m_is_client == true) ? "client": "server"),
		 eap_header_string_c::get_eap_type_string(m_current_eap_type),
		 get_tls_session_type(),
		 eap_tls_trace_string_c::get_tls_session_type_string(get_tls_session_type()),
		 eap_tls_trace_string_c::get_peap_version_string(m_current_peap_version)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_type_tls_peap_c::finish_successful_authentication()");

	eap_status_e status(eap_status_process_general_error);

	if (do_quiet_finish == false)
	{
		if (get_master_session_key()->get_is_valid_data() == false
			|| get_master_session_key()->get_data_length() == 0u)
		{
			set_state(eap_type_tls_peap_state_failure);
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
		}

		eap_status_e status = get_type_partner()->packet_data_crypto_keys(
			get_send_network_id(),
			get_master_session_key());
		if (status != eap_status_ok)
		{
			set_state(eap_type_tls_peap_state_failure);
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		bool send_eap_success = true;
#if !defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
		if (m_is_client == true
			|| (m_current_eap_type == eap_type_peap
				&& m_current_peap_version == peap_version_1))
		{
			send_eap_success = false;
		}
#endif //#if !defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)

		eap_state_notification_c notification(
			m_am_tools,
			get_send_network_id(),
			m_is_client,
			eap_state_notification_eap,
			eap_protocol_layer_eap,
			m_current_eap_type,
			eap_state_none,
			eap_state_authentication_finished_successfully,
			get_last_eap_identifier(), // Note the EAP-Success uses the same EAP-Identifier as the last EAP-Request.
			send_eap_success);
		get_type_partner()->state_notification(&notification);

		if (do_send_empty_acknowledge == true
			&& m_is_client == true
			&& m_current_eap_type == eap_type_peap
			&& m_current_peap_version == peap_version_1
#if !defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
			&& m_use_tppd_tls_peap == true
			&& (m_use_tppd_peapv1_acknowledge_hack == false
				|| get_tls_session_type() == tls_session_type_full_authentication
				|| send_tppd_peapv1_empty_acknowledge == true)
#endif //#if !defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
				)
		{
			// Send empty acknowledge message.
			status = send_empty_eap_ack();
			if (status != eap_status_ok)
			{
				set_state(eap_type_tls_peap_state_failure);
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	set_state(eap_type_tls_peap_state_success);

	// Indicate EAP-TLS/PEAP AM authentication finished successfully.
	m_am_type_tls_peap->authentication_finished(true, get_tls_session_type());

	m_authentication_finished_successfully = true;
	status = eap_status_success;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::send_final_notification()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_TLS_PEAP: %s: function: eap_type_tls_peap_c::send_final_notification(): m_is_valid=%d, m_authentication_finished_successfully=%d\n"),
		(m_is_client == true ? "client": "server"),
		m_is_valid,
		m_authentication_finished_successfully));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_type_tls_peap_c::send_final_notification()");

	if (m_is_valid == true 
		&& m_authentication_finished_successfully == false)
	{
		eap_tls_trace_string_c tls_trace;
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAP_type_TLS_PEAP: %s, EAP-type %s FAILED, m_tls_session_type=%d=%s, PEAP version %s, state=%s\n"),
			 ((m_is_client == true) ? "client": "server"),
			 eap_header_string_c::get_eap_type_string(m_current_eap_type),
			 get_tls_session_type(),
			 eap_tls_trace_string_c::get_tls_session_type_string(get_tls_session_type()),
			 tls_trace.get_peap_version_string(m_current_peap_version),
			 get_state_string()));

		if (m_is_client == false
			&& get_state() == eap_type_tls_peap_state_waiting_for_identity_response)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_TLS_PEAP: %s: function: send_final_notification(): Does not send notiication.\n"),
				 (m_is_client == true ? "client": "server")));
		}
		else
		{
			set_state(eap_type_tls_peap_state_failure);

			// Notifies the lower level of unsuccessfull authentication.
			eap_state_notification_c notification(
				m_am_tools,
				get_send_network_id(),
				m_is_client,
				eap_state_notification_eap,
				eap_protocol_layer_eap,
				m_current_eap_type,
				eap_state_none,
				eap_state_authentication_terminated_unsuccessfully,
				get_last_eap_identifier(),
				false);

			notification.set_authentication_error(eap_status_authentication_failure);

			get_type_partner()->state_notification(&notification);

			// Indicate EAP-TLS/PEAP AM authentication terminated unsuccessfully.
			m_am_type_tls_peap->authentication_finished(false, get_tls_session_type());
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eap_type_tls_peap_c::get_is_client()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_client;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::create_random_eap_identity(
	eap_variable_data_c * const local_identity)
{
	// Generates random username.

	if (local_identity == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u32_t EAP_TLS_PEAP_RANDOM_IDENTITY_LENGTH = 16;
	eap_variable_data_c random_username(m_am_tools);
	eap_variable_data_c random_bytes(m_am_tools);

	eap_status_e status = random_bytes.init(EAP_TLS_PEAP_RANDOM_IDENTITY_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	random_bytes.set_is_valid();
	random_bytes.set_data_length(EAP_TLS_PEAP_RANDOM_IDENTITY_LENGTH);

	status = m_am_tools->get_crypto()->get_rand_bytes(
		random_bytes.get_data(random_bytes.get_data_length()),
		random_bytes.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const u32_t EAP_GSMSIM_RANDOM_IDENTITY_BUFFER_LENGTH
		= 3ul+(EAP_TLS_PEAP_RANDOM_IDENTITY_LENGTH+1u)*4u/3u;
	
	status = random_username.init(EAP_GSMSIM_RANDOM_IDENTITY_BUFFER_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	random_username.set_is_valid();
	random_username.set_data_length(EAP_GSMSIM_RANDOM_IDENTITY_BUFFER_LENGTH);
	
	u32_t random_identity_length = random_username.get_data_length();
	
	status = m_am_tools->convert_bytes_to_ascii_armor(
		random_bytes.get_data_offset(0u, random_bytes.get_data_length()),
		random_bytes.get_data_length(),
		random_username.get_data_offset(0u, random_username.get_data_length()),
		&random_identity_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	random_username.set_data_length(random_identity_length);
	
	status = local_identity->set_copy_of_buffer(&random_username);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::create_eap_fast_mac_identity(
	const eap_am_network_id_c * const send_network_id,
	eap_variable_data_c * const mac_identity)
{
	// EAP-FAST sends special username.
	const u8_t EAP_FAST_PREFIX[] = "PEAP-";

	eap_status_e status = mac_identity->set_copy_of_buffer(EAP_FAST_PREFIX, sizeof(EAP_FAST_PREFIX)-1ul);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c mac_string(m_am_tools);
	if (mac_string.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = mac_string.set_buffer_length(2ul*send_network_id->get_source_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = mac_string.set_data_length(2ul*send_network_id->get_source_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	u32_t target_length(2ul*send_network_id->get_source_length());

	status = m_am_tools->convert_bytes_to_hex_ascii(
		send_network_id->get_source(),
		send_network_id->get_source_length(),
		mac_string.get_data(2ul*send_network_id->get_source_length()),
		&target_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const u32_t TWO_CHARS(2ul);

	for (u32_t ind = 0ul; ind < mac_string.get_data_length(); ind += TWO_CHARS)
	{
		const u8_t dash('-');

		status = mac_identity->add_data(mac_string.get_data_offset(ind, TWO_CHARS), TWO_CHARS);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if ((ind+TWO_CHARS) < mac_string.get_data_length())
		{
			status = mac_identity->add_data(&dash, sizeof(dash));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	status = m_am_tools->convert_ascii_to_uppercase(
		mac_identity->get_data(),
		mac_identity->get_data_length());

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::handle_eap_identity_query(
	const eap_variable_data_c * const user_certificate_identity,
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
	if (local_identity.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

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
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
		if (m_tls_use_identity_privacy == true)
		{

#if defined(USE_FAST_EAP_TYPE)
			if (m_current_eap_type == eap_type_fast)
			{
				// EAP-FAST sends special username.
				status = create_eap_fast_mac_identity(
					&send_network_id,
					&local_identity);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else
#endif //#if defined(USE_FAST_EAP_TYPE)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("EAP_type_TLS_PEAP: this = 0x%08x, %s: eap_type_tls_peap_c::handle_eap_identity_query(): random username and manual realm.\n"),
					 this,
					(m_is_client == true ? "client": "server")));

				// TLS identity privacy uses random username.
				status = create_random_eap_identity(&local_identity);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
		else
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_TLS_PEAP: this = 0x%08x, %s: eap_type_tls_peap_c::handle_eap_identity_query(): manual username and manual realm.\n"),
				 this,
				(m_is_client == true ? "client": "server")));

			// Here manual username could be zero or more bytes in length.
			status = local_identity.set_copy_of_buffer(manual_username);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		if (manual_realm->get_data_length() > 0ul)
		{
			// When manual realm is one or more bytes in length
			// we add @ and manual realm to the identity.
			u8_t at_char = EAP_TLS_PEAP_AT_CHARACTER;
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
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
		if (m_tls_use_identity_privacy == true)
		{
#if defined(USE_FAST_EAP_TYPE)
			if (m_current_eap_type == eap_type_fast)
			{
				// EAP-FAST sends special username.
				status = create_eap_fast_mac_identity(
					&send_network_id,
					&local_identity);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else
#endif //#if defined(USE_FAST_EAP_TYPE)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("EAP_type_TLS_PEAP: %s: eap_type_tls_peap_c::handle_eap_identity_query(): random username and realm from certificate.\n"),
					(m_is_client == true ? "client": "server")));

				// TLS identity privacy uses random username.
				status = create_random_eap_identity(&local_identity);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
		else
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_TLS_PEAP: %s: eap_type_tls_peap_c::handle_eap_identity_query(): manual username and realm from certificate.\n"),
				(m_is_client == true ? "client": "server")));

			status = local_identity.set_copy_of_buffer(manual_username);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		if (user_certificate_identity != 0
			&& user_certificate_identity->get_is_valid_data() == true)
		{
			eap_variable_data_c username(m_am_tools);
			eap_variable_data_c realm(m_am_tools);

			status = m_am_tools->parse_nai(
				user_certificate_identity,
				&username,
				&realm);
			if (status == eap_status_ok)
			{
				if (realm.get_is_valid_data() == true)
				{
					u8_t at_char = EAP_TLS_PEAP_AT_CHARACTER;
					status = local_identity.add_data(&at_char, sizeof(at_char));
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = local_identity.add_data(&realm);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}
		}
		else
		{
			// No realm.
		}
	}
	else if ((use_manual_username == false
				 && use_manual_realm == true
				 && manual_realm != 0
				 && manual_realm->get_is_valid() == true)
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
			 || m_tls_use_identity_privacy == true
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
			 )
	{
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
		if (m_tls_use_identity_privacy == true)
		{
#if defined(USE_FAST_EAP_TYPE)
			if (m_current_eap_type == eap_type_fast)
			{
				// EAP-FAST sends special username.
				status = create_eap_fast_mac_identity(
					&send_network_id,
					&local_identity);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else
#endif //#if defined(USE_FAST_EAP_TYPE)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("EAP_type_TLS_PEAP: %s: eap_type_tls_peap_c::handle_eap_identity_query(): random username and manual realm.\n"),
					(m_is_client == true ? "client": "server")));

				// TLS identity privacy uses random username.
				status = create_random_eap_identity(&local_identity);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
		else
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
		if (user_certificate_identity != 0
			&& user_certificate_identity->get_is_valid_data() == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_TLS_PEAP: %s: eap_type_tls_peap_c::handle_eap_identity_query(): username from certificate and manual realm.\n"),
				(m_is_client == true ? "client": "server")));

			eap_variable_data_c username(m_am_tools);
			eap_variable_data_c realm(m_am_tools);

			status = m_am_tools->parse_nai(
				user_certificate_identity,
				&username,
				&realm);
			if (status == eap_status_ok)
			{
				if (username.get_is_valid_data() == true)
				{
					status = local_identity.set_copy_of_buffer(&username);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_TLS_PEAP: %s: eap_type_tls_peap_c::handle_eap_identity_query(): random username and manual realm.\n"),
				(m_is_client == true ? "client": "server")));

#if defined(USE_FAST_EAP_TYPE)
			if (m_current_eap_type == eap_type_fast)
			{
				// EAP-FAST sends special username.
				status = create_eap_fast_mac_identity(
					&send_network_id,
					&local_identity);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else
#endif //#if defined(USE_FAST_EAP_TYPE)
			{
				status = create_random_eap_identity(&local_identity);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}

		if (manual_realm != 0
			&& manual_realm->get_data_length() > 0ul)
		{
			u8_t at_char = EAP_TLS_PEAP_AT_CHARACTER;
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
		else
		{
			// No realm.
		}
	}
	else if (user_certificate_identity != 0
		&& user_certificate_identity->get_is_valid_data() == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_TLS_PEAP: %s: eap_type_tls_peap_c::handle_eap_identity_query(): username from certificate and realm from certificate.\n"),
			(m_is_client == true ? "client": "server")));

		// Uses NAI from certificate.
		status = local_identity.set_copy_of_buffer(user_certificate_identity);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAP_type_TLS_PEAP: %s: eap_type_tls_peap_c::handle_eap_identity_query(): no identity configured, creates random identity.\n"),
			(m_is_client == true ? "client": "server")));

		// Last possibility is random username.
		status = create_random_eap_identity(&local_identity);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = m_current_identity.set_copy_of_buffer(&local_identity);
	if (status != eap_status_ok)
	{
		restore_saved_previous_state();
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
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
		(EAPL("eap_type_tls_peap_c::handle_eap_identity_query(): identity"),
		local_identity.get_data(),
		local_identity.get_data_length()));


	status = get_type_partner()->complete_eap_identity_query(
		&send_network_id,
		&local_identity,
		eap_identifier);	
	if (status == eap_status_ok)
	{
		set_state(eap_type_tls_peap_state_waiting_for_tls_start);
	}
	else
	{
		m_current_identity.reset();
		get_NAI()->reset();
		restore_saved_previous_state();
	}
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::complete_eap_identity_query(
	const eap_variable_data_c * const user_certificate_identity,
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

	if (m_state == eap_type_tls_peap_state_pending_identity_query)
	{
		if (completion_status != eap_status_ok)
		{
			set_state(eap_type_tls_peap_state_failure);

			// The completion_status error value is more important
			// than return value of set_session_timeout().
			get_type_partner()->set_session_timeout(0ul);

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, completion_status);
		}

		eap_status_e status = handle_eap_identity_query(
			user_certificate_identity,
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
			TRACE_FLAGS_TLS_PEAP_ERROR, 
			(EAPL("ERROR: eap_type_tls_peap_c::complete_eap_identity_query(): ")
			 EAPL("Illegal EAP-Identity query completion in ")
			 EAPL("eap_type_tls_peap_state_variable_e %d=%s.\n"),
			get_state(),
			get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}
}

//--------------------------------------------------

//
eap_status_e eap_type_tls_peap_c::check_received_eap_identifier(
	const eap_header_wr_c * const eap_header)
{
	if (m_is_client == false
		&& get_type_partner()->get_is_tunneled_eap() == true
		&& m_check_identifier_of_eap_identity_response == false)
	{
		// Server cannot exactly verify EAP-Identifier value because of fragmentation.
		if (eap_header->get_identifier() < get_last_eap_identifier())
		{
			eap_status_e status(eap_status_unexpected_message);

			eap_status_string_c status_string;
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_TLS_PEAP_ERROR,
				(EAPL("ERROR: eap_type_tls_peap_c::check_received_eap_identifier() failed,")
				 EAPL("status %d=%s, received EAP-type 0xfe%06x%08x=%s, received EAP-code %d, ")
				 EAPL("received EAP-identifier %d, current EAP-identifier %d, state %s\n"),
				 status,
				 status_string.get_status_string(status),
				 eap_header->get_type().get_vendor_id(),
				 eap_header->get_type().get_vendor_type(),
				 eap_header_string_c::get_eap_type_string(eap_header->get_type()),
				 eap_header->get_code(),
				 eap_header->get_identifier(),
				 get_last_eap_identifier(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
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
				TRACE_FLAGS_TLS_PEAP_ERROR,
				(EAPL("ERROR: eap_type_tls_peap_c::check_received_eap_identifier() failed,")
				 EAPL("status %d=%s, received EAP-type 0xfe%06x%08x=%s, received EAP-code %d, ")
				 EAPL("received EAP-identifier %d, current EAP-identifier %d, state %s\n"),
				 status,
				 status_string.get_status_string(status),
				 eap_header->get_type().get_vendor_id(),
				 eap_header->get_type().get_vendor_type(),
				 eap_header_string_c::get_eap_type_string(eap_header->get_type()),
				 eap_header->get_code(),
				 eap_header->get_identifier(),
				 get_last_eap_identifier(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else if (m_is_client == false
				 && eap_header->get_type() == m_current_eap_type
				 && eap_header->get_identifier() != get_last_eap_identifier())
		{
			eap_status_e status(eap_status_unexpected_message);

			eap_status_string_c status_string;
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_TLS_PEAP_ERROR,
				(EAPL("ERROR: eap_type_tls_peap_c::check_received_eap_identifier() failed,")
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
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: eap_type_tls_peap_c::check_received_eap_identifier() failed,")
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
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::packet_process(
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
		(EAPL("EAP_type_TLS_PEAP: %s, %s: function: eap_type_tls_peap_c::packet_process()\n"),
		(m_is_client == true ? "client": "server"),
		(get_type_partner()->get_is_tunneled_eap() == true ? "tunneled" : "outer most")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_type_tls_peap_c::packet_process()");

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
			TRACE_FLAGS_TLS_PEAP_ERROR,
			(EAPL("ERROR: eap_type_tls_peap_c::packet_process(): ")
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

	eap_tls_peap_header_c tls_peap_header(
		m_am_tools,
		eap_header->get_header_buffer(eap_packet_length),
		eap_packet_length);

	if ((m_is_client == true
		&& eap_header->get_code() == eap_code_request)
		|| (m_is_client == false
		&& eap_header->get_code() == eap_code_response))
	{
		if (eap_header->get_type() == eap_type_identity
			|| eap_header->get_type() == m_current_eap_type)
		{
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
			else if (eap_header->get_type() == m_current_eap_type
				&& eap_header->get_length() < tls_peap_header.get_tls_min_header_length())
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
					TRACE_FLAGS_TLS_PEAP_ERROR,
					(EAPL("ERROR: eap_type_tls_peap_c::packet_process() failed,")
					 EAPL("status %d=%s, received EAP-type 0xfe%06x%08x=%s, received EAP-code %d, ")
					 EAPL("received EAP-identifier %d, current EAP-identifier %d, state %s\n"),
					 status,
					 status_string.get_status_string(status),
					 eap_header->get_type().get_vendor_id(),
					 eap_header->get_type().get_vendor_type(),
					 eap_header_string_c::get_eap_type_string(eap_header->get_type()),
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
							TRACE_FLAGS_TLS_PEAP_ERROR,
							(EAPL("ERROR: eap_type_tls_peap_c::")
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
							m_current_eap_type,
							eap_state_none,
							eap_state_identity_response_received,
							get_last_eap_identifier(),
							false);
						get_type_partner()->state_notification(&notification);
					}
				}
				else
				{
					status = tls_peap_packet_process(
						receive_network_id,
						&tls_peap_header,
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
							TRACE_FLAGS_TLS_PEAP_ERROR,
							(EAPL("ERROR: eap_type_tls_peap_c::tls_peap_packet_process() ")
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
#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
			if (get_state()
				== eap_type_tls_peap_state_tppd_peapv1_waits_eap_success_or_tunneled_packet
				&& m_current_eap_type == eap_type_peap
				&& m_current_peap_version == peap_version_1
				&& m_use_tppd_tls_peap == true
				&& m_use_tppd_peapv1_acknowledge_hack == true
				&& (get_tls_session_type() == tls_session_type_original_session_resumption
					|| get_tls_session_type() == tls_session_type_stateless_session_resumption))
			{
				// EAP-PEAPv1 original session resumption finishes with plain text EAP-SUCCESS.
				// We must forward this to the tunneled EAP-type.
				status = m_tls_record->plain_eap_success_failure_packet_received(
					receive_network_id,
					eap_header->get_code(),
					eap_header->get_identifier());

				if (status == eap_status_ok)
				{
					EAP_GENERAL_HEADER_SET_ERROR_DETECTED(eap_header, false);
				}

				status = finish_successful_authentication(false, false, true);
				if (status != eap_status_success)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else
#endif //#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
			if (m_current_eap_type == eap_type_ttls
				&& get_state() == eap_type_tls_peap_state_waiting_for_request)
			{
				// EAP-TTLS finishes with plain text EAP-SUCCESS.
				// We must forward this to the tunneled EAP-type.
				status = m_tls_record->plain_eap_success_failure_packet_received(
					receive_network_id,
					eap_header->get_code(),
					eap_header->get_identifier());

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
						TRACE_FLAGS_TLS_PEAP_ERROR,
						(EAPL("ERROR: eap_type_tls_peap_c::tls_peap_packet_process() ")
						 EAPL("failed, status %d=%s\n"),
						 status, status_string.get_status_string(status)));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
#if defined(USE_FAST_EAP_TYPE)
			else if (m_current_eap_type == eap_type_fast)
			{
				// In some cases EAP-FAST finishes only with plain text EAP-SUCCESS.
				// We must forward this to the tunneled EAP-type.
				status = m_tls_record->plain_eap_success_failure_packet_received(
					receive_network_id,
					eap_header->get_code(),
					eap_header->get_identifier());

				if (status == eap_status_ok)
				{
					EAP_GENERAL_HEADER_SET_ERROR_DETECTED(eap_header, false);
				}
			}
#endif //#if defined(USE_FAST_EAP_TYPE)
			else if (get_state() == eap_type_tls_peap_state_waiting_for_success)
			{
				EAP_GENERAL_HEADER_SET_ERROR_DETECTED(eap_header, false);

				if (m_wait_eap_success_packet == false)
				{
					/**
					 * @{ check right functionality.
					 * Here we return eap_status_ok, eap_status_success was
					 * returned after successfull
					 * EAP-Request/SIM/Challenge. This may change after EAP,
					 * 802.1X and 802.11i specifications are ready. }
					 */
					status = eap_status_ok;
				}
				else
				{
					if (m_current_eap_type == eap_type_tls)
					{
						status = finish_successful_authentication(false, false, true);
						if (status != eap_status_success)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}
					else
					{
						// We must forward this to the tunneled EAP-type.

						status = m_tls_record->plain_eap_success_failure_packet_received(
							receive_network_id,
							eap_header->get_code(),
							eap_header->get_identifier());

						if (status == eap_status_ok)
						{
							EAP_GENERAL_HEADER_SET_ERROR_DETECTED(eap_header, false);
						}
					}
				}
			}
			else if (get_state() == eap_type_tls_peap_state_success)
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

#if defined(USE_FAST_EAP_TYPE)
			if (m_current_eap_type == eap_type_fast)
			{
				// In some cases EAP-FAST finishes only with plain text EAP-SUCCESS.
				// We must forward this to the tunneled EAP-type.
				status = m_tls_record->plain_eap_success_failure_packet_received(
					receive_network_id,
					eap_header->get_code(),
					eap_header->get_identifier());

				if (status == eap_status_ok)
				{
					EAP_GENERAL_HEADER_SET_ERROR_DETECTED(eap_header, false);
				}
			}
#endif //#if defined(USE_FAST_EAP_TYPE)

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
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::send_empty_eap_ack()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_TLS_PEAP: %s, %s: function: eap_type_tls_peap_c::send_empty_eap_ack()\n"),
		(m_is_client == true ? "client": "server"),
		(get_type_partner()->get_is_tunneled_eap() == true ? "tunneled" : "outer most")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_type_tls_peap_c::send_empty_eap_ack()");

	eap_buf_chain_wr_c eap_fragment_acknowledge_packet(
		eap_write_buffer, 
		m_am_tools, 
		TLS_PEAP_LOCAL_PACKET_BUFFER_LENGTH);

	if (eap_fragment_acknowledge_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_ASSERT_ALWAYS(TLS_PEAP_LOCAL_PACKET_BUFFER_LENGTH
					  >= (m_tls_peap_header_offset+m_trailer_length));
	u32_t packet_buffer_free = TLS_PEAP_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_tls_peap_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_tls_peap_header_offset+m_MTU;
	}

	eap_tls_peap_header_c fragment_acknowledge(
		m_am_tools,
		eap_fragment_acknowledge_packet.get_data_offset(
			m_tls_peap_header_offset,
			(packet_buffer_free-m_tls_peap_header_offset)),
		(packet_buffer_free-m_tls_peap_header_offset));

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
		m_current_eap_type,
		static_cast<u16_t>(packet_buffer_free-m_tls_peap_header_offset),
		m_current_peap_version,
		m_use_eap_expanded_type);

	fragment_acknowledge.set_eap_length(
		static_cast<u16_t>(packet_buffer_free-m_tls_peap_header_offset),
		m_use_eap_expanded_type);

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
		m_current_eap_type,
		m_use_eap_expanded_type);

	u32_t tls_peap_data_offset = 0u;

	update_buffer_indexes(
		TLS_PEAP_LOCAL_PACKET_BUFFER_LENGTH,
		m_tls_peap_header_offset+fragment_acknowledge.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	// No payloads.

	fragment_acknowledge.set_data_length(
		tls_peap_data_offset,
		m_use_eap_expanded_type);
	eap_fragment_acknowledge_packet.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_tls_peap_header_offset
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
			(EAPL("    send: EAP-Response/TLS_PEAP/Acknowledge packet"),
			fragment_acknowledge.get_header_buffer(fragment_acknowledge.get_eap_length()),
			fragment_acknowledge.get_eap_length()));
	}
	else // if (m_is_client == false)
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("    send: EAP-Request/TLS_PEAP/Acknowledge packet"),
			fragment_acknowledge.get_header_buffer(fragment_acknowledge.get_eap_length()),
			fragment_acknowledge.get_eap_length()));
	}

	status = packet_send(
		get_send_network_id(),
		&eap_fragment_acknowledge_packet,
		m_tls_peap_header_offset,
		fragment_acknowledge.get_eap_length(),
		TLS_PEAP_LOCAL_PACKET_BUFFER_LENGTH
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
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::send_tls_peap_start_message(
	const u8_t next_eap_identifier, ///< This is EAP-Identifier of next EAP packet.
	const eap_variable_data_c * const authority_identity_payload
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_TLS_PEAP: %s, %s: function: eap_type_tls_peap_c::send_tls_peap_start_message()\n"),
		(m_is_client == true ? "client": "server"),
		(get_type_partner()->get_is_tunneled_eap() == true ? "tunneled" : "outer most")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_type_tls_peap_c::send_tls_peap_start_message()");

	eap_buf_chain_wr_c eap_tls_start_packet(
		eap_write_buffer, 
		m_am_tools, 
		TLS_PEAP_LOCAL_PACKET_BUFFER_LENGTH);

	if (eap_tls_start_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_ASSERT_ALWAYS(TLS_PEAP_LOCAL_PACKET_BUFFER_LENGTH
					  >= (m_tls_peap_header_offset+m_trailer_length));
	u32_t packet_buffer_free = TLS_PEAP_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_tls_peap_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_tls_peap_header_offset+m_MTU;
	}

	eap_tls_peap_header_c eap_tls_start_header(
		m_am_tools,
		eap_tls_start_packet.get_data_offset(
			m_tls_peap_header_offset,
			(packet_buffer_free-m_tls_peap_header_offset)),
		(packet_buffer_free-m_tls_peap_header_offset));

	if (eap_tls_start_header.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	eap_tls_start_header.reset_header(
		m_am_tools,
		m_current_eap_type,
		static_cast<u16_t>(packet_buffer_free-m_tls_peap_header_offset),
		m_current_peap_version,
		m_use_eap_expanded_type);

	eap_tls_start_header.set_flag_start(true);
	eap_tls_start_header.set_flag_tls_length_included(false);

	eap_tls_start_header.set_eap_length(
		static_cast<u16_t>(
			packet_buffer_free-m_tls_peap_header_offset),
		m_use_eap_expanded_type);

	eap_tls_start_header.set_eap_code(eap_code_request);
	eap_tls_start_header.set_eap_identifier(next_eap_identifier);
	eap_tls_start_header.set_eap_type(
		m_current_eap_type,
		m_use_eap_expanded_type);

	update_buffer_indexes(
		TLS_PEAP_LOCAL_PACKET_BUFFER_LENGTH,
		m_tls_peap_header_offset+eap_tls_start_header.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_tls_start_header.set_data_length(
		0ul,
		m_use_eap_expanded_type);
	eap_tls_start_packet.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_tls_peap_header_offset+eap_tls_start_header.get_header_length()
		+eap_tls_start_header.get_data_length()
		== packet_buffer_offset);

	eap_status_e status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - -
	// Payload is optional authority identity (A-ID) that is used in EAP-FAST.

	if (authority_identity_payload->get_data_length() > 0ul)
	{
		status = eap_tls_start_packet.add_data_to_offset(
			packet_buffer_offset,
			authority_identity_payload->get_data(),
			authority_identity_payload->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		update_buffer_indexes(
			TLS_PEAP_LOCAL_PACKET_BUFFER_LENGTH,
			authority_identity_payload->get_data_length(),
			&packet_buffer_offset,
			&packet_buffer_free);

		// - - - - - - - - - - - - - - - - - - - - - - - -

		eap_tls_start_header.set_data_length(
			authority_identity_payload->get_data_length(),
			m_use_eap_expanded_type);

		status = eap_tls_start_packet.set_data_length(packet_buffer_offset);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("send_tls_peap_start_message(): m_tls_peap_header_offset %d ")
			 EAPL("+ eap_tls_start_header.get_header_length()")
			 EAPL("%d + eap_tls_start_header.get_data_length() ")
			 EAPL("%d = %d packet_buffer_offset %d.\n"),
			 m_tls_peap_header_offset,
			 eap_tls_start_header.get_header_length(),
			 eap_tls_start_header.get_data_length(),
			 (m_tls_peap_header_offset
			  + eap_tls_start_header.get_header_length()
			  + eap_tls_start_header.get_data_length()),
			 packet_buffer_offset));

		EAP_ASSERT_ALWAYS(
			m_tls_peap_header_offset
			+eap_tls_start_header.get_header_length()
			+eap_tls_start_header.get_data_length()
			== packet_buffer_offset);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("    send: EAP-Request/TLS_PEAP/Start packet"),
		eap_tls_start_header.get_header_buffer(eap_tls_start_header.get_eap_length()),
		eap_tls_start_header.get_eap_length()));

	status = packet_send(
		get_send_network_id(),
		&eap_tls_start_packet,
		m_tls_peap_header_offset,
		eap_tls_start_header.get_eap_length(),
		TLS_PEAP_LOCAL_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
		if (m_is_client == false)
		{
			// Server saves the sent EAP-Identifier.
			set_last_eap_identifier(next_eap_identifier);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::start_tls_peap_authentication(
	const eap_variable_data_c * const received_authority_identity_payload
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_TLS_PEAP: %s, %s: function: eap_type_tls_peap_c::start_tls_peap_authentication()\n"),
		(m_is_client == true ? "client": "server"),
		(get_type_partner()->get_is_tunneled_eap() == true ? "tunneled" : "outer most")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_type_tls_peap_c::start_tls_peap_authentication()");

	eap_status_e status = m_tls_record->start_tls_peap_authentication(received_authority_identity_payload);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::eap_tls_peap_fragment_send()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_TLS_PEAP: %s, %s: function: eap_type_tls_peap_c::eap_tls_peap_fragment_send()\n"),
		(m_is_client == true ? "client": "server"),
		(get_type_partner()->get_is_tunneled_eap() == true ? "tunneled" : "outer most")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_type_tls_peap_c::eap_tls_peap_fragment_send()");

	eap_status_e status = eap_status_not_supported;

	if (m_tls_message_send_offset == 0ul
		&& m_tls_message_buffer.get_data_length()
		< tls_record_header_c::get_header_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_tls_peap_fragment_send(): ")
			 EAPL("packet buffer too short, %d bytes.\n"),
			m_tls_message_buffer.get_data_length()));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	else if (m_tls_message_buffer.get_data_length()
			 < m_tls_message_send_offset)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_tls_peap_fragment_send(): ")
			 EAPL("packet buffer %d shorter than ")
			 EAPL("m_tls_message_send_offset %d.\n"),
			 m_tls_message_buffer.get_data_length(),
			 m_tls_message_send_offset));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}


	eap_buf_chain_wr_c eap_tls_peap_fragment(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (eap_tls_peap_fragment.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_ASSERT_ALWAYS(EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH
					  >= (m_tls_peap_header_offset+m_trailer_length));
	u32_t packet_buffer_free
		= EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_tls_peap_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_tls_peap_header_offset+m_MTU;
	}

	u32_t packet_eap_data_free
		= packet_buffer_free
		- m_tls_peap_header_offset
		- eap_tls_peap_header_c::get_tls_max_header_length();

	eap_tls_peap_header_c eap_tls_packet(
		m_am_tools,
		eap_tls_peap_fragment.get_data_offset(
			m_tls_peap_header_offset,
			packet_eap_data_free),
		packet_eap_data_free);

	if (eap_tls_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	eap_tls_packet.reset_header(
		m_am_tools,
		m_current_eap_type,
		static_cast<u16_t>(packet_eap_data_free),
		m_current_peap_version,
		m_use_eap_expanded_type);
	if (m_tls_message_send_offset == 0)
	{
		// This is the first fragment.
		eap_tls_packet.set_flag_tls_length_included(true);
		eap_tls_packet.set_tls_message_length(
			m_tls_message_buffer.get_data_length());
	}

	eap_tls_packet.set_eap_length(
		static_cast<u16_t>(packet_eap_data_free),
		m_use_eap_expanded_type);

	if (m_is_client == true)
	{
		eap_tls_packet.set_eap_code(eap_code_response);
		eap_tls_packet.set_eap_identifier(get_last_eap_identifier());
	}
	else
	{
		eap_tls_packet.set_eap_code(eap_code_request);
		eap_tls_packet.set_eap_identifier(
			static_cast<u8_t>(get_last_eap_identifier()+1ul));
	}
	eap_tls_packet.set_eap_type(
		m_current_eap_type,
		m_use_eap_expanded_type);


	u32_t fragment_length
		= m_MTU
		- eap_tls_peap_header_c::get_tls_max_header_length();
	u32_t pending_message_length
		= m_tls_message_buffer.get_data_length()
		- m_tls_message_send_offset;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP-TLS fragment: packet_eap_data_free %d, ")
		 EAPL("fragment_length %d, pending_message_length %d, ")
		 EAPL("EAP-header length %d, buffer length %d\n"),
		 packet_eap_data_free,
		 fragment_length,
		 pending_message_length,
		 eap_tls_packet.get_header_length(),
		 eap_tls_peap_fragment.get_buffer_length()));

	if (packet_eap_data_free >= pending_message_length)
	{
		// Message data is less than the buffer length,
		// so the fragment is only length of the message data.
		fragment_length = pending_message_length;

		if (m_tls_message_send_offset == 0
			&& m_use_tppd_tls_peap == true
			&& m_includes_tls_handshake_message == true
#if defined(USE_FAST_EAP_TYPE)
			&& m_current_eap_type != eap_type_fast
#endif //#if defined(USE_FAST_EAP_TYPE)
			)
		{
			// TLS-message length is included,
			// even no fragmentation is used.
			eap_tls_packet.set_flag_tls_length_included(true);
		}
		else
		{
			// TLS-message length is not included,
			// because no fragmentation is used.
			eap_tls_packet.set_flag_tls_length_included(false);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP-TLS fragment: packet_eap_data_free %d, ")
			 EAPL("fragment_length %d, pending_message_length %d, ")
			 EAPL("EAP-header length %d\n"),
			 packet_eap_data_free,
			 fragment_length,
			 pending_message_length,
			 eap_tls_packet.get_header_length()));
	}

	if (fragment_length < pending_message_length)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP-TLS fragment: more fragments follow. ")
			 EAPL("fragment_length %d, pending_message_length %d, ")
			 EAPL("EAP-header length %d\n"),
			 fragment_length,
			 pending_message_length,
			 eap_tls_packet.get_header_length()));

		eap_tls_packet.set_flag_more_fragments(true);
	}


	update_buffer_indexes(
		TLS_PEAP_LOCAL_PACKET_BUFFER_LENGTH,
		m_tls_peap_header_offset+eap_tls_packet.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	status = eap_tls_peap_fragment.set_data_length(packet_buffer_offset);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -
	// Payload is TLS-message fragment.

	status = eap_tls_peap_fragment.add_data_to_offset(
		packet_buffer_offset,
		m_tls_message_buffer.get_data_offset(
			m_tls_message_send_offset, fragment_length),
		fragment_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	update_buffer_indexes(
		TLS_PEAP_LOCAL_PACKET_BUFFER_LENGTH,
		fragment_length,
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_tls_packet.set_data_length(
		fragment_length,
		m_use_eap_expanded_type);

	status = eap_tls_peap_fragment.set_data_length(packet_buffer_offset);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_tls_peap_fragment_send(): m_tls_peap_header_offset %d ")
		 EAPL("+ eap_tls_packet.get_header_length()")
		 EAPL("%d + eap_tls_packet.get_data_length() ")
		 EAPL("%d = %d == packet_buffer_offset %d.\n"),
		 m_tls_peap_header_offset,
		 eap_tls_packet.get_header_length(),
		 eap_tls_packet.get_data_length(),
		 (m_tls_peap_header_offset
		  + eap_tls_packet.get_header_length()
		  + eap_tls_packet.get_data_length()),
		 packet_buffer_offset));

	EAP_ASSERT_ALWAYS(
		m_tls_peap_header_offset
		+eap_tls_packet.get_header_length()
		+eap_tls_packet.get_data_length()
		== packet_buffer_offset);

	status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	status = packet_send(
		get_send_network_id(),
		&eap_tls_peap_fragment,
		m_tls_peap_header_offset,
		eap_tls_packet.get_eap_length(),
		TLS_PEAP_LOCAL_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
		m_tls_message_send_offset += fragment_length;

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
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::tls_message_process(
	const eap_am_network_id_c * const /*receive_network_id*/, ///< This is the network identity of the received EAP packet.
	eap_tls_peap_header_c * const received_tls_peap, ///< This is pointer to EAP header including EAP-TLS/PEAP fields.
	const u32_t /*tls_peap_packet_length*/ ///< This is length of received TLS/PEAP EAP packet.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_TLS_PEAP: %s, %s: function: eap_type_tls_peap_c::tls_message_process()\n"),
		(m_is_client == true ? "client": "server"),
		(get_type_partner()->get_is_tunneled_eap() == true ? "tunneled" : "outer most")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_type_tls_peap_c::tls_message_process()");

	if (m_tls_message_buffer.get_is_valid_data() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("tls_message_process: packet buffer invalid.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	if (m_tls_message_buffer.get_data_length() < tls_record_header_c::get_header_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("tls_message_process: packet buffer too short, %d bytes.\n"),
			m_tls_message_buffer.get_data_length()));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	save_current_state();
	set_state(eap_type_tls_peap_state_process_tls_message);

	eap_status_e status = m_tls_record->packet_process(
		&m_tls_message_buffer,
		received_tls_peap->get_eap_identifier());

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
			(EAPL("%s: tls_message_process: Authentication failed.\n"),
			(m_is_client == true) ? "client": "server"));

		restore_saved_previous_state();
		set_state(eap_type_tls_peap_state_failure);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::eap_identity_response_packet_process(
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
		(EAPL("EAP_type_TLS_PEAP: %s: function: eap_type_tls_peap_c::eap_identity_response_packet_process()\n"),
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
		if (m_state == eap_type_tls_peap_state_waiting_for_identity_response
			&& eap_header->get_identifier() != get_last_eap_identifier())
		{
			// Wrong EAP-Identifier in this state.
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_TLS_PEAP_ERROR,
				(EAPL("ERROR: eap_type_tls_peap_c::handle_identity_response_message(): ")
				 EAPL("EAP-Identifier 0x%02x is wrong (0x%02x is correct) in ")
				 EAPL("eap_type_tls_peap_state_variable_e %d=%s.\n"),
				 eap_header->get_identifier(),
				 get_last_eap_identifier(),
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}
		else if (m_tls_peap_test_version == true
			&& m_state == eap_type_tls_peap_state_success) // This one is for testing purposes.
		{
			// NOTE here we can not check the EAP-identifier.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: eap_type_tls_peap_c::handle_identity_response_message(): ")
				 EAPL("EAP-Identifier 0x%02x is not checked in ")
				 EAPL("eap_type_tls_peap_state_variable_e %d=%s.\n"),
				 eap_header->get_identifier(),
				 get_state(),
				 get_state_string()));
		}
	}


	if ((m_state == eap_type_tls_peap_state_waiting_for_identity_response
			|| m_state == eap_type_tls_peap_state_waiting_for_first_response)
		|| (m_tls_peap_test_version == true
			// In test version new authentication could start from this state.
			&& m_state == eap_type_tls_peap_state_success))
	{
		// EAP-Response/Identity is accepted only as a very first message.

		eap_status_e status = eap_status_process_general_error;

		save_current_state();

		// In test version new authentication could start from this state.
		if (m_tls_peap_test_version == true
			&& m_state == eap_type_tls_peap_state_success) // This one is for testing purposes.
		{
			// NOTE here we can not check the EAP-identifier.
			set_state(eap_type_tls_peap_state_waiting_for_identity_response);
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

		eap_variable_data_c authority_identity_payload(m_am_tools);
		if (authority_identity_payload.get_is_valid() == false)
		{
			restore_saved_previous_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

#if defined(USE_FAST_EAP_TYPE)
		if (m_current_eap_type == eap_type_fast)
		{
			// Read the authority identity (A-ID).
			status = m_tls_record->read_authority_identity(&authority_identity_payload);
			if (status != eap_status_ok)
			{
				restore_saved_previous_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
#endif //#if defined(USE_FAST_EAP_TYPE)

		status = send_tls_peap_start_message(next_eap_identifier, &authority_identity_payload);
		if (status != eap_status_ok)
		{
			restore_saved_previous_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		set_last_eap_identifier(next_eap_identifier);
		set_state(eap_type_tls_peap_state_waiting_for_first_response);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: eap_type_tls_peap_c::handle_identity_response_message(): ")
			 EAPL("EAP-Identifier 0x%02x in eap_type_tls_peap_state_variable_e %d=%s. ")
			 EAPL("EAP-Response/Identity is accepted only in ")
			 EAPL("eap_type_tls_peap_state_waiting_for_identity_response.\n"),
			 eap_header->get_identifier(),
			 get_state(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::select_peap_version(
	const u32_t proposed_peap_version)
{
	u32_t version_count = m_accepted_PEAP_versions.get_data_length() / sizeof(u32_t);

	eap_tls_trace_string_c tls_trace;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("this = 0x%08x, eap_type_tls_peap_c::select_peap_version(): ")
		 EAPL("%s: Current PEAP version %d=%s, proposed PEAP version %d=%s.\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 m_current_peap_version,
		 tls_trace.get_peap_version_string(m_current_peap_version),
		 proposed_peap_version,
		 tls_trace.get_peap_version_string(static_cast<peap_version_e>(proposed_peap_version))));

	// Note some PEAP version was set before PEAP actually starts.
	// Here we disable the default selection.
	m_current_peap_version = peap_version_none;

	u32_t *p_accepted_peap_versions
		= reinterpret_cast<u32_t *>(m_accepted_PEAP_versions.get_data(
			m_accepted_PEAP_versions.get_data_length()));
	if (p_accepted_peap_versions == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	u32_t highest_supported_version = peap_version_none;

	for (u32_t ind = 0; ind < version_count; ind++)
	{
		if (highest_supported_version == peap_version_none
			|| highest_supported_version < p_accepted_peap_versions[ind])
		{
			highest_supported_version = p_accepted_peap_versions[ind];
		}

		if (proposed_peap_version == p_accepted_peap_versions[ind])
		{
			m_current_peap_version = static_cast<peap_version_e>(proposed_peap_version);

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_type_tls_peap_c::select_peap_version(): ")
				 EAPL("%s: Accepted PEAP version %d=%s.\n"),
					(m_is_client == true ? "client": "server"),
					m_current_peap_version,
					tls_trace.get_peap_version_string(m_current_peap_version)));
			break;
		}
	} // for()

	// Because no matching PEAP version was not found,
	// we must use the highest version version we support.
	if (m_current_peap_version != peap_version_none)
	{
		// OK, proposed version accepted.
	}
	else if (highest_supported_version != peap_version_none)
	{
		m_current_peap_version = static_cast<peap_version_e>(highest_supported_version);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_type_tls_peap_c::select_peap_version(): ")
			 EAPL("%s: Highest supported PEAP version %d=%s.\n"),
				(m_is_client == true ? "client": "server"),
				m_current_peap_version,
				tls_trace.get_peap_version_string(m_current_peap_version)));
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_no_matching_protocol_version);
	}

	m_tls_record->set_peap_version(
		m_current_peap_version,
		m_use_tppd_tls_peap,
		m_use_tppd_peapv1_acknowledge_hack);

	if (m_is_client == false
		&& static_cast<peap_version_e>(proposed_peap_version) != m_current_peap_version)
	{
		// Server does not accept PEAP version client proposes.
		// Server terminates the session immediately.
		get_type_partner()->set_session_timeout(0ul);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_no_matching_protocol_version);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::tls_peap_packet_process(
	const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
	eap_tls_peap_header_c * const received_tls_peap, ///< This is pointer to EAP header including EAP-TLS/PEAP fields.
	const u32_t tls_peap_packet_length ///< This is length of received TLS/PEAP EAP packet.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_TLS_PEAP: this = 0x%08x, %s, %s, function: eap_type_tls_peap_c::tls_peap_packet_process()\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 (get_type_partner()->get_is_tunneled_eap() == true ? "tunneled" : "outer most")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_type_tls_peap_c::tls_peap_packet_process()");

	if (m_tls_peap_test_version == true
		&& get_state() == eap_type_tls_peap_state_failure)
	{
		// This is for testing.
		if (m_is_client == false
			&& received_tls_peap->get_eap_code() == eap_code_response
			&& received_tls_peap->get_eap_type() == eap_type_identity)
		{
			set_state(eap_type_tls_peap_state_waiting_for_identity_response);
		}
		else if (m_is_client == true
				&& received_tls_peap->get_flag_start() == true)
		{
			set_state(eap_type_tls_peap_state_waiting_for_tls_start);
		}
	}

	if (received_tls_peap->check_header(
			m_am_tools,
			m_current_eap_type,
			m_is_client,
			peap_version_0_xp,
			true) != eap_status_ok
		&& received_tls_peap->check_header(
			m_am_tools,
			m_current_eap_type,
			m_is_client,
			peap_version_1,
			true) != eap_status_ok
		&& received_tls_peap->check_header(
			m_am_tools,
			m_current_eap_type,
			m_is_client,
			peap_version_2,
			true) != eap_status_ok)
	{
		// ERROR: EAP-TLS/PEAP header is corrupted.
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_TLS_PEAP_ERROR,
			(EAPL("ERROR: eap_type_tls_peap_c::tls_peap_packet_process(): ")
			 EAPL("EAP-TLS/PEAP header is corrupted in ")
			 EAPL("eap_type_tls_peap_state_variable_e %d=%s.\n"),
			get_state(),
			get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	else if (received_tls_peap->get_eap_length() > tls_peap_packet_length)
	{
		// ERROR: EAP-Lenght field value is larger than actual received packet.
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_TLS_PEAP_ERROR,
			(EAPL("ERROR: eap_type_tls_peap_c::tls_peap_packet_process(): ")
			 EAPL("EAP-Lenght field %d value is larger than actual received ")
			 EAPL("packet %d in eap_type_tls_peap_state_variable_e %d=%s.\n"),
			received_tls_peap->get_eap_length(),
			tls_peap_packet_length,
			get_state(),
			get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	else if (m_is_client == false
		&& received_tls_peap->get_flag_start() == true)
	{
		// ERROR: Server cannot receive EAP-TLS/PEAP Start message.
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_TLS_PEAP_ERROR,
			(EAPL("ERROR: eap_type_tls_peap_c::tls_peap_packet_process(): ")
			 EAPL("Server cannot receive EAP-TLS/PEAP Start message. ")
			 EAPL("eap_type_tls_peap_state_variable_e %d=%s.\n"),
			get_state(),
			get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}
	else if (m_is_client == true
		&& (get_state() != eap_type_tls_peap_state_waiting_for_request
			&& get_state() != eap_type_tls_peap_state_waiting_for_identity_request
			// EAP-TLS could start without EAP-Request/Identity message.
			&& get_state() != eap_type_tls_peap_state_waiting_for_tls_start
			&& get_state()
			!= eap_type_tls_peap_state_tppd_peapv1_waits_eap_success_or_tunneled_packet
			))
	{
		// ERROR: Client cannot receive EAP-TLS/PEAP message in other states.
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: eap_type_tls_peap_c::tls_peap_packet_process(): ")
			 EAPL("Client cannot receive EAP-TLS/PEAP message in ")
			 EAPL("eap_type_tls_peap_state_variable_e %d=%s.\n"),
			get_state(),
			get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	else if (m_is_client == false
		&& get_state() != eap_type_tls_peap_state_waiting_for_response
		&& get_state() != eap_type_tls_peap_state_waiting_for_first_response
		&& get_state() != eap_type_tls_peap_state_waiting_for_empty_response
		&& get_state() != eap_type_tls_peap_state_waiting_for_empty_tppd_peap_v1_acknowledge
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		&& get_state() != eap_type_tls_peap_state_server_waits_ttls_plain_ms_chap_v2_empty_ack
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		)
	{
		// WARNING: Server cannot receive EAP-TLS/PEAP message in other states.
		// This packet is dropped quietly.
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: eap_type_tls_peap_c::tls_peap_packet_process(): ")
			 EAPL("Server cannot receive EAP-TLS/PEAP message in ")
			 EAPL("eap_type_tls_peap_state_variable_e %d=%s.\n"),
			get_state(),
			get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	else if (received_tls_peap->get_flag_start() == true
		&& get_state() != eap_type_tls_peap_state_waiting_for_tls_start
		&& get_state() != eap_type_tls_peap_state_waiting_for_identity_request)
		// EAP-TLS could start without EAP-Request/Identity message.
	{
		// ERROR: EAP-TLS/PEAP Start message is accepted only in
		// eap_type_tls_peap_state_waiting_for_tls_start.
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_TLS_PEAP_ERROR,
			(EAPL("ERROR: eap_type_tls_peap_c::tls_peap_packet_process(): ")
			 EAPL("EAP-TLS/PEAP Start message is NOT accepted in ")
			 EAPL("eap_type_tls_peap_state_variable_e %d=%s.\n"),
			get_state(),
			get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	// EAP-TLS and PEAP fragmentation support:
	// 
	// Flags include the Length included (L), More fragments (M), and EAP-TLS Start (S) bits.
	// 
	// The L flag is set to indicate the presence of the four octet TLS Message
	// Length field, and MUST be set for the first fragment of a fragmented
	// TLS message or set of messages.
	// 
	// The M flag is set on all but the last fragment.
	// 
	// The S flag is set only within the EAP-TLS start message
	// sent from the EAP server to the peer. This differentiates
	// the EAP-TLS Start message from a fragment acknowledgement.
	// 
	// The TLS Message Length field is four octets, and provides
	// the total length of the TLS message or set of messages
	// that is being fragmented, this simplifies buffer allocation.

	eap_status_e status = eap_status_process_general_error;

	save_current_reassembly_state();

	if (get_reassembly_state() == eap_type_tls_peap_reassembly_state_wait_first_message)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_TLS_PEAP: this = 0x%08x, %s, %s, function: eap_type_tls_peap_c::tls_peap_packet_process(): waits first fragment.\n"),
			 this,
			 (m_is_client == true ? "client": "server"),
			 (get_type_partner()->get_is_tunneled_eap() == true ? "tunneled" : "outer most")));

		if (received_tls_peap->get_flag_more_fragments() == true
			&& received_tls_peap->get_flag_tls_length_included() == false)
		{
			// The first fragmented message must include TLS-length field.
			restore_saved_reassembly_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}


		bool first_fragment = false;
		u32_t tls_message_length = 0ul;

		if (received_tls_peap->get_flag_tls_length_included() == true)
		{
			// This is the first fragment and TLS message length is included.
			// We must allocate buffer for the fragments.

			status = received_tls_peap->get_tls_message_length(&tls_message_length);
			if (status != eap_status_ok)
			{
				restore_saved_reassembly_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			first_fragment = true;
		}
		else if (received_tls_peap->get_flag_more_fragments() == false
			&& received_tls_peap->get_flag_start() == false
			&& received_tls_peap->get_data_length() > 0ul)
		{
			// This is the individual message and TLS message length is not included.
			// We must allocate buffer for the message.

			tls_message_length = received_tls_peap->get_data_length();

			first_fragment = true;
		}


		if (first_fragment == true)
		{
			m_tls_message_buffer.reset();

			if (tls_message_length > 0ul)
			{
				if (tls_message_length > EAP_TLS_PEAP_MAX_MESSAGE_LENGTH)
				{
					restore_saved_reassembly_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_too_long_message);
				}

				// Next allocate buffer for reassembled TLS-message.
				status = m_tls_message_buffer.set_buffer_length(tls_message_length);
				if (status != eap_status_ok)
				{
					restore_saved_reassembly_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				// Copy first fragment to the reassembly buffer.
				status = m_tls_message_buffer.add_data(
					received_tls_peap->get_data(m_am_tools, received_tls_peap->get_data_length()),
					received_tls_peap->get_data_length());
				if (status != eap_status_ok)
				{
					restore_saved_reassembly_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				m_first_fragment_eap_identifier = received_tls_peap->get_eap_identifier();
			}
		}


		if (received_tls_peap->get_flag_more_fragments() == true)
		{
			// This is NOT the last fragment.

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_TLS_PEAP: this = 0x%08x, %s, %s, function: eap_type_tls_peap_c::tls_peap_packet_process(): waits first fragment, not last fragment.\n"),
				 this,
				 (m_is_client == true ? "client": "server"),
				 (get_type_partner()->get_is_tunneled_eap() == true ? "tunneled" : "outer most")));

			// Send fragment acknowledge message.
			status = send_empty_eap_ack();
			if (status != eap_status_ok)
			{
				restore_saved_reassembly_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// Change reassembly state.
			set_reassembly_state(eap_type_tls_peap_reassembly_state_wait_last_fragment);
		}
		else
		{
			// This is the last fragment or non fragmented message.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_TLS_PEAP: this = 0x%08x, %s, %s, function: eap_type_tls_peap_c::tls_peap_packet_process(): waits first fragment, the last fragment, start flag %d, data length %d.\n"),
				 this,
				 (m_is_client == true ? "client": "server"),
				 (get_type_partner()->get_is_tunneled_eap() == true ? "tunneled" : "outer most"),
				 received_tls_peap->get_flag_start(),
				 received_tls_peap->get_data_length()));

			// Change reassembly state.
			set_reassembly_state(eap_type_tls_peap_reassembly_state_message_reassembled);

			if (received_tls_peap->get_flag_start() == true)
			{
				// This is EAP-TLS/PEAP Start message.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("EAP_type_TLS_PEAP: this = 0x%08x, %s, %s, function: eap_type_tls_peap_c::tls_peap_packet_process(): waits first fragment, EAP-TLS/PEAP Start message.\n"),
					 this,
					 (m_is_client == true ? "client": "server"),
					 (get_type_partner()->get_is_tunneled_eap() == true ? "tunneled" : "outer most")));

				save_current_state();
				set_state(eap_type_tls_peap_state_process_tls_start);

				if (m_current_eap_type == eap_type_peap)
				{
					status = select_peap_version(received_tls_peap->get_flag_version());
					if (status != eap_status_ok)
					{
						restore_saved_reassembly_state();
						restore_saved_previous_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(
							m_am_tools,
							eap_status_no_matching_protocol_version);
					}
				}

				if (m_NAI.get_is_valid_data() == false)
				{
					// Do not care of the error. Some times there are no NAI at all.
					(void) get_type_partner()->get_saved_eap_identity(&m_NAI);
				}

				eap_variable_data_c received_authority_identity_payload(m_am_tools);
				if (received_authority_identity_payload.get_is_valid() == false)
				{
					restore_saved_previous_state();
					restore_saved_reassembly_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

#if defined(USE_FAST_EAP_TYPE)
				if (m_current_eap_type == eap_type_fast)
				{
					// Read the received authority identity (A-ID).
					status = received_authority_identity_payload.set_buffer(
						received_tls_peap->get_data(m_am_tools, received_tls_peap->get_data_length()),
						received_tls_peap->get_data_length(),
						false,
						false);
				}
#endif //#if defined(USE_FAST_EAP_TYPE)

				status = start_tls_peap_authentication(&received_authority_identity_payload);
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
					set_state(eap_type_tls_peap_state_waiting_for_request);
				}
			}
			else if (received_tls_peap->get_flag_start() == false
				&& received_tls_peap->get_data_length() == 0)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("EAP_type_TLS_PEAP: this = 0x%08x, %s, %s, function: eap_type_tls_peap_c::tls_peap_packet_process(): waits first fragment, empty EAP-TLS/PEAP message.\n"),
					 this,
					 (m_is_client == true ? "client": "server"),
					 (get_type_partner()->get_is_tunneled_eap() == true ? "tunneled" : "outer most")));

				// Real TLS-tunnel type can be checked here.
				status = received_tls_peap->check_header(
					m_am_tools,
					m_current_eap_type,
					m_is_client,
					m_current_peap_version,
					true);
				if (status != eap_status_ok)
				{
					restore_saved_reassembly_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

#if defined(USE_EAP_CORE_SERVER)
				if (m_is_client == false
					&& get_state()
					== eap_type_tls_peap_state_waiting_for_empty_tppd_peap_v1_acknowledge)
				{
					// Server wait empty PEAP v1 acknowledge
					status = finish_successful_authentication(false, false, true);
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
				else if (m_is_client == false
					&& get_state() == eap_type_tls_peap_state_server_waits_ttls_plain_ms_chap_v2_empty_ack)
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("eap_type_tls_peap_c::tls_peap_packet_process(): ")
						 EAPL("received EAP-TTLS/PEAP empty Ack message in ")
						 EAPL("eap_type_tls_peap_state_variable_e %d=%s, ")
						 EAPL("eap_type_tls_peap_reassembly_state_e %d=%s.\n"),
						 get_state(),
						 get_state_string(),
						 get_reassembly_state(),
						 get_reassembly_state_string()));

					status = m_tls_record->empty_ack_packet_received(
						receive_network_id,
						received_tls_peap->get_identifier());
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
					
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
				else if (m_is_client == false
					&& get_state() == eap_type_tls_peap_state_waiting_for_empty_response)
				{
					// Server waits the client sends an empty response.

					if (received_tls_peap->get_data_length() != 0ul)
					{
						restore_saved_reassembly_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(
							m_am_tools,
							eap_status_process_illegal_packet_error);
					}
					else
					{
						if (m_current_eap_type == eap_type_tls
							|| (m_current_eap_type == eap_type_peap
								&& (get_tls_session_type() == tls_session_type_original_session_resumption
									|| get_tls_session_type() == tls_session_type_stateless_session_resumption)))
						{
							// OK, successfull authentication.
							status = finish_successful_authentication(false, false, true);
							if (status != eap_status_success)
							{
								restore_saved_reassembly_state();
								EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
								return EAP_STATUS_RETURN(m_am_tools, status);
							}
						}
						else if (m_current_eap_type == eap_type_peap
							|| m_current_eap_type == eap_type_ttls
#if defined(USE_FAST_EAP_TYPE)
							|| (m_current_eap_type == eap_type_fast
								&& (get_tls_session_type() == tls_session_type_eap_fast_server_unauthenticated_provisioning_mode_ADHP
									|| get_tls_session_type() == tls_session_type_full_authentication))
#endif //#if defined(USE_FAST_EAP_TYPE)
								)
						{
							save_current_state();
							set_state(eap_type_tls_peap_state_process_tls_message);

							// Now we must start the tunneled EAP-type.
							status = m_tls_record->start_peap_tunneled_authentication(
								receive_network_id,
								received_tls_peap->get_eap_identifier(),
								get_tls_session_type());
							if (status != eap_status_ok)
							{
								restore_saved_previous_state();
								restore_saved_reassembly_state();
								EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
								return EAP_STATUS_RETURN(m_am_tools, status);
							}

							m_tunneled_eap_type_active = true;
							set_state(eap_type_tls_peap_state_waiting_for_response);
						}
						else
						{
							EAP_TRACE_ERROR(
								m_am_tools,
								TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
								(EAPL("ERROR: EAP_type_TLS_PEAP: %s, unknown EAP-type 0xfe%06x%08x=%s\n"),
								 (m_is_client == true) ? "client": "server",
								 m_current_eap_type.get_vendor_id(),
								 m_current_eap_type.get_vendor_type(),
								 eap_header_string_c::get_eap_type_string(m_current_eap_type)));

							restore_saved_reassembly_state();
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}
				}
				else
#endif //#if defined(USE_EAP_CORE_SERVER)
				{
					// This is EAP-TLS/PEAP fragment acknowledge.
					if (m_tls_message_buffer.get_is_valid_data() == true
						&& m_tls_message_send_offset < m_tls_message_buffer.get_data_length())
					{
						// We can send next fragment.

						save_current_state();
						set_state(eap_type_tls_peap_state_process_tls_message);

						status = eap_tls_peap_fragment_send();
						if (status != eap_status_ok)
						{
							restore_saved_previous_state();
							restore_saved_reassembly_state();
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
						
						if (m_is_client == true)
						{
							set_state(eap_type_tls_peap_state_waiting_for_request);
						}
						else
						{
							set_state(eap_type_tls_peap_state_waiting_for_response);
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
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("EAP_type_TLS_PEAP: this = 0x%08x, %s, %s, function: eap_type_tls_peap_c::tls_peap_packet_process(): waits first fragment, non empty EAP-TLS/PEAP message.\n"),
					 this,
					 (m_is_client == true ? "client": "server"),
					 (get_type_partner()->get_is_tunneled_eap() == true ? "tunneled" : "outer most")));


#if defined(USE_EAP_CORE_SERVER)
				if (m_is_client == false
					&& get_state() == eap_type_tls_peap_state_waiting_for_empty_response
					&& received_tls_peap->get_data_length() != 0ul)
				{
					// Server waits the client sends an empty response.
					restore_saved_reassembly_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(
						m_am_tools,
						eap_status_process_illegal_packet_error);
				}
				else if (m_is_client == false
						 && m_current_eap_type == eap_type_peap
						 && get_state() == eap_type_tls_peap_state_waiting_for_first_response)
				{
					// Note PEAP version is NOT checked here.
					status = received_tls_peap->check_header(
						m_am_tools,
						m_current_eap_type,
						m_is_client,
						m_current_peap_version,
						false);
					if (status != eap_status_ok)
					{
						restore_saved_reassembly_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					// Check the PEAP version client selected.
					status = select_peap_version(received_tls_peap->get_flag_version());
					if (status != eap_status_ok)
					{
						restore_saved_reassembly_state();
						restore_saved_previous_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
#endif //#if defined(USE_EAP_CORE_SERVER)

				// NOTE, PEAP version is checked here.
				status = received_tls_peap->check_header(
					m_am_tools,
					m_current_eap_type,
					m_is_client,
					m_current_peap_version,
					true);
				if (status != eap_status_ok)
				{
					restore_saved_reassembly_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				// Process the reassembled TLS message.
				status = tls_message_process(
					receive_network_id,
					received_tls_peap,
					tls_peap_packet_length);

				if (status != eap_status_ok
					&& status != eap_status_pending_request
					&& status != eap_status_success)
				{
					restore_saved_reassembly_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}

			set_reassembly_state(eap_type_tls_peap_reassembly_state_wait_first_message);
		}
	}
	else if (get_reassembly_state() == eap_type_tls_peap_reassembly_state_wait_last_fragment)
	{
		// TLS message length field may or may not be included.

		EAP_ASSERT_ALWAYS(received_tls_peap->get_flag_start() == false);

		// Concatenate fragment to the reassembly buffer.
		status = m_tls_message_buffer.add_data(
			received_tls_peap->get_data(m_am_tools, received_tls_peap->get_data_length()),
			received_tls_peap->get_data_length());
		if (status != eap_status_ok)
		{
			restore_saved_reassembly_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (received_tls_peap->get_flag_more_fragments() == true)
		{
			// This is NOT the last fragment.

			// Send fragment acknowledge message.
			status = send_empty_eap_ack();
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
			set_reassembly_state(eap_type_tls_peap_reassembly_state_message_reassembled);

			// Process the reassembled TLS message.
			status = tls_message_process(
				receive_network_id,
				received_tls_peap,
				tls_peap_packet_length);

			if (status != eap_status_ok
				&& status != eap_status_pending_request
				&& status != eap_status_success)
			{
				restore_saved_reassembly_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			set_reassembly_state(eap_type_tls_peap_reassembly_state_wait_first_message);
		}
	}
	else if (get_reassembly_state() == eap_type_tls_peap_reassembly_state_message_reassembled)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_TLS_PEAP_ERROR,
			(EAPL("ERROR: eap_type_tls_peap_c::tls_peap_packet_process(): ")
			 EAPL("Cannot receive EAP-TLS/PEAP message in ")
			 EAPL("eap_type_tls_peap_state_variable_e %d=%s, ")
			 EAPL("eap_type_tls_peap_reassembly_state_e %d=%s.\n"),
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
			TRACE_FLAGS_TLS_PEAP_ERROR,
			(EAPL("ERROR: eap_type_tls_peap_c::tls_peap_packet_process(): ")
			 EAPL("Cannot receive EAP-TLS/PEAP message in ")
			 EAPL("eap_type_tls_peap_state_variable_e %d=%s, ")
			 EAPL("eap_type_tls_peap_reassembly_state_e %d=%s.\n"),
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
EAP_FUNC_EXPORT u32_t eap_type_tls_peap_c::get_header_offset(
	u32_t * const MTU,
	u32_t * const trailer_length
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Note, EAP-TLS and PEAP supports fragmentation.
	// Here we could tell the MTU is big enough, the maximum memory buffer size is perfect.

	if (m_current_eap_type == eap_type_peap
		&& m_current_peap_version == peap_version_0_xp)
	{
		// PEAPv0 cannot use long tunneled EAP-packets,
		// bacause of the inner EAP-packets does not
		// have own EAP-header. Long inner EAP-packets will be 
		// fragmented in outer PEAPv0 application data and that will cause
		// wrong EAP-identifier values after reassembly.
		u32_t offset = get_type_partner()->get_header_offset(
			MTU,
			trailer_length);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return offset;
	}
	else
	{
		if (MTU != 0)
		{
			*MTU = EAP_TLS_PEAP_MAX_MESSAGE_LENGTH;
		}

		if (trailer_length != 0)
		{
			*trailer_length = 0ul;
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return 0ul; // This is the header offset of the TLS-record header.
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::timer_expired(
	const u32_t /*id*/, void * /*data*/
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::timer_delete_data(
	const u32_t /*id*/, void * /*data*/
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_tls_peap_c::set_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_is_valid = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eap_type_tls_peap_c::get_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_valid;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	status = m_am_type_tls_peap->configure();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_tls_record->configure();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	//----------------------------------------------------------

#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	{
		eap_variable_data_c tls_use_privacy(m_am_tools);

		status = get_type_partner()->read_configure(
			cf_str_EAP_TLS_PEAP_use_identity_privacy.get_field(),
			&tls_use_privacy);
		if (status == eap_status_ok
			&& tls_use_privacy.get_is_valid_data() == true
			&& tls_use_privacy.get_data_length() == sizeof(u32_t)
			&& tls_use_privacy.get_data(sizeof(u32_t)) != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(
				tls_use_privacy.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_tls_use_identity_privacy = false;
				}
				else
				{
					m_tls_use_identity_privacy = true;
				}
			}
		}

		status = eap_status_ok;
	}

	if (m_is_client == false)
	{
		eap_variable_data_c tls_server_use_privacy(m_am_tools);

		status = get_type_partner()->read_configure(
			cf_str_EAP_TLS_PEAP_use_identity_privacy_server.get_field(),
			&tls_server_use_privacy);
		if (status == eap_status_ok
			&& tls_server_use_privacy.get_is_valid_data() == true
			&& tls_server_use_privacy.get_data_length() == sizeof(u32_t)
			&& tls_server_use_privacy.get_data(sizeof(u32_t)) != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(
				tls_server_use_privacy.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_tls_use_identity_privacy = false;
				}
				else
				{
					m_tls_use_identity_privacy = true;
				}
			}
		}

		status = eap_status_ok;
	}

#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)

	//----------------------------------------------------------

	{
		eap_variable_data_c wait_eap_success_packet(m_am_tools);

		status = read_configure(
			cf_str_EAP_TLS_PEAP_wait_eap_success_packet.get_field(),
			&wait_eap_success_packet);

		if (status == eap_status_ok
			&& wait_eap_success_packet.get_is_valid_data() == true)
		{
			u32_t *flag = reinterpret_cast<u32_t *>(
				wait_eap_success_packet.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_wait_eap_success_packet = false;
				}
				else
				{
					// NOTE: when plain PEAP is used no EAP-success is sent 
					// in plain text and this option will be set to false.
					m_wait_eap_success_packet = true;
				}
			}
			else
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_TLS_PEAP_ERROR,
					(EAPL("ERROR: illegal configuration value %s\n"),
					 cf_str_EAP_TLS_PEAP_wait_eap_success_packet.get_field()->get_field()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c check_identifier_of_eap_identity_response(m_am_tools);

		status = read_configure(
			cf_str_EAP_TLS_PEAP_check_identifier_of_eap_identity_response.get_field(),
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
					TRACE_FLAGS_TLS_PEAP_ERROR,
					(EAPL("ERROR: illegal configuration value %s\n"),
					 cf_str_EAP_TLS_PEAP_check_identifier_of_eap_identity_response
					 .get_field()->get_field()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c EAP_TLS_PEAP_check_nai_realm(m_am_tools);

		status = read_configure(
			cf_str_EAP_TLS_PEAP_check_nai_realm.get_field(),
			&EAP_TLS_PEAP_check_nai_realm);
		if (status == eap_status_ok
			&& EAP_TLS_PEAP_check_nai_realm.get_is_valid_data() == true)
		{
			u32_t *check_nai_realm = reinterpret_cast<u32_t *>(
				EAP_TLS_PEAP_check_nai_realm.get_data(sizeof(u32_t)));
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
			cf_str_EAP_TLS_test_version.get_field(),
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
					m_tls_peap_test_version = false;
				}
				else
				{
					m_tls_peap_test_version = true;
				}
			}
		}
	}

	//----------------------------------------------------------

	if (m_current_eap_type == eap_type_peap)
	{
		{
			eap_variable_data_c use_tppd_peapv1_acknowledge_hack(m_am_tools);

			status = read_configure(
				cf_str_EAP_TLS_use_tppd_peapv1_acknowledge_hack.get_field(),
				&use_tppd_peapv1_acknowledge_hack);
			if (status == eap_status_ok
				&& use_tppd_peapv1_acknowledge_hack.get_is_valid_data() == true
				&& use_tppd_peapv1_acknowledge_hack.get_data_length() == sizeof(u32_t)
				&& use_tppd_peapv1_acknowledge_hack.get_data(sizeof(u32_t)) != 0)
			{
				// This is optional value.
				u32_t *flag = reinterpret_cast<u32_t *>(
					use_tppd_peapv1_acknowledge_hack.get_data(sizeof(u32_t)));
				if (flag != 0)
				{
					if (*flag == 0)
					{
						m_use_tppd_peapv1_acknowledge_hack = false;
					}
					else
					{
						m_use_tppd_peapv1_acknowledge_hack = true;
					}
				}
			}
		}


		if (m_is_client == false)
		{
			// Server

			eap_variable_data_c used_peap_version(m_am_tools);

			status = read_configure(
				cf_str_EAP_TLS_PEAP_used_PEAP_version.get_field(),
				&used_peap_version);
			if (status == eap_status_ok
				&& used_peap_version.get_is_valid_data() == true)
			{
				u32_t *p_used_peap_version = reinterpret_cast<u32_t *>(
					used_peap_version.get_data(sizeof(u32_t)));

				if (p_used_peap_version == 0)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_TLS_PEAP_ERROR,
						(EAPL("ERROR: illegal configuration value %s\n"),
						 cf_str_EAP_TLS_PEAP_used_PEAP_version.get_field()->get_field()));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
				}
				else if (*p_used_peap_version > peap_version_2)
				{
					// Not supported PEAP version.
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_TLS_PEAP_ERROR,
						(EAPL("ERROR: Not supported PEAP version configuration %s: %d\n"),
						 cf_str_EAP_TLS_PEAP_used_PEAP_version.get_field()->get_field(),
						 *p_used_peap_version));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
				}
				else
				{
					m_configured_peap_version = static_cast<peap_version_e>(
						*p_used_peap_version);
					m_current_peap_version = m_configured_peap_version;
				}
			}

			//----------------------------------------------------------

			{
				eap_variable_data_c use_tppd_peapv1_acknowledge_hack(m_am_tools);

				status = read_configure(
					cf_str_EAP_TLS_server_use_tppd_peapv1_acknowledge_hack.get_field(),
					&use_tppd_peapv1_acknowledge_hack);
				if (status == eap_status_ok
					&& use_tppd_peapv1_acknowledge_hack.get_is_valid_data() == true
					&& use_tppd_peapv1_acknowledge_hack.get_data_length() == sizeof(u32_t)
					&& use_tppd_peapv1_acknowledge_hack.get_data(sizeof(u32_t)) != 0)
				{
					// This is optional value.
					u32_t *flag = reinterpret_cast<u32_t *>(
						use_tppd_peapv1_acknowledge_hack.get_data(sizeof(u32_t)));
					if (flag != 0)
					{
						if (*flag == 0)
						{
							m_use_tppd_peapv1_acknowledge_hack = false;
						}
						else
						{
							m_use_tppd_peapv1_acknowledge_hack = true;
						}
					}
				}
			}
		}

		//----------------------------------------------------------

		{
			eap_variable_data_c accepted_peap_versions(m_am_tools);

			status = read_configure(
				cf_str_EAP_TLS_PEAP_accepted_PEAP_versions.get_field(),
				&accepted_peap_versions);
			if (status == eap_status_ok
				&& accepted_peap_versions.get_is_valid_data() == true
				&& accepted_peap_versions.get_data_length() >= sizeof(u32_t))
			{
				u32_t *p_accepted_peap_versions
					= reinterpret_cast<u32_t *>(accepted_peap_versions.get_data(
						accepted_peap_versions.get_data_length()));

				if (p_accepted_peap_versions == 0)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_TLS_PEAP_ERROR,
						(EAPL("ERROR: illegal configuration value %s\n"),
						 cf_str_EAP_TLS_PEAP_accepted_PEAP_versions.get_field()->get_field()));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
				}
				else
				{
					u32_t version_count = accepted_peap_versions.get_data_length()
						/ sizeof(u32_t);

					for (u32_t ind = 0ul; ind < version_count; ind++)
					{
						if (p_accepted_peap_versions[ind] > peap_version_2)
						{
							// Not supported PEAP version.
							EAP_TRACE_ERROR(
								m_am_tools,
								TRACE_FLAGS_TLS_PEAP_ERROR,
								(EAPL("ERROR: Not supported PEAP version configuration %s: %d\n"),
								 cf_str_EAP_TLS_PEAP_accepted_PEAP_versions
								 .get_field()->get_field(),
								 *p_accepted_peap_versions));
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(
								m_am_tools,
								eap_status_illegal_configure_field);
						}

						status = m_accepted_PEAP_versions.add_data(
							&(p_accepted_peap_versions[ind]),
							sizeof(p_accepted_peap_versions[ind]));
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}
				}
			}
			else
			{
				// Not configured.
				// Accept only version 0.
				u32_t accepted_peap_version = peap_version_0_xp;

				m_accepted_PEAP_versions.reset();

				status = m_accepted_PEAP_versions.add_data(
					&accepted_peap_version,
					sizeof(accepted_peap_version));
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}

		//----------------------------------------------------------

		if (m_is_client == false)
		{
			// Server could use it's own configuration.

			eap_variable_data_c accepted_peap_versions(m_am_tools);

			status = read_configure(
				cf_str_EAP_TLS_PEAP_server_accepted_PEAP_versions.get_field(),
				&accepted_peap_versions);
			if (status == eap_status_ok
				&& accepted_peap_versions.get_is_valid_data() == true
				&& accepted_peap_versions.get_data_length() >= sizeof(u32_t))
			{
				// Server uses own configuration.
				m_accepted_PEAP_versions.reset();

				u32_t *p_accepted_peap_versions
					= reinterpret_cast<u32_t *>(accepted_peap_versions.get_data(
						accepted_peap_versions.get_data_length()));

				if (p_accepted_peap_versions == 0)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_TLS_PEAP_ERROR,
						(EAPL("ERROR: illegal configuration value %s\n"),
						 cf_str_EAP_TLS_PEAP_accepted_PEAP_versions.get_field()->get_field()));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
				}
				else
				{
					u32_t version_count = accepted_peap_versions.get_data_length()
						/ sizeof(u32_t);

					for (u32_t ind = 0ul; ind < version_count; ind++)
					{
						if (p_accepted_peap_versions[ind] > peap_version_2)
						{
							// Not supported PEAP version.
							EAP_TRACE_ERROR(
								m_am_tools,
								TRACE_FLAGS_TLS_PEAP_ERROR,
								(EAPL("ERROR: Not supported PEAP version configuration %s: %d\n"),
								 cf_str_EAP_TLS_PEAP_accepted_PEAP_versions
								 .get_field()->get_field(),
								 *p_accepted_peap_versions));
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(
								m_am_tools,
								eap_status_illegal_configure_field);
						}

						status = m_accepted_PEAP_versions.add_data(
							&(p_accepted_peap_versions[ind]),
							sizeof(p_accepted_peap_versions[ind]));
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}
				}
			}
			else
			{
				// Not configured.
				// Accept only version 0.
				u32_t accepted_peap_version = peap_version_0_xp;

				m_accepted_PEAP_versions.reset();

				status = m_accepted_PEAP_versions.add_data(
					&accepted_peap_version,
					sizeof(accepted_peap_version));
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c use_tppd_tls_peap(m_am_tools);

		status = read_configure(
			cf_str_EAP_TLS_PEAP_use_tppd_tls_peap.get_field(),
			&use_tppd_tls_peap);
		if (status == eap_status_ok
			&& use_tppd_tls_peap.get_is_valid_data() == true)
		{
			u32_t *use_tppd_tls_peap_flag = reinterpret_cast<u32_t *>(
				use_tppd_tls_peap.get_data(sizeof(u32_t)));
			if (use_tppd_tls_peap_flag != 0)
			{
				if (*use_tppd_tls_peap_flag != 0)
				{
					m_use_tppd_tls_peap = true;
				}
				else
				{
					m_use_tppd_tls_peap = false;
				}
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c use_eap_expanded_type(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_TLS_PEAP_use_eap_expanded_type.get_field(),
			&use_eap_expanded_type);

		if (status != eap_status_ok)
		{
			status = read_configure(
				cf_str_EAP_CORE_use_eap_expanded_type.get_field(),
				&use_eap_expanded_type);
		}

		if (status == eap_status_ok
			&& use_eap_expanded_type.get_data_length() == sizeof(u32_t)
			&& use_eap_expanded_type.get_data() != 0)
		{
			u32_t *flag = reinterpret_cast<u32_t *>(use_eap_expanded_type.get_data(use_eap_expanded_type.get_data_length()));

			if (flag != 0)
			{
				if ((*flag) != 0ul)
				{
					m_use_eap_expanded_type = true;
				}
				else
				{
					m_use_eap_expanded_type = false;
				}
			}
		}
	}

	//----------------------------------------------------------

	m_tls_peap_header_offset = get_type_partner()->get_header_offset(
		&m_MTU, &m_trailer_length);

	if (m_tls_peap_header_offset+m_MTU+m_trailer_length > TLS_PEAP_LOCAL_PACKET_BUFFER_LENGTH)
	{
		EAP_ASSERT_ALWAYS(TLS_PEAP_LOCAL_PACKET_BUFFER_LENGTH
						  >= (m_tls_peap_header_offset+m_trailer_length));

		m_MTU = TLS_PEAP_LOCAL_PACKET_BUFFER_LENGTH
			- (m_tls_peap_header_offset+m_trailer_length);
	}

	//----------------------------------------------------------

#if defined(USE_FAST_EAP_TYPE)
	if (m_current_eap_type == eap_type_fast)
	{
		m_configured_peap_version = peap_version_1;
		m_current_peap_version = peap_version_1;
	}
	else
#endif //#if defined(USE_FAST_EAP_TYPE)
	if (m_current_eap_type == eap_type_tls)
	{
		m_configured_peap_version = peap_version_none;
		m_current_peap_version = peap_version_none;
	}
	else if (m_current_eap_type == eap_type_peap)
	{
		if (m_current_peap_version == peap_version_none)
		{
			// This is the default tunnel type.
			// Default tunnel type is needed if TLS-alert is sent before PEAP-starts.
			m_configured_peap_version = peap_version_2;
			m_current_peap_version = m_configured_peap_version;
		}
	}

	if (m_current_eap_type == eap_type_peap
		&& m_current_peap_version == peap_version_1)
	{
		m_wait_eap_success_packet = false;

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: %s: because plain PEAP is used ")
			 EAPL("m_wait_eap_success_packet is set to false, type 0x%08x.\n"),
			 (m_is_client == true ? "client": "server"),
			 convert_eap_type_to_u32_t(m_current_eap_type)));
	}
	else if (m_current_eap_type == eap_type_ttls)
	{
		m_wait_eap_success_packet = true;

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: %s: because plain TTLS is used ")
			 EAPL("m_wait_eap_success_packet is set to true, type 0x%08x.\n"),
			 (m_is_client == true ? "client": "server"),
			 convert_eap_type_to_u32_t(m_current_eap_type)));
	}


	m_tls_record->set_peap_version(
		m_current_peap_version,
		m_use_tppd_tls_peap,
		m_use_tppd_peapv1_acknowledge_hack);


	if (get_type_partner()->get_is_tunneled_eap() == true)
	{
		m_wait_eap_success_packet = true;

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: %s: because this is tunneled session ")
			 EAPL("m_wait_eap_success_packet is set to true, type 0x%08x.\n"),
			 (m_is_client == true ? "client": "server"),
			 convert_eap_type_to_u32_t(m_current_eap_type)));
	}

	//----------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("this = 0x%08x => 0x%08x, %s: function: eap_type_tls_peap_c::shutdown()\n"),
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this),
		 (m_is_client == true ? "client": "server")));

	if (m_shutdown_was_called == true)
	{
		// Shutdown was already called (this prevents looping forever)
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	m_shutdown_was_called = true;

	send_final_notification();
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_type_tls_peap_c::shutdown() calls m_tls_record->shutdown()\n")));

	// Here we ignore return value. Both shutdown() calls must be done.
	eap_status_e status = m_tls_record->shutdown();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_type_tls_peap_c::shutdown() calls m_am_type_tls_peap->shutdown()\n")));

	status = m_am_type_tls_peap->shutdown();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("this = 0x%08x => 0x%08x, %s: function: eap_type_tls_peap_c::shutdown() returns\n"),
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this),
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::set_tls_master_secret(
	const eap_variable_data_c * const eap_tls_master_session_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("this = 0x%08x => 0x%08x, %s: function: eap_type_tls_peap_c::set_tls_master_secret()\n"),
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this),
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_type_tls_peap_c::set_tls_master_secret():"),
		 eap_tls_master_session_key->get_data(eap_tls_master_session_key->get_data_length()),
		 eap_tls_master_session_key->get_data_length()));

	eap_status_e status = get_master_session_key()->set_copy_of_buffer(eap_tls_master_session_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// NOTE this will be read from AM of EAP-TLS/PEAP type.
	eap_status_e status = m_am_type_tls_peap->type_configure_read(field, data);
	if (status != eap_status_ok)
	{
		// EAP-TLS/PEAP AM did not have configuration parameter.
		// Let's try the global configuration.
		status = get_type_partner()->read_configure(field, data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: eap_type_tls_peap_c::read_configure(): ")
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
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::write_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// NOTE this will be read from AM of EAP-TLS/PEAP type.
	const eap_status_e status = m_am_type_tls_peap->type_configure_write(field, data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_type_tls_peap_c::state_notification(
	const abs_eap_state_notification_c * const state
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAP_type_TLS_PEAP: %s, %s: eap_type_tls_peap_c::state_notification(): ")
		 EAPL("eap_type_tls_peap_state_variable_e %d=%s, notification state=%s.\n"),
		 (m_is_client == true ? "client": "server"),
		 (get_type_partner()->get_is_tunneled_eap() == true ? "tunneled" : "outer most"),
		 get_state(),
		 get_state_string(),
		 eap_state_notification_c::get_state_string(state->get_protocol_layer(), state->get_current_state())));


	if (state->get_protocol_layer() == eap_protocol_layer_general)
	{
		// Just forward these notifications to lower layers.
		get_type_partner()->state_notification(state);
		return;
	}


	eap_tls_trace_string_c tls_trace;


	if (state->get_protocol_layer() == eap_protocol_layer_eap)
	{
		if (state->get_current_state() == eap_state_authentication_terminated_unsuccessfully
#if defined(USE_EAP_PEAPV1_EXTENSIONS)
			|| state->get_current_state() == eap_state_authentication_terminated_unsuccessfully_peapv1_extension
#endif //#if defined(USE_EAP_PEAPV1_EXTENSIONS)
			)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: %s: eap_type_tls_peap_c::state_notification(): ")
				 EAPL("authentication failed: EAP-type 0xfe%06x%08x=%s\n"),
				 (m_is_client == true ? "client": "server"),
				 m_current_eap_type.get_vendor_id(),
				 m_current_eap_type.get_vendor_type(),
				 eap_header_string_c::get_eap_type_string(m_current_eap_type)));

			m_tunneled_eap_type_authentication_state
				= eap_state_authentication_terminated_unsuccessfully;

			// Here we must change the EAP-type of the notification.
			{
				eap_state_notification_c * notification = new eap_state_notification_c(
					m_am_tools,
					state->get_send_network_id(),
					state->get_is_client(),
					eap_state_notification_eap,
					state->get_protocol_layer(),
					m_current_eap_type,
					state->get_previous_state(),
					eap_state_authentication_terminated_unsuccessfully,
					state->get_eap_identifier(),
					false);

				eap_automatic_variable_c<eap_state_notification_c> automatic_notification(m_am_tools, notification);

				if (notification == 0)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					set_state(eap_type_tls_peap_state_failure);
					return;
				}

				notification->set_authentication_error(eap_status_authentication_failure);

				get_type_partner()->state_notification(notification);
			}
		}
#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
		else if (state->get_current_state()
				 == eap_state_tppd_peapv1_authentication_finished_successfully_with_tunneled_eap_success)
		{
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: eap_type_tls_peap_c::state_notification(): ")
				 EAPL("PEAPv1 authentication tunneled EAP-SUCCESS: EAP-type 0xfe%06x%08x=%s\n"),
				 (m_is_client == true ? "client": "server"),
				 m_current_eap_type.get_vendor_id(),
				 m_current_eap_type.get_vendor_type(),
				 eap_header_string_c::get_eap_type_string(m_current_eap_type)));

			m_tunneled_eap_type_authentication_state
				= static_cast<eap_state_variable_e>(state->get_current_state());

			(void) finish_successful_authentication(true, false, true);
		}
#endif //#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
		else if (state->get_current_state() == eap_state_authentication_finished_successfully
#if defined(USE_EAP_PEAPV1_EXTENSIONS)
			|| state->get_current_state() == eap_state_authentication_finished_successfully_peapv1_extension
#endif //#if defined(USE_EAP_PEAPV1_EXTENSIONS)
			)
		{
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: eap_type_tls_peap_c::state_notification(): ")
				 EAPL("authentication EAP-SUCCESS: EAP-type 0xfe%06x%08x=%s\n"),
				 (m_is_client == true ? "client": "server"),
				 m_current_eap_type.get_vendor_id(),
				 m_current_eap_type.get_vendor_type(),
				 eap_header_string_c::get_eap_type_string(m_current_eap_type)));

			m_tunneled_eap_type_authentication_state
				= eap_state_authentication_finished_successfully;

#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
			if (m_current_eap_type == eap_type_peap
				&& m_current_peap_version == peap_version_1
				&& m_use_tppd_tls_peap == true)
			{
				if (m_is_client == true)
				{
#if defined(USE_EAP_PEAPV1_EXTENSIONS)
					if (state->get_current_state() == eap_state_authentication_finished_successfully_peapv1_extension)
					{
						// In this case Server does wait
						// the client send tunneled Extension Response.
						// Here we do not send empty EAP-TLS/PEAP response.
						(void) finish_successful_authentication(false, false, false);
					}
					else
#endif //#if defined(USE_EAP_PEAPV1_EXTENSIONS)
					{
						// In this case Server does not wait
						// the client send empty EAP-TLS/PEAP response.
						(void) finish_successful_authentication(false, false, true);
					}
				}
				else
				{
#if defined(USE_EAP_PEAPV1_EXTENSIONS)
					if (state->get_current_state() == eap_state_authentication_finished_successfully_peapv1_extension)
					{
						// In this case Server does not wait
						// the client send empty EAP-TLS/PEAP response.
						(void) finish_successful_authentication(false, false, true);
					}
					else
#endif //#if defined(USE_EAP_PEAPV1_EXTENSIONS)
					if (m_use_tppd_peapv1_acknowledge_hack == false
						|| get_tls_session_type() == tls_session_type_full_authentication)
					{
						EAP_TRACE_ALWAYS(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("%s: eap_type_tls_peap_c::state_notification(): ")
							 EAPL("Waits empty final acknowledge: EAP-type ")
							 EAPL("0x%08x, tunnel type %s\n"),
							 (m_is_client == true ? "client": "server"),
							 convert_eap_type_to_u32_t(m_current_eap_type),
							 tls_trace.get_peap_version_string(m_current_peap_version)));

						// Server waits the client send empty EAP-TLS/PEAP response.
						set_state(eap_type_tls_peap_state_waiting_for_empty_tppd_peap_v1_acknowledge);
					}
					else
					{
#if !defined(USE_EAP_PEAPV1_EXTENSIONS)
						// In this case Server does not wait
						// the client send empty EAP-TLS/PEAP response.
						(void) finish_successful_authentication(false, false, true);
#else
						EAP_ASSERT_ANYWAY_TOOLS(m_am_tools);
#endif //#if !defined(USE_EAP_PEAPV1_EXTENSIONS)
					}
				}
			}
			else 
#endif //#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
			if (m_current_eap_type == eap_type_ttls)
			{
				if (m_is_client == true)
				{
					// In EAP-TTLS case client finishes immediately.
					(void) finish_successful_authentication(false, false, true);
				}
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
				else if (m_is_client == false
						 && get_state() == eap_type_tls_peap_state_server_waits_ttls_plain_ms_chap_v2_empty_ack)
				{
					// EAP-TTLS server finishes immediately if plain MsChapv2
					// was run inside tunnel.
					(void) finish_successful_authentication(false, false, true);
				}
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
				else if (m_is_client == false)
				{
					(void) finish_successful_authentication(false, false, true);
				}
			}
			else if (m_current_eap_type == eap_type_peap
						&& (m_current_peap_version == peap_version_0_xp
							|| m_current_peap_version == peap_version_1
							|| m_current_peap_version == peap_version_2))
			{
				if (m_is_client == true)
				{
					(void) finish_successful_authentication(false, false, true);
				}
				else
				{
					// Server
					if (m_current_peap_version == peap_version_1
						&& m_use_tppd_tls_peap == true)
					{
						// Server waits the client send empty EAP-TLS/PEAP response.
						set_state(eap_type_tls_peap_state_waiting_for_empty_tppd_peap_v1_acknowledge);
					}
					else
					{
						(void) finish_successful_authentication(false, false, true);
					}
				}
			}
#if defined(USE_FAST_EAP_TYPE)
			else if (m_current_eap_type == eap_type_fast)
			{
				if (m_is_client == true)
				{
					(void) finish_successful_authentication(false, false, true);
				}
				else
				{
					// Server
					(void) finish_successful_authentication(false, false, true);
				}
			}
#endif //#if defined(USE_FAST_EAP_TYPE)
		}
		else if (state->get_current_state() == eap_state_wait_plain_eap_success)
		{
			m_wait_eap_success_packet = true;
			set_state(eap_type_tls_peap_state_waiting_for_success);
		}
		else if (state->get_current_state() == eap_state_authentication_wait_tppd_peapv1_empty_acknowledge)
		{
			if (m_is_client == false)
			{
				// Send plain EAP-Success.
				get_type_partner()->state_notification(state);

				// Server waits the client send empty EAP-TLS/PEAP response.
				set_state(eap_type_tls_peap_state_waiting_for_empty_response);
			}
		}
#if defined(USE_FAST_EAP_TYPE)
		else if (m_is_client == false
			&& m_current_eap_type == eap_type_fast
			&& state->get_current_state() == eap_state_authentication_wait_eap_fast_empty_acknowledge)
		{
			// Server waits an empty EAP-FAST acknowledge.
			set_state(eap_type_tls_peap_state_waiting_for_empty_response);
		}
		else if (m_current_eap_type == eap_type_fast
			&& state->get_current_state() == eap_state_use_eap_failure_in_termination)
		{
			(void) finish_successful_authentication(false, true, true);

			eap_state_notification_c notification(
				m_am_tools,
				get_send_network_id(),
				m_is_client,
				eap_state_notification_eap,
				eap_protocol_layer_eap,
				m_current_eap_type,
				eap_state_none,
				state->get_current_state(),
				get_last_eap_identifier(), // Note the EAP-Success uses the same EAP-Identifier as the last EAP-Request.
				false);

			get_type_partner()->state_notification(&notification);
		}
#endif //#if defined(USE_FAST_EAP_TYPE)
	}
	else if (state->get_protocol_layer() == eap_protocol_layer_internal_type)
	{
		if (state->get_current_state() == tls_peap_state_failure)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: eap_type_tls_peap_c::state_notification(): TLS tunneled ")
				 EAPL("authentication failed: EAP-type 0xfe%06x%08x=%s, tunnel type %s\n"),
				 (m_is_client == true ? "client": "server"),
				 m_current_eap_type.get_vendor_id(),
				 m_current_eap_type.get_vendor_type(),
				 eap_header_string_c::get_eap_type_string(m_current_eap_type),
				 tls_trace.get_peap_version_string(m_current_peap_version)));

			set_state(eap_type_tls_peap_state_failure);
		}
		else if (state->get_current_state() == tls_peap_state_tls_success)
		{

			if (get_state() != eap_type_tls_peap_state_success
				&& get_state() != eap_type_tls_peap_state_waiting_for_success)
			{
				eap_status_e status = eap_status_process_general_error;

				if (m_tunneled_eap_type_active == true)
				{
					EAP_TRACE_ALWAYS(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("%s: eap_type_tls_peap_c::state_notification(): ")
						 EAPL("TLS tunneled authentication ")
						 EAPL("EAP-SUCCESS: EAP-type 0xfe%06x%08x=%s, tunnel type %s, style %d\n"),
						 (m_is_client == true ? "client": "server"),
						 m_current_eap_type.get_vendor_id(),
						 m_current_eap_type.get_vendor_type(),
						 eap_header_string_c::get_eap_type_string(m_current_eap_type),
						 tls_trace.get_peap_version_string(m_current_peap_version),
						 m_use_tppd_tls_peap));
					
					if (m_tunneled_eap_type_authentication_state
						== eap_state_authentication_finished_successfully)
					{
						// Tunneled EAP-type finished successfully.
						if (m_is_client == true)
						{
							// Client
							status = finish_successful_authentication(false, false, true);
						}
						else
						{
							// Server
							if (m_current_eap_type == eap_type_peap
								&& m_current_peap_version == peap_version_1
								&& m_use_tppd_tls_peap == true)
							{
								// Server waits the client send empty EAP-TLS/PEAP response.
								set_state(eap_type_tls_peap_state_waiting_for_empty_tppd_peap_v1_acknowledge);
								status = eap_status_ok;
							}
							else
							{
								status = finish_successful_authentication(false, false, true);
							}
						}
					}
					else
					{
						set_state(eap_type_tls_peap_state_failure);
					}
				}
				else if (get_tls_session_type() == tls_session_type_original_session_resumption
					|| get_tls_session_type() == tls_session_type_stateless_session_resumption)
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("%s: eap_type_tls_peap_c::state_notification(): ")
						 EAPL("TLS resumed session authentication ")
						 EAPL("EAP-SUCCESS: EAP-type 0xfe%06x%08x=%s, m_tls_session_type=%d=%s, tunnel type %s\n"),
						 (m_is_client == true ? "client": "server"),
						 m_current_eap_type.get_vendor_id(),
						 m_current_eap_type.get_vendor_type(),
						 eap_header_string_c::get_eap_type_string(m_current_eap_type),
						 get_tls_session_type(),
						 eap_tls_trace_string_c::get_tls_session_type_string(get_tls_session_type()),
						 tls_trace.get_peap_version_string(m_current_peap_version)));

					// Saved previous session was resumed.
					m_tunneled_eap_type_authentication_state
						= eap_state_authentication_finished_successfully;

					if (m_is_client == true)
					{
						if (m_wait_eap_success_packet == true)
						{
							set_state(eap_type_tls_peap_state_waiting_for_success);
						}
						else
						{
							status = finish_successful_authentication(false, false, true);
						}
					}
					else
					{
						// Server
						status = finish_successful_authentication(false, false, true);
					}
				}
				else
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("%s: eap_type_tls_peap_c::state_notification(): ")
						 EAPL("plain TLS authentication EAP-SUCCESS: EAP-type 0xfe%06x%08x=%s, tunnel type %s\n"),
						 (m_is_client == true ? "client": "server"),
						 m_current_eap_type.get_vendor_id(),
						 m_current_eap_type.get_vendor_type(),
						 eap_header_string_c::get_eap_type_string(m_current_eap_type),
						 tls_trace.get_peap_version_string(m_current_peap_version)));

					// Plain TLS.
					if (m_is_client == true)
					{
						
						if (get_tls_session_type() == tls_session_type_full_authentication)
						{
							// Client must send a empty response message to server.
							
							// Here we swap the addresses.
							eap_am_network_id_c receive_network_id(m_am_tools,
																   get_send_network_id()->get_destination_id(),
																   get_send_network_id()->get_source_id(),
																   get_send_network_id()->get_type());
							
							status = send_empty_eap_ack();
							if (status != eap_status_ok)
							{
								restore_saved_reassembly_state();
								EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
								return;
							}
						}
						
						if (m_current_eap_type == eap_type_tls
							|| m_current_eap_type == eap_type_peap) // This is session resumption case.
						{
							if (m_wait_eap_success_packet == true)
							{
								set_state(eap_type_tls_peap_state_waiting_for_success);
							}
							else
							{
								status = finish_successful_authentication(false, false, true);
							}
						}
						else
						{
							EAP_TRACE_ERROR(
								m_am_tools,
								TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
								(EAPL("ERROR: EAP_type_TLS_PEAP: %s, unknown EAP-type 0xfe%06x%08x=%s\n"),
								 (m_is_client == true) ? "client": "server",
								 m_current_eap_type.get_vendor_id(),
								 m_current_eap_type.get_vendor_type(),
								 eap_header_string_c::get_eap_type_string(m_current_eap_type)));
							
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							set_state(eap_type_tls_peap_state_failure);
							return;
						}
					}
					else
					{
						// Server waits the client send empty EAP-TLS/PEAP response.
						set_state(eap_type_tls_peap_state_waiting_for_empty_response);
						status = eap_status_ok;
					}
				}
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("WARNING: eap_type_tls_peap_c::state_notification(): ")
					 EAPL("duplicate success notification ")
					 EAPL("eap_type_tls_peap_state_variable_e %d=%s, notification state %d=%s.\n"),
					 get_state(),
					 get_state_string(),
					 state->get_current_state(),
					 state->get_current_state_string()));
			}
		}
		else if (state->get_current_state() == tls_peap_state_full_authentication)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: eap_type_tls_peap_c::state_notification(): ")
				 EAPL("full TLS authentication: EAP-type 0xfe%06x%08x=%s\n"),
				 (m_is_client == true ? "client": "server"),
				 m_current_eap_type.get_vendor_id(),
				 m_current_eap_type.get_vendor_type(),
				 eap_header_string_c::get_eap_type_string(m_current_eap_type)));
		}
		else if (state->get_current_state() == tls_peap_state_original_session_resumption)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: eap_type_tls_peap_c::state_notification(): ")
				 EAPL("TLS session resumption: EAP-type 0xfe%06x%08x=%s\n"),
				 (m_is_client == true ? "client": "server"),
				 m_current_eap_type.get_vendor_id(),
				 m_current_eap_type.get_vendor_type(),
				 eap_header_string_c::get_eap_type_string(m_current_eap_type)));
		}
#if defined(USE_EAP_TLS_SESSION_TICKET)
		else if (state->get_current_state() == tls_peap_state_stateless_session_resumption)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: eap_type_tls_peap_c::state_notification(): ")
				 EAPL("TLS stateless session resumption: EAP-type 0xfe%06x%08x=%s\n"),
				 (m_is_client == true ? "client": "server"),
				 m_current_eap_type.get_vendor_id(),
				 m_current_eap_type.get_vendor_type(),
				 eap_header_string_c::get_eap_type_string(m_current_eap_type)));
		}
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
		else if (state->get_current_state()
				 == tls_peap_state_tppd_peapv1_waits_eap_success_or_tunneled_packet)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: eap_type_tls_peap_c::state_notification(): ")
				 EAPL("PEAPv1 waits EAP-Success or tunneled packet: EAP-type 0xfe%06x%08x=%s\n"),
				 (m_is_client == true ? "client": "server"),
				 m_current_eap_type.get_vendor_id(),
				 m_current_eap_type.get_vendor_type(),
				 eap_header_string_c::get_eap_type_string(m_current_eap_type)));

			set_state(eap_type_tls_peap_state_tppd_peapv1_waits_eap_success_or_tunneled_packet);
		}
#endif //#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		else if (state->get_current_state() == tls_peap_state_client_send_ttls_plain_ms_chap_v2_empty_ack)
		{
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: eap_type_tls_peap_c::state_notification(): ")
				 EAPL("sends TTLS/plain MsChapv2 empty Ack: EAP-type 0xfe%06x%08x=%s\n"),
				 (m_is_client == true ? "client": "server"),
				 m_current_eap_type.get_vendor_id(),
				 m_current_eap_type.get_vendor_type(),
				 eap_header_string_c::get_eap_type_string(m_current_eap_type)));

			// Send empty acknowledge message.
			eap_status_e status = send_empty_eap_ack();
			if (status != eap_status_ok)
			{
				set_state(eap_type_tls_peap_state_failure);
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				(void) EAP_STATUS_RETURN(m_am_tools, status);
				return;
			}
		}
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		else if (state->get_current_state() == tls_peap_state_server_waits_ttls_plain_ms_chap_v2_empty_ack)
		{
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: eap_type_tls_peap_c::state_notification(): ")
				 EAPL("waits TTLS/plain MsChapv2 empty Ack: EAP-type 0xfe%06x%08x=%s\n"),
				 (m_is_client == true ? "client": "server"),
				 m_current_eap_type.get_vendor_id(),
				 m_current_eap_type.get_vendor_type(),
				 eap_header_string_c::get_eap_type_string(m_current_eap_type)));

			set_state(eap_type_tls_peap_state_server_waits_ttls_plain_ms_chap_v2_empty_ack);
		}
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		else if (state->get_current_state() == tls_peap_state_peap_tunnel_ready)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: eap_type_tls_peap_c::state_notification(): ")
				 EAPL("TLS tunnel ready: EAP-type 0xfe%06x%08x=%s\n"),
				 (m_is_client == true ? "client": "server"),
				 m_current_eap_type.get_vendor_id(),
				 m_current_eap_type.get_vendor_type(),
				 eap_header_string_c::get_eap_type_string(m_current_eap_type)));

			if (m_is_client == true)
			{
				eap_status_e status = eap_status_process_general_error;

				if (m_current_eap_type == eap_type_tls
					//|| m_current_eap_type == eap_type_ttls TTLS does not send empty ack.
					|| (m_current_eap_type == eap_type_peap
						&& m_current_peap_version < peap_version_2))
				{
					if (get_tls_session_type() == tls_session_type_full_authentication)
					{
						// Client must sent an empty EAP-response ONLY in full authentication.

						// Here we swap the addresses.
						eap_am_network_id_c receive_network_id(
							m_am_tools,
							get_send_network_id()->get_destination_id(),
							get_send_network_id()->get_source_id(),
							get_send_network_id()->get_type());

						status = send_empty_eap_ack();
						if (status != eap_status_ok)
						{
							restore_saved_reassembly_state();
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return;
						}
					}
				}

				if (m_current_eap_type == eap_type_tls)
				{
					if (m_wait_eap_success_packet == true)
					{
						set_state(eap_type_tls_peap_state_waiting_for_success);
					}
					else
					{
						status = finish_successful_authentication(false, false, true);
					}
				}
				else if (m_current_eap_type == eap_type_ttls)
				{
					m_tunneled_eap_type_active = true;

					set_state(eap_type_tls_peap_state_waiting_for_request);
				}
#if defined(USE_FAST_EAP_TYPE)
				else if (m_current_eap_type == eap_type_fast)
				{
					m_tunneled_eap_type_active = true;

					if (get_tls_session_type() == tls_session_type_eap_fast_server_unauthenticated_provisioning_mode_ADHP)
					{
						// Client must sent an empty EAP-response ONLY in unauthenticated provisioning mode.

						// Here we swap the addresses.
						eap_am_network_id_c receive_network_id(
							m_am_tools,
							get_send_network_id()->get_destination_id(),
							get_send_network_id()->get_source_id(),
							get_send_network_id()->get_type());

						status = send_empty_eap_ack();
						if (status != eap_status_ok)
						{
							restore_saved_reassembly_state();
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return;
						}
						set_state(eap_type_tls_peap_state_waiting_for_request);
					}
					else
					{
						set_state(eap_type_tls_peap_state_waiting_for_success);
					}
				}
#endif //#if defined(USE_FAST_EAP_TYPE)
				else if (m_current_eap_type == eap_type_peap)
				{
					m_tunneled_eap_type_active = true;

					if (m_current_peap_version < peap_version_2)
					{

#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
						if (m_is_client == true
							&& m_current_eap_type == eap_type_peap
							&& m_current_peap_version == peap_version_1
							&& m_use_tppd_tls_peap == true
							&& m_use_tppd_peapv1_acknowledge_hack == true
							&& (get_tls_session_type() == tls_session_type_original_session_resumption
								|| get_tls_session_type() == tls_session_type_stateless_session_resumption)
							&& get_state()
							== eap_type_tls_peap_state_tppd_peapv1_waits_eap_success_or_tunneled_packet)
						{
							// Do not change state here.
						}
						else
#endif //#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
						{
							set_state(eap_type_tls_peap_state_waiting_for_request);
						}
					}
				}
				else
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
						(EAPL("ERROR: EAP_type_TLS_PEAP: %s, unknown EAP-type 0xfe%06x%08x=%s\n"),
						 (m_is_client == true) ? "client": "server",
						 m_current_eap_type.get_vendor_id(),
						 m_current_eap_type.get_vendor_type(),
						 eap_header_string_c::get_eap_type_string(m_current_eap_type)));
					
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					set_state(eap_type_tls_peap_state_failure);
					return;
				}
			}
			else
			{
				if (m_current_eap_type == eap_type_peap)
				{
					if (m_current_peap_version == peap_version_2)
					{
						// Server waits the client send EAP-TLS/PEAP response.
						m_tunneled_eap_type_active = true;
						set_state(eap_type_tls_peap_state_waiting_for_response);
					}
					else
					{
						// Server waits the client send empty EAP-TLS/PEAP response.
						set_state(eap_type_tls_peap_state_waiting_for_empty_response);
					}
				}
				else if (m_current_eap_type == eap_type_ttls)
				{
					// Server waits the client send empty EAP-TLS/PEAP response.
					m_tunneled_eap_type_active = true;
					set_state(eap_type_tls_peap_state_waiting_for_response);
				}
			}
		}
		else if (state->get_current_state() == tls_peap_state_peap_tunnel_ready_wait_request)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: eap_type_tls_peap_c::state_notification(): ")
				 EAPL("TLS tunnel ready: EAP-type 0xfe%06x%08x=%s\n"),
				 (m_is_client == true ? "client": "server"),
				 m_current_eap_type.get_vendor_id(),
				 m_current_eap_type.get_vendor_type(),
				 eap_header_string_c::get_eap_type_string(m_current_eap_type)));

			if (m_is_client == true)
			{
#if defined(USE_FAST_EAP_TYPE)
				if (m_current_eap_type == eap_type_fast)
				{
					m_tunneled_eap_type_active = true;

					// Client must sent an empty EAP-response.

					// Here we swap the addresses.
					eap_am_network_id_c receive_network_id(
						m_am_tools,
						get_send_network_id()->get_destination_id(),
						get_send_network_id()->get_source_id(),
						get_send_network_id()->get_type());

					eap_status_e status = send_empty_eap_ack();
					if (status != eap_status_ok)
					{
						restore_saved_reassembly_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return;
					}
					set_state(eap_type_tls_peap_state_waiting_for_request);
				}
				else
#endif //#if defined(USE_FAST_EAP_TYPE)
				{
					EAP_ASSERT_ANYWAY_TOOLS(m_am_tools);
				}
			}
			else
			{
				EAP_ASSERT_ANYWAY_TOOLS(m_am_tools);
			}
		}
		else if (state->get_current_state() == tls_peap_state_pending_tls_messages_processed)
		{
			if (get_state() == eap_type_tls_peap_state_process_tls_message
				|| get_state() == eap_type_tls_peap_state_process_tls_start)
			{
				if (m_is_client == true)
				{
					set_state(eap_type_tls_peap_state_waiting_for_request);
				}
				else
				{
					set_state(eap_type_tls_peap_state_waiting_for_response);
				}
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::query_eap_identity(
	const bool /* must_be_synchronous */,
	eap_variable_data_c * const identity,
	const eap_am_network_id_c * const receive_network_id,
	const u8_t eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_tls_peap_c::query_eap_identity() ")
		 EAPL("in eap_type_tls_peap_state_variable_e %d=%s.\n"),
		 get_state(),
		 get_state_string()));

	if (m_tls_peap_test_version == true
		&& get_state() == eap_type_tls_peap_state_failure)
	{
		// This is for testing.
		if (m_is_client == false)
		{
			set_state(eap_type_tls_peap_state_waiting_for_identity_response);
		}
		else if (m_is_client == true)
		{
			set_state(eap_type_tls_peap_state_waiting_for_tls_start);
		}
	}


	bool use_manual_username(false);
	eap_variable_data_c manual_username(m_am_tools);
	bool use_manual_realm(false);
	eap_variable_data_c manual_realm(m_am_tools);


	if (m_state == eap_type_tls_peap_state_waiting_for_identity_request
		|| (m_tls_peap_test_version == true // This one is for testing purposes.
			&& m_state == eap_type_tls_peap_state_success))
	{
		save_current_state();
		set_state(eap_type_tls_peap_state_pending_identity_query);

		eap_status_e status = eap_status_process_general_error;

		status = m_am_type_tls_peap->query_eap_identity(
			identity,
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
				identity,
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
	else if (m_state == eap_type_tls_peap_state_waiting_for_tls_start)
	{
		// This is re-transmission request. We do not change our state.
		// Just send EAP-Identity again.
		if (get_NAI()->get_is_valid_data() == true)
		{
			eap_status_e status = identity->set_copy_of_buffer(get_NAI());

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_tls_peap_c::query_eap_identity() ")
				 EAPL("returns already obtained NAI in ")
				 EAPL("eap_type_tls_peap_state_variable_e %d=%s.\n"),
				 get_state(),
				 get_state_string()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_TLS_PEAP_ERROR, 
				(EAPL("ERROR: eap_type_tls_peap_c::query_eap_identity(): ")
				 EAPL("EAP-Request/Identity cannot be completed, identity (NAI) ")
				 EAPL("is missing. in eap_type_tls_peap_state_variable_e %d=%s.\n"),
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
	else if (m_state == eap_type_tls_peap_state_pending_identity_query)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_type_tls_peap_c::query_eap_identity(): ")
			 EAPL("Already pending EAP-Identity query in ")
			 EAPL("eap_type_tls_peap_state_variable_e %d=%s.\n"),
			get_state(),
			get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_pending_request);
	}
	else
	{	
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_TLS_PEAP_ERROR,
			(EAPL("ERROR: eap_type_tls_peap_c::query_eap_identity(): ")
			 EAPL("Illegal EAP-Identity query in eap_type_tls_peap_state_variable_e %d=%s.\n"),
			get_state(),
			get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::set_initial_eap_identifier(
	const eap_am_network_id_c * const /*receive_network_id*/,
	const u8_t /*initial_identifier*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::eap_acknowledge(
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	if (get_state() == eap_type_tls_peap_state_waiting_for_success)
	{
		if (m_wait_eap_success_packet == false)
		{
			/**
			 * @{ check right functionality.
			 * Here we return eap_status_ok, eap_status_success was
			 * returned after successfull
			 * EAP-Request/SIM/Challenge. This may change after EAP,
			 * 802.1X and 802.11i specifications are ready. }
			 */
			status = eap_status_ok;
		}
		else
		{
			if (m_current_eap_type == eap_type_tls)
			{
				status = finish_successful_authentication(false, false, true);
				if (status != eap_status_success)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else
			{
				// We must forward this to the tunneled EAP-type.

				status = m_tls_record->plain_eap_success_failure_packet_received(
					receive_network_id,
					eap_code_success,
					m_last_eap_identifier);
			}
		}
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ignored eap_acknowledge(): state %d=%s, is client %d, m_wait_eap_success_packet=%d, m_authentication_finished_successfully=%d\n"),
			get_state(),
			get_state_string(),
			(m_is_client == true),
			m_wait_eap_success_packet,
			m_authentication_finished_successfully));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("this = 0x%08x, %s: eap_type_tls_peap_c::reset(): %d=%s.\n"),
		 this,
		 (m_is_client == true) ? "client": "server",
		 get_state(),
		 get_state_string()));

	m_current_identity.reset();

	if (m_is_client == true)
	{
		// Client waits EAP-Request/Identity.
		m_state = eap_type_tls_peap_state_waiting_for_identity_request;
		m_saved_previous_state = eap_type_tls_peap_state_waiting_for_identity_request;
	}
	else if (m_is_client == false)
	{
		// Server waits EAP-Response/Identity.
		m_state = eap_type_tls_peap_state_waiting_for_identity_response;
		m_saved_previous_state = eap_type_tls_peap_state_waiting_for_identity_response;
	}

	m_reassembly_state = eap_type_tls_peap_reassembly_state_wait_first_message;

	m_saved_previous_reassembly_state = eap_type_tls_peap_reassembly_state_wait_first_message;

	m_tls_message_send_offset = 0ul;

	m_includes_tls_handshake_message = false;

	m_tls_message_buffer.reset();

	m_master_session_key.reset();

	m_tunneled_eap_type_active = false;
	m_tunneled_eap_type_authentication_state = eap_state_none;

	set_tls_session_type(tls_session_type_none);

	eap_status_e status = m_tls_record->reset();

	m_failure_message_received = false;
	m_authentication_finished_successfully = false;
	m_last_eap_identifier = 0ul;

	m_current_peap_version = m_configured_peap_version;

	m_first_fragment_eap_identifier = 0ul;

	m_am_type_tls_peap->reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::set_timer(
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
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::cancel_timer(
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

// This is commented in abs_tls_base_application_c.
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::load_module(
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

// This is commented in abs_tls_base_application_c.
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::unload_module(const eap_type_value_e type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// This call is forwarded to EAPOL AM module because it handles all the 
	// tunneled EAP type handlings for PEAP.
	const eap_status_e status = get_type_partner()->unload_module(type);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// This is commented in abs_tls_base_application_c.
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::restart_authentication(
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

// This is commented in abs_tls_base_application_c.
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::packet_data_crypto_keys(
	const eap_am_network_id_c * const /*send_network_id*/,
	const eap_master_session_key_c * const /*master_session_key*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// NOTE we do NOT forwrd keys to lower layer.

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

// This is commented in abs_tls_base_application_c.
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::check_is_valid_eap_type(
	const eap_type_value_e eap_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// This call is forwarded to TLS AM module because it handles all the 
	// tunneled EAP type handlings for PEAP.
	const eap_status_e status = m_am_type_tls_peap->check_is_valid_eap_type(eap_type);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// This is commented in abs_tls_base_application_c.
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::get_eap_type_list(
	eap_array_c<eap_type_value_e> * const eap_type_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = m_am_type_tls_peap->get_eap_type_list(eap_type_list);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::set_session_timeout(
	const u32_t session_timeout_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = get_type_partner()->set_session_timeout(session_timeout_ms);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::add_rogue_ap(
	eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = get_type_partner()->add_rogue_ap(rogue_ap_list);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::peap_tunnel_ready()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("this = 0x%08x, %s: eap_type_tls_peap_c::peap_tunnel_ready() in ")
		 EAPL("eap_type_tls_peap_state_variable_e %d=%s.\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 get_state(),
		 get_state_string()));

	m_tunneled_eap_type_active = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_tls_peap_c::set_tls_session_type(const tls_session_type_e tls_session_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("this = 0x%08x, %s: eap_type_tls_peap_c::set_tls_session_type() in ")
		 EAPL("m_tls_session_type=%d=%s.\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 tls_session_type,
		 eap_tls_trace_string_c::get_tls_session_type_string(tls_session_type)));

	m_tls_session_type = tls_session_type;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_session_type_e eap_type_tls_peap_c::get_tls_session_type()
{
	return m_tls_session_type;
}

//--------------------------------------------------

// End.
