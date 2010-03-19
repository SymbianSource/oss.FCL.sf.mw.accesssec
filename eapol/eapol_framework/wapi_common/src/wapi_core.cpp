/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/wapi_core.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 131.1.4 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.1.1
*/

// This is enumeration of WAPI source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 712 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "abs_wapi_core.h"
#include "abs_eap_am_mutex.h"
#include "wapi_core.h"
#include "eap_state_notification.h"
#include "eap_network_id_selector.h"
#include "eap_buffer.h"
#include "eap_automatic_variable.h"
#include "wapi_core_retransmission.h"
#include "wai_protocol_packet_header.h"
#include "wapi_strings.h"
#include "eap_crypto_api.h"
#include "eap_automatic_variable.h"
#include "eapol_session_key.h"
#include "wapi_am_crypto_sms4.h"
#include "asn1_der_type.h"
#include "wapi_asn1_der_parser.h"
#include "wapi_am_base_core.h"

//#define WAPI_SKIP_BKID_TEST // This is for testing.

//--------------------------------------------------

// 
EAP_FUNC_EXPORT wapi_core_c::~wapi_core_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_core_c::~wapi_core_c(): %s, this = 0x%08x => 0x%08x.\n"),
		(m_is_client == true) ? "client": "server",
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	EAP_ASSERT(m_shutdown_was_called == true);

	{
		for (u32_t ind = 0ul; ind < WAPI_USKSA_COUNT; ++ind)
		{
			delete m_USKSA[ind];
			m_USKSA[ind] = 0;
		} // for()
	}

	{
		for (u32_t ind = 0ul; ind < WAPI_MSKSA_COUNT; ++ind)
		{
			delete m_MSKSA[ind];
			m_MSKSA[ind] = 0;
		} // for()
	}

	delete m_ec_certificate_store;
	m_ec_certificate_store = 0;

	delete m_am_wapi_core;
	m_am_wapi_core = 0;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4355 ) // 'this' : used in base member initializer list
#endif

// 
EAP_FUNC_EXPORT wapi_core_c::wapi_core_c(
	abs_eap_am_tools_c * const tools,
	abs_wapi_core_c * const partner,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id)
	: m_partner(partner)
	, m_ec_certificate_store(0)
	, m_am_wapi_core(0)
	, m_am_tools(tools)
	, m_wapi_header_offset(0u)
	, m_MTU(0u)
	, m_trailer_length(0u)
	, m_receive_network_id(tools)
	, m_retransmission(0)
	, m_retransmission_time(WAPI_CORE_RETRANSMISSION_TIME)
	, m_retransmission_counter(WAPI_CORE_RETRANSMISSION_COUNTER)
	, m_session_timeout(WAPI_CORE_SESSION_TIMEOUT)
	, m_wapi_core_failure_received_timeout(WAPI_CORE_FAILURE_RECEIVED_TIMEOUT)
	, m_remove_session_timeout(WAPI_CORE_REMOVE_SESSION_TIMEOUT)
	, m_wapi_state(wapi_core_state_none)
	, m_received_wai_message_data(tools, is_client_when_true)
	, m_new_payloads(tools, is_client_when_true)
	, m_preshared_key_PSK(tools)
	, m_BK(tools)
	, m_BKID(tools)
	, m_USKID(0u)
	, m_MSKID(0u)
	, m_ae_certificate_challenge(tools)
	, m_asue_certificate_challenge(tools)
	, m_ae_unicast_challenge(tools)
	, m_asue_unicast_challenge(tools)
	, m_authentication_identifier(tools)
	, m_asue_id(tools)
	, m_asu_id(tools)
	, m_ae_id(tools)
	, m_test_other_asu_id(tools)
	, m_own_certificate(tools)
	, m_peer_certificate(tools)
	, m_ae_certificate(tools)
	, m_wapi_ie_asue(tools)
	, m_wapi_ie_ae(tools)
	, m_unicast_encryption_key_UEK(tools)
	, m_unicast_integrity_check_key_UCK(tools)
	, m_message_authentication_key_MAK(tools)
	, m_key_encryption_key_KEK(tools)
	, m_next_unicast_challenge(tools)
	, m_multicast_key(tools)
	, m_packet_data_number(tools)
	, m_key_announcement(tools)
	, m_own_private_key_d(tools)
	, m_own_public_key_x(tools)
	, m_own_public_key_y(tools)
	, m_peer_public_key_x(tools)
	, m_peer_public_key_y(tools)
	, m_result_of_certificate_verification(tools)
	, m_server_signature_trusted_by_asue(tools)
	, m_server_signature_trusted_by_ae(tools)
	, m_reassemble_packet(tools)
	, m_authentication_type(eapol_key_authentication_type_none)
	, m_wapi_negotiation_state(wapi_negotiation_state_none)
	, m_wapi_pairwise_cipher(eapol_RSNA_key_header_c::eapol_RSNA_cipher_none)
	, m_wapi_group_cipher(eapol_RSNA_key_header_c::eapol_RSNA_cipher_none)
	, m_packet_sequence_number(0u)
	, m_fragment_sequence_number(0u)
	, m_is_client(is_client_when_true)
	, m_is_client_role(is_client_when_true)
	, m_is_valid(false)
	, m_client_restart_authentication_initiated(false)
	, m_marked_removed(false)
	, m_shutdown_was_called(false)
	, m_do_certificate_validation(false)
#if defined(USE_WAPI_CORE_SERVER)
	, m_only_initial_authentication(false)
#endif //#if defined(USE_WAPI_CORE_SERVER)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_core_c::wapi_core_c(): %s, this = 0x%08x => 0x%08x, compiled %s %s.\n"),
		(m_is_client == true) ? "client": "server",
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this),
		__DATE__,
		__TIME__));

	eap_status_e status = m_receive_network_id.set_copy_of_network_id(receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	{
		for (u32_t ind = 0ul; ind < WAPI_USKSA_COUNT; ++ind)
		{
			m_USKSA[ind] = 0;
		} // for()
	}

	{
		for (u32_t ind = 0ul; ind < WAPI_MSKSA_COUNT; ++ind)
		{
			m_MSKSA[ind] = 0;
		}
	}

	{
		for (u32_t ind = 0ul; ind < WAPI_USKSA_COUNT; ++ind)
		{
			m_USKSA[ind] = 0;

			wai_usksa_c * const usksa = new wai_usksa_c(m_am_tools);
			if (usksa == 0
				|| usksa->get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				return;
			}

			m_USKSA[ind] = usksa;

		} // for()
	}

	{
		for (u32_t ind = 0ul; ind < WAPI_MSKSA_COUNT; ++ind)
		{
			m_MSKSA[ind] = 0;

			wai_usksa_c * const msksa = new wai_usksa_c(m_am_tools);
			if (msksa == 0
				|| msksa->get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				return;
			}

			m_MSKSA[ind] = msksa;

		} // for()
	}

	m_am_wapi_core = wapi_am_base_core_c::new_wapi_am_core(
		tools,
		this,
		is_client_when_true,
		&m_receive_network_id);
	if (m_am_wapi_core == 0
		|| m_am_wapi_core->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return;
	}

	m_ec_certificate_store = ec_base_certificate_store_c::new_ec_base_certificate_store_c(
		tools,
		this,
		m_am_wapi_core,
		is_client_when_true);
	if (m_ec_certificate_store == 0
		|| m_ec_certificate_store->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return;
	}

	status = m_ec_certificate_store->set_receive_network_id(&m_receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, status);
		return;
	}

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::initialize(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_receive_network_id.set_copy_of_network_id(receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_authentication_type = authentication_type;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::initialize(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type,
	const eap_variable_data_c * const wapi_ie_ae,
	const eap_variable_data_c * const wapi_ie_asue,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e wapi_pairwise_cipher,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e wapi_group_cipher)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_receive_network_id.set_copy_of_network_id(receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_authentication_type = authentication_type;

	status = m_wapi_ie_ae.set_copy_of_buffer(wapi_ie_ae);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_wapi_ie_asue.set_copy_of_buffer(wapi_ie_asue);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_wapi_pairwise_cipher = wapi_pairwise_cipher;
	m_wapi_group_cipher = wapi_group_cipher;
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
void wapi_core_c::set_wapi_state(wapi_core_state_e wapi_state)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("WAI: %s: wapi_core_c::set_wapi_state(): State from %s to %s, %s.\n"),
		 (m_is_client == true) ? "client": "server",
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
		 wapi_strings_c::get_wapi_core_state_string(wapi_state),
		 wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

	m_wapi_state = wapi_state;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT abs_wapi_core_c * wapi_core_c::get_partner()
{
	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	return m_partner;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void wapi_core_c::set_partner(abs_wapi_core_c * const partner)
{
	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	m_partner = partner;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void wapi_core_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool wapi_core_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void wapi_core_c::object_increase_reference_count()
{
	// This is an empty function to implement here unused interface function.
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u32_t wapi_core_c::object_decrease_reference_count()
{
	return 0u;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool wapi_core_c::get_marked_removed()
{
	return m_marked_removed;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void wapi_core_c::set_marked_removed()
{
	m_marked_removed = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void wapi_core_c::unset_marked_removed()
{
	m_marked_removed = false;
}

//--------------------------------------------------

//
eap_status_e wapi_core_c::initialize_asynchronous_init_remove_wapi_session(
	const u32_t remove_session_timeout)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_core_c::initialize_asynchronous_init_remove_wapi_session(): %s.\n"),
		 (m_is_client == true) ? "client": "server"));

	eap_status_e status = eap_status_process_general_error;


	if (m_is_client_role == false)
	{
		// Server stops re-transmissions.
		// Client can re-transmit until session is removed.
		cancel_retransmission();
	}

	cancel_wapi_failure_timeout();

	cancel_session_timeout();

	set_marked_removed();


	if (remove_session_timeout == 0ul)
	{
		status = asynchronous_init_remove_wapi_session();
	}
	else
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		cancel_asynchronous_init_remove_wapi_session();

		status = m_partner->set_timer(
			this,
			WAPI_CORE_REMOVE_SESSION_TIMEOUT_ID,
			0,
			remove_session_timeout);

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: WAPI_CORE_REMOVE_SESSION_TIMEOUT_ID set %d ms, this = 0x%08x.\n"),
			 (m_is_client == true) ? "client": "server",
			 remove_session_timeout,
			 this));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e wapi_core_c::cancel_asynchronous_init_remove_wapi_session()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_partner->cancel_timer(
		this,
		WAPI_CORE_REMOVE_SESSION_TIMEOUT_ID);

	EAP_UNREFERENCED_PARAMETER(status); // in release
	
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: %s: WAPI_CORE_REMOVE_SESSION_TIMEOUT_ID cancelled status %d, this = 0x%08x.\n"),
		 (m_is_client == true ? "client": "server"),
		 status,
		 this));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
eap_status_e wapi_core_c::asynchronous_init_remove_wapi_session()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_core_c::asynchronous_init_remove_wapi_session(): %s.\n"),
		 (m_is_client == true) ? "client": "server"));

		eap_am_network_id_c send_network_id(
			m_am_tools,
			m_receive_network_id.get_destination_id(),
			m_receive_network_id.get_source_id(),
			m_receive_network_id.get_type());

		eap_status_e status = m_partner->asynchronous_init_remove_wapi_session(
			&send_network_id);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e wapi_core_c::init_end_of_session(
	const abs_eap_state_notification_c * const state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_core_c::init_end_of_session(): %s.\n"),
		 (m_is_client == true) ? "client": "server"));

	eap_status_e status(eap_status_process_general_error);

	// Normally we will remove session after authentication ends.
	// Remove session only if the stack is not already being deleted
	if (m_shutdown_was_called == false)
	{

		#if defined(USE_WAPI_CORE_SIMULATOR_VERSION) && defined(USE_WAPI_CORE_RESTART_AUTHENTICATION)

			// Simulator reuses current session.
			status = restart_authentication(
				state->get_send_network_id(),
				m_is_client);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

		#elif defined(USE_WAPI_CORE_SIMULATOR_VERSION)

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("wapi_core_c::state_notification(): %s, %s, Ignored notification: ")
				 EAPL("Protocol layer %d, State transition from ")
				 EAPL("%d=%s to %d=%s, client %d.\n"),
				 (m_is_client == true) ? "client": "server",
				 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
				 state->get_protocol_layer(), 
				 state->get_previous_state(), 
				 state->get_previous_state_string(), 
				 state->get_current_state(), 
				 state->get_current_state_string(),
				 state->get_is_client()));

		#endif //#if defined(USE_WAPI_CORE_SIMULATOR_VERSION)

		status = initialize_asynchronous_init_remove_wapi_session(m_remove_session_timeout);
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
			(EAPL("wapi_core_c::state_notification(): %s, Ignored notification: ")
			 EAPL("Protocol layer %d, State transition from ")
			 EAPL("%d=%s to %d=%s, client %d when shutdown was called.\n"),
			 (m_is_client == true) ? "client": "server",
			 state->get_protocol_layer(), 
			 state->get_previous_state(), 
			 state->get_previous_state_string(), 
			 state->get_current_state(), 
			 state->get_current_state_string(),
			 state->get_is_client()));

		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void wapi_core_c::state_notification(
	const abs_eap_state_notification_c * const state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_string_c status_string;
	EAP_UNREFERENCED_PARAMETER(status_string); // in release

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_core_c::state_notification(), %s, protocol_layer %d=%s, protocol %d=%s.\n"),
		(m_is_client == true) ? "client": "server",
		state->get_protocol_layer(),
		state->get_protocol_layer_string(),
		state->get_protocol(),
		state->get_protocol_string()));

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_core_c::state_notification(), %s, current_state %d=%s, error %d=%s.\n"),
		(m_is_client == true) ? "client": "server",
		state->get_current_state(),
		state->get_current_state_string(),
		state->get_authentication_error(),
		status_string.get_status_string(state->get_authentication_error())));

	m_partner->state_notification(state);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_core_c::initialize_session_timeout(const u32_t session_timeout_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	cancel_session_timeout();

	eap_status_e status = m_partner->set_timer(
		this,
		WAPI_CORE_SESSION_TIMEOUT_ID,
		0,
		session_timeout_ms);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: %s: WAPI_CORE_SESSION_TIMEOUT_ID set %d ms, this = 0x%08x.\n"),
		 (m_is_client == true) ? "client": "server",
		 session_timeout_ms,
		 this));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::cancel_session_timeout()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_partner->cancel_timer(
		this,
		WAPI_CORE_SESSION_TIMEOUT_ID);
	
	EAP_UNREFERENCED_PARAMETER(status); // in release
	
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: %s: WAPI_CORE_SESSION_TIMEOUT_ID cancelled status %d, this = 0x%08x.\n"),
		 (m_is_client == true ? "client": "server"),
		 status,
		 this));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

eap_status_e wapi_core_c::create_BKID(
	eap_variable_data_c * const BKID,
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::create_BKID(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::create_BKID()");

	if (BKID == 0
		|| BKID->get_is_valid() == false
		|| receive_network_id == 0
		|| receive_network_id->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_process_general_error);

	// BKID = KD_HMAC_SHA256(BK, MACAE || MACASUE)

	crypto_kd_hmac_sha256_c kd_hmac(m_am_tools);
	if (kd_hmac.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c label(m_am_tools);
	if (label.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	const eap_variable_data_c * MAC_1 = receive_network_id->get_destination_id();
	const eap_variable_data_c * MAC_2 = receive_network_id->get_source_id();

	if (m_is_client == true)
	{
		MAC_1 = receive_network_id->get_source_id();
		MAC_2 = receive_network_id->get_destination_id();
	}

	status = label.set_copy_of_buffer(MAC_1);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = label.add_data(MAC_2);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = kd_hmac.expand_key(
		BKID,
		WAPI_BKID_LENGTH,
		&m_BK,
		&label);
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
eap_status_e wapi_core_c::packet_data_session_key(
	eap_variable_data_c * const key, ///< Here is the key.
	const eapol_key_type_e key_type, ///< This the type of the key.
	const u32_t key_index, ///< This is the index of the key.
	const bool key_tx_bit, ///< This is the TX bit of the key.
	const u8_t * const key_RSC, ///< This is the RSC counter
	const u32_t key_RSC_size ///< This is the size of RSC counter
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eapol_session_key_c * eapol_session_key = new eapol_session_key_c(
		m_am_tools,
		key,
		key_type,
		key_index,
		key_tx_bit,
		key_RSC,
		key_RSC_size
		);
	if (eapol_session_key == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (eapol_session_key->get_is_valid() == false)
	{
		delete eapol_session_key;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(m_am_tools,
		m_receive_network_id.get_destination_id(),
		m_receive_network_id.get_source_id(),
		m_receive_network_id.get_type());

	if (send_network_id.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = m_partner->packet_data_session_key(
		&send_network_id,
		eapol_session_key);

	delete eapol_session_key;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e wapi_core_c::create_unicast_key(
	const eap_variable_data_c * const BK,
	const eap_am_network_id_c * const receive_network_id,
	const eap_variable_data_c * const ae_challenge,
	const eap_variable_data_c * const asue_challenge,
	eap_variable_data_c * const unicast_encryption_key_UEK,
	eap_variable_data_c * const unicast_integrity_check_key_UCK,
	eap_variable_data_c * const message_authentication_key_MAK,
	eap_variable_data_c * const key_encryption_key_KEK,
	eap_variable_data_c * const challenge_seed)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::create_unicast_key(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::create_unicast_key()");

	if (BK == 0
		|| BK->get_is_valid_data() == false
		|| receive_network_id == 0
		|| receive_network_id->get_is_valid() == false
		|| ae_challenge == 0
		|| ae_challenge->get_is_valid_data() == false
		|| asue_challenge == 0
		|| asue_challenge->get_is_valid_data() == false
		|| unicast_encryption_key_UEK == 0
		|| unicast_encryption_key_UEK->get_is_valid() == false
		|| unicast_integrity_check_key_UCK == 0
		|| unicast_integrity_check_key_UCK->get_is_valid() == false
		|| message_authentication_key_MAK == 0
		|| message_authentication_key_MAK->get_is_valid() == false
		|| key_encryption_key_KEK == 0
		|| key_encryption_key_KEK->get_is_valid() == false
		|| challenge_seed == 0
		|| challenge_seed->get_is_valid() == false
		)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_process_general_error);

	// Output (96) = KD-HMAC-SHA256(BK, ADDID||N_AE||N_ASUE||Label, Length);

	crypto_kd_hmac_sha256_c kd_hmac(m_am_tools);
	if (kd_hmac.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c label(m_am_tools);
	if (label.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	const eap_variable_data_c * MAC_1 = receive_network_id->get_destination_id();
	const eap_variable_data_c * MAC_2 = receive_network_id->get_source_id();

	if (m_is_client == true)
	{
		MAC_1 = receive_network_id->get_source_id();
		MAC_2 = receive_network_id->get_destination_id();
	}

	status = label.set_copy_of_buffer(MAC_1);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = label.add_data(MAC_2);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = label.add_data(ae_challenge);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = label.add_data(asue_challenge);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = label.add_data(WAPI_UNICAST_KEY_LABEL, WAPI_UNICAST_KEY_LABEL_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c unicast_key(m_am_tools);
	if (unicast_key.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = kd_hmac.expand_key(
		&unicast_key,
		WAPI_UNICAST_KEY_LENGTH,
		BK,
		&label);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// {unicast_encryption_key_UEK (16)
	//  || unicast_integrity_check_key_UCK (16)
	//  || message_authentication_key_MAK (16)
	//  || key_encryption_key_KEK (16)
	//  || Challenge seed (32)}
	// = Output (96)

	u32_t offset(0ul);
	u32_t required_data_length(WAPI_UNICAST_ENCRYPTION_KEY_UEK_LENGTH);

	status = unicast_encryption_key_UEK->set_copy_of_buffer(
		unicast_key.get_data_offset(offset, required_data_length),
		required_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	offset += required_data_length;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	required_data_length = WAPI_UNICAST_INTEGRITY_CHECK_KEY_UCK_LENGTH;

	status = unicast_integrity_check_key_UCK->set_copy_of_buffer(
		unicast_key.get_data_offset(offset, required_data_length),
		required_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	offset += required_data_length;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	required_data_length = WAPI_MESSAGE_AUTHENTICATION_KEY_MAK_LENGTH;

	status = message_authentication_key_MAK->set_copy_of_buffer(
		unicast_key.get_data_offset(offset, required_data_length),
		required_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	offset += required_data_length;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	required_data_length = WAPI_KEY_ENCRYPTION_KEY_KEK_LENGTH;

	status = key_encryption_key_KEK->set_copy_of_buffer(
		unicast_key.get_data_offset(offset, required_data_length),
		required_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	offset += required_data_length;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	required_data_length = WAPI_CHALLENGE_SEED_LENGTH;

	{
		eap_variable_data_c next_challenge(m_am_tools);
		if (next_challenge.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		crypto_sha_256_c sha_256(m_am_tools);
		if (sha_256.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = sha_256.hash_init();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = sha_256.hash_update(
			unicast_key.get_data_offset(offset, required_data_length),
			required_data_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		u32_t md_length(sha_256.get_digest_length());

		status = challenge_seed->set_buffer_length(md_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = challenge_seed->set_data_length(md_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = sha_256.hash_final(
			challenge_seed->get_data(),
			&md_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("next challenge_seed"),
			 challenge_seed->get_data(),
			 challenge_seed->get_data_length()));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e wapi_core_c::create_MAC(
	const wai_message_payloads_c * const payloads,
	eap_variable_data_c * const MAC)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::create_MAC(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::create_MAC()");

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (MAC == 0
		|| MAC->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	crypto_sha_256_c sha_256(m_am_tools);
	if (sha_256.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	crypto_hmac_c hmac_sha_256(
		m_am_tools,
		&sha_256,
		false);
	if (hmac_sha_256.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("WAPI_Core: m_message_authentication_key_MAK"),
		 m_message_authentication_key_MAK.get_data(),
		 m_message_authentication_key_MAK.get_data_length()));

	status = hmac_sha_256.hmac_set_key(&m_message_authentication_key_MAK);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	for (u32_t tlv_index = 0ul; tlv_index < payloads->get_tlv_count(); ++tlv_index)
	{
		const wai_variable_data_c * tlv = payloads->get_tlv(tlv_index);
		if (tlv == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		if (tlv->get_payload_type() != wai_payload_type_message_authentication_code)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WAPI_Core: MAC: input data"),
				tlv->get_data(tlv->get_data_length()),
				tlv->get_data_length()));

			status = hmac_sha_256.hmac_update(
				tlv->get_data(tlv->get_data_length()),
				tlv->get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	} // for()

	status = MAC->set_buffer_length(hmac_sha_256.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = MAC->set_data_length(hmac_sha_256.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t md_length(hmac_sha_256.get_digest_length());
	
	status = hmac_sha_256.hmac_final(
		MAC->get_data(hmac_sha_256.get_digest_length()),
		&md_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = MAC->set_data_length(WAPI_MESSAGE_AUTHENTICATION_CODE_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("WAPI_Core: MAC"),
		 MAC->get_data(),
		 MAC->get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e wapi_core_c::create_HASH(
	const wai_message_payloads_c * const payloads,
	const bool hash_all_payloads,
	eap_variable_data_c * const HASH)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::create_HASH(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::create_HASH()");

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (HASH == 0
		|| HASH->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	crypto_sha_256_c sha_256(m_am_tools);
	if (sha_256.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = sha_256.hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	for (u32_t tlv_index = 0ul; tlv_index < payloads->get_tlv_count(); ++tlv_index)
	{
		const wai_variable_data_c * tlv = payloads->get_tlv(tlv_index);
		if (tlv == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		if (hash_all_payloads == true
			|| (tlv->get_payload_type() != wai_payload_type_message_authentication_code
				&& tlv->get_payload_type() != wai_payload_type_signature_attributes))
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WAPI_Core: HASH: input data"),
				tlv->get_data(tlv->get_data_length()),
				tlv->get_data_length()));

			status = sha_256.hash_update(
				tlv->get_data(tlv->get_data_length()),
				tlv->get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	} // for()

	status = HASH->set_buffer_length(sha_256.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = HASH->set_data_length(sha_256.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t md_length(sha_256.get_digest_length());
	
	status = sha_256.hash_final(
		HASH->get_data(sha_256.get_digest_length()),
		&md_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("WAPI_Core: HASH"),
		 HASH->get_data(),
		 HASH->get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_WAPI_CORE_SERVER)

eap_status_e wapi_core_c::encrypt_multicast_key_data(
	const eap_variable_data_c * const multicast_key,
	const eap_variable_data_c * const key_announcement,
	wai_variable_data_c * const key_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TODO: WAPI_Core: this = 0x%08x, %s: wapi_core_c::encrypt_multicast_key_data(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::encrypt_multicast_key_data()");

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("WAPI_Core: multicast_key"),
		 multicast_key->get_data(),
		 multicast_key->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("WAPI_Core: m_key_encryption_key_KEK"),
		 m_key_encryption_key_KEK.get_data(),
		 m_key_encryption_key_KEK.get_data_length()));

	wapi_am_crypto_sms4_c sms4(m_am_tools);

	status = sms4.set_key(&m_key_encryption_key_KEK);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c encrypted_multicast_key(m_am_tools);

	status = encrypted_multicast_key.set_buffer_length(multicast_key->get_data_length());
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = encrypted_multicast_key.set_data_length(encrypted_multicast_key.get_buffer_length());
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		eap_variable_data_c iv_block(m_am_tools);

		status = iv_block.set_buffer_length(multicast_key->get_data_length());
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = iv_block.set_data_length(iv_block.get_buffer_length());
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = sms4.ecb_encrypt(
			key_announcement->get_data(multicast_key->get_data_length()),
			iv_block.get_data(multicast_key->get_data_length()),
			multicast_key->get_data_length()/16);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WAPI_Core: iv_block"),
			 iv_block.get_data(),
			 iv_block.get_data_length()));

		// encrypted_multicast_key = multicast_key XOR iv_block.
		const u8_t * const pIV = iv_block.get_data(multicast_key->get_data_length());
		const u8_t * const pdata = multicast_key->get_data(multicast_key->get_data_length());
		u8_t * const output = encrypted_multicast_key.get_data(multicast_key->get_data_length());

		if (pIV == 0
			|| pdata == 0
			|| output == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		for (u32_t ind = 0u; ind < multicast_key->get_data_length(); ind++)
		{
			output[ind] = pdata[ind] ^ pIV[ind];
		}
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("WAPI_Core: encrypted_multicast_key"),
		 encrypted_multicast_key.get_data(),
		 encrypted_multicast_key.get_data_length()));

	status = key_data->create(
		wai_payload_type_key_data,
		encrypted_multicast_key.get_data(),
		encrypted_multicast_key.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_WAPI_CORE_SERVER)

//--------------------------------------------------

eap_status_e wapi_core_c::decrypt_multicast_key_data(
	const wai_variable_data_c * const key_data,
	const eap_variable_data_c * const key_announcement,
	eap_variable_data_c * const multicast_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TODO: WAPI_Core: this = 0x%08x, %s: wapi_core_c::decrypt_multicast_key_data(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::decrypt_multicast_key_data()");

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("WAPI_Core: key_data"),
		 key_data->get_type_data(key_data->get_type_data_length()),
		 key_data->get_type_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("WAPI_Core: m_key_encryption_key_KEK"),
		 m_key_encryption_key_KEK.get_data(),
		 m_key_encryption_key_KEK.get_data_length()));

	wapi_am_crypto_sms4_c sms4(m_am_tools);

	status = sms4.set_key(&m_key_encryption_key_KEK);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = multicast_key->set_buffer_length(key_data->get_type_data_length());
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = multicast_key->set_data_length(multicast_key->get_buffer_length());
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	{
		eap_variable_data_c iv_block(m_am_tools);
		if (iv_block.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = iv_block.set_buffer_length(key_data->get_type_data_length());
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = iv_block.set_data_length(iv_block.get_buffer_length());
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = sms4.ecb_encrypt(
			key_announcement->get_data(key_data->get_type_data_length()),
			iv_block.get_data(key_data->get_type_data_length()),
			key_data->get_type_data_length()/16);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WAPI_Core: iv_block"),
			 iv_block.get_data(),
			 iv_block.get_data_length()));

		// multicast_key = encrypted_multicast_key XOR iv_block.
		const u8_t * const pIV = iv_block.get_data(key_data->get_type_data_length());
		const u8_t * const pdata = key_data->get_type_data(key_data->get_type_data_length());
		u8_t * const output = multicast_key->get_data(key_data->get_type_data_length());

		if (pIV == 0
			|| pdata == 0
			|| output == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		for (u32_t ind = 0u; ind < key_data->get_type_data_length(); ind++)
		{
			output[ind] = pdata[ind] ^ pIV[ind];
		}
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("WAPI_Core: multicast_key"),
		 multicast_key->get_data(),
		 multicast_key->get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e wapi_core_c::create_multicast_key(
	const eap_variable_data_c * const notification_master_key,
	eap_variable_data_c * const multicast_key)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TODO: WAPI_Core: this = 0x%08x, %s: wapi_core_c::create_multicast_key(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::create_multicast_key()");

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("WAPI_Core: notification_master_key"),
		 notification_master_key->get_data(),
		 notification_master_key->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("WAPI_Core: m_key_encryption_key_KEK"),
		 m_key_encryption_key_KEK.get_data(),
		 m_key_encryption_key_KEK.get_data_length()));

	// multicas_key = KD_HMAC_SHA256(notification_master_key, string label)

	crypto_kd_hmac_sha256_c kd_hmac(m_am_tools);
	if (kd_hmac.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c label(m_am_tools);
	if (label.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = label.add_data(WAPI_MULTICAST_KEY_EXPANSION_LABEL, WAPI_MULTICAST_KEY_EXPANSION_LABEL_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("WAPI_Core: label"),
		 label.get_data(),
		 label.get_data_length()));

	status = kd_hmac.expand_key(
		multicast_key,
		WAPI_MULTICAST_KEY_LENGTH,
		notification_master_key,
		&label);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("WAPI_Core: multicast_key"),
		 multicast_key->get_data(),
		 multicast_key->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e wapi_core_c::create_signature_attributes(
	wai_variable_data_c * const data_signature,
	const eap_variable_data_c * const signer_id,
	const eap_variable_data_c * const signature)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::create_signature_attributes(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::create_signature_attributes()");

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	wai_variable_data_c data_identity(m_am_tools);
	if (data_identity.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = data_identity.create(
		wai_payload_type_identity,
		signer_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("data_identity"),
		 data_identity.get_full_tlv_buffer()->get_data(),
		 data_identity.get_full_tlv_buffer()->get_data_length()));

	status = data_signature->create(
		wai_payload_type_signature_attributes,
		data_identity.get_full_tlv_buffer());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("data_signature"),
		 data_signature->get_full_tlv_buffer()->get_data(),
		 data_signature->get_full_tlv_buffer()->get_data_length()));

	u8_t hash_algorithm_id(WAI_HASH_ALGORITHM_ID);
	u8_t signature_algorithm_id(WAI_SIGNATURE_ALGORITHM_ID);
	u8_t signature_parameter_id(WAI_SIGNATURE_PARAMETER_ID);
	u16_t signature_parameter_content_length(sizeof(WAPI_ECDH_OID_PARAMETER));
	u16_t signature_length(static_cast<u16_t>(signature->get_data_length()));

	u16_t signature_algorithm_length(
		sizeof(hash_algorithm_id)
		+ sizeof(signature_algorithm_id)
		+ sizeof(signature_parameter_id)
		+ sizeof(signature_parameter_content_length)
		+ signature_parameter_content_length);


	{
		u16_t network_order_signature_algorithm_length(eap_htons(signature_algorithm_length));

		status = data_signature->add_data(
			wai_payload_type_signature_attributes,
			&network_order_signature_algorithm_length,
			sizeof(network_order_signature_algorithm_length));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("data_signature"),
			 data_signature->get_full_tlv_buffer()->get_data(),
			 data_signature->get_full_tlv_buffer()->get_data_length()));
	}

	status = data_signature->add_data(
		wai_payload_type_signature_attributes,
		&hash_algorithm_id,
		sizeof(hash_algorithm_id));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("data_signature"),
		 data_signature->get_full_tlv_buffer()->get_data(),
		 data_signature->get_full_tlv_buffer()->get_data_length()));

	status = data_signature->add_data(
		wai_payload_type_signature_attributes,
		&signature_algorithm_id,
		sizeof(signature_algorithm_id));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("data_signature"),
		 data_signature->get_full_tlv_buffer()->get_data(),
		 data_signature->get_full_tlv_buffer()->get_data_length()));

	status = data_signature->add_data(
		wai_payload_type_signature_attributes,
		&signature_parameter_id,
		sizeof(signature_parameter_id));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("data_signature"),
		 data_signature->get_full_tlv_buffer()->get_data(),
		 data_signature->get_full_tlv_buffer()->get_data_length()));

	{
		u16_t network_order_signature_parameter_content_length(eap_htons(signature_parameter_content_length));

		status = data_signature->add_data(
			wai_payload_type_signature_attributes,
			&network_order_signature_parameter_content_length,
			sizeof(network_order_signature_parameter_content_length));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("data_signature"),
			 data_signature->get_full_tlv_buffer()->get_data(),
			 data_signature->get_full_tlv_buffer()->get_data_length()));
	}

	status = data_signature->add_data(
		wai_payload_type_signature_attributes,
		WAPI_ECDH_OID_PARAMETER,
		sizeof(WAPI_ECDH_OID_PARAMETER));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("data_signature"),
		 data_signature->get_full_tlv_buffer()->get_data(),
		 data_signature->get_full_tlv_buffer()->get_data_length()));

	{
		u16_t network_order_signature_length(eap_htons(signature_length));

		status = data_signature->add_data(
			wai_payload_type_signature_attributes,
			&network_order_signature_length,
			sizeof(network_order_signature_length));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("data_signature"),
			 data_signature->get_full_tlv_buffer()->get_data(),
			 data_signature->get_full_tlv_buffer()->get_data_length()));
	}

	status = data_signature->add_data(
		wai_payload_type_signature_attributes,
		signature);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("data_signature"),
		 data_signature->get_full_tlv_buffer()->get_data(),
		 data_signature->get_full_tlv_buffer()->get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e wapi_core_c::parse_signature_attributes(
	const wai_variable_data_c * const data_signature,
	eap_variable_data_c * const signer_id,
	eap_variable_data_c * const signature)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::parse_signature_attributes(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::parse_signature_attributes()");

	eap_status_e status(eap_status_process_general_error);

	if (signer_id == 0
		|| signer_id->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	u16_t signature_length(0ul);

	u16_t signature_algorithm_length(0ul);

	u32_t offset(0ul);
	u32_t remaining_data(data_signature->get_type_data_length());

	if (remaining_data > data_signature->get_full_tlv_buffer()->get_data_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	status = signer_id->reset_start_offset_and_data_length();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		// Read the ASN1/DER encoded Identity (Subject name, Issuer name, and Sequence number).

		if (data_signature->get_data_length() < (offset+remaining_data))
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		void * const identity_header_begins = data_signature->get_type_data_offset(
			offset,
			remaining_data);
		if (identity_header_begins == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		ec_cs_tlv_header_c identity_header(
			m_am_tools,
			identity_header_begins,
			remaining_data);
		if (identity_header.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_variable_data_c input_data(
			m_am_tools,
			identity_header.get_data(identity_header.get_data_length()),
			identity_header.get_data_length(),
			false,
			false);
		if (input_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		wapi_asn1_der_parser_c asn1_der_parser(m_am_tools);
		if (asn1_der_parser.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = asn1_der_parser.decode(&input_data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = asn1_der_parser.get_wapi_identity(
			signer_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		const u32_t used_data_length(identity_header.get_header_length() + identity_header.get_data_length());

		offset += used_data_length;
		remaining_data -= used_data_length;

	}

	{
		if (data_signature->get_data_length() < (offset+sizeof(u16_t)))
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u16_t * const network_order_signature_algorithm_length =
			reinterpret_cast<u16_t *>(data_signature->get_type_data_offset(
										  offset,
										  sizeof(*network_order_signature_algorithm_length)));
		if (network_order_signature_algorithm_length == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		signature_algorithm_length = eap_read_u16_t_network_order(
			network_order_signature_algorithm_length,
			sizeof(*network_order_signature_algorithm_length));

		offset += sizeof(*network_order_signature_algorithm_length) + signature_algorithm_length;
	}

	// NOTE, we skip all the Signature algorithm content.

	{
		if (data_signature->get_data_length() < (offset+sizeof(u16_t)))
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u16_t * const network_order_signature_length = reinterpret_cast<u16_t *>(data_signature->get_type_data_offset(
			offset,
			sizeof(*network_order_signature_length)));
		if (network_order_signature_length == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		signature_length = eap_read_u16_t_network_order(
			network_order_signature_length,
			sizeof(*network_order_signature_length));

		offset += sizeof(*network_order_signature_length);
	}


	{
		if (data_signature->get_data_length() < (offset+signature_length))
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u8_t * const pointer_to_signature = data_signature->get_type_data_offset(
			offset,
			signature_length);
		if (pointer_to_signature == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = signature->set_copy_of_buffer(
			pointer_to_signature,
			signature_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		offset += signature_length;
	}

	if (offset != data_signature->get_type_data_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e wapi_core_c::create_result_of_certificate_verification(
	wai_variable_data_c * const result_of_certificate_verification,
	const eap_variable_data_c * const ae_challenge,
	const eap_variable_data_c * const asue_challenge,
	const wapi_certificate_result_e asue_certificate_result,
	const eap_variable_data_c * const asue_certificate,
	const wapi_certificate_result_e ae_certificate_result,
	const eap_variable_data_c * const ae_certificate)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::create_result_of_certificate_verification(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::create_result_of_certificate_verification()");

	eap_status_e status(eap_status_process_general_error);

	if (result_of_certificate_verification == 0
		|| result_of_certificate_verification->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (ae_challenge == 0
		|| ae_challenge->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (asue_challenge == 0
		|| asue_challenge->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (asue_certificate == 0
		|| asue_certificate->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (ae_certificate == 0
		|| ae_certificate->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_core_c::create_result_of_certificate_verification(): ae_challenge"),
		 ae_challenge->get_data(),
		 ae_challenge->get_data_length()));

	status = result_of_certificate_verification->create(
		wai_payload_type_result_of_certificate_verification,
		ae_challenge);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_core_c::create_result_of_certificate_verification(): asue_challenge"),
		 asue_challenge->get_data(),
		 asue_challenge->get_data_length()));

	status = result_of_certificate_verification->add_data(
		wai_payload_type_result_of_certificate_verification,
		asue_challenge);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		u8_t verification_result_1(asue_certificate_result);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("wapi_core_c::create_result_of_certificate_verification(): verification_result_1"),
			 &verification_result_1,
			 sizeof(verification_result_1)));

		status = result_of_certificate_verification->add_data(
			wai_payload_type_result_of_certificate_verification,
			&verification_result_1,
			sizeof(verification_result_1));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	{
		wai_variable_data_c data_asue_certificate(m_am_tools);
		if (data_asue_certificate.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("wapi_core_c::create_result_of_certificate_verification(): asue_certificate"),
			 asue_certificate->get_data(),
			 asue_certificate->get_data_length()));

		status = data_asue_certificate.create(
			wai_payload_type_certificate,
			asue_certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = result_of_certificate_verification->add_data(
			wai_payload_type_result_of_certificate_verification,
			data_asue_certificate.get_full_tlv_buffer());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	{
		u8_t verification_result_2(ae_certificate_result);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("wapi_core_c::create_result_of_certificate_verification(): verification_result_2"),
			 &verification_result_2,
			 sizeof(verification_result_2)));

		status = result_of_certificate_verification->add_data(
			wai_payload_type_result_of_certificate_verification,
			&verification_result_2,
			sizeof(verification_result_2));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	{
		wai_variable_data_c data_ae_certificate(m_am_tools);
		if (data_ae_certificate.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("wapi_core_c::create_result_of_certificate_verification(): ae_certificate"),
			 ae_certificate->get_data(),
			 ae_certificate->get_data_length()));

		status = data_ae_certificate.create(
			wai_payload_type_certificate,
			ae_certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = result_of_certificate_verification->add_data(
			wai_payload_type_result_of_certificate_verification,
			data_ae_certificate.get_full_tlv_buffer());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e wapi_core_c::parse_result_of_certificate_verification(
	const wai_variable_data_c * const result_of_certificate_verification,
	eap_variable_data_c * const ae_challenge,
	eap_variable_data_c * const asue_challenge,
	wapi_certificate_result_e * const asue_certificate_result,
	eap_variable_data_c * const asue_certificate,
	wapi_certificate_result_e * const ae_certificate_result,
	eap_variable_data_c * const ae_certificate)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::parse_result_of_certificate_verification(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::parse_result_of_certificate_verification()");

	eap_status_e status(eap_status_process_general_error);

	if (result_of_certificate_verification == 0
		|| result_of_certificate_verification->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (ae_challenge == 0
		|| ae_challenge->get_is_valid() == false
		|| asue_challenge == 0
		|| asue_challenge->get_is_valid() == false
		|| asue_certificate == 0
		|| asue_certificate->get_is_valid() == false
		|| ae_certificate == 0
		|| ae_certificate->get_is_valid() == false
		|| asue_certificate_result == 0
		|| ae_certificate_result == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t offset(0ul);

	if (result_of_certificate_verification->get_type_data_length() < (offset+WAPI_CHALLENGE_LENGTH))
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	status = ae_challenge->set_copy_of_buffer(
		result_of_certificate_verification->get_type_data_offset(offset, WAPI_CHALLENGE_LENGTH),
		WAPI_CHALLENGE_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	offset += WAPI_CHALLENGE_LENGTH;

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_core_c::parse_result_of_certificate_verification(): ae_challenge"),
		 ae_challenge->get_data(),
		 ae_challenge->get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (result_of_certificate_verification->get_type_data_length() < (offset+WAPI_CHALLENGE_LENGTH))
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	status = asue_challenge->set_copy_of_buffer(
		result_of_certificate_verification->get_type_data_offset(offset, WAPI_CHALLENGE_LENGTH),
		WAPI_CHALLENGE_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	offset += WAPI_CHALLENGE_LENGTH;

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_core_c::parse_result_of_certificate_verification(): asue_challenge"),
		 asue_challenge->get_data(),
		 asue_challenge->get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	
	{
		if (result_of_certificate_verification->get_type_data_length() < (offset+sizeof(u8_t)))
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u8_t * const verification_result_1 = result_of_certificate_verification->get_type_data_offset(offset, sizeof(*verification_result_1));

		if (verification_result_1 == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		*asue_certificate_result = static_cast<wapi_certificate_result_e>(*verification_result_1);

		offset += sizeof(*verification_result_1);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("wapi_core_c::parse_result_of_certificate_verification(): verification_result_1"),
			 verification_result_1,
			 sizeof(*verification_result_1)));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		if (result_of_certificate_verification->get_type_data_length() < offset)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		u32_t data_length(result_of_certificate_verification->get_type_data_length() - offset);

		if (result_of_certificate_verification->get_type_data_length() < (offset+data_length))
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		ec_cs_tlv_header_c certificate_1(
			m_am_tools,
			result_of_certificate_verification->get_type_data_offset(offset, data_length),
			data_length);
		if (certificate_1.get_is_valid() == false
			|| certificate_1.check_header() != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = asue_certificate->set_copy_of_buffer(
			certificate_1.get_data(certificate_1.get_data_length()),
			certificate_1.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		offset += (certificate_1.get_header_length() + certificate_1.get_data_length());

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("wapi_core_c::parse_result_of_certificate_verification(): asue_certificate"),
			 asue_certificate->get_data(),
			 asue_certificate->get_data_length()));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		if (result_of_certificate_verification->get_type_data_length() < (offset+sizeof(u8_t)))
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u8_t * const verification_result_2 = result_of_certificate_verification->get_type_data_offset(offset, sizeof(*verification_result_2));

		if (verification_result_2 == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		*ae_certificate_result = static_cast<wapi_certificate_result_e>(*verification_result_2);

		offset += sizeof(*verification_result_2);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("wapi_core_c::parse_result_of_certificate_verification(): verification_result_2"),
			 verification_result_2,
			 sizeof(*verification_result_2)));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		if (result_of_certificate_verification->get_type_data_length() < offset)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		u32_t data_length(result_of_certificate_verification->get_type_data_length() - offset);

		if (result_of_certificate_verification->get_type_data_length() < (offset+data_length))
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		ec_cs_tlv_header_c certificate_2(
			m_am_tools,
			result_of_certificate_verification->get_type_data_offset(offset, data_length),
			data_length);
		if (certificate_2.get_is_valid() == false
			|| certificate_2.check_header() != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = ae_certificate->set_copy_of_buffer(
			certificate_2.get_data(certificate_2.get_data_length()),
			certificate_2.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		offset += (certificate_2.get_header_length() + certificate_2.get_data_length());

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("wapi_core_c::parse_result_of_certificate_verification(): ae_certificate"),
			 ae_certificate->get_data(),
			 ae_certificate->get_data_length()));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e wapi_core_c::packet_send(
	wai_message_c * const new_wai_message_data,
	const wai_protocol_subtype_e wapi_subtype)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::packet_send(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::packet_send()");

	eap_status_e status(eap_status_process_general_error);

	if (new_wai_message_data == 0
		|| new_wai_message_data->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(m_am_tools,
		m_receive_network_id.get_destination_id(),
		m_receive_network_id.get_source_id(),
		m_receive_network_id.get_type());

	if (send_network_id.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_ASSERT_ALWAYS(m_MTU > m_trailer_length);

#if defined(USE_WAPI_CORE_SERVER)
	if (m_is_client == false)
	{
		++m_packet_sequence_number;
	}
#endif //#if defined(USE_WAPI_CORE_SERVER)

	// Both client and server initializes re-transmission.
	// Client will process re-transmitted request again.
	// Server will re-transmit the packet when timer elapses and no response is received.
	init_retransmission(
		&send_network_id,
		&m_received_wai_message_data,
		new_wai_message_data,
		m_packet_sequence_number,
		wapi_subtype);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = packet_fragment(new_wai_message_data, m_packet_sequence_number);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e wapi_core_c::packet_fragment(
	wai_message_c * const new_wai_message_data,
	const u16_t packet_sequence_number)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::packet_fragment(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::packet_fragment()");

	eap_status_e status(eap_status_process_general_error);

	if (new_wai_message_data == 0
		|| new_wai_message_data->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(m_am_tools,
		m_receive_network_id.get_destination_id(),
		m_receive_network_id.get_source_id(),
		m_receive_network_id.get_type());

	if (send_network_id.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_ASSERT_ALWAYS(m_MTU > m_trailer_length);

	wai_protocol_packet_header_c wai(
		m_am_tools,
		new_wai_message_data->get_wai_message_data()->get_data(),
		new_wai_message_data->get_wai_message_data()->get_data_length());

	if (wai.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("wapi_core_c::packet_fragment(): %s, packet buffer corrupted.\n"),
			 (m_is_client_role == true) ? "client": "server"
			 ));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	WAI_PROTOCOL_PACKET_TRACE_HEADER("full packet", &wai, m_is_client);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	const u32_t data_length(wai.get_data_length());
	const u32_t header_length(wai.get_header_length());
	const u32_t FRAGMENT_MULTIPLIER = 8ul;
	const u32_t header_remainder_length(header_length % FRAGMENT_MULTIPLIER);
	const u32_t data_mtu(m_MTU - header_length - header_remainder_length);
	const u32_t data_mtu_8(data_mtu - (data_mtu % FRAGMENT_MULTIPLIER));

	u32_t data_fragment_length = (header_remainder_length + data_mtu_8);
	const u32_t fragment_count = ((data_length + data_fragment_length - 1) / data_fragment_length);

	if (fragment_count == 1ul
		&& data_length < data_fragment_length)
	{
		data_fragment_length = data_length;
	}

	const u32_t last_data_fragment_length = (data_length - ((fragment_count-1) * data_fragment_length));
	const u32_t one_packet_length = (header_length + data_fragment_length);
	EAP_UNREFERENCED_PARAMETER(one_packet_length);


	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("wapi_core_c::packet_fragment(): packet_sequence_number=%d, m_MTU=%d, packet_length=%d, data_length=%d, fragment_count=%d, data_fragment_length=%d, last_data_fragment_length=%d, one_packet_length=%d\n"),
		packet_sequence_number,
		m_MTU,
		(header_length+data_length),
		data_length,
		fragment_count,
		data_fragment_length,
		last_data_fragment_length,
		one_packet_length));

	EAP_ASSERT(last_data_fragment_length <= data_fragment_length);

	u32_t current_fragment_length(data_fragment_length);

	for (u32_t frag_ind = 0ul; frag_ind < fragment_count; ++frag_ind)
	{
		u32_t buffer_size = m_wapi_header_offset + wai.get_header_length() + current_fragment_length + m_trailer_length;

		// Creates a fragment.
		eap_buf_chain_wr_c wai_packet(
			eap_write_buffer, 
			m_am_tools, 
			buffer_size);

		if (wai_packet.get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("wapi_core_c::packet_fragment(): %s, packet buffer corrupted.\n"),
				 (m_is_client == true) ? "client": "server"
				 ));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = wai_packet.add_data_to_offset(
			m_wapi_header_offset,
			wai.get_header_buffer(wai.get_header_length()),
			wai.get_header_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = wai_packet.add_data_to_offset(
			m_wapi_header_offset+wai.get_header_length(),
			wai.get_data_offset(frag_ind * data_fragment_length, current_fragment_length),
			current_fragment_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		wai_protocol_packet_header_c wai_fragment_header(
			m_am_tools,
			wai_packet.get_data_offset(m_wapi_header_offset, wai.get_header_length() + current_fragment_length),
			wai.get_header_length() + current_fragment_length);

		if (wai_fragment_header.get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("wapi_core_c::packet_fragment(): %s, packet buffer corrupted.\n"),
				 (m_is_client_role == true) ? "client": "server"
				 ));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		status = wai_fragment_header.set_packet_sequence_number(packet_sequence_number);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = wai_fragment_header.set_fragment_sequence_number(static_cast<u8_t>(frag_ind));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = wai_fragment_header.set_length(wai.get_header_length() + current_fragment_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if ((frag_ind+1ul) < fragment_count)
		{
			// Not last fragment.
			wai_fragment_header.set_flag(wai_fragment_header.get_flag() | wai_protocol_packet_header_c::m_flag_mask_fragment_exists);
		}
		else
		{
			// Last fragment.
			wai_fragment_header.set_flag(wai_fragment_header.get_flag() & ~wai_protocol_packet_header_c::m_flag_mask_fragment_exists);
		}

		if ((frag_ind+2ul) == fragment_count)
		{
			current_fragment_length = last_data_fragment_length;
		}

		WAI_PROTOCOL_PACKET_TRACE_HEADER("fragment", &wai_fragment_header, m_is_client);

		status = packet_send(
			&send_network_id,
			&wai_packet,
			m_wapi_header_offset,
			wai_fragment_header.get_length(),
			buffer_size);

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e wapi_core_c::packet_reassemble(const wai_protocol_packet_header_c * const wai)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::packet_reassemble(): wait fragment number %d, packet fragment number %d, state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 m_fragment_sequence_number,
		 wai->get_fragment_sequence_number(),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("           %s: wapi_core_c::packet_reassemble(): sequence number %d, required sequence number %d.\n"),
		(m_is_client == true) ? "client": "server",
		wai->get_packet_sequence_number(),
		m_packet_sequence_number));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::packet_reassemble()");

	eap_status_e status(eap_status_process_general_error);

	if (wai == 0
		|| wai->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	status = wai->check_header();

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (wai->get_fragment_sequence_number() != m_fragment_sequence_number)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::packet_reassemble(): fragment sequence number %d != required fragment sequence number %d.\n"),
			(m_is_client == true) ? "client": "server",
			wai->get_fragment_sequence_number(),
			m_fragment_sequence_number));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}


	wai_protocol_packet_header_c reass_wai(
		m_am_tools);
	
	if (wai->get_fragment_sequence_number() == 0u)
	{
		m_reassemble_packet.reset();

		// Add header and data.
		status = m_reassemble_packet.set_copy_of_buffer(
			wai->get_header_buffer(wai->get_length()),
			wai->get_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = reass_wai.set_header_buffer(
			m_reassemble_packet.get_data(),
			m_reassemble_packet.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		status = reass_wai.set_header_buffer(
			m_reassemble_packet.get_data(),
			m_reassemble_packet.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (wai->get_packet_sequence_number() != reass_wai.get_packet_sequence_number())
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: WAI: %s: wapi_core_c::packet_reassemble(): sequence number %d != required sequence number %d.\n"),
				(m_is_client == true) ? "client": "server",
				wai->get_packet_sequence_number(),
				reass_wai.get_packet_sequence_number()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
		}

		if (wai->get_subtype() != reass_wai.get_subtype())
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: WAI: %s: wapi_core_c::packet_reassemble(): sub-type %d != required sub-type %d.\n"),
				(m_is_client == true) ? "client": "server",
				wai->get_subtype(),
				reass_wai.get_subtype()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
		}

		// Add data.
		status = m_reassemble_packet.add_data(
			wai->get_data(wai->get_data_length()),
			wai->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = reass_wai.set_header_buffer(
			m_reassemble_packet.get_data(),
			m_reassemble_packet.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = reass_wai.set_length(reass_wai.get_length() + wai->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = reass_wai.set_fragment_sequence_number(wai->get_fragment_sequence_number());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = reass_wai.set_flag(wai->get_flag());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	++m_fragment_sequence_number;

	WAI_PROTOCOL_PACKET_TRACE_HEADER("reassembled packet", &reass_wai, m_is_client_role);

	if ((reass_wai.get_flag() & wai_protocol_packet_header_c::m_flag_mask_fragment_exists) != 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_pending_request);
	}

	status = m_received_wai_message_data.set_wai_message_data(&m_reassemble_packet);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	// This is the last fragment.

	m_fragment_sequence_number = 0ul;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::start_authentication()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::start_authentication(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::start_authentication()");

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	m_fragment_sequence_number = 0ul;
	m_packet_sequence_number = 0ul;

#if defined(USE_WAPI_CORE_SERVER)

	if (m_wapi_negotiation_state == wapi_negotiation_state_none
		|| m_only_initial_authentication == true)
	{
		m_wapi_negotiation_state = wapi_negotiation_state_initial_negotiation;
	}
	else if (m_wapi_negotiation_state == wapi_negotiation_state_initial_negotiation)
	{
		m_wapi_negotiation_state = wapi_negotiation_state_rekeying;
	}
	else if (m_wapi_negotiation_state == wapi_negotiation_state_rekeying)
	{
		// Randomly change to initial negotiation.
		crypto_random_c rand(m_am_tools);
		if (rand.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		const u32_t MIN_LIMIT = 0ul;
		const u32_t MAX_LIMIT = 100ul;
		const u32_t SELECTION_LIMIT = MAX_LIMIT/2ul;

		if (rand.get_rand_integer(MIN_LIMIT, MAX_LIMIT) <= SELECTION_LIMIT)
		{
			m_wapi_negotiation_state = wapi_negotiation_state_initial_negotiation;
		}
	}

	if (m_is_client == false
		&& (m_wapi_state == wapi_core_state_none
			|| m_wapi_state == wapi_core_state_authentication_ok
			|| m_wapi_state == wapi_core_state_authentication_failed))
	{
		if (m_authentication_type == eapol_key_authentication_type_WAI_PSK)
		{
			set_wapi_state(wapi_core_state_start_unicast_key_negotiation);

			status = start_unicast_key_negotiation();
		}
		else if (m_authentication_type == eapol_key_authentication_type_WAI_certificate)
		{
			set_wapi_state(wapi_core_state_start_certificate_negotiation);

			status = start_certificate_negotiation();
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_authentication_type);
		}
	}
	else
#endif //#if defined(USE_WAPI_CORE_SERVER)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::start_authentication(): Verify state %s != %s, negotiation state = %s.\n"),
			(m_is_client == true) ? "client": "server",
			wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
			wapi_strings_c::get_wapi_core_state_string(wapi_core_state_none),
			wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

		status =  eap_status_unexpected_message;
		(void) EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::allow_authentication()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::allow_authentication(): state=%s, negotiation_state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
		 wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::allow_authentication()");

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	m_fragment_sequence_number = 0ul;

	if (m_wapi_negotiation_state == wapi_negotiation_state_none)
	{
		m_wapi_negotiation_state = wapi_negotiation_state_initial_negotiation;
	}
	else if (m_wapi_negotiation_state == wapi_negotiation_state_initial_negotiation)
	{
		m_wapi_negotiation_state = wapi_negotiation_state_rekeying;
	}

	if (m_wapi_state == wapi_core_state_none)
	{
		if (m_authentication_type == eapol_key_authentication_type_WAI_PSK)
		{
			set_wapi_state(wapi_core_state_wait_unicast_key_negotiation_request_message);
			status = eap_status_ok;
		}
		else if (m_authentication_type == eapol_key_authentication_type_WAI_certificate)
		{
			set_wapi_state(wapi_core_state_wait_authentication_activation_message);
			status = eap_status_ok;
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_authentication_type);
		}
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::allow_authentication(): Verify state %s != %s, negotiation state = %s.\n"),
			(m_is_client == true) ? "client": "server",
			wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
			wapi_strings_c::get_wapi_core_state_string(wapi_core_state_none),
			wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::init_bksa_caching_timeout()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::init_bksa_caching_timeout(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::init_bksa_caching_timeout()");

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: Removes BKSA cache\n"),
		 (m_is_client == true ? "client": "server")));

	// Now we do not use BKSA cache, clean-up state.
	(void) reset();

	// Timeout value zero will remove state immediately.
	status = set_session_timeout(0ul);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::reset_cached_bksa()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::reset_cached_bksa(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::reset_cached_bksa()");

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Now we do not use BKSA cache, clean-up state.
	status = reset();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::read_reassociation_parameters(
	const eap_am_network_id_c * const /* receive_network_id */, ///< source includes remote address, destination includes local address.
	const eapol_key_authentication_type_e /* required_authentication_type */,
	eap_variable_data_c * const /* BKSA */,
	const eap_variable_data_c * const /* received_ie */,
	const eap_variable_data_c * const /* sent_ie */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::read_reassociation_parameters(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::read_reassociation_parameters()");

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Now we do not support cached BKSAs.

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_WAPI_CORE_SERVER)

eap_status_e wapi_core_c::increase_u128_t_network_order(
	eap_variable_data_c * const u128_t_integer) const
{
	u64_t half_integer[2];

	half_integer[1ul] = eap_read_u64_t_network_order(
		u128_t_integer->get_data(sizeof(u64_t)),
		sizeof(u64_t));

	half_integer[0ul] = eap_read_u64_t_network_order(
		u128_t_integer->get_data_offset(sizeof(u64_t), sizeof(u64_t)),
		sizeof(u64_t));

	if (half_integer[0ul] == (~0UL))
	{
		++half_integer[1ul];
	}
	++half_integer[0ul];

	eap_status_e status = eap_write_u64_t_network_order(
		u128_t_integer->get_data(sizeof(u64_t)),
		sizeof(u64_t),
		half_integer[1ul]);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = eap_write_u64_t_network_order(
		u128_t_integer->get_data_offset(sizeof(u64_t), sizeof(u64_t)),
		sizeof(u64_t),
		half_integer[0ul]);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_WAPI_CORE_SERVER)

//--------------------------------------------------

#if defined(USE_WAPI_CORE_SERVER)

eap_status_e wapi_core_c::start_certificate_negotiation()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::start_certificate_negotiation(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::start_certificate_negotiation()");

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	m_packet_sequence_number = 0u;

	status = m_ec_certificate_store->query_asu_id();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_WAPI_CORE_SERVER)

//--------------------------------------------------

#if defined(USE_WAPI_CORE_SERVER)

eap_status_e wapi_core_c::start_unicast_key_negotiation()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::start_unicast_key_negotiation(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::start_unicast_key_negotiation()");

	eap_status_e status(eap_status_process_general_error);

	if (m_authentication_type != eapol_key_authentication_type_WAI_PSK
		&& m_authentication_type != eapol_key_authentication_type_WAI_certificate)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_authentication_type);
	}

	if (m_wapi_state != wapi_core_state_start_unicast_key_negotiation)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::start_unicast_key_negotiation(): Verify state %s != %s, negotiation state = %s.\n"),
			(m_is_client == true) ? "client": "server",
			wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
			wapi_strings_c::get_wapi_core_state_string(wapi_core_state_start_unicast_key_negotiation),
			wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Create BKID.

	status = create_BKID(&m_BKID, &m_receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Create AE challenge.

	if (m_wapi_negotiation_state == wapi_negotiation_state_initial_negotiation)
	{
		crypto_random_c rand(m_am_tools);
		if (rand.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = rand.get_rand_bytes(
			&m_ae_unicast_challenge,
			WAPI_CHALLENGE_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		status = m_ae_unicast_challenge.set_copy_of_buffer(&m_next_unicast_challenge);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Create the Unicast Key Negotiation Request message.

	wai_message_payloads_c * const payloads = new wai_message_payloads_c(m_am_tools, m_is_client);
	eap_automatic_variable_c<wai_message_payloads_c> automatic_payloads(m_am_tools, payloads);

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = payloads->initialise_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->get_wai_protocol_packet_header_writable()->set_subtype(wai_protocol_subtype_unicast_key_negotiation_request);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds FLAG to data field.

	{
		wai_variable_data_c data_flag(m_am_tools);
		if (data_flag.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u8_t flag(wai_data_flag_mask_none);

		if (m_wapi_negotiation_state == wapi_negotiation_state_rekeying)
		{
			flag = wai_data_flag_mask_USK_Rekeying;
		}

		status = data_flag.create(
			wai_payload_type_flag,
			&flag,
			sizeof(flag));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_flag);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds BKID to data field.

	{
		wai_variable_data_c data_BKID(m_am_tools);
		if (data_BKID.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = data_BKID.create(
			wai_payload_type_bkid,
			&m_BKID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_BKID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds USKID to data field.

	{
		wai_variable_data_c data_USKID(m_am_tools);
		if (data_USKID.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (m_wapi_negotiation_state == wapi_negotiation_state_rekeying)
		{
			m_USKID = (m_USKID + 1u) % 2;
		}

		status = data_USKID.create(
			wai_payload_type_uskid,
			&m_USKID,
			sizeof(m_USKID));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_USKID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds ADDID to data field.

	{
		wai_variable_data_c data_ADDID(m_am_tools);
		if (data_ADDID.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		const eap_variable_data_c * MAC_1 = m_receive_network_id.get_source_id();
		const eap_variable_data_c * MAC_2 = m_receive_network_id.get_destination_id();

		if (m_is_client == true)
		{
			MAC_1 = m_receive_network_id.get_destination_id();
			MAC_2 = m_receive_network_id.get_source_id();
		}

		status = data_ADDID.create(
			wai_payload_type_addid,
			MAC_1);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = data_ADDID.add_data(
			wai_payload_type_addid,
			MAC_2);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_ADDID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds AE Challenge to data field.

	{
		wai_variable_data_c data_AE_challenge(m_am_tools);
		if (data_AE_challenge.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = data_AE_challenge.create(
			wai_payload_type_nonce,
			&m_ae_unicast_challenge);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_AE_challenge);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Create and send message.

	wai_message_c new_wai_message_data(m_am_tools, m_is_client);
	if (new_wai_message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->create_wai_tlv_message(&new_wai_message_data, false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	//m_packet_sequence_number = 0u;

	//cancel_retransmission();

	status = packet_send(
		&new_wai_message_data,
		payloads->get_wai_protocol_packet_header_writable()->get_subtype());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	set_wapi_state(wapi_core_state_wait_unicast_key_negotiation_response_message);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_WAPI_CORE_SERVER)

//--------------------------------------------------

#if defined(USE_WAPI_CORE_SERVER)

eap_status_e wapi_core_c::start_multicast_key_announcement()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::start_multicast_key_announcement(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::start_multicast_key_announcement()");

	eap_status_e status(eap_status_process_general_error);

	if (m_authentication_type != eapol_key_authentication_type_WAI_PSK
		&& m_authentication_type != eapol_key_authentication_type_WAI_certificate)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_authentication_type);
	}

	if (m_wapi_state != wapi_core_state_start_multicast_key_announcement)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::start_multicast_key_announcement(): Verify state %s != %s, negotiation state = %s.\n"),
			(m_is_client == true) ? "client": "server",
			wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
			wapi_strings_c::get_wapi_core_state_string(wapi_core_state_start_multicast_key_announcement),
			wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Create multicast key.

	crypto_random_c rand(m_am_tools);
	if (rand.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c notification_master_key(m_am_tools);
	if (notification_master_key.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = rand.get_rand_bytes(
		&notification_master_key,
		WAPI_NOTIFICATION_MASTER_KEY_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = create_multicast_key(&notification_master_key, &m_multicast_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Create the Multicast Key announcement message.

	wai_message_payloads_c * const payloads = new wai_message_payloads_c(m_am_tools, m_is_client);
	eap_automatic_variable_c<wai_message_payloads_c> automatic_payloads(m_am_tools, payloads);

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = payloads->initialise_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->get_wai_protocol_packet_header_writable()->set_subtype(wai_protocol_subtype_multicast_key_announcement);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds FLAG to data field.

	{
		wai_variable_data_c data_flag(m_am_tools);
		if (data_flag.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u8_t flag(wai_data_flag_mask_none);

		status = data_flag.create(
			wai_payload_type_flag,
			&flag,
			sizeof(flag));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_flag);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds MSKID to data field.

	{
		wai_variable_data_c data_flag(m_am_tools);
		if (data_flag.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (m_wapi_negotiation_state == wapi_negotiation_state_initial_negotiation)
		{
			m_MSKID = 0u;
		}
		else
		{
			m_MSKID = (m_MSKID + 1u) % 2;
		}

		status = data_flag.create(
			wai_payload_type_mskid_stakeyid,
			&m_MSKID,
			sizeof(m_MSKID));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_flag);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds USKID to data field.

	{
		wai_variable_data_c data_USKID(m_am_tools);
		if (data_USKID.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = data_USKID.create(
			wai_payload_type_uskid,
			&m_USKID,
			sizeof(m_USKID));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_USKID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds ADDID to data field.

	{
		wai_variable_data_c data_ADDID(m_am_tools);
		if (data_ADDID.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		const eap_variable_data_c * MAC_1 = m_receive_network_id.get_source_id();
		const eap_variable_data_c * MAC_2 = m_receive_network_id.get_destination_id();

		if (m_is_client == true)
		{
			MAC_1 = m_receive_network_id.get_destination_id();
			MAC_2 = m_receive_network_id.get_source_id();
		}

		status = data_ADDID.create(
			wai_payload_type_addid,
			MAC_1);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = data_ADDID.add_data(
			wai_payload_type_addid,
			MAC_2);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_ADDID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds Data Packet Number to data field.

	{
		wai_variable_data_c data_packet_number(m_am_tools);
		if (data_packet_number.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (m_wapi_negotiation_state == wapi_negotiation_state_initial_negotiation)
		{
			const u8_t TEST_DATA_PACKET_NUMBER[] =
			{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			};

			status = m_packet_data_number.set_copy_of_buffer(
				TEST_DATA_PACKET_NUMBER,
				sizeof(TEST_DATA_PACKET_NUMBER));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			status = increase_u128_t_network_order(
				&m_packet_data_number);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		status = data_packet_number.create(
			wai_payload_type_data_sequence_number,
			&m_packet_data_number);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_packet_number);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds Key Announcement to data field.

	{
		wai_variable_data_c key_announcement(m_am_tools);
		if (key_announcement.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (m_wapi_negotiation_state == wapi_negotiation_state_initial_negotiation)
		{
			const u8_t TEST_KEY_ANNOUNCEMENT[] =
			{
				0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36,
				0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36,
			};

			status = m_key_announcement.set_copy_of_buffer(
				TEST_KEY_ANNOUNCEMENT,
				sizeof(TEST_KEY_ANNOUNCEMENT));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			status = increase_u128_t_network_order(
				&m_key_announcement);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		status = key_announcement.create(
			wai_payload_type_key_announcement_identifier,
			&m_key_announcement);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&key_announcement);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds Key Data to data field.

		{
			wai_variable_data_c key_data(m_am_tools);
			if (key_data.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = encrypt_multicast_key_data(&notification_master_key, &m_key_announcement, &key_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = payloads->add_tlv(&key_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds MAC to data field.

	{
		wai_variable_data_c data_MAC(m_am_tools);
		if (data_MAC.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_variable_data_c MAC(m_am_tools);
		if (MAC.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = create_MAC(payloads, &MAC);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = MAC.set_data_length(WAPI_MESSAGE_AUTHENTICATION_CODE_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = data_MAC.create(
			wai_payload_type_message_authentication_code,
			&MAC);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_MAC);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Create and send message.

	wai_message_c new_wai_message_data(m_am_tools, m_is_client);
	if (new_wai_message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->create_wai_tlv_message(&new_wai_message_data, false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	//m_packet_sequence_number = 0u;

	//cancel_retransmission();

	status = packet_send(
		&new_wai_message_data,
		payloads->get_wai_protocol_packet_header_writable()->get_subtype());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	set_wapi_state(wapi_core_state_wait_multicast_announcement_response_message);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_WAPI_CORE_SERVER)

//--------------------------------------------------

eap_status_e wapi_core_c::handle_authentication_activation(
	const eap_am_network_id_c * const receive_network_id,
	const wai_protocol_packet_header_c * const wai)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::handle_authentication_activation(): state=%s, negotiation state = %s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
		 wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::handle_authentication_activation()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_process_general_error);

	if (m_authentication_type != eapol_key_authentication_type_WAI_certificate)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_authentication_type);
	}

	if (m_wapi_state != wapi_core_state_wait_authentication_activation_message
		&& m_wapi_state != wapi_core_state_wait_access_authentication_response_message
		&& m_wapi_state != wapi_core_state_authentication_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::handle_authentication_activation(): Verify state %s != %s, negotiation state = %s.\n"),
			(m_is_client == true) ? "client": "server",
			wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
			wapi_strings_c::get_wapi_core_state_string(wapi_core_state_wait_authentication_activation_message),
			wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (wai == 0
		|| wai->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	status = wai->check_header();

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (wai->get_packet_sequence_number() != WAI_FIRST_SEQUENCE_NUMBER)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::handle_authentication_activation(): sequence number %d != required sequence number %d.\n"),
			(m_is_client == true) ? "client": "server",
			wai->get_packet_sequence_number(),
			WAI_FIRST_SEQUENCE_NUMBER));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	m_packet_sequence_number = WAI_FIRST_SEQUENCE_NUMBER;

	set_wapi_state(wapi_core_state_process_authentication_activation_message);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_authentication_type == eapol_key_authentication_type_WAI_certificate)
	{
		// Here we swap the addresses.
		eap_am_network_id_c send_network_id(m_am_tools,
			m_receive_network_id.get_destination_id(),
			m_receive_network_id.get_source_id(),
			m_receive_network_id.get_type());

		if (send_network_id.get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// This is notification to eapol_core_c object.
		// WAI unicast negotiation started successfully.
		eap_state_notification_c * notification = new eap_state_notification_c(
			m_am_tools,
			&send_network_id,
			m_is_client,
			eap_state_notification_generic,
			eap_protocol_layer_wai,
			eapol_key_handshake_type_wai_handshake,
			eapol_key_state_wapi_authentication_running,
			eapol_key_state_wapi_authentication_running,
			0ul,
			false);
		if (notification == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
		m_partner->state_notification(notification);

		delete notification;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	wai_message_payloads_c parser(
		m_am_tools,
		m_is_client);
	if (parser.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t padding_length(0ul);

	status = parser.parse_wai_payloads(
		wai->get_header_buffer(wai->get_header_buffer_length()), ///< This is the start of the message buffer.
		wai->get_header_buffer_length(), ///< This is the length of the buffer. This must match with the length of all payloads.
		&padding_length ///< Length of possible padding is set to this variable.
		);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify BK rekeying flag.

	{
		wai_variable_data_c * const flag_payload = parser.get_tlv_pointer(wai_payload_type_flag);
		if (flag_payload == 0
			|| flag_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u8_t * const flag = flag_payload->get_data(sizeof(*flag));
		if (flag == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (m_wapi_negotiation_state == wapi_negotiation_state_rekeying)
		{
			if (((*flag) & wai_data_flag_mask_BK_Rekeying) == 0)
			{
				m_wapi_negotiation_state = wapi_negotiation_state_initial_negotiation;

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("WARNING: WAPI_Core: this = 0x%08x, %s: wapi_core_c::handle_authentication_activation(): changed to %s.\n"),
					 this,
					 (m_is_client == true ? "client": "server"),
					 wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));
			}
		}
		else
		{
			if (((*flag) & wai_data_flag_mask_BK_Rekeying) != 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Save Authentication Identifier.

	{
		wai_variable_data_c * const authentication_identifier = parser.get_tlv_pointer(wai_payload_type_authentication_identifier);
		if (authentication_identifier == 0
			|| authentication_identifier->get_is_valid_data() == false
			|| authentication_identifier->get_data_length() < WAPI_AUTHENTICATION_IDENTIFIER_LENGTH)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (m_wapi_negotiation_state == wapi_negotiation_state_rekeying)
		{
			// Verify the Authentication Identifier.
			if (m_am_tools->memcmp(
				m_authentication_identifier.get_data(WAPI_AUTHENTICATION_IDENTIFIER_LENGTH),
				authentication_identifier->get_data(WAPI_AUTHENTICATION_IDENTIFIER_LENGTH),
				WAPI_AUTHENTICATION_IDENTIFIER_LENGTH) != 0)
			{
				EAP_TRACE_DATA_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("ERROR: local m_authentication_identifier"),
					 m_authentication_identifier.get_data(),
					 m_authentication_identifier.get_data_length()));

				EAP_TRACE_DATA_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("ERROR: received authentication_identifier"),
					authentication_identifier->get_data(WAPI_AUTHENTICATION_IDENTIFIER_LENGTH),
					WAPI_AUTHENTICATION_IDENTIFIER_LENGTH));

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}
		}
		else
		{
			status = m_authentication_identifier.set_copy_of_buffer(
				authentication_identifier->get_type_data(WAPI_AUTHENTICATION_IDENTIFIER_LENGTH),
				WAPI_AUTHENTICATION_IDENTIFIER_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Save ASU-ID.

	{
		wai_variable_data_c * const asu_id = parser.get_tlv_pointer(wai_payload_type_identity);
		if (asu_id == 0
			|| asu_id->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		status = m_asu_id.set_copy_of_buffer(
			asu_id->get_type_data(asu_id->get_type_data_length()),
			asu_id->get_type_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("m_asu_id"),
			 m_asu_id.get_data(),
			 m_asu_id.get_data_length()));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Save STA_AE certificate.

	{
		wai_variable_data_c * const sta_ae_certificate = parser.get_tlv_pointer(wai_payload_type_certificate);
		if (sta_ae_certificate == 0
			|| sta_ae_certificate->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		status = m_peer_certificate.set_copy_of_buffer(
			sta_ae_certificate->get_type_data(sta_ae_certificate->get_type_data_length()),
			sta_ae_certificate->get_type_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify the ECDH parameter.

	{
		wai_variable_data_c * const echd_parameter = parser.get_tlv_pointer(wai_payload_type_echd_parameter);
		if (echd_parameter == 0
			|| echd_parameter->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (sizeof(WAPI_ECDH_OID_PARAMETER) != echd_parameter->get_type_data_length()
			|| m_am_tools->memcmp(
				WAPI_ECDH_OID_PARAMETER,
				echd_parameter->get_type_data(sizeof(WAPI_ECDH_OID_PARAMETER)),
				sizeof(WAPI_ECDH_OID_PARAMETER)) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Create ASUE challenge.

	if (m_asue_certificate_challenge.get_is_valid_data() == false)
	{
		crypto_random_c rand(m_am_tools);
		if (rand.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = rand.get_rand_bytes(
			&m_asue_certificate_challenge,
			WAPI_CHALLENGE_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Selects own certificate issued by ASU-ID.

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("m_asu_id"),
		 m_asu_id.get_data(),
		 m_asu_id.get_data_length()));

	status = m_ec_certificate_store->select_certificate(&m_asu_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e wapi_core_c::handle_access_authentication_response(
	const eap_am_network_id_c * const receive_network_id,
	const wai_protocol_packet_header_c * const wai)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::handle_access_authentication_response(): state=%s, negotiation state = %s\n"),
		this,
		(m_is_client == true ? "client": "server"),
		wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
		wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::handle_access_authentication_response()");

	if (m_authentication_type != eapol_key_authentication_type_WAI_certificate)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_authentication_type);
	}

	if (m_wapi_state != wapi_core_state_wait_access_authentication_response_message
		&& m_wapi_state != wapi_core_state_wait_unicast_key_negotiation_request_message
		&& m_wapi_state != wapi_core_state_wait_unicast_key_negotiation_confirmation_message
		&& m_wapi_state != wapi_core_state_authentication_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::handle_access_authentication_response(): Verify state %s != %s, negotiation state = %s.\n"),
			(m_is_client == true) ? "client": "server",
			wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
			wapi_strings_c::get_wapi_core_state_string(wapi_core_state_wait_access_authentication_response_message),
			wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	eap_status_e status(eap_status_process_general_error);

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (wai == 0
		|| wai->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	status = wai->check_header();

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (wai->get_packet_sequence_number() != (m_packet_sequence_number + 1u))
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::handle_access_authentication_response(): sequence number %d != required sequence number %d.\n"),
			(m_is_client == true) ? "client": "server",
			wai->get_packet_sequence_number(),
			(m_packet_sequence_number + 1u)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	++m_packet_sequence_number;

	set_wapi_state(wapi_core_state_process_access_authentication_response_message);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	wai_message_payloads_c parser(
		m_am_tools,
		m_is_client);
	if (parser.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t padding_length(0ul);

	status = parser.parse_wai_payloads(
		wai->get_header_buffer(wai->get_header_buffer_length()), ///< This is the start of the message buffer.
		wai->get_header_buffer_length(), ///< This is the length of the buffer. This must match with the length of all payloads.
		&padding_length ///< Length of possible padding is set to this variable.
		);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify BK rekeying flag.

	{
		wai_variable_data_c * const flag_payload = parser.get_tlv_pointer(wai_payload_type_flag);
		if (flag_payload == 0
			|| flag_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u8_t * const pointer_to_flag = flag_payload->get_data(sizeof(*pointer_to_flag));
		if (pointer_to_flag == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		m_do_certificate_validation = false;

		if (m_wapi_negotiation_state == wapi_negotiation_state_rekeying)
		{
			if (((*pointer_to_flag) & wai_data_flag_mask_BK_Rekeying) == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			if (((*pointer_to_flag) & wai_data_flag_mask_Certificate_Validation_Request) != 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::handle_access_authentication_response(): no certificate validation\n"),
				this,
				(m_is_client == true ? "client": "server")));
		}
		else
		{
			if (((*pointer_to_flag) & wai_data_flag_mask_BK_Rekeying) != 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::handle_access_authentication_response(): does certificate validation\n"),
				this,
				(m_is_client == true ? "client": "server")));

			m_do_certificate_validation = true;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify AE identity.

	{

		wai_variable_data_c * const ae_identity = parser.get_tlv_pointer(wai_payload_type_identity);
		if (ae_identity == 0
			|| ae_identity->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (m_ae_id.compare(
				ae_identity->get_type_data(ae_identity->get_type_data_length()),
				ae_identity->get_type_data_length()) != 0)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: local m_ae_id"),
				 m_ae_id.get_data(),
				 m_ae_id.get_data_length()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: received AE-ID"),
				 ae_identity->get_type_data(ae_identity->get_type_data_length()),
				 ae_identity->get_type_data_length()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Verify ASUE identity.

		wai_variable_data_c * const asue_identity = ae_identity->get_next_payload_with_same_tlv_type();
		if (asue_identity == 0
			|| asue_identity->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (m_asue_id.compare(
				asue_identity->get_type_data(asue_identity->get_type_data_length()),
				asue_identity->get_type_data_length()) != 0)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: local m_asue_id"),
				 m_asue_id.get_data(),
				 m_asue_id.get_data_length()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: received ASUE-ID"),
				 asue_identity->get_type_data(asue_identity->get_type_data_length()),
				 asue_identity->get_type_data_length()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify ASUE challenge.

	{

		wai_variable_data_c * const asue_challenge = parser.get_tlv_pointer(wai_payload_type_nonce);
		if (asue_challenge == 0
			|| asue_challenge->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (m_asue_certificate_challenge.compare(
				asue_challenge->get_type_data(asue_challenge->get_type_data_length()),
				asue_challenge->get_type_data_length()) != 0)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: local m_asue_certificate_challenge"),
				 m_asue_certificate_challenge.get_data(),
				 m_asue_certificate_challenge.get_data_length()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: received ASUE-challenge"),
				 asue_challenge->get_type_data(asue_challenge->get_type_data_length()),
				 asue_challenge->get_type_data_length()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Save AE challenge.

		wai_variable_data_c * const ae_challenge = asue_challenge->get_next_payload_with_same_tlv_type();
		if (ae_challenge == 0
			|| ae_challenge->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		status = m_ae_certificate_challenge.set_copy_of_buffer(ae_challenge->get_data(WAPI_CHALLENGE_LENGTH), WAPI_CHALLENGE_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	wai_variable_data_c * ae_signature_trusted_by_asue = 0;

	if (m_do_certificate_validation == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::handle_access_authentication_response(): does certificate validation\n"),
			this,
			(m_is_client == true ? "client": "server")));

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Save result of certificate_verification.

		{
			wai_variable_data_c * const result_of_certificate_verification = parser.get_tlv_pointer(wai_payload_type_result_of_certificate_verification);
			if (result_of_certificate_verification == 0
				|| result_of_certificate_verification->get_is_valid_data() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			status = m_result_of_certificate_verification.set_copy_of_buffer(result_of_certificate_verification);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			{
				eap_variable_data_c ae_challenge(m_am_tools);
				eap_variable_data_c asue_challenge(m_am_tools);
				eap_variable_data_c asue_certificate(m_am_tools);

				wapi_certificate_result_e asue_certificate_result(wapi_certificate_result_none);
				wapi_certificate_result_e ae_certificate_result(wapi_certificate_result_none);

				status = parse_result_of_certificate_verification(
					&m_result_of_certificate_verification,
					&ae_challenge,
					&asue_challenge,
					&asue_certificate_result,
					&asue_certificate,
					&ae_certificate_result,
					&m_ae_certificate);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				// Verify AE-Challenge.
				if (m_ae_certificate_challenge.compare(&ae_challenge) != 0)
				{
					EAP_TRACE_DATA_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("ERROR: local m_ae_certificate_challenge"),
						 m_ae_certificate_challenge.get_data(),
						 m_ae_certificate_challenge.get_data_length()));

					EAP_TRACE_DATA_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("ERROR: received AE-challenge"),
						 ae_challenge.get_data(),
						 ae_challenge.get_data_length()));

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
				}

				// Verify ASUE-Challenge.
				if (m_asue_certificate_challenge.compare(&asue_challenge) != 0)
				{
					EAP_TRACE_DATA_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("ERROR: local m_asue_certificate_challenge"),
						 m_asue_certificate_challenge.get_data(),
						 m_asue_certificate_challenge.get_data_length()));

					EAP_TRACE_DATA_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("ERROR: received ASUE-challenge"),
						 asue_challenge.get_data(),
						 asue_challenge.get_data_length()));

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
				}

				// Verify ASUE-Certificate.
				if (m_own_certificate.compare(&asue_certificate) != 0)
				{
					EAP_TRACE_DATA_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("ERROR: local m_own_certificate"),
						 m_own_certificate.get_data(),
						 m_own_certificate.get_data_length()));

					EAP_TRACE_DATA_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("ERROR: received ASUE-Certificate"),
						 asue_certificate.get_data(),
						 asue_certificate.get_data_length()));

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
				}

				if (asue_certificate_result != wapi_certificate_result_valid)
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: WAPI_Core: this = 0x%08x, %s: wapi_core_c::handle_access_authentication_response(): asue_certificate_result=%d\n"),
						this,
						(m_is_client == true ? "client": "server"),
						asue_certificate_result));

					switch (asue_certificate_result)
					{
					case wapi_certificate_result_issuer_is_unknown:
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_unknown_ca);
					case wapi_certificate_result_certificate_is_based_on_an_untrusted_root:
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_unknown_ca);
					case wapi_certificate_result_certificate_is_not_time_valid:
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_certificate_expired);
					case wapi_certificate_result_certificate_have_not_a_valid_signature:
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_certificate);
					case wapi_certificate_result_certificate_is_revoked:
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_certificate_revoked);
					case wapi_certificate_result_certificate_is_not_valid_for_proposed_usage:
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_certificate);
					case wapi_certificate_result_revocation_state_of_the_certificate_is_unknown:
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_certificate);
					default:
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
					}
				}

				if (ae_certificate_result != wapi_certificate_result_valid)
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: WAPI_Core: this = 0x%08x, %s: wapi_core_c::handle_access_authentication_response(): ae_certificate_result=%d\n"),
						this,
						(m_is_client == true ? "client": "server"),
						ae_certificate_result));

					switch (ae_certificate_result)
					{
					case wapi_certificate_result_issuer_is_unknown:
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_unknown_ca);
					case wapi_certificate_result_certificate_is_based_on_an_untrusted_root:
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_unknown_ca);
					case wapi_certificate_result_certificate_is_not_time_valid:
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_certificate_expired);
					case wapi_certificate_result_certificate_have_not_a_valid_signature:
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_certificate);
					case wapi_certificate_result_certificate_is_revoked:
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_certificate_revoked);
					case wapi_certificate_result_certificate_is_not_valid_for_proposed_usage:
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_certificate);
					case wapi_certificate_result_revocation_state_of_the_certificate_is_unknown:
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_certificate);
					default:
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
					}
				}
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Save server signature trusted by ASUE.

		{
			wai_variable_data_c * const server_signature_trusted_by_asue = parser.get_tlv_pointer(wai_payload_type_signature_attributes);
			if (server_signature_trusted_by_asue == 0
				|| server_signature_trusted_by_asue->get_is_valid_data() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			status = m_server_signature_trusted_by_asue.set_copy_of_buffer(server_signature_trusted_by_asue);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
			// Save server signature trusted by AE.
			// NOTE: This is used only when server trusted by ASUE is different than server trusted by AE.

			wai_variable_data_c * const server_signature_trusted_by_ae = server_signature_trusted_by_asue->get_next_payload_with_same_tlv_type();
			if (server_signature_trusted_by_ae == 0
				|| server_signature_trusted_by_ae->get_is_valid_data() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
			// Save Signature of AE. This is always the last signature.

			ae_signature_trusted_by_asue = server_signature_trusted_by_ae->get_next_payload_with_same_tlv_type();

			if ((ae_signature_trusted_by_asue == 0
				|| ae_signature_trusted_by_asue->get_is_valid_data() == false))
			{
				// Server trusted by AE is the same as server trusted by ASUE.
				status = m_server_signature_trusted_by_ae.set_copy_of_buffer(server_signature_trusted_by_asue);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				// Signature of AE is always the last signature.
				ae_signature_trusted_by_asue = server_signature_trusted_by_ae;
			}
			else
			{
				// Server trusted by AE is different than server trusted by ASUE.
				status = m_server_signature_trusted_by_ae.set_copy_of_buffer(server_signature_trusted_by_ae);
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
			(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::handle_access_authentication_response(): no certificate validation\n"),
			this,
			(m_is_client == true ? "client": "server")));

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Save Signature of AE.

		ae_signature_trusted_by_asue = parser.get_tlv_pointer(wai_payload_type_signature_attributes);
		if (ae_signature_trusted_by_asue == 0
			|| ae_signature_trusted_by_asue->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		wai_variable_data_c * ae_key_data = 0;

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Compare ASUE key data.
		{
			wai_variable_data_c * const asue_key_data = parser.get_tlv_pointer(wai_payload_type_key_data);
			if (asue_key_data == 0
				|| asue_key_data->get_is_valid_data() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			u32_t offset(0ul);

			const u8_t * const point_type = asue_key_data->get_type_data_offset(offset, sizeof(u8_t));
			if (point_type == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			if (*point_type != WAI_EC_POINT_TYPE_NO_COMPRESSION_ID)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			offset += sizeof(*point_type);

			const u32_t x_key_element_length((1ul + asue_key_data->get_type_data_length() - sizeof(*point_type)) / 2ul);
			const u32_t y_key_element_length(asue_key_data->get_type_data_length() - sizeof(*point_type) - x_key_element_length);

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: this = 0x%08x, %s: sizeof(*point_type)=%d, *point_type=0x%02x, get_type_data_length()=%d, x_key_element_length=%d, y_key_element_length=%d\n"),
				 this,
				 (m_is_client == true ? "client": "server"),
				 sizeof(*point_type),
				 *point_type,
				 asue_key_data->get_type_data_length(),
				 x_key_element_length,
				 y_key_element_length));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("m_own_public_key_x"),
				 m_own_public_key_x.get_data(),
				 m_own_public_key_x.get_data_length()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("received public_key_x"),
				 asue_key_data->get_type_data_offset(offset, x_key_element_length),
				 x_key_element_length));

			if (m_own_public_key_x.compare(
				asue_key_data->get_type_data_offset(offset, x_key_element_length),
				x_key_element_length) != 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			offset += x_key_element_length;

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("m_own_public_key_y"),
				 m_own_public_key_y.get_data(),
				 m_own_public_key_y.get_data_length()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("received public_key_y"),
				 asue_key_data->get_type_data_offset(offset, y_key_element_length),
				 y_key_element_length));

			if (m_own_public_key_y.compare(
				asue_key_data->get_type_data_offset(offset, y_key_element_length),
				y_key_element_length) != 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			ae_key_data = asue_key_data->get_next_payload_with_same_tlv_type();
			if (asue_key_data == 0
				|| asue_key_data->get_is_valid_data() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Save AE key data.
		{
			u32_t offset(0ul);

			const u8_t * const point_type = ae_key_data->get_type_data_offset(offset, sizeof(u8_t));
			if (point_type == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			if (*point_type != WAI_EC_POINT_TYPE_NO_COMPRESSION_ID)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			offset += sizeof(*point_type);

			const u32_t x_key_element_length((1ul + ae_key_data->get_type_data_length() - sizeof(*point_type)) / 2ul);
			const u32_t y_key_element_length(ae_key_data->get_type_data_length() - sizeof(*point_type) - x_key_element_length);

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: this = 0x%08x, %s: sizeof(*point_type)=%d, *point_type=0x%02x, get_type_data_length()=%d, x_key_element_length=%d, y_key_element_length=%d\n"),
				 this,
				 (m_is_client == true ? "client": "server"),
				 sizeof(*point_type),
				 *point_type,
				 ae_key_data->get_type_data_length(),
				 x_key_element_length,
				 y_key_element_length));

			status = m_peer_public_key_x.set_copy_of_buffer(
				ae_key_data->get_type_data_offset(offset, x_key_element_length),
				x_key_element_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("m_peer_public_key_x"),
				 m_peer_public_key_x.get_data(),
				 m_peer_public_key_x.get_data_length()));

			offset += x_key_element_length;

			status = m_peer_public_key_y.set_copy_of_buffer(
				ae_key_data->get_type_data_offset(offset, y_key_element_length),
				y_key_element_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("m_peer_public_key_y"),
				 m_peer_public_key_y.get_data(),
				 m_peer_public_key_y.get_data_length()));
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify Signature of AE.

	{
		if (ae_signature_trusted_by_asue == 0
			|| ae_signature_trusted_by_asue->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		eap_variable_data_c signature_data(m_am_tools);
		if (signature_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_variable_data_c received_ae_id(m_am_tools);
		if (received_ae_id.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = parse_signature_attributes(
			ae_signature_trusted_by_asue,
			&received_ae_id,
			&signature_data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("received_ae_id"),
			 received_ae_id.get_data(),
			 received_ae_id.get_data_length()));

		if (received_ae_id.compare(&m_ae_id) != 0)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: local m_ae_id"),
				 m_ae_id.get_data(),
				 m_ae_id.get_data_length()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: received AE-ID"),
				 received_ae_id.get_data(received_ae_id.get_data_length()),
				 received_ae_id.get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		eap_variable_data_c HASH(m_am_tools);
		if (HASH.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		{
			wai_message_payloads_c * const signature_payload = new wai_message_payloads_c(m_am_tools, m_is_client);
			eap_automatic_variable_c<wai_message_payloads_c> automatic_signature_payload(m_am_tools, signature_payload);

			if (signature_payload == 0
				|| signature_payload->get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			// Copy all payloads except the last signature.
			for (u32_t index = 0ul; (index+1ul) < parser.get_tlv_count(); ++index)
			{
				const wai_variable_data_c * const payload = parser.get_tlv(index);

				if (payload != 0)
				{
					status = signature_payload->insert_payload(payload);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}

			status = create_HASH(signature_payload, true, &HASH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		status = m_ec_certificate_store->set_ae_certificate(
			&m_ae_certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_ec_certificate_store->verify_signature_with_public_key(
			&m_ae_id,
			&HASH,
			&signature_data,
			true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_WAPI_CORE_SERVER)

eap_status_e wapi_core_c::handle_access_authentication_request(
	const eap_am_network_id_c * const receive_network_id,
	const wai_protocol_packet_header_c * const wai)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::handle_access_authentication_request(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::handle_access_authentication_request()");

	if (m_authentication_type != eapol_key_authentication_type_WAI_certificate)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_authentication_type);
	}

	if (m_wapi_state != wapi_core_state_wait_access_authentication_request_message
		&& m_wapi_state != wapi_core_state_wait_unicast_key_negotiation_response_message
		&& m_wapi_state != wapi_core_state_authentication_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::handle_access_authentication_request(): Verify state %s != %s, negotiation state = %s.\n"),
			(m_is_client == true) ? "client": "server",
			wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
			wapi_strings_c::get_wapi_core_state_string(wapi_core_state_wait_multicast_announcement_message),
			wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	eap_status_e status(eap_status_process_general_error);

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (wai == 0
		|| wai->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	status = wai->check_header();

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (wai->get_packet_sequence_number() != m_packet_sequence_number)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::handle_access_authentication_request(): sequence number %d != required sequence number %d.\n"),
			(m_is_client == true) ? "client": "server",
			wai->get_packet_sequence_number(),
			m_packet_sequence_number));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	set_wapi_state(wapi_core_state_process_access_authentication_request_message);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	wai_message_payloads_c parser(
		m_am_tools,
		m_is_client);
	if (parser.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t padding_length(0ul);

	status = parser.parse_wai_payloads(
		wai->get_header_buffer(wai->get_header_buffer_length()), ///< This is the start of the message buffer.
		wai->get_header_buffer_length(), ///< This is the length of the buffer. This must match with the length of all payloads.
		&padding_length ///< Length of possible padding is set to this variable.
		);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify BK rekeying flag.

	{
		wai_variable_data_c * const flag_payload = parser.get_tlv_pointer(wai_payload_type_flag);
		if (flag_payload == 0
			|| flag_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u8_t * const flag = flag_payload->get_data(sizeof(*flag));
		if (flag == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		m_do_certificate_validation = false;

		if (m_wapi_negotiation_state == wapi_negotiation_state_rekeying)
		{
			if (((*flag) & wai_data_flag_mask_BK_Rekeying) == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			if (((*flag) & wai_data_flag_mask_Certificate_Validation_Request) != 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::handle_access_authentication_request(): no certificate validation\n"),
				this,
				(m_is_client == true ? "client": "server")));
		}
		else
		{
			if (((*flag) & wai_data_flag_mask_BK_Rekeying) != 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			if (((*flag) & wai_data_flag_mask_Certificate_Validation_Request) == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::handle_access_authentication_request(): does certificate validation\n"),
				this,
				(m_is_client == true ? "client": "server")));

			m_do_certificate_validation = true;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify the Authentication identifier parameter.

	{
		wai_variable_data_c * const authentication_identifier = parser.get_tlv_pointer(wai_payload_type_authentication_identifier);
		if (authentication_identifier == 0
			|| authentication_identifier->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (authentication_identifier->get_type_data_length() != m_authentication_identifier.get_data_length()
			|| m_am_tools->memcmp(
				m_authentication_identifier.get_data(),
				authentication_identifier->get_type_data(authentication_identifier->get_type_data_length()),
				authentication_identifier->get_type_data_length()) != 0)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: local m_authentication_identifier"),
				 m_authentication_identifier.get_data(),
				 m_authentication_identifier.get_data_length()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: received Authentication identifier"),
				 authentication_identifier->get_type_data(authentication_identifier->get_type_data_length()),
				 authentication_identifier->get_type_data_length()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify the ECDH parameter.

	{
		wai_variable_data_c * const echd_parameter = parser.get_tlv_pointer(wai_payload_type_echd_parameter);
		if (echd_parameter == 0
			|| echd_parameter->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (sizeof(WAPI_ECDH_OID_PARAMETER) != echd_parameter->get_type_data_length()
			|| m_am_tools->memcmp(
				WAPI_ECDH_OID_PARAMETER,
				echd_parameter->get_type_data(sizeof(WAPI_ECDH_OID_PARAMETER)),
				sizeof(WAPI_ECDH_OID_PARAMETER)) != 0)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: local ECDH parameter"),
				 WAPI_ECDH_OID_PARAMETER,
				 sizeof(WAPI_ECDH_OID_PARAMETER)));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: received ECDH parameter"),
				 echd_parameter->get_type_data(echd_parameter->get_type_data_length()),
				 echd_parameter->get_type_data_length()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify the ID of STA_AE parameter.

	{
		wai_variable_data_c * const ae_id = parser.get_tlv_pointer(wai_payload_type_identity);
		if (ae_id == 0
			|| ae_id->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (m_ae_id.get_data_length() != ae_id->get_type_data_length()
			|| m_am_tools->memcmp(
				ae_id->get_type_data(m_ae_id.get_data_length()),
				m_ae_id.get_data(),
				m_ae_id.get_data_length()) != 0)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: local m_ae_id"),
				 m_ae_id.get_data(),
				 m_ae_id.get_data_length()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: received AE-ID"),
				 ae_id->get_type_data(ae_id->get_type_data_length()),
				 ae_id->get_type_data_length()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
		else
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("m_ae_id"),
				 m_ae_id.get_data(),
				 m_ae_id.get_data_length()));
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Save ASUE challenge.

	{
		wai_variable_data_c * const asue_challenge = parser.get_tlv_pointer(wai_payload_type_nonce);
		if (asue_challenge == 0
			|| asue_challenge->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		status = m_asue_certificate_challenge.set_copy_of_buffer(
			asue_challenge->get_type_data(asue_challenge->get_type_data_length()),
			asue_challenge->get_type_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Save ASUE key data.

	{
		wai_variable_data_c * const asue_key_data = parser.get_tlv_pointer(wai_payload_type_key_data);
		if (asue_key_data == 0
			|| asue_key_data->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		u32_t offset(0ul);

		const u8_t * const point_type = asue_key_data->get_type_data_offset(offset, sizeof(u8_t));
		if (point_type == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (*point_type != WAI_EC_POINT_TYPE_NO_COMPRESSION_ID)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		offset += sizeof(*point_type);

		const u32_t x_key_element_length((1ul + asue_key_data->get_type_data_length() - sizeof(*point_type)) / 2ul);
		const u32_t y_key_element_length(asue_key_data->get_type_data_length() - sizeof(*point_type) - x_key_element_length);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WAPI_Core: this = 0x%08x, %s: sizeof(*point_type)=%d, *point_type=0x%02x, get_type_data_length()=%d, x_key_element_length=%d, y_key_element_length=%d\n"),
			 this,
			 (m_is_client == true ? "client": "server"),
			 sizeof(*point_type),
			 *point_type,
			 asue_key_data->get_type_data_length(),
			 x_key_element_length,
			 y_key_element_length));

		status = m_peer_public_key_x.set_copy_of_buffer(
			asue_key_data->get_type_data_offset(offset, x_key_element_length),
			x_key_element_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("m_peer_public_key_x"),
			 m_peer_public_key_x.get_data(),
			 m_peer_public_key_x.get_data_length()));

		offset += x_key_element_length;

		status = m_peer_public_key_y.set_copy_of_buffer(
			asue_key_data->get_type_data_offset(offset, y_key_element_length),
			y_key_element_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("m_peer_public_key_y"),
			 m_peer_public_key_y.get_data(),
			 m_peer_public_key_y.get_data_length()));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Save STA_ASUE certificate.

	{
		wai_variable_data_c * const sta_asue_certificate = parser.get_tlv_pointer(wai_payload_type_certificate);
		if (sta_asue_certificate == 0
			|| sta_asue_certificate->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		status = m_peer_certificate.set_copy_of_buffer(
			sta_asue_certificate->get_type_data(sta_asue_certificate->get_type_data_length()),
			sta_asue_certificate->get_type_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify Signature of ASUE.

	{
		wai_variable_data_c * const signature_payload = parser.get_tlv_pointer(wai_payload_type_signature_attributes);
		if (signature_payload == 0
			|| signature_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		eap_variable_data_c signature_data(m_am_tools);
		if (signature_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = parse_signature_attributes(
			signature_payload,
			&m_asue_id,
			&signature_data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("m_asue_id"),
			 m_asue_id.get_data(),
			 m_asue_id.get_data_length()));

		eap_variable_data_c HASH(m_am_tools);
		if (HASH.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = create_HASH(&parser, false, &HASH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_ec_certificate_store->verify_signature_with_public_key(
			&m_asue_id,
			&HASH,
			&signature_data,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_WAPI_CORE_SERVER)

//--------------------------------------------------

eap_status_e wapi_core_c::handle_unicast_key_negotiation_request(
	const eap_am_network_id_c * const receive_network_id,
	const wai_protocol_packet_header_c * const wai)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::handle_unicast_key_negotiation_request(): state=%s, negotiation state = %s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
		 wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::handle_unicast_key_negotiation_request()");

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_wapi_state != wapi_core_state_wait_unicast_key_negotiation_request_message
		&& m_wapi_state != wapi_core_state_wait_unicast_key_negotiation_confirmation_message
		&& m_wapi_state != wapi_core_state_authentication_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::handle_unicast_key_negotiation_request(): Verify state %s != %s, negotiation state = %s.\n"),
			(m_is_client == true) ? "client": "server",
			wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
			wapi_strings_c::get_wapi_core_state_string(wapi_core_state_wait_unicast_key_negotiation_request_message),
			wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	if (m_authentication_type != eapol_key_authentication_type_WAI_PSK
		&& m_authentication_type != eapol_key_authentication_type_WAI_certificate)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_authentication_type);
	}

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (wai == 0
		|| wai->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	status = wai->check_header();

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (wai->get_packet_sequence_number() != (m_packet_sequence_number + 1u))
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::handle_unicast_key_negotiation_request(): sequence number %d != required sequence number %d.\n"),
			(m_is_client == true) ? "client": "server",
			wai->get_packet_sequence_number(),
			(m_packet_sequence_number + 1u)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	++m_packet_sequence_number;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_authentication_type == eapol_key_authentication_type_WAI_PSK)
	{
		// Here we swap the addresses.
		eap_am_network_id_c send_network_id(m_am_tools,
			m_receive_network_id.get_destination_id(),
			m_receive_network_id.get_source_id(),
			m_receive_network_id.get_type());

		if (send_network_id.get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// This is notification to eapol_core_c object.
		// WAI unicast negotiation started successfully.
		eap_state_notification_c * notification = new eap_state_notification_c(
			m_am_tools,
			&send_network_id,
			m_is_client,
			eap_state_notification_generic,
			eap_protocol_layer_wai,
			eapol_key_handshake_type_wai_handshake,
			eapol_key_state_wapi_authentication_running,
			eapol_key_state_wapi_authentication_running,
			0ul,
			false);
		if (notification == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
		m_partner->state_notification(notification);

		delete notification;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = create_BKID(&m_BKID, receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	wai_message_payloads_c parser(
		m_am_tools,
		m_is_client);
	if (parser.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t padding_length(0ul);

	status = parser.parse_wai_payloads(
		wai->get_header_buffer(wai->get_header_buffer_length()), ///< This is the start of the message buffer.
		wai->get_header_buffer_length(), ///< This is the length of the buffer. This must match with the length of all payloads.
		&padding_length ///< Length of possible padding is set to this variable.
		);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify BKID.

	{
		wai_variable_data_c * const BKID_payload = parser.get_tlv_pointer(wai_payload_type_bkid);
		if (BKID_payload == 0
			|| BKID_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (m_BKID.compare(
			BKID_payload->get_data(BKID_payload->get_data_length()),
			BKID_payload->get_data_length()) != 0)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: local m_BKID"),
				 m_BKID.get_data(),
				 m_BKID.get_data_length()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: received BKID"),
				 BKID_payload->get_data(BKID_payload->get_data_length()),
				 BKID_payload->get_data_length()));

#if defined(WAPI_SKIP_BKID_TEST)
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: WAPI_Core: this = 0x%08x, %s: wapi_core_c::handle_unicast_key_negotiation_request(): Skips BKID test.\n"),
				 this,
				 (m_is_client == true ? "client": "server")));
#else
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
#endif //#if !defined(WAPI_SKIP_BKID_TEST)

		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify USK rekeying flag.

	{
		wai_variable_data_c * const flag_payload = parser.get_tlv_pointer(wai_payload_type_flag);
		if (flag_payload == 0
			|| flag_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u8_t * const flag = flag_payload->get_data(sizeof(*flag));
		if (flag == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (m_wapi_negotiation_state == wapi_negotiation_state_rekeying)
		{
			if (((*flag) & wai_data_flag_mask_USK_Rekeying) == 0)
			{
				m_wapi_negotiation_state = wapi_negotiation_state_initial_negotiation;

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("WARNING: WAPI_Core: this = 0x%08x, %s: wapi_core_c::handle_unicast_key_negotiation_request(): change to %s.\n"),
					 this,
					 (m_is_client == true ? "client": "server"),
					 wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));
			}
		}
		else
		{
			if (((*flag) & wai_data_flag_mask_USK_Rekeying) != 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify USKID.

	{
		wai_variable_data_c * const USKID_payload = parser.get_tlv_pointer(wai_payload_type_uskid);
		if (USKID_payload == 0
			|| USKID_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u8_t * const USKID_pointer = USKID_payload->get_data(sizeof(*USKID_pointer));
		if (USKID_pointer == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		u8_t USKID = (*USKID_pointer) & wai_data_uskid_mask_uskid;

		if (USKID >= WAPI_USKSA_COUNT
			|| m_USKSA[USKID] == 0
			|| m_USKSA[USKID]->get_is_valid_data() == true)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		m_USKID = USKID;

		m_USKSA[USKID]->set_USKID(m_USKID);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Save AE challenge.

	{
		wai_variable_data_c * const ae_challenge = parser.get_tlv_pointer(wai_payload_type_nonce);
		if (ae_challenge == 0
			|| ae_challenge->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (m_wapi_negotiation_state == wapi_negotiation_state_rekeying)
		{
			// Verify the AE challenge.
			if (m_am_tools->memcmp(m_next_unicast_challenge.get_data(WAPI_CHALLENGE_LENGTH), ae_challenge->get_data(WAPI_CHALLENGE_LENGTH), WAPI_CHALLENGE_LENGTH) != 0)
			{
				EAP_TRACE_DATA_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("ERROR: local m_next_unicast_challenge"),
					 m_next_unicast_challenge.get_data(),
					 m_next_unicast_challenge.get_data_length()));

				EAP_TRACE_DATA_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("ERROR: received AE Challenge"),
					 ae_challenge->get_data(WAPI_CHALLENGE_LENGTH),
					 WAPI_CHALLENGE_LENGTH));

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}
		}

		status = m_ae_unicast_challenge.set_copy_of_buffer(ae_challenge->get_data(WAPI_CHALLENGE_LENGTH), WAPI_CHALLENGE_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Create ASUE challenge.

	{
		crypto_random_c rand(m_am_tools);
		if (rand.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = rand.get_rand_bytes(
			&m_asue_unicast_challenge,
			WAPI_CHALLENGE_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Create unicast session key.

	status = create_unicast_key(
		&m_BK,
		receive_network_id,
		&m_ae_unicast_challenge,
		&m_asue_unicast_challenge,
		&m_unicast_encryption_key_UEK,
		&m_unicast_integrity_check_key_UCK,
		&m_message_authentication_key_MAK,
		&m_key_encryption_key_KEK,
		&m_next_unicast_challenge);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Create the Unicast Key Negotiation Response message.

	wai_message_payloads_c * const payloads = new wai_message_payloads_c(m_am_tools, m_is_client);
	// Automatic variable deletes payloads when control returns from this function.
	eap_automatic_variable_c<wai_message_payloads_c> automatic_payloads(m_am_tools, payloads);

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = payloads->initialise_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->get_wai_protocol_packet_header_writable()->set_subtype(wai_protocol_subtype_unicast_key_negotiation_response);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds FLAG to data field.

	{
		wai_variable_data_c data_flag(m_am_tools);
		if (data_flag.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u8_t flag(wai_data_flag_mask_none);

		if (m_wapi_negotiation_state == wapi_negotiation_state_rekeying)
		{
			flag = wai_data_flag_mask_USK_Rekeying;
		}

		status = data_flag.create(
			wai_payload_type_flag,
			&flag,
			sizeof(flag));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_flag);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds BKID to data field.

	{
		wai_variable_data_c data_BKID(m_am_tools);
		if (data_BKID.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = data_BKID.create(
			wai_payload_type_bkid,
			&m_BKID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_BKID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds USKID to data field.

	{
		wai_variable_data_c data_USKID(m_am_tools);
		if (data_USKID.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = data_USKID.create(
			wai_payload_type_uskid,
			&m_USKID,
			sizeof(m_USKID));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_USKID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds ADDID to data field.

	{
		wai_variable_data_c data_ADDID(m_am_tools);
		if (data_ADDID.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		const eap_variable_data_c * MAC_1 = receive_network_id->get_destination_id();
		const eap_variable_data_c * MAC_2 = receive_network_id->get_source_id();

		if (m_is_client == true)
		{
			MAC_1 = receive_network_id->get_source_id();
			MAC_2 = receive_network_id->get_destination_id();
		}

		status = data_ADDID.create(
			wai_payload_type_addid,
			MAC_1);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = data_ADDID.add_data(
			wai_payload_type_addid,
			MAC_2);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_ADDID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds ASUE Challenge to data field.

	{
		wai_variable_data_c data_ASUE_challenge(m_am_tools);
		if (data_ASUE_challenge.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = data_ASUE_challenge.create(
			wai_payload_type_nonce,
			&m_asue_unicast_challenge);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_ASUE_challenge);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds AE Challenge to data field.

	{
		wai_variable_data_c data_AE_challenge(m_am_tools);
		if (data_AE_challenge.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = data_AE_challenge.create(
			wai_payload_type_nonce,
			&m_ae_unicast_challenge);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_AE_challenge);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds WIE ASUE to data field.

	{
		wai_variable_data_c data_WIE_ASUE(m_am_tools);
		if (data_WIE_ASUE.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_ASSERT_TOOLS(m_am_tools, m_wapi_ie_asue.get_is_valid() == true && m_wapi_ie_asue.get_data_length() > 0ul);

		status = data_WIE_ASUE.create(
			wai_payload_type_wie,
			&m_wapi_ie_asue);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_WIE_ASUE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds MAC to data field.

	{
		wai_variable_data_c data_MAC(m_am_tools);
		if (data_MAC.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_variable_data_c MAC(m_am_tools);
		if (MAC.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = create_MAC(payloads, &MAC);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = MAC.set_data_length(WAPI_MESSAGE_AUTHENTICATION_CODE_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = data_MAC.create(
			wai_payload_type_message_authentication_code,
			&MAC);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_MAC);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Create and send message.

	{
		wai_message_c new_wai_message_data(m_am_tools, m_is_client);
		if (new_wai_message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->create_wai_tlv_message(&new_wai_message_data, false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		//cancel_retransmission();

		status = packet_send(
			&new_wai_message_data,
			payloads->get_wai_protocol_packet_header_writable()->get_subtype());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	set_wapi_state(wapi_core_state_wait_unicast_key_negotiation_confirmation_message);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_WAPI_CORE_SERVER)

eap_status_e wapi_core_c::handle_unicast_key_negotiation_response(
	const eap_am_network_id_c * const receive_network_id,
	const wai_protocol_packet_header_c * const wai)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::handle_unicast_key_negotiation_response(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::handle_unicast_key_negotiation_response()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_wapi_state != wapi_core_state_wait_unicast_key_negotiation_response_message
		&& m_wapi_state != wapi_core_state_wait_multicast_announcement_response_message)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::handle_unicast_key_negotiation_response(): Verify state %s != %s, negotiation state = %s.\n"),
			(m_is_client == true) ? "client": "server",
			wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
			wapi_strings_c::get_wapi_core_state_string(wapi_core_state_wait_unicast_key_negotiation_response_message),
			wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	if (m_authentication_type != eapol_key_authentication_type_WAI_PSK
		&& m_authentication_type != eapol_key_authentication_type_WAI_certificate)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_authentication_type);
	}

	eap_status_e status(eap_status_process_general_error);

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (wai == 0
		|| wai->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	status = wai->check_header();

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (wai->get_packet_sequence_number() != m_packet_sequence_number)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::handle_unicast_key_negotiation_response(): sequence number %d != required sequence number %d.\n"),
			(m_is_client == true) ? "client": "server",
			wai->get_packet_sequence_number(),
			m_packet_sequence_number));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	wai_message_payloads_c parser(
		m_am_tools,
		m_is_client);
	if (parser.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t padding_length(0ul);

	status = parser.parse_wai_payloads(
		wai->get_header_buffer(wai->get_header_buffer_length()), ///< This is the start of the message buffer.
		wai->get_header_buffer_length(), ///< This is the length of the buffer. This must match with the length of all payloads.
		&padding_length ///< Length of possible padding is set to this variable.
		);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify BKID.

	{
		wai_variable_data_c * const BKID_payload = parser.get_tlv_pointer(wai_payload_type_bkid);
		if (BKID_payload == 0
			|| BKID_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (m_BKID.compare(
			BKID_payload->get_data(BKID_payload->get_data_length()),
			BKID_payload->get_data_length()) != 0)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: local m_BKID"),
				 m_BKID.get_data(),
				 m_BKID.get_data_length()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: received BKID"),
				 BKID_payload->get_data(BKID_payload->get_data_length()),
				 BKID_payload->get_data_length()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify USK rekeying flag.

	{
		wai_variable_data_c * const flag_payload = parser.get_tlv_pointer(wai_payload_type_flag);
		if (flag_payload == 0
			|| flag_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u8_t * const flag = flag_payload->get_data(sizeof(*flag));
		if (flag == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (m_wapi_negotiation_state == wapi_negotiation_state_rekeying)
		{
			if (((*flag) & wai_data_flag_mask_USK_Rekeying) == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}
		}
		else
		{
			if (((*flag) & wai_data_flag_mask_USK_Rekeying) != 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify USKID.

	{
		wai_variable_data_c * const USKID_payload = parser.get_tlv_pointer(wai_payload_type_uskid);
		if (USKID_payload == 0
			|| USKID_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u8_t * const USKID_pointer = USKID_payload->get_data(sizeof(*USKID_pointer));
		if (USKID_pointer == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		u8_t USKID = (*USKID_pointer) & wai_data_uskid_mask_uskid;

		if (USKID >= WAPI_USKSA_COUNT
			|| m_USKSA[USKID] == 0
			|| m_USKSA[USKID]->get_is_valid_data() == true)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		m_USKID = USKID;

		m_USKSA[USKID]->set_USKID(m_USKID);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Save ASUE challenge.

	{
		wai_variable_data_c * const asue_challenge = parser.get_tlv_pointer(wai_payload_type_nonce);
		if (asue_challenge == 0
			|| asue_challenge->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		status = m_asue_unicast_challenge.set_copy_of_buffer(asue_challenge->get_data(WAPI_CHALLENGE_LENGTH), WAPI_CHALLENGE_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Verify AE challenge.

		wai_variable_data_c * const ae_challenge = asue_challenge->get_next_payload_with_same_tlv_type();
		if (ae_challenge == 0
			|| ae_challenge->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (m_ae_unicast_challenge.compare(
			ae_challenge->get_data(ae_challenge->get_data_length()),
			ae_challenge->get_data_length()) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify WIE_ASUE.

	if (m_wapi_negotiation_state == wapi_negotiation_state_initial_negotiation)
	{
		wai_variable_data_c * const wie_asue = parser.get_tlv_pointer(wai_payload_type_wie);
		if (wie_asue == 0
			|| wie_asue->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (m_wapi_ie_asue.compare(
			wie_asue->get_data(wie_asue->get_data_length()),
			wie_asue->get_data_length()) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Create unicast session key.

	status = create_unicast_key(
		&m_BK,
		receive_network_id,
		&m_ae_unicast_challenge,
		&m_asue_unicast_challenge,
		&m_unicast_encryption_key_UEK,
		&m_unicast_integrity_check_key_UCK,
		&m_message_authentication_key_MAK,
		&m_key_encryption_key_KEK,
		&m_next_unicast_challenge);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify MAC.

	{
		wai_variable_data_c * const received_MAC = parser.get_tlv_pointer(wai_payload_type_message_authentication_code);
		if (received_MAC == 0
			|| received_MAC->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		eap_variable_data_c local_MAC(m_am_tools);
		if (local_MAC.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = create_MAC(&parser, &local_MAC);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = local_MAC.set_data_length(WAPI_MESSAGE_AUTHENTICATION_CODE_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (local_MAC.compare(
			received_MAC->get_data(received_MAC->get_data_length()),
			received_MAC->get_data_length()) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WAI: %s: wapi_core_c::handle_unicast_key_negotiation_response(): MAC OK.\n"),
				(m_is_client == true) ? "client": "server"));
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Create the Unicast Key Negotiation Confirmation message.

	wai_message_payloads_c * const payloads = new wai_message_payloads_c(m_am_tools, m_is_client);
	eap_automatic_variable_c<wai_message_payloads_c> automatic_payloads(m_am_tools, payloads);

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = payloads->initialise_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->get_wai_protocol_packet_header_writable()->set_subtype(wai_protocol_subtype_unicast_key_negotiation_confirmation);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds FLAG to data field.

	{
		wai_variable_data_c data_flag(m_am_tools);
		if (data_flag.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u8_t flag(wai_data_flag_mask_none);

		if (m_wapi_negotiation_state == wapi_negotiation_state_rekeying)
		{
			flag = wai_data_flag_mask_USK_Rekeying;
		}

		status = data_flag.create(
			wai_payload_type_flag,
			&flag,
			sizeof(flag));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_flag);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds BKID to data field.

	{
		wai_variable_data_c data_BKID(m_am_tools);
		if (data_BKID.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = data_BKID.create(
			wai_payload_type_bkid,
			&m_BKID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_BKID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds USKID to data field.

	{
		wai_variable_data_c data_USKID(m_am_tools);
		if (data_USKID.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = data_USKID.create(
			wai_payload_type_uskid,
			&m_USKID,
			sizeof(m_USKID));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_USKID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds ADDID to data field.

	{
		wai_variable_data_c data_ADDID(m_am_tools);
		if (data_ADDID.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		const eap_variable_data_c * MAC_1 = receive_network_id->get_source_id();
		const eap_variable_data_c * MAC_2 = receive_network_id->get_destination_id();

		if (m_is_client == true)
		{
			MAC_1 = receive_network_id->get_destination_id();
			MAC_2 = receive_network_id->get_source_id();
		}

		status = data_ADDID.create(
			wai_payload_type_addid,
			MAC_1);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = data_ADDID.add_data(
			wai_payload_type_addid,
			MAC_2);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_ADDID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds ASUE Challenge to data field.

	{
		wai_variable_data_c data_ASUE_challenge(m_am_tools);
		if (data_ASUE_challenge.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = data_ASUE_challenge.create(
			wai_payload_type_nonce,
			&m_asue_unicast_challenge);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_ASUE_challenge);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds WIE AE to data field.

	{
		wai_variable_data_c data_WIE_AE(m_am_tools);
		if (data_WIE_AE.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = data_WIE_AE.create(
			wai_payload_type_wie,
			&m_wapi_ie_ae);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_WIE_AE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds MAC to data field.

	{
		wai_variable_data_c data_MAC(m_am_tools);
		if (data_MAC.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_variable_data_c MAC(m_am_tools);
		if (MAC.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = create_MAC(payloads, &MAC);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = MAC.set_data_length(WAPI_MESSAGE_AUTHENTICATION_CODE_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = data_MAC.create(
			wai_payload_type_message_authentication_code,
			&MAC);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_MAC);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Create and send message.

	wai_message_c new_wai_message_data(m_am_tools, m_is_client);
	if (new_wai_message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->create_wai_tlv_message(&new_wai_message_data, false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	//cancel_retransmission();

	status = packet_send(
		&new_wai_message_data,
		payloads->get_wai_protocol_packet_header_writable()->get_subtype());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Install unicast session key.

	{
		eap_variable_data_c unicast_session_key(m_am_tools);
		if (unicast_session_key.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = unicast_session_key.set_copy_of_buffer(&m_unicast_encryption_key_UEK);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = unicast_session_key.add_data(&m_unicast_integrity_check_key_UCK);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = packet_data_session_key(
			&unicast_session_key,
			eapol_key_type_unicast,
			m_USKID,
			false,
			m_packet_data_number.get_data(),
			m_packet_data_number.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_wapi_state(wapi_core_state_start_multicast_key_announcement);

	status = start_multicast_key_announcement();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_WAPI_CORE_SERVER)

//--------------------------------------------------

eap_status_e wapi_core_c::handle_unicast_key_negotiation_confirmation(
	const eap_am_network_id_c * const receive_network_id,
	const wai_protocol_packet_header_c * const wai)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::handle_unicast_key_negotiation_confirmation(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::handle_unicast_key_negotiation_confirmation()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_wapi_state != wapi_core_state_wait_unicast_key_negotiation_confirmation_message
		&& m_wapi_state != wapi_core_state_wait_multicast_announcement_message)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::handle_unicast_key_negotiation_confirmation(): Verify state %s != %s, negotiation state = %s.\n"),
			(m_is_client == true) ? "client": "server",
			wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
			wapi_strings_c::get_wapi_core_state_string(wapi_core_state_wait_unicast_key_negotiation_confirmation_message),
			wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	if (m_authentication_type != eapol_key_authentication_type_WAI_PSK
		&& m_authentication_type != eapol_key_authentication_type_WAI_certificate)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_authentication_type);
	}

	eap_status_e status(eap_status_process_general_error);

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (wai == 0
		|| wai->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	status = wai->check_header();

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (wai->get_packet_sequence_number() != (m_packet_sequence_number + 1u))
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::handle_unicast_key_negotiation_confirmation(): sequence number %d != required sequence number %d.\n"),
			(m_is_client == true) ? "client": "server",
			wai->get_packet_sequence_number(),
			(m_packet_sequence_number + 1u)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	++m_packet_sequence_number;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	wai_message_payloads_c parser(
		m_am_tools,
		m_is_client);
	if (parser.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t padding_length(0ul);

	status = parser.parse_wai_payloads(
		wai->get_header_buffer(wai->get_header_buffer_length()), ///< This is the start of the message buffer.
		wai->get_header_buffer_length(), ///< This is the length of the buffer. This must match with the length of all payloads.
		&padding_length ///< Length of possible padding is set to this variable.
		);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify BKID.

	{
		wai_variable_data_c * const BKID_payload = parser.get_tlv_pointer(wai_payload_type_bkid);
		if (BKID_payload == 0
			|| BKID_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (m_BKID.compare(
			BKID_payload->get_data(BKID_payload->get_data_length()),
			BKID_payload->get_data_length()) != 0)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: local m_BKID"),
				 m_BKID.get_data(),
				 m_BKID.get_data_length()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: received BKID"),
				 BKID_payload->get_data(BKID_payload->get_data_length()),
				 BKID_payload->get_data_length()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify MAC.

	{
		wai_variable_data_c * const received_MAC = parser.get_tlv_pointer(wai_payload_type_message_authentication_code);
		if (received_MAC == 0
			|| received_MAC->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		eap_variable_data_c local_MAC(m_am_tools);
		if (local_MAC.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = create_MAC(&parser, &local_MAC);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = local_MAC.set_data_length(WAPI_MESSAGE_AUTHENTICATION_CODE_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (local_MAC.compare(
			received_MAC->get_data(received_MAC->get_data_length()),
			received_MAC->get_data_length()) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WAI: %s: wapi_core_c::handle_unicast_key_negotiation_confirmation(): MAC OK.\n"),
				(m_is_client == true) ? "client": "server"));
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify USK rekeying flag.

	{
		wai_variable_data_c * const flag_payload = parser.get_tlv_pointer(wai_payload_type_flag);
		if (flag_payload == 0
			|| flag_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u8_t * const flag = flag_payload->get_data(sizeof(*flag));
		if (flag == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (m_wapi_negotiation_state == wapi_negotiation_state_rekeying)
		{
			if (((*flag) & wai_data_flag_mask_USK_Rekeying) == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}
		}
		else
		{
			if (((*flag) & wai_data_flag_mask_USK_Rekeying) != 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify USKID.

	{
		wai_variable_data_c * const USKID_payload = parser.get_tlv_pointer(wai_payload_type_uskid);
		if (USKID_payload == 0
			|| USKID_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u8_t * const USKID_pointer = USKID_payload->get_data(sizeof(*USKID_pointer));
		if (USKID_pointer == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		u8_t USKID = (*USKID_pointer) & wai_data_uskid_mask_uskid;

		if (USKID >= WAPI_USKSA_COUNT
			|| m_USKSA[USKID] == 0
			|| m_USKSA[USKID]->get_is_valid_data() == true)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		m_USKID = USKID;

		m_USKSA[USKID]->set_USKID(m_USKID);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify ASUE challenge.

	{

		wai_variable_data_c * const asue_challenge = parser.get_tlv_pointer(wai_payload_type_nonce);
		if (asue_challenge == 0
			|| asue_challenge->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (m_asue_unicast_challenge.compare(
			asue_challenge->get_data(asue_challenge->get_data_length()),
			asue_challenge->get_data_length()) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify WIE_AE.

	{
		wai_variable_data_c * const wie_ae = parser.get_tlv_pointer(wai_payload_type_wie);
		if (wie_ae == 0
			|| wie_ae->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (m_wapi_ie_ae.compare(
			wie_ae->get_data(wie_ae->get_data_length()),
			wie_ae->get_data_length()) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Install unicast session key.

	{
		eap_variable_data_c unicast_session_key(m_am_tools);
		if (unicast_session_key.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = unicast_session_key.set_copy_of_buffer(&m_unicast_encryption_key_UEK);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = unicast_session_key.add_data(&m_unicast_integrity_check_key_UCK);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = packet_data_session_key(
			&unicast_session_key,
			eapol_key_type_unicast,
			m_USKID,
			false,
			m_packet_data_number.get_data(),
			m_packet_data_number.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_wapi_negotiation_state == wapi_negotiation_state_initial_negotiation)
	{
	    set_wapi_state(wapi_core_state_wait_multicast_announcement_message);
	}
	else if (m_wapi_negotiation_state == wapi_negotiation_state_rekeying)
	{
        // Here we swap the addresses.
        eap_am_network_id_c send_network_id(m_am_tools,
            m_receive_network_id.get_destination_id(),
            m_receive_network_id.get_source_id(),
            m_receive_network_id.get_type());

        if (send_network_id.get_is_valid_data() == false)
        {
            EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
            return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
        }

        eap_state_notification_c * notification = new eap_state_notification_c(
            m_am_tools,
            &send_network_id,
            m_is_client,
            eap_state_notification_generic,
            eap_protocol_layer_wai,
            eapol_key_handshake_type_wai_handshake,
            eapol_key_state_wapi_authentication_running,
            eapol_key_state_wapi_authentication_finished_successfull,
            0ul,
            false);
        if (notification == 0)
        {
            EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
            return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
        }

        state_notification(notification);

        delete notification;

		set_wapi_state(wapi_core_state_authentication_ok);
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::handle_unicast_key_negotiation_confirmation(): negotiation state = %s.\n"),
			(m_is_client == true) ? "client": "server",
			wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

        EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
        return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e wapi_core_c::handle_multicast_key_announcement(
	const eap_am_network_id_c * const receive_network_id,
	const wai_protocol_packet_header_c * const wai)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::handle_multicast_key_announcement(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::handle_multicast_key_announcement()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_wapi_state != wapi_core_state_wait_multicast_announcement_message
		&& m_wapi_state != wapi_core_state_authentication_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::handle_multicast_key_announcement(): Verify state %s != %s, negotiation state = %s.\n"),
			(m_is_client == true) ? "client": "server",
			wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
			wapi_strings_c::get_wapi_core_state_string(wapi_core_state_wait_multicast_announcement_message),
			wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	if (m_authentication_type != eapol_key_authentication_type_WAI_PSK
		&& m_authentication_type != eapol_key_authentication_type_WAI_certificate)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_authentication_type);
	}

	eap_status_e status(eap_status_process_general_error);

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (wai == 0
		|| wai->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	status = wai->check_header();

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (wai->get_packet_sequence_number() != (m_packet_sequence_number + 1u))
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::handle_multicast_key_announcement(): sequence number %d != required sequence number %d.\n"),
			(m_is_client == true) ? "client": "server",
			wai->get_packet_sequence_number(),
			(m_packet_sequence_number + 1u)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	++m_packet_sequence_number;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	wai_message_payloads_c parser(
		m_am_tools,
		m_is_client);
	if (parser.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t padding_length(0ul);

	status = parser.parse_wai_payloads(
		wai->get_header_buffer(wai->get_header_buffer_length()), ///< This is the start of the message buffer.
		wai->get_header_buffer_length(), ///< This is the length of the buffer. This must match with the length of all payloads.
		&padding_length ///< Length of possible padding is set to this variable.
		);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify MAC.

	{
		wai_variable_data_c * const received_MAC = parser.get_tlv_pointer(wai_payload_type_message_authentication_code);
		if (received_MAC == 0
			|| received_MAC->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		eap_variable_data_c local_MAC(m_am_tools);
		if (local_MAC.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = create_MAC(&parser, &local_MAC);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = local_MAC.set_data_length(WAPI_MESSAGE_AUTHENTICATION_CODE_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (local_MAC.compare(
			received_MAC->get_data(received_MAC->get_data_length()),
			received_MAC->get_data_length()) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WAI: %s: wapi_core_c::handle_multicast_key_announcement(): MAC OK.\n"),
				(m_is_client == true) ? "client": "server"));
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify USK rekeying flag.

	{
		wai_variable_data_c * const flag_payload = parser.get_tlv_pointer(wai_payload_type_flag);
		if (flag_payload == 0
			|| flag_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u8_t * const flag = flag_payload->get_data(sizeof(*flag));
		if (flag == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (((*flag) & wai_data_flag_mask_USK_Rekeying) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify MSKID.

	{
		wai_variable_data_c * const MSKID_payload = parser.get_tlv_pointer(wai_payload_type_mskid_stakeyid);
		if (MSKID_payload == 0
			|| MSKID_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u8_t * const MSKID_pointer = MSKID_payload->get_data(sizeof(*MSKID_pointer));
		if (MSKID_pointer == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		u8_t MSKID = (*MSKID_pointer) & wai_data_uskid_mask_mskid;

		if (MSKID >= WAPI_MSKSA_COUNT
			|| m_MSKSA[MSKID] == 0
			|| m_MSKSA[MSKID]->get_is_valid_data() == true)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		m_MSKID = MSKID;

		m_MSKSA[MSKID]->set_USKID(m_MSKID);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify USKID.

	{
		wai_variable_data_c * const USKID_payload = parser.get_tlv_pointer(wai_payload_type_uskid);
		if (USKID_payload == 0
			|| USKID_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u8_t * const USKID_pointer = USKID_payload->get_data(sizeof(*USKID_pointer));
		if (USKID_pointer == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		u8_t USKID = (*USKID_pointer) & wai_data_uskid_mask_uskid;

		if (USKID >= WAPI_USKSA_COUNT
			|| m_USKSA[USKID] == 0
			|| m_USKSA[USKID]->get_is_valid_data() == true)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		m_USKID = USKID;

		m_USKSA[USKID]->set_USKID(m_USKID);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Read Data Packet Number.

	{

		wai_variable_data_c * const packet_data_number = parser.get_tlv_pointer(wai_payload_type_data_sequence_number);
		if (packet_data_number == 0
			|| packet_data_number->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		status = m_packet_data_number.set_copy_of_buffer(
			packet_data_number->get_data(packet_data_number->get_data_length()),
			packet_data_number->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Read Key Announcement.

	{

		wai_variable_data_c * const key_announcement = parser.get_tlv_pointer(wai_payload_type_key_announcement_identifier);
		if (key_announcement == 0
			|| key_announcement->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		status = m_key_announcement.set_copy_of_buffer(
			key_announcement->get_data(key_announcement->get_data_length()),
			key_announcement->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Read and decrypt Key Data.

		{

			wai_variable_data_c * const key_data = parser.get_tlv_pointer(wai_payload_type_key_data);
			if (key_data == 0
				|| key_data->get_is_valid_data() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			eap_variable_data_c notification_master_key(m_am_tools);
			if (notification_master_key.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = decrypt_multicast_key_data(key_data, &m_key_announcement, &notification_master_key);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = create_multicast_key(&notification_master_key, &m_multicast_key);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Create the Multicast Key announcement response message.

	wai_message_payloads_c * const payloads = new wai_message_payloads_c(m_am_tools, m_is_client);
	eap_automatic_variable_c<wai_message_payloads_c> automatic_payloads(m_am_tools, payloads);

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = payloads->initialise_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->get_wai_protocol_packet_header_writable()->set_subtype(wai_protocol_subtype_multicast_key_announcement_response);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds FLAG to data field.

	{
		wai_variable_data_c data_flag(m_am_tools);
		if (data_flag.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u8_t flag(wai_data_flag_mask_none);

		status = data_flag.create(
			wai_payload_type_flag,
			&flag,
			sizeof(flag));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_flag);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds MSKID to data field.

	{
		wai_variable_data_c data_flag(m_am_tools);
		if (data_flag.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = data_flag.create(
			wai_payload_type_mskid_stakeyid,
			&m_MSKID,
			sizeof(m_MSKID));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_flag);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds USKID to data field.

	{
		wai_variable_data_c data_USKID(m_am_tools);
		if (data_USKID.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = data_USKID.create(
			wai_payload_type_uskid,
			&m_USKID,
			sizeof(m_USKID));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_USKID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds ADDID to data field.

	{
		wai_variable_data_c data_ADDID(m_am_tools);
		if (data_ADDID.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		const eap_variable_data_c * MAC_1 = receive_network_id->get_destination_id();
		const eap_variable_data_c * MAC_2 = receive_network_id->get_source_id();

		if (m_is_client == true)
		{
			MAC_1 = receive_network_id->get_source_id();
			MAC_2 = receive_network_id->get_destination_id();
		}

		status = data_ADDID.create(
			wai_payload_type_addid,
			MAC_1);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = data_ADDID.add_data(
			wai_payload_type_addid,
			MAC_2);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_ADDID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds Key Announcement to data field.

	{
		wai_variable_data_c key_announcement(m_am_tools);
		if (key_announcement.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = key_announcement.create(
			wai_payload_type_data_sequence_number,
			&m_key_announcement);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&key_announcement);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Adds MAC to data field.

	{
		wai_variable_data_c data_MAC(m_am_tools);
		if (data_MAC.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_variable_data_c MAC(m_am_tools);
		if (MAC.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = create_MAC(payloads, &MAC);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = MAC.set_data_length(WAPI_MESSAGE_AUTHENTICATION_CODE_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = data_MAC.create(
			wai_payload_type_message_authentication_code,
			&MAC);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_tlv(&data_MAC);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Create and send message.

	wai_message_c new_wai_message_data(m_am_tools, m_is_client);
	if (new_wai_message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = payloads->create_wai_tlv_message(&new_wai_message_data, false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	//cancel_retransmission();

	status = packet_send(
		&new_wai_message_data,
		payloads->get_wai_protocol_packet_header_writable()->get_subtype());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Install multicast session key.

	status = packet_data_session_key(
		&m_multicast_key,
		eapol_key_type_broadcast,
		m_MSKID,
		false,
		m_packet_data_number.get_data(),
		m_packet_data_number.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
	    m_wapi_negotiation_state = wapi_negotiation_state_rekeying;

		// Here we swap the addresses.
		eap_am_network_id_c send_network_id(m_am_tools,
			m_receive_network_id.get_destination_id(),
			m_receive_network_id.get_source_id(),
			m_receive_network_id.get_type());

		if (send_network_id.get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// This notification to eapol_core_c object.
		// WAPI authentication finished successfully.
		eap_state_notification_c * notification = new eap_state_notification_c(
			m_am_tools,
			&send_network_id,
			m_is_client,
			eap_state_notification_generic,
			eap_protocol_layer_wai,
			eapol_key_handshake_type_wai_handshake,
			eapol_key_state_wapi_authentication_running,
			eapol_key_state_wapi_authentication_finished_successfull,
			0ul,
			false);
		if (notification == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		state_notification(notification);

		delete notification;
	}

	cancel_session_timeout();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_wapi_state(wapi_core_state_authentication_ok);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_WAPI_CORE_SERVER)

eap_status_e wapi_core_c::handle_multicast_key_announcement_response(
	const eap_am_network_id_c * const receive_network_id,
	const wai_protocol_packet_header_c * const wai)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::handle_multicast_key_announcement_response(): state=%s, negotiation state = %s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
		 wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::handle_multicast_key_announcement_response()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_wapi_state != wapi_core_state_wait_multicast_announcement_response_message
		&& m_wapi_state != wapi_core_state_authentication_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::handle_multicast_key_announcement_response(): Verify state %s != %s, negotiation state = %s.\n"),
			(m_is_client == true) ? "client": "server",
			wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
			wapi_strings_c::get_wapi_core_state_string(wapi_core_state_wait_multicast_announcement_response_message),
			wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	if (m_authentication_type != eapol_key_authentication_type_WAI_PSK
		&& m_authentication_type != eapol_key_authentication_type_WAI_certificate)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_authentication_type);
	}

	eap_status_e status(eap_status_process_general_error);

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (wai == 0
		|| wai->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	status = wai->check_header();

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	wai_message_payloads_c parser(
		m_am_tools,
		m_is_client);
	if (parser.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t padding_length(0ul);

	status = parser.parse_wai_payloads(
		wai->get_header_buffer(wai->get_header_buffer_length()), ///< This is the start of the message buffer.
		wai->get_header_buffer_length(), ///< This is the length of the buffer. This must match with the length of all payloads.
		&padding_length ///< Length of possible padding is set to this variable.
		);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify MAC.

	{
		wai_variable_data_c * const received_MAC = parser.get_tlv_pointer(wai_payload_type_message_authentication_code);
		if (received_MAC == 0
			|| received_MAC->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		eap_variable_data_c local_MAC(m_am_tools);
		if (local_MAC.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = create_MAC(&parser, &local_MAC);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = local_MAC.set_data_length(WAPI_MESSAGE_AUTHENTICATION_CODE_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (local_MAC.compare(
			received_MAC->get_data(received_MAC->get_data_length()),
			received_MAC->get_data_length()) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WAI: %s: wapi_core_c::handle_multicast_key_announcement_response(): MAC OK.\n"),
				(m_is_client == true) ? "client": "server"));
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify USK rekeying flag.

	{
		wai_variable_data_c * const flag_payload = parser.get_tlv_pointer(wai_payload_type_flag);
		if (flag_payload == 0
			|| flag_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u8_t * const flag = flag_payload->get_data(sizeof(*flag));
		if (flag == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (((*flag) & wai_data_flag_mask_USK_Rekeying) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify MSKID.

	{
		wai_variable_data_c * const MSKID_payload = parser.get_tlv_pointer(wai_payload_type_mskid_stakeyid);
		if (MSKID_payload == 0
			|| MSKID_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u8_t * const MSKID_pointer = MSKID_payload->get_data(sizeof(*MSKID_pointer));
		if (MSKID_pointer == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		u8_t MSKID = (*MSKID_pointer) & wai_data_uskid_mask_mskid;

		if (MSKID != m_MSKID
			|| m_MSKSA[MSKID] == 0
			|| m_MSKSA[MSKID]->get_is_valid_data() == true)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify USKID.

	{
		wai_variable_data_c * const USKID_payload = parser.get_tlv_pointer(wai_payload_type_uskid);
		if (USKID_payload == 0
			|| USKID_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		const u8_t * const USKID_pointer = USKID_payload->get_data(sizeof(*USKID_pointer));
		if (USKID_pointer == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		u8_t USKID = (*USKID_pointer) & wai_data_uskid_mask_uskid;

		if (USKID >= WAPI_USKSA_COUNT
			|| m_USKSA[USKID] == 0
			|| m_USKSA[USKID]->get_is_valid_data() == true)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Verify Key Announcement.

	{

		wai_variable_data_c * const key_announcement = parser.get_tlv_pointer(wai_payload_type_key_announcement_identifier);
		if (key_announcement == 0
			|| key_announcement->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (m_key_announcement.compare(
			key_announcement->get_data(key_announcement->get_data_length()),
			key_announcement->get_data_length()) != 0)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: local m_key_announcement"),
				 m_key_announcement.get_data(),
				 m_key_announcement.get_data_length()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: received key_announcement"),
				key_announcement->get_data(key_announcement->get_data_length()),
				key_announcement->get_data_length()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Install multicast session key.

	status = packet_data_session_key(
		&m_multicast_key,
		eapol_key_type_broadcast,
		m_MSKID,
		false,
		m_packet_data_number.get_data(),
		m_packet_data_number.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
	    m_wapi_negotiation_state = wapi_negotiation_state_rekeying;

		// Here we swap the addresses.
		eap_am_network_id_c send_network_id(m_am_tools,
			m_receive_network_id.get_destination_id(),
			m_receive_network_id.get_source_id(),
			m_receive_network_id.get_type());

		if (send_network_id.get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// This notification to eapol_core_c object.
		// WAPI authentication finished successfully.
		eap_state_notification_c * notification = new eap_state_notification_c(
			m_am_tools,
			&send_network_id,
			m_is_client,
			eap_state_notification_generic,
			eap_protocol_layer_wai,
			eapol_key_handshake_type_wai_handshake,
			eapol_key_state_wapi_authentication_running,
			eapol_key_state_wapi_authentication_finished_successfull,
			0ul,
			false);
		if (notification == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		state_notification(notification);

		delete notification;
	}

	cancel_session_timeout();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_wapi_state(wapi_core_state_authentication_ok);

	//cancel_retransmission();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_WAPI_CORE_SERVER)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::packet_process(
	const eap_am_network_id_c * const receive_network_id,
	eap_general_header_base_c * const packet_data,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("WAI: %s: wapi_core_c::packet_process(): state = %s, negotiation state = %s.\n"),
		(m_is_client == true) ? "client": "server",
		wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
		wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status(eap_status_process_general_error);


	// This automatic variable stores the current packet sequence number.
	// If the received packet is illegal the current packet sequence number is restored.
	eap_automatic_simple_value_c<u16_t> automatic_packet_sequence_number(
		m_am_tools,
		&m_packet_sequence_number,
		m_packet_sequence_number);

	// This automatic variable stores the current WAPI-state.
	// If the received packet is illegal the current WAPI-state is restored.
	eap_automatic_simple_value_c<wapi_core_state_e> automatic_wapi_state(
		m_am_tools,
		&m_wapi_state,
		m_wapi_state);


	if (m_wapi_state == wapi_core_state_none)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: WAI: %s: wapi_core_c::packet_process(): Verify state %s == %s, negotiation state = %s, drop packet.\n"),
			(m_is_client == true) ? "client": "server",
			wapi_strings_c::get_wapi_core_state_string(m_wapi_state),
			wapi_strings_c::get_wapi_core_state_string(wapi_core_state_none),
			wapi_strings_c::get_wapi_negotiation_state_string(m_wapi_negotiation_state)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	if (packet_data == 0
		|| packet_data->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (packet_length < eap_header_base_c::get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	wai_protocol_packet_header_c wai(
		m_am_tools,
		packet_data->get_header_buffer(packet_length),
		packet_length);

	if (wai.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet_process: %s, packet buffer corrupted.\n"),
			 (m_is_client_role == true) ? "client": "server"
			 ));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA|TRACE_TEST_VECTORS, 
		(EAPL("WAI-packet"),
		 wai.get_header_buffer(packet_length),
		 packet_length));

	WAI_PROTOCOL_PACKET_TRACE_HEADER("wapi_core_c::packet_process(): ->", &wai, m_is_client_role);

	status = wai.check_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (m_shutdown_was_called == true
		&& m_is_client_role == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: WAPI_Core: %s, wapi_core_c::packet_process(): %s packet dropped quietly because shutdown was already called.\n"),
			 (m_is_client_role == true) ? "client": "server",
			 wapi_strings_c::get_wai_protocol_subtype_string(wai.get_subtype())));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	status = packet_reassemble(&wai);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	wai_protocol_packet_header_c reass_wai(
		m_am_tools,
		m_reassemble_packet.get_data(),
		m_reassemble_packet.get_data_length());
		
	if (reass_wai.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("wapi_core_c::packet_process(): %s, packet buffer corrupted.\n"),
			 (m_is_client_role == true) ? "client": "server"
			 ));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}


	if (m_is_client_role == true)
	{
		status = check_retransmission(&reass_wai);

		if (status == eap_status_ok)
		{
			// OK, re-transmitted an old packet.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


		switch(reass_wai.get_subtype())
		{
		case wai_protocol_subtype_authentication_activation:
			status = handle_authentication_activation(receive_network_id, &reass_wai);
			break;
		case wai_protocol_subtype_access_authentication_response:
			status = handle_access_authentication_response(receive_network_id, &reass_wai);
			break;
		case wai_protocol_subtype_unicast_key_negotiation_request:
			status = handle_unicast_key_negotiation_request(receive_network_id, &reass_wai);
			break;
		case wai_protocol_subtype_unicast_key_negotiation_confirmation:
			status = handle_unicast_key_negotiation_confirmation(receive_network_id, &reass_wai);
			break;
		case wai_protocol_subtype_multicast_key_announcement:
			status = handle_multicast_key_announcement(receive_network_id, &reass_wai);
			break;
		default:
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: WAPI_Core: %s, wapi_core_c::packet_process(): Unknown %d=%s packet dropped quietly.\n"),
				 (m_is_client_role == true) ? "client": "server",
				 reass_wai.get_subtype(),
				 wapi_strings_c::get_wai_protocol_subtype_string(reass_wai.get_subtype())));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
		};
	}
#if defined(USE_WAPI_CORE_SERVER)
	else
	{
		switch(reass_wai.get_subtype())
		{
		case wai_protocol_subtype_access_authentication_request:
			status = handle_access_authentication_request(receive_network_id, &reass_wai);
			break;
		case wai_protocol_subtype_unicast_key_negotiation_response:
			status = handle_unicast_key_negotiation_response(receive_network_id, &reass_wai);
			break;
		case wai_protocol_subtype_multicast_key_announcement_response:
			status = handle_multicast_key_announcement_response(receive_network_id, &reass_wai);
			break;
		default:
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: WAPI_Core: %s, wapi_core_c::packet_process(): Unknown %d=%s packet dropped quietly.\n"),
				 (m_is_client_role == true) ? "client": "server",
				 reass_wai.get_subtype(),
				 wapi_strings_c::get_wai_protocol_subtype_string(reass_wai.get_subtype())));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
		};
	}
#endif //#if defined(USE_WAPI_CORE_SERVER)

	if (status == eap_status_ok
		|| status == eap_status_pending_request)
	{
		automatic_packet_sequence_number.do_not_restore_variable();
		automatic_wapi_state.do_not_restore_variable();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_core_c::packet_send(
	const eap_am_network_id_c * const send_network_id,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const u32_t buffer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	wai_protocol_packet_header_c wai(
		m_am_tools,
		sent_packet->get_data_offset(
			header_offset, data_length),
		data_length);

	if (wai.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet_send(): %s, packet buffer corrupted.\n"),
			 (m_is_client_role == true) ? "client": "server"
			 ));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_ASSERT(header_offset < sent_packet->get_data_length());
	EAP_ASSERT(data_length <= sent_packet->get_data_length());
	EAP_ASSERT(sent_packet->get_data_length() <= buffer_length);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA|TRACE_TEST_VECTORS, 
		(EAPL("WAI-packet"),
		 wai.get_header_buffer(data_length),
		 data_length));

	WAI_PROTOCOL_PACKET_TRACE_HEADER("wapi_core_c::packet_send(): <-", &wai, m_is_client_role);

	if (m_shutdown_was_called == true
		&& m_is_client_role == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: WAPI_Core: %s, wapi_core_c::packet_send(): %s packet dropped quietly because shutdown was already called.\n"),
			 (m_is_client_role == true) ? "client": "server",
			 wapi_strings_c::get_wai_protocol_subtype_string(wai.get_subtype())));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	eap_status_e status = m_partner->packet_send(
		send_network_id, sent_packet, header_offset, data_length, buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::resend_packet(
	const eap_am_network_id_c * const send_network_id,
	const wai_message_c * const wai_message_data,
	const u32_t retransmission_counter,
	const u16_t packet_sequence_number)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(retransmission_counter); // Only trace uses this.

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("<- WAPI_Core: %s: wapi_core_c::resend_packet(), counter %d.\n"),
		 (m_is_client_role == true) ? "client": "server",
		 retransmission_counter
		 ));

	// We make a copy because random error test may corrupt the data.
	wai_message_c * const copy_packet = wai_message_data->copy();

	if (copy_packet == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// NOTE: send packet directly to partner object.
	// This will skip initialization of re-transmission for re-transmitted packet.
	eap_status_e status = packet_fragment(
		copy_packet,
		packet_sequence_number);

	delete copy_packet;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::cancel_retransmission()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: WAPI_CORE_TIMER_RETRANSMISSION_ID cancelled.\n"),
			 (m_is_client_role == true ? "client": "server")
			 ));

		if (m_is_client_role == false)
		{
			// Only WAPI-server uses timer to re-transmits WAI-packets.
			m_partner->cancel_timer(this, WAPI_CORE_TIMER_RETRANSMISSION_ID);
		}

		m_retransmission.reset();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::init_retransmission(
	const eap_am_network_id_c * const send_network_id,
	const wai_message_c * const received_wai_message_data,
	const wai_message_c * const new_wai_message_data,
	const u16_t packet_sequence_number,
	const wai_protocol_subtype_e wapi_subtype
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	if (m_is_client_role == false)
	{
		if (m_retransmission_time == 0u
			|| m_retransmission_counter == 0u)
		{
			// No retransmission.
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
	}

	EAP_ASSERT(send_network_id->get_source() != 0);
	EAP_ASSERT(send_network_id->get_destination() != 0);

	wapi_core_retransmission_c * retransmission = new wapi_core_retransmission_c(
		m_am_tools,
		send_network_id,
		received_wai_message_data,
		new_wai_message_data,
		m_retransmission_time,
		m_retransmission_counter,
		packet_sequence_number,
		wapi_subtype);
	if (retransmission == 0
		|| retransmission->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = m_retransmission.add_object_to_begin(
		retransmission,
		true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (m_is_client_role == false)
	{
		// Only WAPI-server uses timer to re-transmits WAI-packets.
		m_partner->cancel_timer(this, WAPI_CORE_TIMER_RETRANSMISSION_ID);

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: WAPI_CORE_TIMER_RETRANSMISSION_ID cancelled.\n"),
			 (m_is_client_role == true ? "client": "server")
			 ));
	}

	retransmission = m_retransmission.get_object(0ul);

	if (retransmission == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (retransmission->get_is_valid() == true)
	{
		if (m_is_client_role == false)
		{
			// Only WAPI-server uses timer to re-transmits WAI-packets.
			u32_t next_retransmission_time = retransmission->get_next_retransmission_time();

			eap_status_e status = m_partner->set_timer(this, WAPI_CORE_TIMER_RETRANSMISSION_ID, 0,
				next_retransmission_time);

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("TIMER: %s: WAPI_CORE_TIMER_RETRANSMISSION_ID set %d ms.\n"),
				 (m_is_client_role == true ? "client": "server"),
				 next_retransmission_time));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
	}
	else
	{
		(void) m_retransmission.remove_object(0ul);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

}

//--------------------------------------------------

eap_status_e wapi_core_c::check_retransmission(const wai_protocol_packet_header_c * const received_wai)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::check_retransmission(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::check_retransmission()");

	EAP_ASSERT(m_is_client == true);

	eap_status_e status(eap_status_process_general_error);

	if (received_wai == 0
		|| received_wai->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	for (u32_t index = 0ul; index < m_retransmission.get_object_count(); ++index)
	{
		const wapi_core_retransmission_c * const retransmission = m_retransmission.get_object(index);
		if (retransmission == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_not_found);
		}

		const wai_message_c * const message = retransmission->get_wai_received_message_data();
		if (message == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_not_found);
		}
		else
		{
			wai_protocol_packet_header_c wai(
				m_am_tools,
				message->get_wai_message_data()->get_data(),
				message->get_wai_message_data()->get_data_length());

			if (wai.get_is_valid() == false)
			{
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("wapi_core_c::packet_fragment(): %s, packet buffer corrupted.\n"),
					 (m_is_client_role == true) ? "client": "server"
					 ));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: wapi_core_c::check_retransmission(): wai.get_version()=%d, received_wai->get_version()=%d\n"),
				 (m_is_client == true ? "client": "server"),
				 wai.get_version(),
				 received_wai->get_version()));

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: wapi_core_c::check_retransmission(): wai.get_type()=%d, received_wai->get_type()=%d\n"),
				 (m_is_client == true ? "client": "server"),
				 wai.get_type(),
				 received_wai->get_type()));

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: wapi_core_c::check_retransmission(): wai.get_subtype()=%d, received_wai->get_subtype()=%d\n"),
				 (m_is_client == true ? "client": "server"),
				 wai.get_subtype(),
				 received_wai->get_subtype()));

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: wapi_core_c::check_retransmission(): wai.get_packet_sequence_number()=%d, received_wai->get_packet_sequence_number()=%d\n"),
				 (m_is_client == true ? "client": "server"),
				 wai.get_packet_sequence_number(),
				 received_wai->get_packet_sequence_number()));

			if (wai.get_version() == received_wai->get_version()
				&& wai.get_type() == received_wai->get_type()
				&& wai.get_subtype() == received_wai->get_subtype()
				&& wai.get_packet_sequence_number() == received_wai->get_packet_sequence_number())
			{
				status = resend_packet(
					retransmission->get_send_network_id(),
					retransmission->get_wai_message_data(),
					retransmission->get_retransmission_counter(),
					retransmission->get_packet_sequence_number());
				if (status == eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		} // for()
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_found);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_core_c::set_wapi_failure_timeout()
{
	eap_status_e status = m_partner->set_timer(
		this,
		WAPI_CORE_FAILURE_RECEIVED_ID,
		0,
		m_wapi_core_failure_received_timeout);
	if (status != eap_status_ok)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: TIMER: %s: WAPI_CORE_FAILURE_RECEIVED_ID failed.\n"),
			 (m_is_client_role == true ? "client": "server")
			 ));
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: WAPI_CORE_FAILURE_RECEIVED_ID set %d ms.\n"),
			 (m_is_client_role == true ? "client": "server"),
			 m_wapi_core_failure_received_timeout
			 ));
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_core_c::cancel_wapi_failure_timeout()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: %s: WAPI_CORE_FAILURE_RECEIVED_ID cancelled.\n"),
		 (m_is_client_role == true ? "client": "server")
		 ));

	return m_partner->cancel_timer(
		this,
		WAPI_CORE_FAILURE_RECEIVED_ID);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u32_t wapi_core_c::get_header_offset(
	u32_t * const MTU,
	u32_t * const trailer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const u32_t offset = m_partner->get_header_offset(MTU, trailer_length);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("wapi_core_c::get_header_offset(): offset=%d, MTU=%d, trailer_length=%d\n"),
		offset,
		*MTU,
		*trailer_length));

	return offset;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_core_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

#if !defined(USE_EAP_DEBUG_TRACE)
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_core_c::configure(): %s\n"),
		 ((m_is_client == true) ? "client": "server")));
#else
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_core_c::configure(): %s: this = 0x%08x => 0x%08x.\n"),
		 ((m_is_client == true) ? "client": "server"),
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));
#endif

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::configure()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(USE_EAP_TEST_VECTORS)

	{
		eap_variable_data_c data(m_am_tools);

		eap_status_e status = m_partner->read_configure(
			cf_str_EAP_TRACE_only_trace_messages.get_field(),
			&data);
		if (status == eap_status_ok
			&& data.get_data_length() == sizeof(u32_t)
			&& data.get_data(data.get_data_length()) != 0)
		{
			if (*(reinterpret_cast<u32_t *>(data.get_data(data.get_data_length()))) != 0u)
			{
				// Activate only WAPI message traces.
				m_am_tools->set_trace_mask(
					eap_am_tools_c::eap_trace_mask_always
					| eap_am_tools_c::eap_trace_mask_eap_messages);
			}
			else
			{
				// Disable only WAPI message traces.
				m_am_tools->set_trace_mask(
					m_am_tools->get_trace_mask() & (~eap_am_tools_c::eap_trace_mask_eap_messages));
			}
		}
		else
		{
			// Disable only WAPI message traces.
			m_am_tools->set_trace_mask(
				m_am_tools->get_trace_mask() & (~eap_am_tools_c::eap_trace_mask_eap_messages));
		}
	}


	{
		eap_variable_data_c data(m_am_tools);

		eap_status_e status = m_partner->read_configure(
			cf_str_EAP_TRACE_only_test_vectors.get_field(),
			&data);
		if (status == eap_status_ok
			&& data.get_data_length() == sizeof(u32_t)
			&& data.get_data(data.get_data_length()) != 0)
		{
			if (*(reinterpret_cast<u32_t *>(data.get_data(data.get_data_length()))) != 0u)
			{
				// Activates only WAPI test vector traces.
				m_am_tools->set_trace_mask(eap_am_tools_c::eap_trace_mask_test_vectors);
			}
		}
	}


	{
		eap_variable_data_c data(m_am_tools);

		eap_status_e status = m_partner->read_configure(
			cf_str_EAP_TRACE_crypto_test_vectors_sha1.get_field(),
			&data);
		if (status == eap_status_ok
			&& data.get_data_length() == sizeof(u32_t)
			&& data.get_data(data.get_data_length()) != 0)
		{
			if (*(reinterpret_cast<u32_t *>(data.get_data(data.get_data_length()))) != 0u)
			{
				// Activates SHA1 WAPI test vector traces.
				m_am_tools->set_trace_mask(m_am_tools->get_trace_mask()
					| eap_am_tools_c::eap_trace_mask_crypto_sha1);
			}
		}
	}


	{
		eap_variable_data_c data(m_am_tools);

		eap_status_e status = m_partner->read_configure(
			cf_str_EAP_TRACE_crypto_test_vectors_rc4.get_field(),
			&data);
		if (status == eap_status_ok
			&& data.get_data_length() == sizeof(u32_t)
			&& data.get_data(data.get_data_length()) != 0)
		{
			if (*(reinterpret_cast<u32_t *>(data.get_data(data.get_data_length()))) != 0u)
			{
				// Activates RC4 WAPI test vector traces.
				m_am_tools->set_trace_mask(m_am_tools->get_trace_mask()
					| eap_am_tools_c::eap_trace_mask_crypto_rc4);
			}
		}
	}


	{
		eap_variable_data_c data(m_am_tools);

		eap_status_e status = m_partner->read_configure(
			cf_str_EAP_TRACE_crypto_test_vectors_md4.get_field(),
			&data);
		if (status == eap_status_ok
			&& data.get_data_length() == sizeof(u32_t)
			&& data.get_data(data.get_data_length()) != 0)
		{
			if (*(reinterpret_cast<u32_t *>(data.get_data(data.get_data_length()))) != 0u)
			{
				// Activates MD4 WAPI test vector traces.
				m_am_tools->set_trace_mask(m_am_tools->get_trace_mask()
					| eap_am_tools_c::eap_trace_mask_crypto_md4);
			}
		}
	}


	{
		eap_variable_data_c data(m_am_tools);

		eap_status_e status = m_partner->read_configure(
			cf_str_EAP_TRACE_crypto_test_vectors_test_random.get_field(),
			&data);
		if (status == eap_status_ok
			&& data.get_data_length() == sizeof(u32_t)
			&& data.get_data(data.get_data_length()) != 0)
		{
			if (*(reinterpret_cast<u32_t *>(data.get_data(data.get_data_length()))) != 0u)
			{
				// Activates test random generator WAPI test vector traces.
				m_am_tools->set_trace_mask(m_am_tools->get_trace_mask()
					| eap_am_tools_c::eap_trace_mask_crypto_test_random
					| eap_am_tools_c::eap_trace_mask_crypto_sha1);
			}
		}
	}

#endif //#if defined(USE_EAP_TEST_VECTORS)

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(USE_WAPI_CORE_SERVER)
	if (m_is_client == false)
	{
		eap_variable_data_c retransmission_time(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_WAPI_CORE_retransmission_time.get_field(),
			&retransmission_time);
		if (status == eap_status_ok
			&& retransmission_time.get_is_valid_data() == true)
		{
			u32_t *retransmission_time_value = reinterpret_cast<u32_t *>(
				retransmission_time.get_data(sizeof(u32_t)));
			if (retransmission_time_value != 0)
			{
				m_retransmission_time = *retransmission_time_value;
			}
			else
			{
				m_retransmission_time = WAPI_CORE_RETRANSMISSION_TIME;
			}
		}
		else
		{
			m_retransmission_time = WAPI_CORE_RETRANSMISSION_TIME;
		}
	}
#endif //#if defined(USE_WAPI_CORE_SERVER)

	{
		eap_variable_data_c retransmission_counter(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_WAPI_CORE_retransmission_counter.get_field(),
			&retransmission_counter);
		if (status == eap_status_ok
			&& retransmission_counter.get_is_valid_data() == true)
		{
			u32_t *retransmission_counter_value = reinterpret_cast<u32_t *>(
				retransmission_counter.get_data(sizeof(u32_t)));
			if (retransmission_counter_value != 0)
			{
				m_retransmission_counter = *retransmission_counter_value;
			}
			else
			{
				m_retransmission_counter = WAPI_CORE_RETRANSMISSION_COUNTER;
			}
		}
		else
		{
			m_retransmission_counter = WAPI_CORE_RETRANSMISSION_COUNTER;
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c session_timeout(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_WAPI_CORE_session_timeout.get_field(),
			&session_timeout);
		if (status == eap_status_ok
			&& session_timeout.get_is_valid_data() == true)
		{
			u32_t *handler_timeout = reinterpret_cast<u32_t *>(
				session_timeout.get_data(sizeof(u32_t)));
			if (handler_timeout != 0)
			{
				m_session_timeout = *handler_timeout;
			}
			else
			{
				m_session_timeout = WAPI_CORE_SESSION_TIMEOUT;
			}
		}
		else
		{
			m_session_timeout = WAPI_CORE_SESSION_TIMEOUT;
		}
	}


#if defined(USE_WAPI_CORE_SERVER)

	if (m_is_client == false)
	{
		eap_variable_data_c session_timeout(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_WAPI_CORE_server_session_timeout.get_field(),
			&session_timeout);
		if (status == eap_status_ok
			&& session_timeout.get_is_valid_data() == true)
		{
			u32_t *handler_timeout = reinterpret_cast<u32_t *>(
				session_timeout.get_data(sizeof(u32_t)));
			if (handler_timeout != 0)
			{
				// This is optional.
				m_session_timeout = *handler_timeout;
			}
		}
	}

	//----------------------------------------------------------

	if (m_is_client == false)
	{
		eap_variable_data_c only_initial_authentication(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_WAPI_CORE_server_only_initial_authentication.get_field(),
			&only_initial_authentication);
		if (status == eap_status_ok
			&& only_initial_authentication.get_is_valid_data() == true)
		{
			u32_t *flag = reinterpret_cast<u32_t *>(
				only_initial_authentication.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_only_initial_authentication = false;
				}
				else
				{
					m_only_initial_authentication = true;
				}
			}
		}
	}

	//----------------------------------------------------------

	if (m_is_client == false)
	{
		eap_status_e status = m_partner->read_configure(
			cf_str_WAPI_CORE_server_test_other_asu_id.get_field(),
			&m_test_other_asu_id);
		if (status == eap_status_ok
			&& m_test_other_asu_id.get_is_valid_data() == true)
		{
			// This is optional for testing purposes.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::configure(): Other ASU ID\n"),
				 this,
				 (m_is_client == true ? "client": "server")));
		}
	}

#endif //#if defined(USE_WAPI_CORE_SERVER)

	//----------------------------------------------------------

	{
		eap_variable_data_c failure_received_timeout(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_WAPI_CORE_failure_received_timeout.get_field(),
			&failure_received_timeout);
		if (status == eap_status_ok
			&& failure_received_timeout.get_is_valid_data() == true)
		{
			u32_t *timeout = reinterpret_cast<u32_t *>(
				failure_received_timeout.get_data(sizeof(u32_t)));
			if (timeout != 0)
			{
				m_wapi_core_failure_received_timeout = *timeout;
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_status_e status = read_configure(
			cf_str_WAPI_CORE_PSK.get_field(),
			&m_preshared_key_PSK);
		if (status == eap_status_ok)
		{
			if (m_preshared_key_PSK.get_data_length() == WAPI_BK_LENGTH)
			{
				status = m_BK.set_copy_of_buffer(&m_preshared_key_PSK);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else
			{
				// Create BK from PSK and label.
				crypto_kd_hmac_sha256_c kd_hmac(m_am_tools);
				if (kd_hmac.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				const eap_variable_data_c label(
					m_am_tools,
					WAPI_PRESHARED_KEY_LABEL,
					WAPI_PRESHARED_KEY_LABEL_LENGTH,
					false,
					false);
				if (label.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = kd_hmac.expand_key(
					&m_BK,
					WAPI_BK_LENGTH,
					&m_preshared_key_PSK,
					&label);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
	}

	//----------------------------------------------------------

	m_wapi_header_offset = m_partner->get_header_offset(&m_MTU, &m_trailer_length);


	// Add session timeout.
	initialize_session_timeout(m_session_timeout);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_core_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status(eap_status_ok);

#if !defined(USE_EAP_DEBUG_TRACE)
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_core_c::shutdown(): %s: m_shutdown_was_called=%d.\n"),
		 ((m_is_client == true) ? "client": "server"),
		 m_shutdown_was_called));
#else
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_core_c::shutdown(): %s: this = 0x%08x => 0x%08x, ")
		 EAPL("m_shutdown_was_called=%d.\n"),
		 ((m_is_client == true) ? "client": "server"),
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this),
		 m_shutdown_was_called));
#endif

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::shutdown()");

	if (m_shutdown_was_called == true)
	{
		// Shutdown was already called once.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_shutdown_was_called = true;

	cancel_retransmission();
	cancel_session_timeout();
	cancel_wapi_failure_timeout();
	cancel_asynchronous_init_remove_wapi_session();

	if (m_partner != 0)
	{
		cancel_session_timeout();
	}

	if (m_ec_certificate_store != 0)
	{
		m_ec_certificate_store->shutdown();
	}

	if (m_am_wapi_core != 0)
	{
		m_am_wapi_core->shutdown();
	}

#if !defined(USE_EAP_DEBUG_TRACE)
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_core_c::shutdown(): %s: m_shutdown_was_called=%d, status=%d returns.\n"),
		 ((m_is_client == true) ? "client": "server"),
		 m_shutdown_was_called,
		 status));
#else
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_core_c::shutdown(): %s: this = 0x%08x => 0x%08x, ")
		 EAPL("m_shutdown_was_called=%d, status=%d returns.\n"),
		 ((m_is_client == true) ? "client": "server"),
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this),
		 m_shutdown_was_called,
		 status));
#endif

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_core_c::restart_authentication(
	const eap_am_network_id_c * const send_network_id,
	const bool is_client_when_true)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	// Here we swap the addresses.
	eap_am_network_id_c receive_network_id(m_am_tools,
		send_network_id->get_destination_id(),
		send_network_id->get_source_id(),
		send_network_id->get_type());

	eap_status_e status = eap_status_process_general_error;

	initialize_session_timeout(m_session_timeout);

	if (is_client_when_true == false)
	{
		status = start_authentication();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_client_restart_authentication_initiated = true;
	}
	else
	{
		if (m_client_restart_authentication_initiated == true)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}

		status = allow_authentication();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_client_restart_authentication_initiated = true;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->read_configure(field, data);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::write_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->write_configure(field, data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_core_c::timer_expired(
	const u32_t id, void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(data); // Only trace uses this.
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: [0x%08x]->wapi_core_c::timer_expired(id 0x%02x, data 0x%08x), %s.\n"),
		 this,
		 id,
		 data,
		 (m_is_client == true) ? "client": "server"));

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status(eap_status_process_general_error);

	if (id == WAPI_CORE_TIMER_RETRANSMISSION_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: WAPI_CORE_TIMER_RETRANSMISSION_ID elapsed.\n"),
			 (m_is_client == true ? "client": "server")
			 ));

		if (m_retransmission.get_object_count() > 0ul)
		{
			wapi_core_retransmission_c * const retransmission = m_retransmission.get_object(0ul);

			if (retransmission != 0
				&& retransmission->get_is_valid() == true
				&& retransmission->get_retransmission_counter() > 0)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("TIMER: %s, new retransmission, retransmission->get_is_valid()=%d, ")
					 EAPL("retransmission->get_retransmission_counter()=%d.\n"),
					 (m_is_client == true) ? "client": "server",
					 retransmission->get_is_valid(),
					 retransmission->get_retransmission_counter()));
				
				status = eap_status_ok;

				if (retransmission->get_wapi_subtype() == wai_protocol_subtype_unicast_key_negotiation_request
					|| retransmission->get_wapi_subtype() == wai_protocol_subtype_multicast_key_announcement)
				{
					// Also the previous message must be re-transmitted.
					if (m_retransmission.get_object_count() > 1ul)
					{
						wapi_core_retransmission_c * const prev_retransmission = m_retransmission.get_object(1ul);
						
						if (prev_retransmission != 0
							&& prev_retransmission->get_is_valid() == true
							&& prev_retransmission->get_retransmission_counter() > 0)
						{
							status = resend_packet(
								prev_retransmission->get_send_network_id(),
								prev_retransmission->get_wai_message_data(),
								prev_retransmission->get_retransmission_counter(),
								prev_retransmission->get_packet_sequence_number());
						}
					}
				}
				
				if (status == eap_status_ok)
				{
					status = resend_packet(
						retransmission->get_send_network_id(),
						retransmission->get_wai_message_data(),
						retransmission->get_retransmission_counter(),
						retransmission->get_packet_sequence_number());
				}
				
				if (status == eap_status_ok)
				{
					if (retransmission->get_retransmission_counter() > 0u)
					{
						// OK, initialize the next time to retransmit.
						u32_t next_retransmission_time
							= retransmission->get_next_retransmission_time();

						status = m_partner->set_timer(
							this,
							WAPI_CORE_TIMER_RETRANSMISSION_ID,
							0,
							next_retransmission_time);
						if (status != eap_status_ok)
						{
							EAP_TRACE_DEBUG(
								m_am_tools, 
								TRACE_FLAGS_DEFAULT, 
								(EAPL("ERROR: TIMER: %s: WAPI_CORE_TIMER_RETRANSMISSION_ID ")
								 EAPL("set %d ms, retransmission_counter %d, failed.\n"),
								 (m_is_client == true ? "client": "server"),
								 next_retransmission_time,
								 retransmission->get_retransmission_counter()));
						}
						else
						{
							retransmission->get_next_retransmission_counter(); // This decrements the counter.
							
							EAP_TRACE_DEBUG(
								m_am_tools, 
								TRACE_FLAGS_DEFAULT, 
								(EAPL("TIMER: %s: WAPI_CORE_TIMER_RETRANSMISSION_ID ")
								 EAPL("set %d ms, retransmission_counter %d.\n"),
								 (m_is_client == true ? "client": "server"),
								 next_retransmission_time,
								 retransmission->get_retransmission_counter()));
						}
					}

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else
				{
					status = eap_status_ok;

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("TIMER: %s, no retransmission, m_retransmission=0x%08x.\n"),
					 (m_is_client == true) ? "client": "server",
					 retransmission));
				if (retransmission != 0)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("TIMER: %s, no retransmission, retransmission->get_is_valid()=%d, ")
						 EAPL("retransmission->get_retransmission_counter()=%d.\n"),
						 (m_is_client == true) ? "client": "server",
						 retransmission->get_is_valid(),
						 retransmission->get_retransmission_counter()));
				}
				
				// No good WAI-Response received to WAI-Requests.
				// Terminate the session.

				{
					eap_am_network_id_c send_network_id(
						m_am_tools,
						m_receive_network_id.get_destination_id(),
						m_receive_network_id.get_source_id(),
						m_receive_network_id.get_type());

					eap_state_notification_c notification(
						m_am_tools,
						&send_network_id,
						m_is_client,
						eap_state_notification_eap,
						eap_protocol_layer_eap,
						eap_type_none,
						eap_state_none,
						eap_state_authentication_terminated_unsuccessfully,
						0ul,
						false);

					notification.set_authentication_error(eap_status_authentication_failure);
					
					state_notification(&notification);
				}

				status = eap_status_ok;
			}
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("TIMER: %s, no retransmission, count of m_retransmission=%d.\n"),
				 (m_is_client == true) ? "client": "server",
				 m_retransmission.get_object_count()));
		}
	}
	else if (id == WAPI_CORE_SESSION_TIMEOUT_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: WAPI_CORE_SESSION_TIMEOUT_ID elapsed.\n"),
			 (m_is_client == true ? "client": "server")
			 ));

		// we will remove this session immediately.
		status = initialize_asynchronous_init_remove_wapi_session(0ul);

		{
			// Here we swap the addresses.
			eap_am_network_id_c send_network_id(m_am_tools,
				m_receive_network_id.get_destination_id(),
				m_receive_network_id.get_source_id(),
				m_receive_network_id.get_type());

			if (send_network_id.get_is_valid_data() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			// This notification to eapol_core_c object.
			// WAI authentication terminated unsuccessfully.
			eap_state_notification_c * notification = new eap_state_notification_c(
				m_am_tools,
				&send_network_id,
				m_is_client,
				eap_state_notification_generic,
				eap_protocol_layer_wai,
				eapol_key_handshake_type_wai_handshake,
				eapol_key_state_wapi_authentication_running,
				eapol_key_state_wapi_authentication_terminated_unsuccessfull,
				0ul,
				false);
			if (notification == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			notification->set_authentication_error(eap_status_authentication_failure);

			state_notification(notification);

			delete notification;

			set_wapi_state(wapi_core_state_authentication_failed);
		}

		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (id == WAPI_CORE_REMOVE_SESSION_TIMEOUT_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: WAPI_CORE_REMOVE_SESSION_TIMEOUT_ID elapsed.\n"),
			 (m_is_client == true ? "client": "server")
			 ));

		status = asynchronous_init_remove_wapi_session();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_core_c::timer_delete_data(
	const u32_t id, void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(data); // Only trace uses this.

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: [0x%08x]->wapi_core_c::timer_delete_data(id 0x%02x, data 0x%08x): %s.\n"),
		 this,
		 id,
		 data,
		 (m_is_client == true) ? "client": "server"
		 ));

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	if (id == WAPI_CORE_TIMER_RETRANSMISSION_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: WAPI_CORE_TIMER_RETRANSMISSION_ID delete data.\n"),
			 (m_is_client == true ? "client": "server")
			 ));

		if (m_retransmission.get_object_count() > 0ul)
		{
			wapi_core_retransmission_c * const retransmission = m_retransmission.get_object(0ul);

			if (retransmission != 0
				&& retransmission->get_is_valid() == true
				&& retransmission->get_retransmission_counter() > 0)
			{
				// Do not delete yet.
				// cancel_retransmission() will delete m_retransmission.
			}
			else if (retransmission != 0)
			{
				(void) m_retransmission.remove_object(0ul);
			}
		}
	}
	else if (id == WAPI_CORE_REMOVE_SESSION_TIMEOUT_ID)
	{
		// Nothing to do.
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_core_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

#if !defined(USE_EAP_DEBUG_TRACE)
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_core_c::reset(): %s.\n"),
		 ((m_is_client == true) ? "client": "server")));
#else
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_core_c::reset(): %s: this = 0x%08x => 0x%08x.\n"),
		 ((m_is_client == true) ? "client": "server"),
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));
#endif

	eap_status_e status = eap_status_ok;

	cancel_retransmission();

	cancel_session_timeout();

	cancel_wapi_failure_timeout();

	cancel_asynchronous_init_remove_wapi_session();

    // restart message sequencing
    m_packet_sequence_number = 0ul;

	// Add session timeout.
	initialize_session_timeout(m_session_timeout);

	m_wapi_state = wapi_core_state_none;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_core_c::set_session_timeout(
	const u32_t session_timeout_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = initialize_session_timeout(session_timeout_ms);
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
EAP_FUNC_EXPORT eap_status_e wapi_core_c::set_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id, 
	void * const p_data,
	const u32_t p_time_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->set_timer(
		p_initializer, 
		p_id, 
		p_data,
		p_time_ms);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_core_c::cancel_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->cancel_timer(
		p_initializer, 
		p_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_core_c::cancel_all_timers()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->cancel_all_timers();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::set_authentication_role(const bool when_true_set_client)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	cancel_retransmission();

	cancel_wapi_failure_timeout();

	m_is_client_role = when_true_set_client;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::cancel_authentication_session()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::cancel_authentication_session(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::cancel_authentication_session()");

	cancel_retransmission();
	cancel_wapi_failure_timeout();
	cancel_session_timeout();

	m_fragment_sequence_number = 0ul;
	m_packet_sequence_number = 0u;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::check_bksa_cache(
	const eapol_key_authentication_type_e selected_eapol_key_authentication_type,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::check_bksa_cache(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::check_bksa_cache()");

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::complete_query_asu_id(
	const eap_variable_data_c * const asn1_der_subject_name,
	const eap_variable_data_c * const asn1_der_issuer_name,
	const eap_variable_data_c * const asn1_der_sequence_number,
	const eap_status_e id_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::complete_query_asu_id(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::complete_query_asu_id()");

	if (id_status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, id_status);
	}

	eap_status_e status = m_asu_id.set_copy_of_buffer(asn1_der_subject_name);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_asu_id.add_data(asn1_der_issuer_name);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_asu_id.add_data(asn1_der_sequence_number);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	status = m_ec_certificate_store->get_own_certificate();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::complete_get_own_certificate(
	const eap_variable_data_c * const own_certificate)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::complete_get_own_certificate(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::complete_get_own_certificate()");

	eap_status_e status(eap_status_not_supported);

#if defined(USE_WAPI_CORE_SERVER)
	if (m_is_client == false
		&& m_wapi_state == wapi_core_state_start_certificate_negotiation)
	{
		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Saves own certificate.

		status = m_own_certificate.set_copy_of_buffer(own_certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Reads the ID of STA_AE

		status = m_ec_certificate_store->read_id_of_certificate(&m_own_certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	}
#endif //#if defined(USE_WAPI_CORE_SERVER)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::complete_select_certificate(
	const eap_variable_data_c * const issuer_ID,
	const eap_variable_data_c * const certificate_ID,
	const eap_variable_data_c * const certificate)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::complete_select_certificate(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::complete_select_certificate()");

	eap_status_e status(eap_status_not_supported);

	if (issuer_ID == 0
		|| issuer_ID->get_is_valid() == false
		|| certificate_ID == 0
		|| certificate_ID->get_is_valid() == false
		|| certificate == 0
		|| certificate->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_is_client == true
		&& m_wapi_state == wapi_core_state_process_authentication_activation_message)
	{
		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Saves own ID.

		status = m_asue_id.set_copy_of_buffer(certificate_ID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("m_asue_id"),
			 m_asue_id.get_data(),
			 m_asue_id.get_data_length()));

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Saves own certificate.

		status = m_own_certificate.set_copy_of_buffer(certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Reads the ID of STA_AE

		status = m_ec_certificate_store->read_id_of_certificate(&m_peer_certificate);
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

EAP_FUNC_EXPORT eap_status_e wapi_core_c::complete_read_id_of_certificate(
	const eap_variable_data_c * const ID)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::complete_read_id_of_certificate(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::complete_read_id_of_certificate()");

	eap_status_e status(eap_status_not_supported);

#if defined(USE_WAPI_CORE_SERVER)
	if (m_is_client == false
		&& m_wapi_state == wapi_core_state_start_certificate_negotiation)
	{
		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Save AE-ID.

		status = m_ae_id.set_copy_of_buffer(ID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("m_ae_id"),
			 m_ae_id.get_data(),
			 m_ae_id.get_data_length()));

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Create Authentication Identifier.

		if (m_wapi_negotiation_state == wapi_negotiation_state_initial_negotiation)
		{
			crypto_random_c rand(m_am_tools);
			if (rand.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = rand.get_rand_bytes(
				&m_authentication_identifier,
				WAPI_AUTHENTICATION_IDENTIFIER_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("new local m_authentication_identifier"),
				 m_authentication_identifier.get_data(),
				 m_authentication_identifier.get_data_length()));
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Create the Authentication Activation Packet.

		wai_message_payloads_c * const payloads = new wai_message_payloads_c(m_am_tools, m_is_client);
		eap_automatic_variable_c<wai_message_payloads_c> automatic_payloads(m_am_tools, payloads);

		if (payloads == 0
			|| payloads->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = payloads->initialise_header();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->get_wai_protocol_packet_header_writable()->set_subtype(wai_protocol_subtype_authentication_activation);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds FLAG to data field.

		{
			wai_variable_data_c data_flag(m_am_tools);
			if (data_flag.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u8_t flag(wai_data_flag_mask_none);

			if (m_wapi_negotiation_state == wapi_negotiation_state_rekeying)
			{
				flag = wai_data_flag_mask_BK_Rekeying;
			}

			status = data_flag.create(
				wai_payload_type_flag,
				&flag,
				sizeof(flag));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = payloads->add_tlv(&data_flag);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds Authentication Identifier to data field.

		{
			wai_variable_data_c data_authentication_identifier(m_am_tools);
			if (data_authentication_identifier.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = data_authentication_identifier.create(
				wai_payload_type_authentication_identifier,
				&m_authentication_identifier);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = payloads->add_tlv(&data_authentication_identifier);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds ID of local ASU to data field.

		{
			wai_variable_data_c data_id_of_local_asu(m_am_tools);
			if (data_id_of_local_asu.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			if (m_test_other_asu_id.get_is_valid_data() == true)
			{
				status = data_id_of_local_asu.create(
					wai_payload_type_identity,
					&m_test_other_asu_id);
			}
			else
			{
				status = data_id_of_local_asu.create(
					wai_payload_type_identity,
					&m_asu_id);
			}

			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = payloads->add_tlv(&data_id_of_local_asu);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds STA_AE Certificate to data field.

		{
			wai_variable_data_c data_certificate(m_am_tools);
			if (data_certificate.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = data_certificate.create(
				wai_payload_type_certificate,
				&m_own_certificate);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = payloads->add_tlv(&data_certificate);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds ECDH parameter to data field.

		{
			wai_variable_data_c data_ecdh_parameter(m_am_tools);
			if (data_ecdh_parameter.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = data_ecdh_parameter.create(
				wai_payload_type_echd_parameter,
				WAPI_ECDH_OID_PARAMETER,
				sizeof(WAPI_ECDH_OID_PARAMETER));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = payloads->add_tlv(&data_ecdh_parameter);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Create and send message.

		wai_message_c new_wai_message_data(m_am_tools, m_is_client);
		if (new_wai_message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->create_wai_tlv_message(&new_wai_message_data, false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		//cancel_retransmission();

		status = packet_send(
			&new_wai_message_data,
			payloads->get_wai_protocol_packet_header_writable()->get_subtype());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		set_wapi_state(wapi_core_state_wait_access_authentication_request_message);

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	}
	else
#endif //#if defined(USE_WAPI_CORE_SERVER)
	if (m_is_client == true
		&& m_wapi_state == wapi_core_state_process_authentication_activation_message)
	{
		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Saves ID of STA_AE.

		status = m_ae_id.set_copy_of_buffer(ID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("m_ae_id"),
			 m_ae_id.get_data(),
			 m_ae_id.get_data_length()));

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Creates ECDH temporary keys.

		status = m_ec_certificate_store->create_ecdh_temporary_keys();
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

EAP_FUNC_EXPORT eap_status_e wapi_core_c::complete_create_signature_with_private_key(
	const eap_variable_data_c * const signature,
	const eap_status_e signature_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::complete_create_signature_with_private_key(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::complete_create_signature_with_private_key()");

	if (signature_status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, signature_status);
	}

	eap_status_e status(eap_status_not_supported);

	
#if defined(USE_WAPI_CORE_SERVER)
	if (m_is_client == false
		&& m_wapi_state == wapi_core_state_process_access_authentication_request_message_AE_signature_trusted_by_ASUE)
	{
		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds signature of AE trusted by ASUE to data field.

		{
			wai_variable_data_c data_signature(m_am_tools);
			if (data_signature.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("m_ae_id"),
				 m_ae_id.get_data(),
				 m_ae_id.get_data_length()));

			status = create_signature_attributes(
				&data_signature,
				&m_ae_id,
				signature);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_new_payloads.add_tlv(&data_signature);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Create and send message.

		wai_message_c new_wai_message_data(m_am_tools, m_is_client);
		if (new_wai_message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_new_payloads.create_wai_tlv_message(&new_wai_message_data, false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		//cancel_retransmission();

		status = packet_send(
			&new_wai_message_data,
			m_new_payloads.get_wai_protocol_packet_header_writable()->get_subtype());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_new_payloads.reset();

		set_wapi_state(wapi_core_state_start_unicast_key_negotiation);

		status = start_unicast_key_negotiation();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	}
	else if (m_is_client == false
		&& m_wapi_state == wapi_core_state_process_access_authentication_request_message_ASU_signature_trusted_by_AE)
	{
		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds signature of server trusted by AE to data field.

		status = create_signature_attributes(
			&m_server_signature_trusted_by_ae,
			&m_asu_id,
			signature);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Creates ECDH temporary keys.

		status = m_ec_certificate_store->create_ecdh_temporary_keys();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (m_is_client == false
		&& m_wapi_state == wapi_core_state_process_access_authentication_request_message)
	{
		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds signature of server trusted by ASUE to data field.

		status = create_signature_attributes(
			&m_server_signature_trusted_by_asue,
			&m_asu_id,
			signature);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		{
			eap_variable_data_c HASH(m_am_tools);
			if (HASH.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			wai_message_payloads_c * const payloads = new wai_message_payloads_c(m_am_tools, m_is_client);
			eap_automatic_variable_c<wai_message_payloads_c> automatic_payloads(m_am_tools, payloads);

			if (payloads == 0
				|| payloads->get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = payloads->insert_payload(&m_result_of_certificate_verification);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = payloads->insert_payload(&m_server_signature_trusted_by_asue);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = create_HASH(payloads, true, &HASH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("m_asu_id"),
				 m_asu_id.get_data(),
				 m_asu_id.get_data_length()));

			set_wapi_state(wapi_core_state_process_access_authentication_request_message_ASU_signature_trusted_by_AE);

			status = m_ec_certificate_store->create_signature_with_private_key(
				&HASH,
				&m_asu_id);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}
	else
#endif //#if defined(USE_WAPI_CORE_SERVER)
	if (m_is_client == true
		&& m_wapi_state == wapi_core_state_process_authentication_activation_message)
	{
		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds Signature of ASUE to data field.

		{
			wai_variable_data_c data_signature(m_am_tools);
			if (data_signature.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("m_asue_id"),
				 m_asue_id.get_data(),
				 m_asue_id.get_data_length()));

			status = create_signature_attributes(
				&data_signature,
				&m_asue_id,
				signature);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_new_payloads.add_tlv(&data_signature);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Create and send message.

		wai_message_c new_wai_message_data(m_am_tools, m_is_client);
		if (new_wai_message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_new_payloads.create_wai_tlv_message(&new_wai_message_data, false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = packet_send(
			&new_wai_message_data,
			m_new_payloads.get_wai_protocol_packet_header_writable()->get_subtype());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_new_payloads.reset();

		set_wapi_state(wapi_core_state_wait_access_authentication_response_message);

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::complete_verify_signature_with_public_key(
	const eap_status_e verification_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::complete_verify_signature_with_public_key(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::complete_verify_signature_with_public_key()");

	eap_status_e status(eap_status_not_supported);

#if defined(USE_WAPI_CORE_SERVER)
	if (m_is_client == false
		&& m_wapi_state == wapi_core_state_process_access_authentication_request_message)
	{
		if (verification_status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, verification_status);
		}

		// Create the AE challenge.
		if (m_ae_certificate_challenge.get_is_valid_data() == false)
		{
			crypto_random_c rand(m_am_tools);
			if (rand.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = rand.get_rand_bytes(
				&m_ae_certificate_challenge,
				WAPI_CHALLENGE_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		if (m_do_certificate_validation == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::complete_verify_signature_with_public_key(): does certificate validation\n"),
				this,
				(m_is_client == true ? "client": "server")));

			// First we need to create verification results by server (ASU) of both certificates, ASUE certificate and AE certificate.
			// Second thing to create are server (ASU) signatures trusted by ASUE and AE.
			//     Signature trusted by ASUE signs field Authentication Result for certificate in the Certificate Authentication Response packet.
			//     Signature trusted by AE signs both fields Authentication Result for certificate and Signature trusted by ASUE in the Certificate Authentication Response packet.
			// All operations are simulated here without external server (ASU) and without Certificate Authentication Request and Certificate Authentication Response packets.

			// Create the result of certificate verification.
			status = create_result_of_certificate_verification(
				&m_result_of_certificate_verification,
				&m_ae_certificate_challenge,
				&m_asue_certificate_challenge,
				wapi_certificate_result_valid,
				&m_peer_certificate, // ASUE certificate
				wapi_certificate_result_valid,
				&m_own_certificate); // AE certificate
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
			// Create Signature of ASU.

			{
				eap_variable_data_c HASH(m_am_tools);
				if (HASH.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				wai_message_payloads_c * const payloads = new wai_message_payloads_c(m_am_tools, m_is_client);
				eap_automatic_variable_c<wai_message_payloads_c> automatic_payloads(m_am_tools, payloads);

				if (payloads == 0
					|| payloads->get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = payloads->initialise_header();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = payloads->get_wai_protocol_packet_header_writable()->set_subtype(wai_protocol_subtype_certificate_authentication_response);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = payloads->add_tlv(&m_result_of_certificate_verification);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = create_HASH(payloads, true, &HASH);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				EAP_TRACE_DATA_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("m_asu_id"),
					 m_asu_id.get_data(),
					 m_asu_id.get_data_length()));

				status = m_ec_certificate_store->create_signature_with_private_key(
					&HASH,
					&m_asu_id);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::complete_verify_signature_with_public_key(): no certificate validation\n"),
				this,
				(m_is_client == true ? "client": "server")));

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
			// Creates ECDH temporary keys.

			set_wapi_state(wapi_core_state_process_access_authentication_request_message_ASU_signature_trusted_by_AE);

			status = m_ec_certificate_store->create_ecdh_temporary_keys();
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		}
	}
	else
#endif //#if defined(USE_WAPI_CORE_SERVER)
	if (m_is_client == true
		&& m_wapi_state == wapi_core_state_process_access_authentication_response_message)
	{
		if (verification_status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, verification_status);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Verify Signature of ASU.

		if (m_do_certificate_validation == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::complete_verify_signature_with_public_key(): does certificate validation\n"),
				this,
				(m_is_client == true ? "client": "server")));

			if (m_server_signature_trusted_by_ae.get_is_valid_data() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			eap_variable_data_c signature_data(m_am_tools);
			if (signature_data.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			eap_variable_data_c received_asu_id(m_am_tools);
			if (received_asu_id.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = parse_signature_attributes(
				&m_server_signature_trusted_by_ae,
				&received_asu_id,
				&signature_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("received_asu_id"),
				 received_asu_id.get_data(),
				 received_asu_id.get_data_length()));

			eap_variable_data_c HASH(m_am_tools);
			if (HASH.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
			// Adds Multiple Certificate Verification Result to data field.

			{
				status = m_new_payloads.reset();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = m_new_payloads.add_tlv(&m_result_of_certificate_verification);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}

			status = create_HASH(&m_new_payloads, false, &HASH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			set_wapi_state(wapi_core_state_process_access_authentication_response_message_ASU_signature);

			status = m_ec_certificate_store->verify_signature_with_public_key(
				&m_asu_id,
				&HASH,
				&signature_data,
				false);
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
				(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::complete_verify_signature_with_public_key(): no certificate validation\n"),
				this,
				(m_is_client == true ? "client": "server")));

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
			// Create temporary ECDH keys.

			set_wapi_state(wapi_core_state_process_access_authentication_response_message_ASU_signature);

			status = m_ec_certificate_store->create_ecdh(
				&m_own_private_key_d,
				&m_peer_public_key_x,
				&m_peer_public_key_y);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		}
	}
	else if (m_is_client == true
		&& m_wapi_state == wapi_core_state_process_access_authentication_response_message_ASU_signature)
	{
		if (verification_status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, verification_status);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Create temporary ECDH keys.

		status = m_ec_certificate_store->create_ecdh(
			&m_own_private_key_d,
			&m_peer_public_key_x,
			&m_peer_public_key_y);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::complete_create_ecdh_temporary_keys(
	const eap_variable_data_c * const private_key_d,
	const eap_variable_data_c * const public_key_x,
	const eap_variable_data_c * const public_key_y)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::complete_create_ecdh_temporary_keys(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::complete_create_ecdh_temporary_keys()");

	eap_status_e status(eap_status_not_supported);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("private_key_d"),
		 private_key_d->get_data(),
		 private_key_d->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("public_key_x"),
		 public_key_x->get_data(),
		 public_key_x->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("public_key_y"),
		 public_key_y->get_data(),
		 public_key_y->get_data_length()));

	
#if defined(USE_WAPI_CORE_SERVER)
	if (m_is_client == false
		&& m_wapi_state == wapi_core_state_process_access_authentication_request_message_ASU_signature_trusted_by_AE)
	{
		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Save ECDH keys.

		// We do not use the new keys. Only the first generated keys.
		if (m_own_private_key_d.get_is_valid_data() == false
			|| m_own_public_key_x.get_is_valid_data() == false
			|| m_own_public_key_y.get_is_valid_data() == false)
		{
			status = m_own_private_key_d.set_copy_of_buffer(private_key_d);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_own_public_key_x.set_copy_of_buffer(public_key_x);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_own_public_key_y.set_copy_of_buffer(public_key_y);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Create temporary ECDH keys.

		status = m_ec_certificate_store->create_ecdh(
			&m_own_private_key_d,
			&m_peer_public_key_x,
			&m_peer_public_key_y);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	}
	else
#endif //#if defined(USE_WAPI_CORE_SERVER)
	if (m_is_client == true
		&& m_wapi_state == wapi_core_state_process_authentication_activation_message)
	{
		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Save ECDH keys.

		// We do not use the new keys. Only the first generated keys.
		if (m_own_private_key_d.get_is_valid_data() == false
			|| m_own_public_key_x.get_is_valid_data() == false
			|| m_own_public_key_y.get_is_valid_data() == false)
		{
			status = m_own_private_key_d.set_copy_of_buffer(private_key_d);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_own_public_key_x.set_copy_of_buffer(public_key_x);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_own_public_key_y.set_copy_of_buffer(public_key_y);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Create the Access Authentication Request Packet.

		m_new_payloads.reset();

		if (m_new_payloads.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = m_new_payloads.initialise_header();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_new_payloads.get_wai_protocol_packet_header_writable()->set_subtype(wai_protocol_subtype_access_authentication_request);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds FLAG to data field.

		{
			wai_variable_data_c data_flag(m_am_tools);
			if (data_flag.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u8_t flag(wai_data_flag_mask_none | wai_data_flag_mask_Certificate_Validation_Request);

			if (m_wapi_negotiation_state == wapi_negotiation_state_rekeying)
			{
				flag = wai_data_flag_mask_BK_Rekeying;
			}

			status = data_flag.create(
				wai_payload_type_flag,
				&flag,
				sizeof(flag));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_new_payloads.add_tlv(&data_flag);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds Authentication Identifier to data field.

		{
			wai_variable_data_c data_authentication_identifier(m_am_tools);
			if (data_authentication_identifier.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = data_authentication_identifier.create(
				wai_payload_type_authentication_identifier,
				&m_authentication_identifier);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_new_payloads.add_tlv(&data_authentication_identifier);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds ASUE Challenge to data field.

		{
			wai_variable_data_c data_ASUE_challenge(m_am_tools);
			if (data_ASUE_challenge.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = data_ASUE_challenge.create(
				wai_payload_type_nonce,
				&m_asue_certificate_challenge);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_new_payloads.add_tlv(&data_ASUE_challenge);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds ASUE key data to data field.

		{
			wai_variable_data_c ASUE_key_data(m_am_tools);
			if (ASUE_key_data.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u8_t ec_point_type(WAI_EC_POINT_TYPE_NO_COMPRESSION_ID);

			status = ASUE_key_data.create(
				wai_payload_type_key_data,
				&ec_point_type,
				sizeof(ec_point_type));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = ASUE_key_data.add_data(
				wai_payload_type_key_data,
				&m_own_public_key_x);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = ASUE_key_data.add_data(
				wai_payload_type_key_data,
				&m_own_public_key_y);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_new_payloads.add_tlv(&ASUE_key_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds ID of STA_AE to data field.

		{
			wai_variable_data_c data_id_of_ae(m_am_tools);
			if (data_id_of_ae.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("m_ae_id"),
				 m_ae_id.get_data(),
				 m_ae_id.get_data_length()));

			status = data_id_of_ae.create(
				wai_payload_type_identity,
				&m_ae_id);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_new_payloads.add_tlv(&data_id_of_ae);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds STA_ASUE Certificate to data field.

		{
			wai_variable_data_c data_certificate(m_am_tools);
			if (data_certificate.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = data_certificate.create(
				wai_payload_type_certificate,
				&m_own_certificate);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_new_payloads.add_tlv(&data_certificate);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds ECDH parameter to data field.

		{
			wai_variable_data_c data_ecdh_parameter(m_am_tools);
			if (data_ecdh_parameter.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = data_ecdh_parameter.create(
				wai_payload_type_echd_parameter,
				WAPI_ECDH_OID_PARAMETER,
				sizeof(WAPI_ECDH_OID_PARAMETER));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_new_payloads.add_tlv(&data_ecdh_parameter);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds optional ASU list trusted by ASUE. We do not add.


		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Create Signature of ASUE.

		{
			eap_variable_data_c HASH(m_am_tools);
			if (HASH.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = create_HASH(&m_new_payloads, false, &HASH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("m_asue_id"),
				 m_asue_id.get_data(),
				 m_asue_id.get_data_length()));

			status = m_ec_certificate_store->create_signature_with_private_key(
				&HASH,
				&m_asue_id);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

bool wapi_core_c::compare_issuer_name(const eap_variable_data_c * const asue_id, const eap_variable_data_c * const ae_id)
{
	eap_variable_data_c asue_subject_name(m_am_tools);
	eap_variable_data_c asue_issuer_name(m_am_tools);
	eap_variable_data_c asue_sequence_number(m_am_tools);

	if (asue_subject_name.get_is_valid() == false
		|| asue_issuer_name.get_is_valid() == false
		|| asue_sequence_number.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return false;
	}

	{
		wapi_asn1_der_parser_c asue(m_am_tools);

		if (asue.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			return false;
		}

		eap_status_e status = asue.decode(asue_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return false;
		}

		status = asue.get_wapi_identity(
			&asue_subject_name,
			&asue_issuer_name,
			&asue_sequence_number);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return false;
		}
	}


	eap_variable_data_c ae_subject_name(m_am_tools);
	eap_variable_data_c ae_issuer_name(m_am_tools);
	eap_variable_data_c ae_sequence_number(m_am_tools);

	if (ae_subject_name.get_is_valid() == false
		|| ae_issuer_name.get_is_valid() == false
		|| ae_sequence_number.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return false;
	}

	{
		wapi_asn1_der_parser_c ae(m_am_tools);

		if (ae.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			return false;
		}

		eap_status_e status = ae.decode(ae_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return false;
		}

		status = ae.get_wapi_identity(
			&ae_subject_name,
			&ae_issuer_name,
			&ae_sequence_number);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return false;
		}
	}

	return asue_issuer_name.compare(&ae_issuer_name) == 0;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_core_c::complete_create_ecdh(
	const eap_variable_data_c * const K_AB_x4,
	const eap_variable_data_c * const K_AB_y4)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: wapi_core_c::complete_create_ecdh(): state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 wapi_strings_c::get_wapi_core_state_string(m_wapi_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_core_c::complete_create_ecdh()");

	eap_variable_data_c key(m_am_tools);
	if (key.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("K_AB_x4"),
		 K_AB_x4->get_data(),
		 K_AB_x4->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("K_AB_y4"),
		 K_AB_y4->get_data(),
		 K_AB_y4->get_data_length()));

	eap_status_e status(eap_status_process_general_error);

	// Only the x-coordinate is used in key generation.
	status = key.set_copy_of_buffer(K_AB_x4);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// BK || Challenge seed = KD_HMAC_SHA256((yxP) abscissa, NONCE_AE || NONCE_ASUE || string label)

	crypto_kd_hmac_sha256_c kd_hmac(m_am_tools);
	if (kd_hmac.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c label(m_am_tools);
	if (label.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = label.set_copy_of_buffer(&m_ae_certificate_challenge);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = label.add_data(&m_asue_certificate_challenge);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = label.add_data(WAPI_CERTIFICATE_KEY_LABEL, WAPI_CERTIFICATE_KEY_LABEL_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c bk_challenge_seed(m_am_tools);
	if (bk_challenge_seed.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = kd_hmac.expand_key(
		&bk_challenge_seed,
		WAPI_BK_LENGTH + WAPI_CHALLENGE_SEED_LENGTH,
		&key,
		&label);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_BK.set_copy_of_buffer(
		bk_challenge_seed.get_data(WAPI_BK_LENGTH),
		WAPI_BK_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		eap_variable_data_c next_challenge(m_am_tools);
		if (next_challenge.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		crypto_sha_256_c sha_256(m_am_tools);
		if (sha_256.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = sha_256.hash_init();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = sha_256.hash_update(
			bk_challenge_seed.get_data_offset(WAPI_BK_LENGTH, WAPI_CHALLENGE_SEED_LENGTH),
			WAPI_CHALLENGE_SEED_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		u32_t md_length(sha_256.get_digest_length());

		status = m_authentication_identifier.set_buffer_length(md_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_authentication_identifier.set_data_length(md_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = sha_256.hash_final(
			m_authentication_identifier.get_data(),
			&md_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("next local m_authentication_identifier"),
			 m_authentication_identifier.get_data(),
			 m_authentication_identifier.get_data_length()));
	}

#if defined(USE_WAPI_CORE_SERVER)
	if (m_is_client == false
		&& m_wapi_state == wapi_core_state_process_access_authentication_request_message_ASU_signature_trusted_by_AE)
	{
		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Create the Access Authentication Request Packet.

		m_new_payloads.reset();

		if (m_new_payloads.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = m_new_payloads.initialise_header();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_new_payloads.get_wai_protocol_packet_header_writable()->set_subtype(wai_protocol_subtype_access_authentication_response);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds FLAG to data field.

		{
			wai_variable_data_c data_flag(m_am_tools);
			if (data_flag.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u8_t flag(wai_data_flag_mask_none | wai_data_flag_mask_Optional_Field | wai_data_flag_mask_Certificate_Validation_Request);

			if (m_wapi_negotiation_state == wapi_negotiation_state_rekeying)
			{
				flag = wai_data_flag_mask_BK_Rekeying;
			}

			status = data_flag.create(
				wai_payload_type_flag,
				&flag,
				sizeof(flag));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_new_payloads.add_tlv(&data_flag);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds ASUE Challenge to data field.

		{
			wai_variable_data_c data_ASUE_challenge(m_am_tools);
			if (data_ASUE_challenge.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = data_ASUE_challenge.create(
				wai_payload_type_nonce,
				&m_asue_certificate_challenge);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_new_payloads.add_tlv(&data_ASUE_challenge);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds AE Challenge to data field.

		{
			wai_variable_data_c data_AE_challenge(m_am_tools);
			if (data_AE_challenge.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = data_AE_challenge.create(
				wai_payload_type_nonce,
				&m_ae_certificate_challenge);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_new_payloads.add_tlv(&data_AE_challenge);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds Access Result to data field.

		{
			wai_variable_data_c data_AE_challenge(m_am_tools);
			if (data_AE_challenge.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			wapi_access_result_e result(wapi_access_result_successfull_access);

			status = data_AE_challenge.create(
				wai_payload_type_access_result,
				&result,
				sizeof(result));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_new_payloads.add_tlv(&data_AE_challenge);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds ASUE key data to data field.

		{
			wai_variable_data_c ASUE_key_data(m_am_tools);
			if (ASUE_key_data.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u8_t ec_point_type(WAI_EC_POINT_TYPE_NO_COMPRESSION_ID);

			status = ASUE_key_data.create(
				wai_payload_type_key_data,
				&ec_point_type,
				sizeof(ec_point_type));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = ASUE_key_data.add_data(
				wai_payload_type_key_data,
				&m_peer_public_key_x);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = ASUE_key_data.add_data(
				wai_payload_type_key_data,
				&m_peer_public_key_y);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_new_payloads.add_tlv(&ASUE_key_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds AE key data to data field.

		{
			wai_variable_data_c ASUE_key_data(m_am_tools);
			if (ASUE_key_data.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u8_t ec_point_type(WAI_EC_POINT_TYPE_NO_COMPRESSION_ID);

			status = ASUE_key_data.create(
				wai_payload_type_key_data,
				&ec_point_type,
				sizeof(ec_point_type));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = ASUE_key_data.add_data(
				wai_payload_type_key_data,
				&m_own_public_key_x);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = ASUE_key_data.add_data(
				wai_payload_type_key_data,
				&m_own_public_key_y);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_new_payloads.add_tlv(&ASUE_key_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds ID of STA_AE to data field.

		{
			wai_variable_data_c data_id_of_ae(m_am_tools);
			if (data_id_of_ae.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("m_ae_id"),
				 m_ae_id.get_data(),
				 m_ae_id.get_data_length()));

			status = data_id_of_ae.create(
				wai_payload_type_identity,
				&m_ae_id);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_new_payloads.add_tlv(&data_id_of_ae);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds ID of STA_ASUE to data field.

		{
			wai_variable_data_c data_id_of_asue(m_am_tools);
			if (data_id_of_asue.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("m_asue_id"),
				 m_asue_id.get_data(),
				 m_asue_id.get_data_length()));

			status = data_id_of_asue.create(
				wai_payload_type_identity,
				&m_asue_id);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_new_payloads.add_tlv(&data_id_of_asue);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Adds Multiple Certificate Verification Result to data field.

		if (m_do_certificate_validation == true)
		{
			status = m_new_payloads.add_tlv(&m_result_of_certificate_verification);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_new_payloads.add_tlv(&m_server_signature_trusted_by_asue);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (compare_issuer_name(&m_asu_id, &m_ae_id) == false)
			{
				status = m_new_payloads.add_tlv(&m_server_signature_trusted_by_ae);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Create Signature of AE.

		{
			eap_variable_data_c HASH(m_am_tools);
			if (HASH.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = create_HASH(&m_new_payloads, true, &HASH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("m_asue_id"),
				 m_asue_id.get_data(),
				 m_asue_id.get_data_length()));

			set_wapi_state(wapi_core_state_process_access_authentication_request_message_AE_signature_trusted_by_ASUE);

			status = m_ec_certificate_store->create_signature_with_private_key(
				&HASH,
				&m_ae_id);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}
	else
#endif //#if defined(USE_WAPI_CORE_SERVER)
	if (m_is_client == true
		&& m_wapi_state == wapi_core_state_process_access_authentication_response_message_ASU_signature)
	{
		set_wapi_state(wapi_core_state_wait_unicast_key_negotiation_request_message);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------
// End.
