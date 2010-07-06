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
* %version: 37 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 77 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_type_gsmsim.h"
#include "eap_type_gsmsim_header.h"
#include "eap_type_gsmsim_payloads.h"
#include "eap_type_gsmsim_mac_attributes.h"
#include "abs_eap_am_type_gsmsim.h"
#include "eap_crypto_api.h"
#include "eap_state_notification.h"
#include "abs_eap_am_mutex.h"
#include "eap_automatic_variable.h"
#include "eap_am_type_gsmsim.h"


//--------------------------------------------------

/** @file */

// 
EAP_FUNC_EXPORT eap_type_gsmsim_c::~eap_type_gsmsim_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::~eap_type_gsmsim_c(): this = 0x%08x => 0x%08x\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	EAP_ASSERT(m_shutdown_was_called == true);

	if (m_free_am_type_gsmsim == true
		&& m_am_type_gsmsim != 0)
	{
		delete m_am_type_gsmsim;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4355 ) // 'this' : used in base member initializer list
#endif

// 
EAP_FUNC_EXPORT eap_type_gsmsim_c::eap_type_gsmsim_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_base_type_c * const partner,
	eap_am_type_gsmsim_c * const am_type_gsmsim,
	const bool free_am_type_gsmsim,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id)
	: eap_base_type_c(tools, partner)
	, m_am_tools(tools)
	, m_state(eap_type_gsmsim_state_none)
	, m_saved_previous_state(eap_type_gsmsim_state_none)
	, m_send_network_id(m_am_tools)
	, m_nonce_mt(m_am_tools)
	, m_nonce_s(m_am_tools)
	, m_IV(m_am_tools)
	, m_saved_EAP_packet(m_am_tools)
	, m_XKEY(m_am_tools)
	, m_K_encr(m_am_tools)
	, m_K_aut(m_am_tools)
	, m_master_session_key(m_am_tools, eap_type_gsmsim)
	, m_IMSI(m_am_tools)
	, m_pseudonym(m_am_tools)
	, m_reauthentication_identity(m_am_tools)
	, m_automatic_realm(m_am_tools)
	, m_automatic_realm_read(false)
	, m_identity(m_am_tools)
	, m_NAI(m_am_tools)
	, m_n_rands(m_am_tools)
	, m_n_sres(m_am_tools)
	, m_gsmsim_version_list(m_am_tools)
#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	, m_triplets(0)
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	, m_reauthentication_counter(0u)
	, m_include_identity_to_start_response(gsmsim_payload_NONE)
	, m_start_response_includes_identity(gsmsim_payload_NONE)
	, m_failure_message_received(false)
	, m_authentication_finished_successfully(false)
	, m_last_eap_identifier(0)
	, m_gsmsim_selected_version(GSMSIM_ILLEGAL_VERSION)
	, m_2_digit_mnc_map_of_mcc_of_imsi_array(tools)
	, m_uma_automatic_realm_prefix(tools)
	, m_use_uma_profile(false)
	, m_am_type_gsmsim(am_type_gsmsim)
#if defined(_DEBUG) && defined(USE_EAP_GSMSIM_TEST_VECTORS)
	, m_nonce_mt_file(tools)
#endif //#if defined(_DEBUG) && defined(USE_EAP_GSMSIM_TEST_VECTORS)
	, m_manual_username(tools)
	, m_manual_realm(tools)
	, m_gsmsim_header_offset(0u)
	, m_MTU(0u)
	, m_trailer_length(0u)
	, m_minimum_rand_count(EAP_TYPE_GSMSIM_DEFAULT_MINIMUM_RAND_COUNT)
	, m_length_of_mnc(EAP_TYPE_GSMSIM_DEFAULT_MNC_LENGTH_3_BYTES)
	, m_authentication_type(GSMSIM_AUTHENTICATION_TYPE_NONE)
	, m_identity_type(GSMSIM_IDENTITY_TYPE_NONE)
	, m_client_error_code(eap_gsmsim_client_error_code_none)
	, m_gsmsim_notification_code(eap_gsmsim_notification_none)
	, m_failure_message_delay_time(EAP_TYPE_GSMSIM_TIMER_TIMEOUT_VALUE_DELAY_FAILURE_MESSAGE_SENT)
	, m_is_valid(false)
	, m_is_client(is_client_when_true)
	, m_wait_eap_success_packet(true)
	, m_check_identifier_of_eap_identity_response(false)
	, m_free_am_type_gsmsim(free_am_type_gsmsim)
#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)
	, m_client_responds_retransmitted_packets(false)
#endif //#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)
	, m_gsmsim_test_version(false)
	, m_gsmsim_randomly_refuse_eap_identity(false)
	, m_check_nai_realm(false)
	, m_fail_reauthentication_counter_check(false)
	, m_accept_eap_identity_response(true)
	, m_use_random_identity_on_eap_identity_response(false)
	, m_shutdown_was_called(false)
	, m_reset_was_called(false)
	, m_do_rand_uniqueness_check(true)
	, m_use_pseudonym_identity(true)
	, m_use_reauthentication_identity(true)
	, m_erroneus_packet_received(false)
	, m_sim_notification_packet_received(false)
	, m_use_manual_username(false)
	, m_use_manual_realm(false)
	, m_randomly_fail_successfull_authentication(false)
	, m_allow_use_result_indication(true)
	, m_use_result_indication(false)
	, m_use_eap_expanded_type(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::eap_type_gsmsim_c(): this = 0x%08x => 0x%08x, ")
		 EAPL("partner 0x%08x, type partner 0x%08x, compiled %s %s\n"),
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this),
		 partner,
		 get_type_partner(),
		__DATE__,
		__TIME__));

	// This is the only supported version.
	m_supported_versions[0] = GSMSIM_VERSION_1;

	if (m_am_type_gsmsim == 0)
	{
		// Something wrong with AM.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}
	m_am_type_gsmsim->set_am_partner(this);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if !defined(NO_EAP_TYPE_GSMSIM_MESSAGE_STATE_CHECK)

	initialize_state(eap_type_gsmsim_state_pending_kc_sres_query, false, false,
		gsmsim_subtype_Notification,
		gsmsim_subtype_Challenge, // Re-transmitted EAP-Request/SIM/Challenge is allowed.
		gsmsim_subtype_NONE,
		gsmsim_subtype_NONE);

	initialize_state(eap_type_gsmsim_state_pending_triplet_query, false, false,
		gsmsim_subtype_Notification,
		gsmsim_subtype_Start, // Note EAP-Response/SIM/Start message is allowed here, eap_type_gsmsim_c::handle_start_response_message() will drop EAP-Response/SIM/Start message quietly.
		gsmsim_subtype_Client_Error,
		gsmsim_subtype_Challenge); // Re-transmitted EAP-Response/SIM/Challenge is allowed.

	initialize_state(eap_type_gsmsim_state_waiting_for_start_request, false, false,
		gsmsim_subtype_Notification,
		gsmsim_subtype_Start,
		gsmsim_subtype_NONE,
		gsmsim_subtype_NONE);

	initialize_state(eap_type_gsmsim_state_pseydonym_waiting_for_start_request, false, false,
		gsmsim_subtype_Notification,
		gsmsim_subtype_Start,
		gsmsim_subtype_Re_authentication,
		gsmsim_subtype_NONE);

	initialize_state(eap_type_gsmsim_state_imsi_waiting_for_start_request, false, false,
		gsmsim_subtype_Notification,
		gsmsim_subtype_Start,
		gsmsim_subtype_NONE,
		gsmsim_subtype_NONE);

	initialize_state(eap_type_gsmsim_state_waiting_for_start_response, true, false,
		gsmsim_subtype_Notification,
		gsmsim_subtype_Start,
		gsmsim_subtype_Client_Error,
		gsmsim_subtype_NONE);

	initialize_state(eap_type_gsmsim_state_waiting_for_notification_request_success, false, true,
		gsmsim_subtype_Notification,
		gsmsim_subtype_Challenge,
		gsmsim_subtype_Re_authentication,
		gsmsim_subtype_NONE);

	initialize_state(eap_type_gsmsim_state_waiting_for_notification_response_failure, true, false,
		gsmsim_subtype_Notification,
		gsmsim_subtype_NONE,
		gsmsim_subtype_NONE,
		gsmsim_subtype_NONE);

	initialize_state(eap_type_gsmsim_state_waiting_for_notification_response_success, true, false,
		gsmsim_subtype_Notification,
		gsmsim_subtype_NONE,
		gsmsim_subtype_NONE,
		gsmsim_subtype_NONE);

	initialize_state(eap_type_gsmsim_state_waiting_for_start_response_with_at_permanent_identity, true, false,
		gsmsim_subtype_Notification,
		gsmsim_subtype_Start,
		gsmsim_subtype_Client_Error,
		gsmsim_subtype_NONE);

	initialize_state(eap_type_gsmsim_state_waiting_for_start_response_with_at_full_auth_identity, true, false,
		gsmsim_subtype_Notification,
		gsmsim_subtype_Start,
		gsmsim_subtype_Client_Error,
		gsmsim_subtype_NONE);

	initialize_state(eap_type_gsmsim_state_waiting_for_start_response_with_at_any_identity, true, false,
		gsmsim_subtype_Notification,
		gsmsim_subtype_Start,
		gsmsim_subtype_Client_Error,
		gsmsim_subtype_NONE);

	initialize_state(eap_type_gsmsim_state_analyse_start_request, false, false,
		gsmsim_subtype_Notification,
		gsmsim_subtype_NONE,
		gsmsim_subtype_NONE,
		gsmsim_subtype_NONE);

	initialize_state(eap_type_gsmsim_state_waiting_for_challenge_request, false, false,
		gsmsim_subtype_Notification,
		gsmsim_subtype_Challenge,
		gsmsim_subtype_Start,
		gsmsim_subtype_NONE);

	initialize_state(eap_type_gsmsim_state_waiting_for_challenge_response, false, false,
		gsmsim_subtype_Notification,
		gsmsim_subtype_Challenge,
		gsmsim_subtype_Start,
		gsmsim_subtype_Client_Error);

	initialize_state(eap_type_gsmsim_state_waiting_for_reauth_request, false, false,
		gsmsim_subtype_Notification,
		gsmsim_subtype_Re_authentication,
		gsmsim_subtype_Start,
		gsmsim_subtype_NONE);

	initialize_state(eap_type_gsmsim_state_waiting_for_reauth_response, false, false,
		gsmsim_subtype_Notification,
		gsmsim_subtype_Re_authentication,
		gsmsim_subtype_Start,
		gsmsim_subtype_Client_Error);

	initialize_state(eap_type_gsmsim_state_success, false, false,
		gsmsim_subtype_Notification,
		gsmsim_subtype_Challenge,
		gsmsim_subtype_NONE,
		gsmsim_subtype_NONE);

	initialize_state(eap_type_gsmsim_state_waiting_for_success, false, false,
		gsmsim_subtype_Notification,
		gsmsim_subtype_Challenge,
		gsmsim_subtype_Re_authentication,
		gsmsim_subtype_NONE);

	initialize_state(eap_type_gsmsim_state_failure, false, false,
		gsmsim_subtype_NONE,
		gsmsim_subtype_NONE,
		gsmsim_subtype_NONE,
		gsmsim_subtype_NONE);

#endif //#if !defined(NO_EAP_TYPE_GSMSIM_MESSAGE_STATE_CHECK)

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		// Here we swap the addresses.
		eap_am_network_id_c send_network_id(m_am_tools,
			receive_network_id->get_destination_id(),
			receive_network_id->get_source_id(),
			receive_network_id->get_type());

		eap_status_e status = m_send_network_id.set_copy_of_network_id(&send_network_id);

		if (status != eap_status_ok
			|| m_send_network_id.get_is_valid_data() == false)
		{
			(void)EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			return;
		}
	}

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//-----------------------------------------------

#if !defined(NO_EAP_TYPE_GSMSIM_MESSAGE_STATE_CHECK)

//
EAP_FUNC_EXPORT void eap_type_gsmsim_c::initialize_state(
				const eap_type_gsmsim_state_variable_e state,
				const bool must_be_initiator,
				const bool must_be_responder,
				const gsmsim_subtype_e type0,
				const gsmsim_subtype_e type1,
				const gsmsim_subtype_e type2,
				const gsmsim_subtype_e type3)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_parameters[(state)].init_state(must_be_initiator, must_be_responder,
		type0, type1, type2, type3);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

#endif //#if !defined(NO_EAP_TYPE_GSMSIM_MESSAGE_STATE_CHECK)

//--------------------------------------------------

/**
 * This function stores the last encryption IV. In CBC-mode previous encrypted block is
 * used as a IV of next block.
 */
eap_status_e eap_type_gsmsim_c::store_last_encryption_iv(const eap_variable_data_c * const encryption_IV)
{
	return m_IV.get_payload_buffer()->set_copy_of_buffer(encryption_IV);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_gsmsim_version eap_type_gsmsim_c::select_version(
	const gsmsim_variable_data_c * const version_payload,
	bool * const includes_other_version_than_1)
{
	u32_t version_payload_length = version_payload->get_original_header()->get_data_length();
	u32_t real_payload_length = version_payload->get_original_header()->get_reserved();
	eap_gsmsim_version selected_version = GSMSIM_ILLEGAL_VERSION;

	if (real_payload_length == 0
		|| real_payload_length > version_payload_length)
	{
		return GSMSIM_ILLEGAL_VERSION;
	}

	u32_t version_count = real_payload_length/sizeof(u16_t);
	u16_t *payload_version_list = reinterpret_cast<u16_t *>(version_payload->get_original_header()->get_data(real_payload_length));

	for (u32_t ind = 0u; ind < version_count; ind++)
	{
		u8_t * const payload_version_network_order = reinterpret_cast<u8_t *>(&(payload_version_list[ind]));
		u16_t payload_version_host_order
			= eap_read_u16_t_network_order(payload_version_network_order, sizeof(u16_t));
		if (payload_version_host_order == static_cast<u16_t>(GSMSIM_VERSION_1))
		{
			selected_version = static_cast<eap_gsmsim_version>(payload_version_host_order);
		}
		else if (payload_version_host_order != static_cast<u16_t>(GSMSIM_VERSION_1))
		{
			*includes_other_version_than_1 = true;
		}
	}

	return selected_version;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_type_gsmsim_c::get_identity_string(const eap_type_gsmsim_identity_type identity_type)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(identity_type, GSMSIM_IDENTITY_TYPE_NONE)
	else EAP_IF_RETURN_STRING(identity_type, GSMSIM_IDENTITY_TYPE_IMSI_ID)
	else EAP_IF_RETURN_STRING(identity_type, GSMSIM_IDENTITY_TYPE_PSEUDONYM_ID)
	else EAP_IF_RETURN_STRING(identity_type, GSMSIM_IDENTITY_TYPE_RE_AUTH_ID)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(identity_type);
		return EAPL("Unknown AKA identity");
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_type_gsmsim_c::get_state_string(eap_type_gsmsim_state_variable_e state)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_waiting_for_identity_request)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_pending_identity_query)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_waiting_for_start_request)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_imsi_waiting_for_start_request)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_pseydonym_waiting_for_start_request)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_analyse_start_request)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_waiting_for_challenge_request)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_analyses_challenge_request)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_pending_kc_sres_query)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_waiting_for_success)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_waiting_for_reauth_request)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_analyses_reauthentication_request)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_pending_pseudonym_decode_query)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_waiting_for_identity_response)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_waiting_for_start_response_with_at_permanent_identity)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_waiting_for_start_response_with_at_full_auth_identity)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_waiting_for_start_response_with_at_any_identity)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_waiting_for_start_response)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_waiting_for_challenge_response)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_pending_triplet_query)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_analyses_challenge_response)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_analyses_start_response)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_waiting_for_notification_request_success)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_waiting_for_notification_response_failure)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_waiting_for_notification_response_success)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_waiting_for_reauth_response)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_analyses_reauthentication_response)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_success)
	else EAP_IF_RETURN_STRING(state, eap_type_gsmsim_state_failure)
	else
#else
EAP_UNREFERENCED_PARAMETER(state);
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown GSMSIM state");
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_type_gsmsim_c::get_state_string() const
{
	return get_state_string(m_state);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_type_gsmsim_c::get_saved_previous_state_string() const
{
	return get_state_string(m_saved_previous_state);
}

//--------------------------------------------------

/**
 * This function sets the new state and notifies the lower layer of this change.
 */
void eap_type_gsmsim_c::set_state(eap_type_gsmsim_state_variable_e state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	eap_type_gsmsim_state_variable_e previous_state = m_state;
	
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::set_state(): old state %d=%s\n"),
		 m_state,
		 get_state_string()));

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::set_state(): new state %d=%s\n"),
		 state,
		 get_state_string(state)));

	m_state = state;
	
	eap_type_gsmsim_state_notification_c notification(
		m_am_tools,
		&m_send_network_id,
		m_is_client,
		eap_state_notification_eap,
		eap_protocol_layer_eap_type,
		eap_type_gsmsim,
		previous_state,
		state,
		m_last_eap_identifier,
		false);
	state_notification(&notification);
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

#if defined(USE_EAP_GSMSIM_VERIFY_STATES)

/**
 * This function checks the valid states.
 */
bool eap_type_gsmsim_c::verify_states(
	const eap_type_gsmsim_state_variable_e * const valid_states,
	const u32_t count) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	for (u32_t ind = 0ul; ind < count; ind++)
	{
		if (m_state == valid_states[ind])
		{
			return true;
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return false;
}

#endif //#if defined(USE_EAP_GSMSIM_VERIFY_STATES)

//--------------------------------------------------

#if !defined(NO_EAP_TYPE_GSMSIM_MESSAGE_STATE_CHECK)

EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::check_valid_state(gsmsim_subtype_e type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	const eap_type_gsmsim_state_variable_parameters_c * const state_variable = get_state_variable();

	if (state_variable == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_gsmsim_state);
	}

	if (state_variable->check_initiator(!get_is_client()) == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_GSMSIM_ERROR,
			(EAPL("ERROR: eap_type_gsmsim_state_c::check_valid_state(): Initiator type %d is wrong in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			get_is_client(), m_state, get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_gsmsim_state);
	}

	if (state_variable->check_valid_types(type) == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_GSMSIM_ERROR,
			(EAPL("ERROR: eap_type_gsmsim_state_c::check_valid_state(): gsmsim_subtype_e %d is wrong in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			type, m_state, get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_subtype);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif //#if !defined(NO_EAP_TYPE_GSMSIM_MESSAGE_STATE_CHECK)

//--------------------------------------------------

#if !defined(NO_EAP_TYPE_GSMSIM_MESSAGE_STATE_CHECK)

EAP_FUNC_EXPORT const eap_type_gsmsim_state_variable_parameters_c * eap_type_gsmsim_c::get_state_variable()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	if (m_state < eap_type_gsmsim_state_last_value)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return &(m_parameters[m_state]);
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return 0;
	}
}

#endif //#if !defined(NO_EAP_TYPE_GSMSIM_MESSAGE_STATE_CHECK)

//--------------------------------------------------

/**
 * This function saves the current m_state to m_saved_previous_state.
 * The saved state is restored in error case.
 */
EAP_FUNC_EXPORT void eap_type_gsmsim_c::save_current_state()
{
	m_saved_previous_state = m_state;
}

//--------------------------------------------------

/**
 * This function restores the saved state.
 */
EAP_FUNC_EXPORT void eap_type_gsmsim_c::restore_saved_previous_state()
{
	set_state(m_saved_previous_state);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::store_identity(
	const eap_variable_data_c * const IMSI_or_pseudonym,
	const bool IMSI_is_used)
{
	eap_status_e status = m_identity.init(IMSI_or_pseudonym->get_data_length()+1u);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	m_identity.set_is_valid();

	if (IMSI_is_used == true)
	{
		// Note the first octet is reserved for IMSI prefix.
		status = m_identity.set_copy_of_buffer(GSMSIM_IMSI_PREFIX_CHARACTER, 1u);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = m_identity.add_data(IMSI_or_pseudonym);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/// not used: expansion_0 = prf(key, seed | 0)
/// not used: expansion_i = prf(key, expansion_i-1 | seed | i), where i = 1, 2...

/// The following is from "DIGITAL SIGNATURE STANDARD (DSS)" FIPS PUB 186-2:
/// Let x be the signer's private key. The following may be used to generate m values of x:
/// Step 1. Choose a new, secret value for the seed-key, XKEY.
/// Step 2. In hexadecimal notation let
///             t = 67452301 EFCDAB89 98BADCFE 10325476 C3D2E1F0.
///             This is the initial value for H0 || H1 || H2 || H3 || H4 in the SHS.
/// Step 3. For j = 0 to m - 1 do
///             a. XSEEDj = optional user input.
///             b. XVAL = (XKEY + XSEEDj) mod 2^b.
///             c. xj = G(t,XVAL) mod q.
///             d. XKEY = (1 + XKEY + xj) mod 2^b.
/// 
/// Within GSMSIM the following parameters are used:
/// 160-bit XKEY and XVAL values are used, so b = 160.
/// XKEY = SHA1(n*Kc| NONCE_MT)
/// The optional user input values (XSEED_j) are set to zero.
/// xj = G(t, XVAL)

/// Random generator become as follows:
/// Step 1. Choose a new, secret value for the seed-key, XKEY.
/// Step 2. In hexadecimal notation let
///             t = 67452301 EFCDAB89 98BADCFE 10325476 C3D2E1F0.
///             This is the initial value for H0 || H1 || H2 || H3 || H4 in the SHS.
/// Step 3. For j = 0 to m - 1 do
///             c. xj = G(t,XKEY).
///             d. XKEY = (1 + XKEY + xj) mod 2^b.

EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::data_exp(
	const u32_t data_length,
	eap_variable_data_c * const expansion,
	const eap_variable_data_c * const key,
	const eap_variable_data_c * const seed)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	EAP_UNREFERENCED_PARAMETER(seed);

	u32_t count = data_length/EAP_TYPE_GSMSIM_KEYMAT_SIZE;
	if ((data_length % EAP_TYPE_GSMSIM_KEYMAT_SIZE) != 0)
	{
		++count;
	}

	status = expansion->init(count*EAP_TYPE_GSMSIM_KEYMAT_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	expansion->set_is_valid();
	expansion->set_data_length(count*EAP_TYPE_GSMSIM_KEYMAT_SIZE);

	status = m_am_tools->get_crypto()->dss_pseudo_random(
		expansion->get_data(),
		expansion->get_data_length(),
		key->get_data(),
		key->get_data_length());

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::generate_shared_secred_keys(
	const u32_t key_length,
	const eap_variable_data_c * const n_Kc,
	const eap_variable_data_c * const n_sres,
	eap_variable_data_c * const XKEY,
	eap_variable_data_c * const K_encr,
	eap_variable_data_c * const K_aut,
	eap_variable_data_c * const master_session_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(n_sres);

	u16_t selected_version = eap_htons(static_cast<u16_t>(m_gsmsim_selected_version));

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("generate_shared_secred_keys():\n")));

	if (m_NAI.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_nai);
	}
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("full auth NAI"),
		m_NAI.get_data(),
		m_NAI.get_data_length()));

	if (n_Kc->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, (EAPL("n*Kc"),
		n_Kc->get_data(),
		n_Kc->get_data_length()));

	if (n_sres->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, (EAPL("n*SRES"),
		n_sres->get_data(),
		n_sres->get_data_length()));

	if (m_nonce_mt.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("NONCE MT"),
		m_nonce_mt.get_data(),
		m_nonce_mt.get_data_length()));

	if (m_gsmsim_version_list.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("version list"),
		m_gsmsim_version_list.get_data(),
		m_gsmsim_version_list.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("selected version"),
		&selected_version,
		sizeof(selected_version)));

	eap_status_e status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	// XKEY = SHA1(NAI | n*Kc | NONCE_MT | Version List | Selected Version)

	crypto_sha1_c sha1(m_am_tools);

	if (sha1.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (sha1.hash_init() != eap_status_ok)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_GSMSIM_ERROR,
			(EAPL("ERROR: generate_shared_secred_keys(): init() failed.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = sha1.hash_update(
		m_NAI.get_data(),
		m_NAI.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(
		n_Kc->get_data(),
		n_Kc->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(
		m_nonce_mt.get_data(),
		m_nonce_mt.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(
		m_gsmsim_version_list.get_data(),
		m_gsmsim_version_list.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(
		reinterpret_cast<u8_t *>(&selected_version),
		sizeof(selected_version));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = XKEY->init(key_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	XKEY->set_is_valid();
	XKEY->set_data_length(key_length);

	u32_t md_length = key_length;

	status = sha1.hash_final(
		XKEY->get_data_offset(0u, key_length),
		&md_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_ASSERT_ALWAYS(md_length == key_length);


	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("generate_shared_secred_keys(): XKEY\n")));
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("     XKEY"),
		XKEY->get_data(),
		XKEY->get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t aes_key_length = m_am_tools->get_crypto()->aes_key_length();
	u32_t data_length = aes_key_length + EAP_TYPE_GSMSIM_MAC_SIZE + EAP_TYPE_GSMSIM_MASTER_SESSION_KEY_SIZE;

	eap_variable_data_c expansion(m_am_tools);
	eap_variable_data_c seed(m_am_tools);

	status = seed.add_data(&m_NAI);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = data_exp(
		data_length,
		&expansion,
		XKEY,
		&seed);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("generate_shared_secred_keys(): expansion\n")));
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("expansion"),
		expansion.get_data(),
		expansion.get_data_length()));

	u8_t *data = expansion.get_data_offset(0u, data_length);
	if (data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	const u8_t * const data_begin = data;

	EAP_UNREFERENCED_PARAMETER(data_begin);

	// K_encr, K_aut and master_session_key

	status = K_encr->set_copy_of_buffer(data, aes_key_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	data += aes_key_length;
	EAP_ASSERT_ALWAYS(static_cast<u32_t>(data-data_begin) <= data_length);

	status = K_aut->set_copy_of_buffer(data, EAP_TYPE_GSMSIM_MAC_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	data += EAP_TYPE_GSMSIM_MAC_SIZE;
	EAP_ASSERT_ALWAYS(static_cast<u32_t>(data-data_begin) <= data_length);

	status = master_session_key->set_copy_of_buffer(data, EAP_TYPE_GSMSIM_MASTER_SESSION_KEY_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	data += EAP_TYPE_GSMSIM_MASTER_SESSION_KEY_SIZE;
	EAP_ASSERT_ALWAYS(static_cast<u32_t>(data-data_begin) <= data_length);


	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("generate_shared_secred_keys(): K_encr\n")));
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("   K_encr"),
		K_encr->get_data(),
		K_encr->get_data_length()));

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("generate_shared_secred_keys(): K_aut\n")));
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("    K_aut"),
		K_aut->get_data(),
		K_aut->get_data_length()));

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("generate_shared_secred_keys(): master_session_key\n")));
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL(" MSK+EMSK"),
		master_session_key->get_data(),
		master_session_key->get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - -


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::generate_reauth_shared_secred_keys(
	const u32_t key_length,
	const eap_variable_data_c * const orig_XKEY,
	const u32_t reauth_counter,
	const eap_variable_data_c * const reauth_identity,
	const eap_variable_data_c * const reauth_nonce_s,
	eap_variable_data_c * const master_session_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	u16_t counter = eap_htons(static_cast<u16_t>(reauth_counter));
	eap_variable_data_c reauth_XKEY(m_am_tools);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("generate_reauth_shared_secred_keys():\n")));
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("reauth NAI"),
		reauth_identity->get_data(),
		reauth_identity->get_data_length()));
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("reauth_counter"),
		&counter,
		sizeof(counter)));
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("NONCE_S"),
		reauth_nonce_s->get_data(),
		reauth_nonce_s->get_data_length()));
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("orig_XKEY"),
		orig_XKEY->get_data(),
		orig_XKEY->get_data_length()));

	eap_status_e status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	// XKEY = SHA1(Identity|counter|NONCE_S|original XKEY)

	crypto_sha1_c sha1(m_am_tools);

	if (sha1.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (sha1.hash_init() != eap_status_ok)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_GSMSIM_ERROR,
			(EAPL("ERROR: generate_reauth_shared_secred_keys(): init() failed.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = sha1.hash_update(
		reauth_identity->get_data(),
		reauth_identity->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(
		&counter,
		sizeof(counter));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(
		reauth_nonce_s->get_data(),
		reauth_nonce_s->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(
		orig_XKEY->get_data(),
		orig_XKEY->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = reauth_XKEY.init(key_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	reauth_XKEY.set_is_valid();
	reauth_XKEY.set_data_length(key_length);

	u32_t md_length = key_length;

	status = sha1.hash_final(
		reauth_XKEY.get_data_offset(0u, key_length),
		&md_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_ASSERT_ALWAYS(md_length == key_length);


	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("generate_reauth_shared_secred_keys(): reauth_XKEY\n")));
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("reauth_XKEY"),
		reauth_XKEY.get_data(),
		reauth_XKEY.get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t aes_key_length = m_am_tools->get_crypto()->aes_key_length();
	u32_t data_length = aes_key_length + EAP_TYPE_GSMSIM_MAC_SIZE + EAP_TYPE_GSMSIM_MASTER_SESSION_KEY_SIZE;

	eap_variable_data_c expansion(m_am_tools);
	eap_variable_data_c seed(m_am_tools);

	status = seed.add_data(&m_NAI);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = data_exp(
		data_length,
		&expansion,
		&reauth_XKEY,
		&seed);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("generate_reauth_shared_secred_keys(): expansion\n")));
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("expansion"),
		expansion.get_data(),
		expansion.get_data_length()));

	u8_t *data = expansion.get_data_offset(0u, data_length);
	if (data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	const u8_t * const data_begin = data;

	EAP_UNREFERENCED_PARAMETER(data_begin);

	// Only master_session_key is used in re-authentication.

	status = master_session_key->set_copy_of_buffer(data, EAP_TYPE_GSMSIM_MASTER_SESSION_KEY_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	data += EAP_TYPE_GSMSIM_MASTER_SESSION_KEY_SIZE;
	EAP_ASSERT_ALWAYS(static_cast<u32_t>(data-data_begin) <= data_length);


	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("generate_reauth_shared_secred_keys(): master_session_key\n")));
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("     MSK+EMSK"),
		master_session_key->get_data(),
		master_session_key->get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - -


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
/**
 * This function stores pointer to the received triplet array.
 */
void eap_type_gsmsim_c::set_triplets(eap_type_sim_triplet_array_c * const triplets)
{
	if (m_triplets != 0)
	{
		delete m_triplets;
		m_triplets = 0;
	}
	m_triplets = triplets;
}
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::save_version(
	const u16_t * const payload_version_list,
	const u32_t version_count,
	const eap_gsmsim_version selected_version)
{
	m_gsmsim_selected_version = selected_version;

	eap_status_e status = m_gsmsim_version_list.set_copy_of_buffer(
		payload_version_list,
		sizeof(payload_version_list[0])*version_count);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_type_gsmsim_c::random_selection()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	crypto_random_c rand(m_am_tools);

	if (rand.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return false;
	}

	return (rand.get_rand_integer(0, 1) != 0);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::send_final_notification()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_is_valid == true)
	{
		if (m_is_client == true
			&& m_n_rands.get_is_valid_data() == true)
		{
			eap_status_e status = m_am_type_gsmsim->set_rand_is_used(&m_n_rands);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_data_payload);
			}
		}

		if (m_authentication_finished_successfully == false)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
				(EAPL("EAP_type_GSMSIM: %s, authentication FAILED, state %s\n"),
				 (m_is_client == true) ? "client": "server",
				 get_state_string()));

			if (m_gsmsim_notification_code != eap_gsmsim_notification_none)
			{
				// We have received EAP-Request/SIM notification, we pass the received code to the adaptation module.
				m_am_type_gsmsim->handle_gsmsim_notification(m_gsmsim_notification_code);
			}

			set_state(eap_type_gsmsim_state_failure);

			// Notifies the lower level of unsuccessfull authentication.
			eap_state_notification_c notification(
				m_am_tools,
				&m_send_network_id,
				m_is_client,
				eap_state_notification_eap,
				eap_protocol_layer_eap,
				eap_type_gsmsim,
				eap_state_none,
				eap_state_authentication_terminated_unsuccessfully,
				m_last_eap_identifier,
				false);

			notification.set_authentication_error(eap_status_authentication_failure);

			state_notification(&notification);

			// Indicate GSMSIM AM authentication finish.
			m_am_type_gsmsim->authentication_finished(false, m_authentication_type, m_identity_type);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::add_padding_payload(
	gsmsim_header_c * const gsmsim,
	const u32_t gsmsim_buffer_length,
	const u32_t eap_header_size,
	u32_t * const gsmsim_data_offset,
	u32_t * const gsmsim_data_free,
	u32_t * const packet_buffer_free,
	u32_t * const packet_buffer_offset,
	const u32_t plaintext_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	gsmsim_payload_AT_header_c gp_padding(
		m_am_tools,
		gsmsim->get_data_offset(
			*gsmsim_data_offset, *gsmsim_data_free),
		*gsmsim_data_free);

	if (gp_padding.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	crypto_aes_c aes(m_am_tools);
	crypto_cbc_c cbc_aes(m_am_tools, &aes, false);

	if (cbc_aes.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t cbc_aes_data_length = cbc_aes.aligned_data_length(plaintext_length);
	u32_t padding_bytes_length = 0u;

	if (cbc_aes_data_length > plaintext_length+gsmsim_payload_AT_header_c::get_header_length())
	{
		// Fill with zero (0x00) bytes.
		padding_bytes_length = cbc_aes_data_length - (plaintext_length+gsmsim_payload_AT_header_c::get_header_length());
	}

	u32_t padding_payload_length = gsmsim_payload_AT_header_c::get_header_length()+padding_bytes_length;

	if ((padding_payload_length % EAP_TYPE_GSMSIM_PADDING_MODULUS) != 0)
	{
		// ERROR
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_padding);
	}

	if (padding_payload_length > EAP_TYPE_GSMSIM_PADDING_MAX_VALUE)
	{
		padding_payload_length = 0ul;
		padding_bytes_length = 0ul;
	}

	// Note the reserved field is the begin of padding.
	// The reserved field is set zero in reset_header() function.
	gp_padding.reset_header(static_cast<u16_t>(padding_payload_length));
	gp_padding.set_data_length(static_cast<u16_t>(padding_bytes_length));
	gp_padding.set_current_payload(gsmsim_payload_AT_PADDING);

	if (padding_payload_length > 0u)
	{
		if (padding_bytes_length > 0ul)
		{
			u8_t *padding = gp_padding.get_data(padding_bytes_length);
			if (padding == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
			}

			cbc_aes.add_padding_bytes(
				padding,
				padding_bytes_length,
				0ul);
		}

		update_payload_indexes(
			gsmsim_buffer_length,
			eap_header_size,
			gp_padding.get_header_length()+gp_padding.get_data_length(),
			gsmsim_data_offset,
			gsmsim_data_free,
			packet_buffer_offset,
			packet_buffer_free);

		EAP_GSMSIM_TRACE_PAYLOAD("Payload added", &gp_padding);
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("GSMSIM: Padding payload not needed.\n")));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::add_variable_payload(
	gsmsim_header_c * const gsmsim,
	const u32_t gsmsim_buffer_length,
	const u32_t eap_header_size,
	u32_t * const gsmsim_data_offset,
	u32_t * const gsmsim_data_free,
	u32_t * const packet_buffer_free,
	u32_t * const packet_buffer_offset,
	const eap_variable_data_c * const data_payload,
	const gsmsim_payload_AT_type_e data_payload_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;
	u16_t data_length = 0u;

	if (data_payload != 0)
	{
		if (data_payload->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_data_payload);
		}

		if (data_payload->get_data_length() > gsmsim_payload_AT_header_c::get_max_payload_data_length())
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		data_length = static_cast<u16_t>(data_payload->get_data_length());
	}
	else
	{
		// No data.
		data_length = 0u;
	}

	gsmsim_payload_AT_header_c gp_data(
		m_am_tools,
		gsmsim->get_data_offset(*gsmsim_data_offset, *gsmsim_data_free),
		*gsmsim_data_free);

	if (gp_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	gp_data.reset_header(data_length);

	if (data_length > 0u)
	{
		u8_t *payload_buffer = gp_data.get_data(data_length);
		if (payload_buffer == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_am_tools->memmove(
			payload_buffer,
			data_payload->get_data(),
			data_payload->get_data_length());
	}

	gp_data.set_data_length(data_length);

	status = eap_status_ok;


	gp_data.set_current_payload(data_payload_type);

	update_payload_indexes(
		gsmsim_buffer_length,
		eap_header_size,
		gp_data.get_header_length()+gp_data.get_data_length(),
		gsmsim_data_offset,
		gsmsim_data_free,
		packet_buffer_offset,
		packet_buffer_free);

	EAP_GSMSIM_TRACE_PAYLOAD("Payload added", &gp_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// Note the specification of IMSI payload is not same as pseudonym.
// IMSI and pseudonym specifications should be integrated.
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::add_pseudonym_or_imsi_payload(
	gsmsim_header_c * const gsmsim,
	const u32_t gsmsim_buffer_length,
	const u32_t eap_header_size,
	u32_t * const gsmsim_data_offset,
	u32_t * const gsmsim_data_free,
	u32_t * const packet_buffer_free,
	u32_t * const packet_buffer_offset,
	const eap_variable_data_c * const pseudonym_or_imsi,
	const gsmsim_payload_AT_type_e data_payload_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	if (pseudonym_or_imsi->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_data_payload);
	}

	u32_t padding_zero_count = 0u;
	// Add padding zero octets
	if ((pseudonym_or_imsi->get_data_length() % 4u) != 0)
	{
		padding_zero_count = 4u - (pseudonym_or_imsi->get_data_length() % 4u);
	}

	if (pseudonym_or_imsi->get_data_length()+padding_zero_count
		> gsmsim_payload_AT_header_c::get_max_payload_data_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (pseudonym_or_imsi->get_data_length()+padding_zero_count > *packet_buffer_free)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	gsmsim_payload_AT_header_c gp_data(
		m_am_tools,
		gsmsim->get_data_offset(
			*gsmsim_data_offset, 
			*gsmsim_data_free),
		*gsmsim_data_free);

	if (gp_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	gp_data.reset_header(static_cast<u16_t>(pseudonym_or_imsi->get_data_length()+padding_zero_count));

	u8_t *payload_buffer = gp_data.get_data(pseudonym_or_imsi->get_data_length()+padding_zero_count);

	if (payload_buffer == 0
		|| pseudonym_or_imsi->get_data_length() == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_am_tools->memmove(
		payload_buffer,
		pseudonym_or_imsi->get_data(),
		pseudonym_or_imsi->get_data_length());

	if (padding_zero_count > 0u)
	{
		m_am_tools->memset(
			payload_buffer+(pseudonym_or_imsi->get_data_length()),
			0,
			padding_zero_count);
	}

	// Note the reserved field includes the actual length of pseudonym in network order.
	// This must be less or equal to the length field.
	gp_data.set_reserved(static_cast<u16_t>(pseudonym_or_imsi->get_data_length()));

	gp_data.set_data_length(static_cast<u16_t>(pseudonym_or_imsi->get_data_length()+padding_zero_count));

	status = eap_status_ok;

	gp_data.set_current_payload(data_payload_type);

	update_payload_indexes(
		gsmsim_buffer_length,
		eap_header_size,
		gp_data.get_header_length()+gp_data.get_data_length(),
		gsmsim_data_offset,
		gsmsim_data_free,
		packet_buffer_offset,
		packet_buffer_free);

	EAP_GSMSIM_TRACE_PAYLOAD("Payload added", &gp_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::add_version_list(
	gsmsim_header_c * const gsmsim,
	const u32_t gsmsim_buffer_length,
	const u32_t eap_header_size,
	u32_t * const gsmsim_data_offset,
	u32_t * const gsmsim_data_free,
	u32_t * const packet_buffer_free,
	u32_t * const packet_buffer_offset,
	const eap_gsmsim_version *gsmsim_versions,
	const u32_t gsmsim_versions_count,
	const gsmsim_payload_AT_type_e data_payload_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	u32_t version_list_size = sizeof(u16_t)*gsmsim_versions_count;
	u32_t padding_zero_count = 0u;
	// Add padding zero octets
	if ((version_list_size % 4u) != 0)
	{
		padding_zero_count = 4u - (version_list_size % 4u);
	}

	if (version_list_size+padding_zero_count
		> gsmsim_payload_AT_header_c::get_max_payload_data_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (version_list_size+padding_zero_count > *packet_buffer_free)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	gsmsim_payload_AT_header_c gp_data(
		m_am_tools,
		gsmsim->get_data_offset(
			*gsmsim_data_offset, 
			*gsmsim_data_free),
		*gsmsim_data_free);

	if (gp_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	gp_data.reset_header(static_cast<u16_t>(version_list_size+padding_zero_count));

	u8_t *payload_buffer = gp_data.get_data(version_list_size+padding_zero_count);

	if (payload_buffer == 0
		|| version_list_size == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u16_t *payload_version_list = reinterpret_cast<u16_t *>(payload_buffer);
	u32_t ind;
	for (ind = 0u; ind < gsmsim_versions_count; ind++)
	{
		payload_version_list[ind] = eap_htons(static_cast<u16_t>(gsmsim_versions[ind]));
	}

	if (padding_zero_count > 0u)
	{
		m_am_tools->memset(
			payload_buffer+(version_list_size),
			0,
			padding_zero_count);
	}

	// Note the reserved field includes the actual length of version list in network order.
	// This must be less or equal to the length field.
	gp_data.set_reserved(static_cast<u16_t>(version_list_size));

	gp_data.set_data_length(static_cast<u16_t>(version_list_size+padding_zero_count));

	status = eap_status_ok;

	gp_data.set_current_payload(data_payload_type);

	update_payload_indexes(
		gsmsim_buffer_length,
		eap_header_size,
		gp_data.get_header_length()+gp_data.get_data_length(),
		gsmsim_data_offset,
		gsmsim_data_free,
		packet_buffer_offset,
		packet_buffer_free);

	EAP_GSMSIM_TRACE_PAYLOAD("Payload added", &gp_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::add_notification_payload(
	gsmsim_header_c * const gsmsim,
	const u32_t gsmsim_buffer_length,
	const u32_t eap_header_size,
	u32_t * const gsmsim_data_offset,
	u32_t * const gsmsim_data_free,
	u32_t * const packet_buffer_free,
	u32_t * const packet_buffer_offset,
	const eap_gsmsim_notification_codes_e notification_code)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	gsmsim_payload_AT_header_c gp_data(
		m_am_tools,
		gsmsim->get_data_offset(
			*gsmsim_data_offset, 
			*gsmsim_data_free),
		*gsmsim_data_free);

	if (gp_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	gp_data.reset_header(0u);

	// Note the reserved field includes the notificatio code in network order.
	gp_data.set_reserved(static_cast<u16_t>(notification_code));

	gp_data.set_data_length(0u);

	status = eap_status_ok;

	gp_data.set_current_payload(gsmsim_payload_AT_NOTIFICATION);

	update_payload_indexes(
		gsmsim_buffer_length,
		eap_header_size,
		gp_data.get_header_length()+gp_data.get_data_length(),
		gsmsim_data_offset,
		gsmsim_data_free,
		packet_buffer_offset,
		packet_buffer_free);

	EAP_GSMSIM_TRACE_PAYLOAD("Payload added", &gp_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::add_client_error_payload(
	gsmsim_header_c * const gsmsim,
	const u32_t gsmsim_buffer_length,
	const u32_t eap_header_size,
	u32_t * const gsmsim_data_offset,
	u32_t * const gsmsim_data_free,
	u32_t * const packet_buffer_free,
	u32_t * const packet_buffer_offset,
	const eap_gsmsim_client_error_code_e client_error_code)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	gsmsim_payload_AT_header_c gp_data(
		m_am_tools,
		gsmsim->get_data_offset(
			*gsmsim_data_offset, 
			*gsmsim_data_free),
		*gsmsim_data_free);

	if (gp_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	gp_data.reset_header(0u);

	// Note the reserved field includes the triplet status in network order.
	// This must be less or equal to the length field.
	gp_data.set_reserved(static_cast<u16_t>(client_error_code));

	gp_data.set_data_length(0u);

	status = eap_status_ok;

	gp_data.set_current_payload(gsmsim_payload_AT_CLIENT_ERROR_CODE);

	update_payload_indexes(
		gsmsim_buffer_length,
		eap_header_size,
		gp_data.get_header_length()+gp_data.get_data_length(),
		gsmsim_data_offset,
		gsmsim_data_free,
		packet_buffer_offset,
		packet_buffer_free);

	EAP_GSMSIM_TRACE_PAYLOAD("Payload added", &gp_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::add_version_payload(
	gsmsim_header_c * const gsmsim,
	const u32_t gsmsim_buffer_length,
	const u32_t eap_header_size,
	u32_t * const gsmsim_data_offset,
	u32_t * const gsmsim_data_free,
	u32_t * const packet_buffer_free,
	u32_t * const packet_buffer_offset,
	const eap_gsmsim_version version)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	gsmsim_payload_AT_header_c gp_data(
		m_am_tools,
		gsmsim->get_data_offset(
			*gsmsim_data_offset, 
			*gsmsim_data_free),
		*gsmsim_data_free);

	if (gp_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	gp_data.reset_header(0u);

	// Note the reserved field includes the selected version in network order.
	gp_data.set_reserved(static_cast<u16_t>(version));

	gp_data.set_data_length(0u);

	status = eap_status_ok;

	gp_data.set_current_payload(gsmsim_payload_AT_SELECTED_VERSION);

	update_payload_indexes(
		gsmsim_buffer_length,
		eap_header_size,
		gp_data.get_header_length()+gp_data.get_data_length(),
		gsmsim_data_offset,
		gsmsim_data_free,
		packet_buffer_offset,
		packet_buffer_free);

	EAP_GSMSIM_TRACE_PAYLOAD("Payload added", &gp_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::add_counter_payload(
	gsmsim_header_c * const gsmsim,
	const u32_t gsmsim_buffer_length,
	const u32_t eap_header_size,
	u32_t * const gsmsim_data_offset,
	u32_t * const gsmsim_data_free,
	u32_t * const packet_buffer_free,
	u32_t * const packet_buffer_offset,
	u16_t counter)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	gsmsim_payload_AT_header_c gp_data(
		m_am_tools,
		gsmsim->get_data_offset(
			*gsmsim_data_offset, 
			*gsmsim_data_free),
		*gsmsim_data_free);

	if (gp_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	gp_data.reset_header(0u);

	// Note the reserved field includes the selected version in network order.
	gp_data.set_reserved(counter);

	gp_data.set_data_length(0u);

	status = eap_status_ok;

	gp_data.set_current_payload(gsmsim_payload_AT_COUNTER);

	update_payload_indexes(
		gsmsim_buffer_length,
		eap_header_size,
		gp_data.get_header_length()+gp_data.get_data_length(),
		gsmsim_data_offset,
		gsmsim_data_free,
		packet_buffer_offset,
		packet_buffer_free);

	EAP_GSMSIM_TRACE_PAYLOAD("Payload added", &gp_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::add_simple_payload(
	gsmsim_header_c * const gsmsim,
	const u32_t gsmsim_buffer_length,
	const u32_t eap_header_size,
	u32_t * const gsmsim_data_offset,
	u32_t * const gsmsim_data_free,
	u32_t * const packet_buffer_free,
	u32_t * const packet_buffer_offset,
	const gsmsim_payload_AT_type_e data_payload_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	gsmsim_payload_AT_header_c gp_data(
		m_am_tools,
		gsmsim->get_data_offset(
			*gsmsim_data_offset, 
			*gsmsim_data_free),
		*gsmsim_data_free);

	if (gp_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	gp_data.reset_header(0u);

	gp_data.set_reserved(0u);

	gp_data.set_data_length(0u);

	status = eap_status_ok;

	gp_data.set_current_payload(data_payload_type);

	update_payload_indexes(
		gsmsim_buffer_length,
		eap_header_size,
		gp_data.get_header_length()+gp_data.get_data_length(),
		gsmsim_data_offset,
		gsmsim_data_free,
		packet_buffer_offset,
		packet_buffer_free);

	EAP_GSMSIM_TRACE_PAYLOAD("Payload added", &gp_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::encrypt_DATA_payload(
	u8_t * const data,
	const u32_t cbc_aes_data_length,
	const eap_variable_data_c * const IV,
	const eap_variable_data_c * const encryption_key
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	if (data == 0
		|| cbc_aes_data_length == 0
		|| IV == 0
		|| IV->get_is_valid_data() == false
		|| encryption_key == 0
		|| encryption_key->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}
	
	crypto_aes_c aes(m_am_tools);
	crypto_cbc_c cbc_aes(m_am_tools, &aes, false);

	if (cbc_aes.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t aes_key_length = aes.get_key_length();
	if (encryption_key->get_data_length() < aes_key_length)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	status = cbc_aes.set_encryption_key(
		IV->get_data(),
		IV->get_data_length(),
		encryption_key->get_data(),
		aes_key_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = cbc_aes.encrypt_data(
		data,
		cbc_aes_data_length);

	store_last_encryption_iv(cbc_aes.get_tmp_IV());

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::add_mac_payload(
	gsmsim_header_c * const gsmsim,
	const u32_t gsmsim_buffer_length,
	const u32_t eap_header_size,
	u32_t * const gsmsim_data_offset,
	u32_t * const gsmsim_data_free,
	u32_t * const packet_buffer_free,
	u32_t * const packet_buffer_offset,
	u8_t ** const MAC_data,
	u32_t * const MAC_data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	gsmsim_payload_AT_header_c gp_MAC(
		m_am_tools,
		gsmsim->get_data_offset(
			*gsmsim_data_offset, *gsmsim_data_free),
		*gsmsim_data_free);

	if (gp_MAC.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	u32_t eap_type_gsmsim_mac_size = EAP_TYPE_GSMSIM_MAC_SIZE;

	gp_MAC.reset_header(static_cast<u16_t>(eap_type_gsmsim_mac_size));
	gp_MAC.set_data_length(static_cast<u16_t>(eap_type_gsmsim_mac_size));
	gp_MAC.set_current_payload(gsmsim_payload_AT_MAC);

	*MAC_data = gp_MAC.get_data(eap_type_gsmsim_mac_size);
	if (*MAC_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}
	*MAC_data_length = eap_type_gsmsim_mac_size;

	m_am_tools->memset(*MAC_data, 0, eap_type_gsmsim_mac_size);

	// MAC is calculated later using call create_message_authentication_code().

	update_payload_indexes(
		gsmsim_buffer_length,
		eap_header_size,
		gp_MAC.get_header_length()+gp_MAC.get_data_length(),
		gsmsim_data_offset,
		gsmsim_data_free,
		packet_buffer_offset,
		packet_buffer_free);

	EAP_GSMSIM_TRACE_PAYLOAD("Payload added", &gp_MAC);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::check_version_list(
	const gsmsim_payload_AT_header_c * const payload,
	const u16_t version_list_length,
	u8_t *version_list,
	bool * const includes_other_version_than_1)
{
	eap_status_e status(eap_status_process_general_error);

	if (payload->get_data_length() > version_list_length)
	{
		// Check padding bytes are zero.
		const u8_t * const padding = &version_list[version_list_length];
		const u32_t padding_count = payload->get_data_length() - version_list_length;

		crypto_aes_c aes(m_am_tools);
		crypto_cbc_c cbc_aes(m_am_tools, &aes, false);

		if (cbc_aes.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = cbc_aes.check_padding_bytes(
			padding,
			padding_count,
			0ul);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			// Illegal padding byte.
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_padding);
		}
	}

	gsmsim_variable_data_c tmp_version_list(m_am_tools);

	status = tmp_version_list.set_buffer(
		payload, version_list, version_list_length, false, false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_gsmsim_version selected_version = select_version(&tmp_version_list, includes_other_version_than_1);

	if (selected_version == GSMSIM_ILLEGAL_VERSION)
	{
		// ERROR, no supported version.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::check_version_list(), illegal version list.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_no_matching_protocol_version);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::parse_generic_payload(
	const gsmsim_payload_AT_type_e current_payload,
	const gsmsim_payload_AT_header_c * const payload,
	gsmsim_payloads_c * const p_gsmsim_payloads,
	const gsmsim_subtype_e subtype)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_GSMSIM_TRACE_PAYLOAD("Parsing payload", payload);

	if ((payload->get_payload_length() % static_cast<u16_t>(GSMSIM_PAYLOAD_LENGTH_ALIGN)) != 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_GSMSIM_ERROR,
			(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
			 EAPL("current payload 0x%04x=%s, length 0x%04x not aligned to 0x%04x.\n"),
			payload, current_payload, payload->get_payload_AT_string(),
			payload->get_payload_length(), GSMSIM_PAYLOAD_LENGTH_ALIGN));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);		
	}

	eap_status_e status(eap_status_process_general_error);

	if (current_payload == gsmsim_payload_AT_NONCE_MT)
	{
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |AT_NONCE_MT    | Length = 5    |           Reserved            |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// |                           NONCE_MT                            |
		// |                                                               |
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		if (payload->get_reserved() != 0u)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_GSMSIM_ERROR,
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, reserved field incorrect 0x%04x.\n"),
				payload, current_payload, payload->get_payload_AT_string(),
				 payload->get_payload_length(), payload->get_reserved()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		if (payload->get_data_length() != EAP_TYPE_GSMSIM_NONCE_MT_SIZE)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_GSMSIM_ERROR,
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data length incorrect 0x%04x.\n"),
				payload, current_payload, payload->get_payload_AT_string(),
				 payload->get_payload_length(), payload->get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u8_t * buffer
			= static_cast<u8_t *>(payload->get_data(EAP_TYPE_GSMSIM_NONCE_MT_SIZE));

		if (buffer == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data buffer incorrect.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		// Note here we get a reference to the data bytes of the received packet.
		status = p_gsmsim_payloads->get_NONCE_MT()->set_buffer(
			payload, buffer, payload->get_data_length(), false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == gsmsim_payload_AT_NONCE_S)
	{
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |AT_NONCE_S     | Length = 5    |           Reserved            |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// |                           NONCE_S                             |
		// |                                                               |
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		if (payload->get_reserved() != 0u)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, reserved field incorrect 0x%04x.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), payload->get_reserved()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		if (payload->get_data_length() != EAP_TYPE_GSMSIM_NONCE_MT_SIZE)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data length incorrect 0x%04x.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), payload->get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u8_t * buffer
			= static_cast<u8_t *>(payload->get_data(EAP_TYPE_GSMSIM_NONCE_MT_SIZE));

		if (buffer == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data buffer incorrect.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		// Note here we get a reference to the data bytes of the received packet.
		status = p_gsmsim_payloads->get_NONCE_S()->set_buffer(
			payload, buffer, payload->get_data_length(), false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == gsmsim_payload_AT_RAND)
	{
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// | AT_RAND       | Length        |           Reserved            |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                            n*RAND ...
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		if (payload->get_reserved() != 0u)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, reserved field incorrect 0x%04x.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), payload->get_reserved()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		if (payload->get_data_length() < m_minimum_rand_count*SIM_RAND_LENGTH)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x. Too few RAND bytes 0x%04x, 0x%04x bytes required.\n"),
				payload,
				current_payload,
				payload->get_payload_AT_string(),
				payload->get_payload_length(),
				payload->get_data_length(),
				m_minimum_rand_count*SIM_RAND_LENGTH));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_not_enough_challenges);
		}

		if ((payload->get_data_length() % SIM_RAND_LENGTH) != 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, n*RAND length ")
				 EAPL("0x%04x is not multiple of one RAND length 0x%04x bytes.\n"),
				payload,
				current_payload,
				payload->get_payload_AT_string(),
				payload->get_payload_length(),
				payload->get_data_length(),
				SIM_RAND_LENGTH));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_data_payload);
		}

		u8_t * n_rands = static_cast<u8_t *>(payload->get_data(payload->get_data_length()));
		if (n_rands == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data buffer incorrect.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		status = p_gsmsim_payloads->get_n_RANDs()->set_buffer(
			payload, n_rands, payload->get_data_length(), false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == gsmsim_payload_AT_PADDING)
	{
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  AT_PADDING   | Length        | Padding...                    |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
		// |                                                               |
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		u8_t * padding = 0;

		// Note two first octets of padding are the reserved field. It must be zero.
		if (payload->get_reserved() != 0u)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, reserved field incorrect 0x%04x.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), payload->get_reserved()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		// NOTE padding data length could be zero.
		if (payload->get_data_length() != 0u)
		{
			padding = static_cast<u8_t *>(payload->get_data(payload->get_data_length()));
		}

		status = p_gsmsim_payloads->get_padding_payload()->set_buffer(
			payload, padding, payload->get_data_length(), false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == gsmsim_payload_AT_NEXT_PSEUDONYM)
	{
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// | AT_NEXT...YM  | Length        | Actual Pseudonym Length       |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// |                           Pseudonym                           |
		// |                                                               |
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		// Note the reserved field includes the actual length of pseudonym.
		// This must be less or equal to the length field.
		u16_t pseudonym_length = payload->get_reserved();
		if (pseudonym_length == 0u
			|| pseudonym_length > payload->get_data_length())
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, pseudonym length field incorrect 0x%04x.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), payload->get_reserved()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u8_t * pseudonym = static_cast<u8_t *>(payload->get_data(pseudonym_length));
		if (pseudonym == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_GSMSIM_ERROR,
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): current payload 0x%04x=%s, length 0x%04x, data buffer incorrect.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		status = p_gsmsim_payloads->get_NEXT_PSEUDONYM()->set_buffer(
			payload, pseudonym, pseudonym_length, false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == gsmsim_payload_AT_NEXT_REAUTH_ID)
	{
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// | AT_NEXT...ID  | Length        | Actual Identity Length        |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// |                  Reauthentication identity                    |
		// |                                                               |
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		// Note the reserved field includes the actual length of reauthentication identity.
		// This must be less or equal to the length field.
		u16_t next_reauth_id_length = payload->get_reserved();
		if (next_reauth_id_length == 0u
			|| next_reauth_id_length > payload->get_data_length())
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, reauthentication identity length field incorrect 0x%04x.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), payload->get_reserved()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u8_t * next_reauth_id = static_cast<u8_t *>(payload->get_data(next_reauth_id_length));
		if (next_reauth_id == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data buffer incorrect.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		status = p_gsmsim_payloads->get_NEXT_REAUTH_ID()->set_buffer(
			payload, next_reauth_id, next_reauth_id_length, false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == gsmsim_payload_AT_RESULT_IND)
	{
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// | AT_RESULT_IND | Length = 1    |      Reserved                 |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		if (payload->get_data_length() != GSMSIM_PAYLOAD_ZERO_DATA_LENGTH)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data length incorrect 0x%04x, should be 0x%04x.\n"),
				 payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), 
				 payload->get_data_length(), GSMSIM_PAYLOAD_ZERO_DATA_LENGTH));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
			 EAPL("current payload 0x%04x=%s, length 0x%04x, notification code %d.\n"),
			payload,
			current_payload,
			payload->get_payload_AT_string(),
			payload->get_payload_length(),
			payload->get_reserved()));

		status = p_gsmsim_payloads->get_RESULT_IND()->set_buffer(
			payload, 0, 0u, false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == gsmsim_payload_AT_NOTIFICATION)
	{
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |AT_NOTIFICATION| Length = 1    |      Notification Code        |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		if (payload->get_data_length() != GSMSIM_PAYLOAD_ZERO_DATA_LENGTH)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data length incorrect 0x%04x, should be 0x%04x.\n"),
				 payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), 
				 payload->get_data_length(), GSMSIM_PAYLOAD_ZERO_DATA_LENGTH));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		// Note the reserved field includes the notification code (triplet status).
		eap_gsmsim_notification_codes_e notification_code = static_cast<eap_gsmsim_notification_codes_e>(payload->get_reserved());
		EAP_UNREFERENCED_PARAMETER(notification_code);

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
			 EAPL("current payload 0x%04x=%s, length 0x%04x, notification code %d.\n"),
			payload,
			current_payload,
			payload->get_payload_AT_string(),
			payload->get_payload_length(),
			payload->get_reserved()));

		status = p_gsmsim_payloads->get_NOTIFICATION()->set_buffer(
			payload, 0, 0u, false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == gsmsim_payload_AT_COUNTER)
	{
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |AT_COUNTER     | Length = 1    |      Counter                  |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		if (payload->get_data_length() != GSMSIM_PAYLOAD_ZERO_DATA_LENGTH)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data length incorrect 0x%04x, should be 0x%04x.\n"),
				 payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), 
				 payload->get_data_length(), GSMSIM_PAYLOAD_ZERO_DATA_LENGTH));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		status = p_gsmsim_payloads->get_COUNTER()->set_buffer(
			payload, 0, 0u, false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == gsmsim_payload_AT_COUNTER_TOO_SMALL)
	{
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |AT_COUNTER_TOO.| Length = 1    |           Reserved            |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		if (payload->get_data_length() != GSMSIM_PAYLOAD_ZERO_DATA_LENGTH)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data length incorrect 0x%04x, should be 0x%04x.\n"),
				 payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), 
				 payload->get_data_length(), GSMSIM_PAYLOAD_ZERO_DATA_LENGTH));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
			 EAPL("current payload 0x%04x=%s, length 0x%04x, reserved %d.\n"),
			payload,
			current_payload,
			payload->get_payload_AT_string(),
			payload->get_payload_length(),
			payload->get_reserved()));

		status = p_gsmsim_payloads->get_counter_too_small()->set_buffer(
			payload, 0, 0u, false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == gsmsim_payload_AT_MAC)
	{
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// | AT_MAC        | Length = 5    |           Reserved            |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// |                           MAC                                 |
		// |                                                               |
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		if (payload->get_reserved() != 0u)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, reserved field incorrect 0x%04x.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), payload->get_reserved()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		if (payload->get_data_length() != EAP_TYPE_GSMSIM_MAC_SIZE)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data length incorrect 0x%04x.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), payload->get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u8_t * buffer
			= static_cast<u8_t *>(payload->get_data(EAP_TYPE_GSMSIM_MAC_SIZE));

		if (buffer == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data buffer incorrect.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		status = p_gsmsim_payloads->get_MAC()->set_buffer(
			payload, buffer, payload->get_data_length(), false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == gsmsim_payload_AT_IV)
	{
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// | AT_IV         | Length = 5    |           Reserved            |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// |                 Initialization Vector (optional)              |
		// |                                                               |
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		if (payload->get_reserved() != 0u)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, reserved field incorrect 0x%04x.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), payload->get_reserved()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		crypto_aes_c aes(m_am_tools);

		if (aes.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (payload->get_data_length() != aes.get_block_size())
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data length incorrect 0x%04x.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), payload->get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u8_t * buffer
			= static_cast<u8_t *>(payload->get_data(payload->get_data_length()));

		if (buffer == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data buffer incorrect.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		// Note here we get a reference to the data bytes of the received packet.
		status = p_gsmsim_payloads->get_IV()->set_buffer(
			payload, buffer, payload->get_data_length(), false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == gsmsim_payload_AT_ENCR_DATA)
	{
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// | AT_ENCR_DATA  | Length        |           Reserved            |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// |                    Encrypted Data (optional)                  |
		// |                                                               |
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		if (payload->get_reserved() != 0u)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, reserved field incorrect 0x%04x.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), payload->get_reserved()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		if (payload->get_data_length() < 8u)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data length incorrect 0x%04x.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), payload->get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u8_t * buffer
			= static_cast<u8_t *>(payload->get_data(payload->get_data_length()));

		if (buffer == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data buffer incorrect.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		status = p_gsmsim_payloads->get_ENCR_DATA()->set_buffer(
			payload, buffer, payload->get_data_length(), false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == gsmsim_payload_AT_PERMANENT_ID_REQ)
	{
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |AT_PERM..._REQ | Length = 1    |           Reserved            |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		if (payload->get_data_length() != GSMSIM_PAYLOAD_ZERO_DATA_LENGTH)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data length incorrect 0x%04x, should be 0x%04x.\n"),
				 payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), 
				 payload->get_data_length(), GSMSIM_PAYLOAD_ZERO_DATA_LENGTH));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		status = p_gsmsim_payloads->get_PERMANENT_ID_REQ()->set_buffer(
			payload, 0, 0, false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == gsmsim_payload_AT_FULLAUTH_ID_REQ)
	{
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |AT_FULL..._REQ | Length = 1    |           Reserved            |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		if (payload->get_data_length() != GSMSIM_PAYLOAD_ZERO_DATA_LENGTH)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data length incorrect 0x%04x, should be 0x%04x.\n"),
				 payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), 
				 payload->get_data_length(), GSMSIM_PAYLOAD_ZERO_DATA_LENGTH));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		status = p_gsmsim_payloads->get_FULLAUTH_ID_REQ()->set_buffer(
			payload, 0, 0, false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == gsmsim_payload_AT_ANY_ID_REQ)
	{
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |AT_ANY..._REQ  | Length = 1    |           Reserved            |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		if (payload->get_data_length() != GSMSIM_PAYLOAD_ZERO_DATA_LENGTH)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data length incorrect 0x%04x, should be 0x%04x.\n"),
				 payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), 
				 payload->get_data_length(), GSMSIM_PAYLOAD_ZERO_DATA_LENGTH));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		status = p_gsmsim_payloads->get_ANY_ID_REQ()->set_buffer(
			payload, 0, 0, false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == gsmsim_payload_AT_IDENTITY)
	{
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// | AT_IDENTITY   | Length        | Actual Identity Length        |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// .                 Current Identity (optional)                   .
		// |                                                               |
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		u16_t identity_length = payload->get_reserved();

		if (payload->get_data_length() == 0
			|| identity_length > payload->get_data_length()
			|| identity_length < 1u)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data length incorrect 0x%04x, identity_length 0x%04x.\n"),
				 payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), 
				 payload->get_data_length(), identity_length));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u8_t * identity_data
			= static_cast<u8_t *>(payload->get_data(payload->get_data_length()));

		if (identity_data == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data buffer incorrect.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		if (identity_length < payload->get_data_length())
		{
			crypto_aes_c aes(m_am_tools);
			crypto_cbc_c cbc_aes(m_am_tools, &aes, false);

			if (cbc_aes.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			// Includes padding bytes. Those must be zero.
			eap_status_e status = cbc_aes.check_padding_bytes(
				identity_data+identity_length,
				payload->get_data_length()-identity_length,
				0ul);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// We assume the prefix byte is included.
		status = p_gsmsim_payloads->get_IDENTITY_payload()->set_buffer(
			payload, identity_data, identity_length, false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == gsmsim_payload_AT_VERSION_LIST)
	{
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// | AT_VERSION_L..| Length        | Actual Version List Length    |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  Supported Version 1          |  Padding                      |                        
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   

		// Note the reserved field includes the actual length of version list.
		// This must be less or equal to the length field.
		u16_t version_list_length = payload->get_reserved();
		if (version_list_length == 0u
			|| version_list_length > payload->get_data_length())
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, version list length field incorrect 0x%04x.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), payload->get_reserved()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u8_t * version_list = static_cast<u8_t *>(payload->get_data(version_list_length));
		if (version_list == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data buffer incorrect.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		bool includes_other_version_than_1 = false;

		eap_status_e status = check_version_list(payload, version_list_length, version_list, &includes_other_version_than_1);
		if (status != eap_status_ok)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data buffer incorrect.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		p_gsmsim_payloads->set_includes_other_version_than_1(includes_other_version_than_1);

		status = p_gsmsim_payloads->get_VERSION_LIST()->set_buffer(
			payload, version_list, version_list_length, false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == gsmsim_payload_AT_SELECTED_VERSION)
	{
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// | AT_SELECTED...| Length = 1    |    Selected Version           |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		if (payload->get_data_length() != GSMSIM_PAYLOAD_ZERO_DATA_LENGTH)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data length incorrect 0x%04x, should be 0x%04x.\n"),
				 payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), 
				 payload->get_data_length(), GSMSIM_PAYLOAD_ZERO_DATA_LENGTH));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		// Note the reserved field includes the selected version.
		eap_gsmsim_version selected_version = static_cast<eap_gsmsim_version>(payload->get_reserved());

		if (selected_version != GSMSIM_VERSION_1) // This is the only supported GSMSIM version.
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, illegal GSMSIM version %d.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), selected_version));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
			 EAPL("current payload 0x%04x=%s, length 0x%04x, selected_version %d.\n"),
			payload,
			current_payload,
			payload->get_payload_AT_string(),
			payload->get_payload_length(),
			selected_version));

		status = p_gsmsim_payloads->get_SELECTED_VERSION()->set_buffer(
			payload, 0, 0u, false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == gsmsim_payload_AT_CLIENT_ERROR_CODE)
	{
		// The format of the AT_CLIENT_ERROR_CODE attribute is shown below.

		//  0                   1                   2                   3
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |AT_CLIENT_ERR..| Length = 1    |     Client Error Code         |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// Note the reserved field includes the selected version.

		if (payload->get_data_length() != GSMSIM_PAYLOAD_ZERO_DATA_LENGTH)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data length incorrect 0x%04x, should be 0x%04x.\n"),
				 payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), 
				 payload->get_data_length(), GSMSIM_PAYLOAD_ZERO_DATA_LENGTH));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		eap_gsmsim_client_error_code_e client_error_code = static_cast<eap_gsmsim_client_error_code_e>(payload->get_reserved());

		if (client_error_code > eap_gsmsim_client_error_code_maximum_value)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, illegal GSMSIM version %d.\n"),
				payload, current_payload, payload->get_payload_AT_string(), payload->get_payload_length(), client_error_code));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_gsmsim_c::parse_generic_payload(0x%08x): ")
			 EAPL("current payload 0x%04x=%s, length 0x%04x, client_error_code %d.\n"),
			payload,
			current_payload,
			payload->get_payload_AT_string(),
			payload->get_payload_length(),
			client_error_code));

		status = p_gsmsim_payloads->get_CLIENT_ERROR_CODE()->set_buffer(
			payload, 0, 0u, false, false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (128 <= current_payload && current_payload <= 255)
	{
		// Unknown skippable attribute.
		if (subtype == gsmsim_subtype_Start)
		{
			// EAP-Request/SIM/Start and EAP-Response/SIM/Start messages may
			// include unknown non-skippable attributes if version list includes
			// other than version 1.
			p_gsmsim_payloads->set_includes_unknown_attribute(current_payload);

			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("IGNORED: eap_type_gsmsim_c::parse_generic_payload(): Marked non-skippable attribute %d=0x%04x.\n"),
				current_payload,
				current_payload));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
		else
		{
			// Silently ignore this payload.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("IGNORED: eap_type_gsmsim_c::parse_generic_payload(): Ignored skippable attribute %d=0x%04x.\n"),
				current_payload,
				current_payload));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
	}
	else
	{
		// Unknown non-skippable attribute.
		if (subtype == gsmsim_subtype_Start)
		{
			// EAP-Request/SIM/Start and EAP-Response/SIM/Start messages may
			// include unknown non-skippable attributes if version list includes
			// other than version 1.
			p_gsmsim_payloads->set_includes_unknown_attribute(current_payload);

			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("IGNORED: eap_type_gsmsim_c::parse_generic_payload(): Marked non-skippable attribute %d=0x%04x.\n"),
				current_payload,
				current_payload));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
		else
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::parse_generic_payload(): Unknown non-skippable attribute %d=0x%04x.\n"),
				current_payload,
				current_payload));
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unsupported_gsmsim_payload);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::analyse_gsmsim_packet(
	const eap_am_network_id_c * const receive_network_id,
	gsmsim_header_c * const received_gsmsim,
	const u32_t gsmsim_packet_length,
	gsmsim_payloads_c * const p_gsmsim_payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	if (m_is_client == true)
	{
		// Client

		if (received_gsmsim->get_subtype() == gsmsim_subtype_Start)
		{
			status = handle_start_request_message(
				receive_network_id,
				received_gsmsim,
				gsmsim_packet_length,
				p_gsmsim_payloads);
		}
		else if (received_gsmsim->get_subtype() == gsmsim_subtype_Challenge)
		{
			status = handle_challenge_request_message(
				receive_network_id,
				received_gsmsim,
				gsmsim_packet_length,
				p_gsmsim_payloads);
		}
		else if (received_gsmsim->get_subtype() == gsmsim_subtype_Notification)
		{
			status = handle_gsmsim_notification_request_message(
				receive_network_id,
				received_gsmsim,
				gsmsim_packet_length,
				p_gsmsim_payloads);
		}
		else if (received_gsmsim->get_subtype() == gsmsim_subtype_Re_authentication)
		{
			status = handle_reauthentication_request_message(
				receive_network_id,
				received_gsmsim,
				gsmsim_packet_length,
				p_gsmsim_payloads);
		}
		else
		{
			// Unknown message in this state.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::analyse_gsmsim_packet(): ")
				 EAPL("Unknown message %d=%s in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				received_gsmsim->get_subtype(),
				received_gsmsim->get_subtype_string(),
				m_state,
				get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
	else
	{
		// Server

#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
		if (received_gsmsim->get_subtype() == gsmsim_subtype_Start)
		{
			status = handle_start_response_message(
				received_gsmsim,
				gsmsim_packet_length,
				p_gsmsim_payloads);
		}
		else if (received_gsmsim->get_subtype() == gsmsim_subtype_Challenge)
		{
			status = handle_challenge_response_message(
				receive_network_id,
				received_gsmsim,
				gsmsim_packet_length,
				p_gsmsim_payloads);
		}
		else if (received_gsmsim->get_subtype() == gsmsim_subtype_Notification)
		{
			status = handle_notification_response_message(
				receive_network_id,
				received_gsmsim,
				gsmsim_packet_length,
				p_gsmsim_payloads);
		}
		else if (received_gsmsim->get_subtype() == gsmsim_subtype_Re_authentication)
		{
			status = handle_reauthentication_response_message(
				receive_network_id,
				received_gsmsim,
				gsmsim_packet_length,
				p_gsmsim_payloads);
		}
		else if (received_gsmsim->get_subtype() == gsmsim_subtype_Client_Error)
		{
			status = handle_client_error_response_message(
				receive_network_id,
				received_gsmsim,
				gsmsim_packet_length,
				p_gsmsim_payloads);
		}
		else
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
		{
			// Unknown message in this state.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::analyse_gsmsim_packet(): ")
				 EAPL("Unknown message %d=%s in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				received_gsmsim->get_subtype(),
				received_gsmsim->get_subtype_string(),
				m_state,
				get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::parse_gsmsim_payload(
	const gsmsim_payload_AT_header_c * const p_payload,
	u32_t * const buffer_length,
	gsmsim_payloads_c * const p_gsmsim_payloads,
	const gsmsim_subtype_e subtype)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	gsmsim_payload_AT_header_c payload(
		m_am_tools,
		p_payload->get_header_buffer(*buffer_length),
		*buffer_length); // Const correctness is gone.

	gsmsim_payload_AT_type_e current_payload = payload.get_current_payload();

	eap_status_e status = eap_status_header_corrupted;

	if (payload.get_is_valid() == true
		&& current_payload != gsmsim_payload_NONE)
	{
		if (*buffer_length < payload.get_header_length()+payload.get_data_length())
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_GSMSIM_ERROR,
				(EAPL("ERROR: eap_type_gsmsim_c::parse_gsmsim_payload(0x%08x): current payload 0x%04x=%s, data length 0x%04x, buffer length 0x%04x.\n"),
				payload.get_header_buffer(0ul),
				 current_payload,
				 payload.get_payload_AT_string(),
				 payload.get_data_length(),
				 *buffer_length));
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_GSMSIM_ERROR,
				(EAPL("ERROR: eap_type_gsmsim_c::parse_gsmsim_payload(): GSMSIM-payload header is corrupted.\n")));
			EAP_TRACE_DATA_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("payload"),
				payload.get_header_buffer(*buffer_length),
				*buffer_length));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		status = parse_generic_payload(current_payload, &payload, p_gsmsim_payloads, subtype);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_ASSERT_ALWAYS(*buffer_length >= payload.get_header_length()+payload.get_data_length());
		*buffer_length -= payload.get_header_length()+payload.get_data_length();

		while(*buffer_length >= payload.get_header_length()
			&& payload.get_is_valid() == true
			&& payload.get_header_buffer_length() >= (payload.get_header_length()+payload.get_data_length()))
		{
			payload.set_header_buffer(
					payload.get_next_header(),
					payload.get_header_buffer_length()-(payload.get_header_length()+payload.get_data_length()));
			if (payload.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}

			current_payload = payload.get_current_payload();

			if (*buffer_length < payload.get_header_length()+payload.get_data_length())
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_GSMSIM_ERROR,
					(EAPL("ERROR: eap_type_gsmsim_c::parse_gsmsim_payload(0x%08x): current payload 0x%04x=%s, data length 0x%04x, buffer length 0x%04x.\n"),
					 payload.get_header_buffer(0ul),
					 current_payload,
					 payload.get_payload_AT_string(),
					 payload.get_data_length(),
					 *buffer_length));
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_GSMSIM_ERROR,
					(EAPL("ERROR: eap_type_gsmsim_c::parse_gsmsim_payload(): GSMSIM-payload header is corrupted.\n")));
				EAP_TRACE_DATA_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("payload"),
					payload.get_header_buffer(*buffer_length),
					*buffer_length));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}

			status = parse_generic_payload(current_payload, &payload, p_gsmsim_payloads, subtype);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_ASSERT_ALWAYS(*buffer_length >= payload.get_header_length()+payload.get_data_length());
			*buffer_length -= payload.get_header_length()+payload.get_data_length();
		}
	}

	if (*buffer_length != 0u)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_GSMSIM_ERROR,
			(EAPL("ERROR: eap_type_gsmsim_c::parse_gsmsim_payload(): ")
			 EAPL("GSMSIM-header is corrupted. Buffer length and payload length does not match. %lu illegal bytes.\n"),
			 *buffer_length));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::parse_gsmsim_packet(
	gsmsim_header_c * const gsmsim,
	const u32_t gsmsim_packet_length,
	gsmsim_payloads_c * const p_gsmsim_payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (gsmsim->get_length() < gsmsim->get_header_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_GSMSIM_ERROR,
			(EAPL("ERROR: eap_type_gsmsim_c::parse_gsmsim_packet(): ")
			 EAPL("GSMSIM-header is corrupted. Buffer length and payload ")
			 EAPL("length does not match. GSMSIM-header length %lu < minimum GSMSIM-header length %lu.\n"),
			gsmsim->get_length(),
			gsmsim->get_header_length()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	if (gsmsim->get_length() > gsmsim_packet_length)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::parse_gsmsim_packet(): ")
			 EAPL("GSMSIM-header is corrupted. Buffer length and payload ")
			 EAPL("length does not match. GSMSIM-header length %lu > packet length %lu\n"),
			gsmsim->get_length(),
			gsmsim_packet_length));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	u32_t buffer_length = gsmsim->get_length() - gsmsim->get_header_length();

	if (buffer_length == 0u)
	{
		// No payload in this packet.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}


	gsmsim_payload_AT_header_c payload(
		m_am_tools,
		gsmsim->get_data(buffer_length),
		buffer_length);

	if (payload.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: No gsmsim_payload_AT_header_c.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}


	eap_status_e status = parse_gsmsim_payload(
		&payload,
		&buffer_length,
		p_gsmsim_payloads,
		gsmsim->get_subtype());

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (buffer_length != 0u)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_GSMSIM_ERROR,
			(EAPL("ERROR: eap_type_gsmsim_c::parse_gsmsim_packet(): ")
			 EAPL("GSMSIM-header is corrupted. Buffer length and payload ")
			 EAPL("length does not match. Illegal byte count %lu\n"),
			buffer_length));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_gsmsim_packet(
	const eap_am_network_id_c * const receive_network_id,
	gsmsim_header_c * const received_gsmsim,
	const u32_t gsmsim_length,
	gsmsim_payloads_c * const p_gsmsim_payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_header_corrupted);

#if !defined(NO_EAP_TYPE_GSMSIM_MESSAGE_STATE_CHECK)

	status = check_valid_state(received_gsmsim->get_subtype());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

#endif //#if !defined(NO_EAP_TYPE_GSMSIM_MESSAGE_STATE_CHECK)

	status = parse_gsmsim_packet(received_gsmsim, gsmsim_length, p_gsmsim_payloads);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = analyse_gsmsim_packet(
		receive_network_id,
		received_gsmsim,
		gsmsim_length,
		p_gsmsim_payloads);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

// 
EAP_FUNC_EXPORT void eap_type_gsmsim_c::packet_trace(
	eap_const_string prefix,
	const eap_am_network_id_c * const /* receive_network_id */,
	eap_header_wr_c * const eap_packet,
	const u32_t /* eap_packet_length */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(prefix);

	if (eap_packet->get_length() > eap_header_base_c::get_header_length()
		&& eap_packet->get_type() == eap_type_gsmsim)
	{
		gsmsim_header_c gsmsim_eap(
			m_am_tools,
			eap_packet->get_header_buffer(eap_packet->get_header_buffer_length()),
			eap_packet->get_header_buffer_length());

		gsmsim_eap.get_code(); // This is just to make some use in release version.

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("%s EAP_type_GSMSIM: %s, (0x%08x), code=0x%02x=%s, identifier=0x%02x, ")
			 EAPL("length=0x%04x, type=0x%08x=%s, subtype=0x%02x=%s\n"),
			 prefix,
			 (m_is_client == true) ? "client": "server",
			 this,
			 gsmsim_eap.get_code(),
			 gsmsim_eap.get_code_string(),
			 gsmsim_eap.get_identifier(),
			 gsmsim_eap.get_length(),
			 convert_eap_type_to_u32_t(gsmsim_eap.get_type()),
			 gsmsim_eap.get_eap_type_string(),
			 gsmsim_eap.get_subtype(),
			 gsmsim_eap.get_subtype_string()));
		
		EAP_TRACE_DEBUG(m_am_tools, eap_am_tools_c::eap_trace_mask_eap_messages,
			(EAPL("\n\t%s\n\tcode       = 0x%02x   = %s\n\tidentifier = 0x%02x")
			 EAPL("\n\tlength     = 0x%04x = %lu\n\ttype       = 0x%08x   = %s\n\tsubtype    = 0x%02x   = %s\n"),
			(m_is_client == true) ? "client": "server",
			gsmsim_eap.get_code(),
			gsmsim_eap.get_code_string(),
			gsmsim_eap.get_identifier(),
			gsmsim_eap.get_length(),
			gsmsim_eap.get_length(),
			convert_eap_type_to_u32_t(gsmsim_eap.get_type()),
			gsmsim_eap.get_eap_type_string(),
			gsmsim_eap.get_subtype(),
			gsmsim_eap.get_subtype_string()));
	}
	else if (eap_packet->get_length() > eap_header_base_c::get_header_length())
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("%s EAP_type_GSMSIM: %s, (0x%08x), code=0x%02x=%s, identifier=0x%02x, length=0x%04x, type=0x%08x=%s\n"),
			prefix,
			(m_is_client == true) ? "client": "server",
			this,
			eap_packet->get_code(),
			eap_packet->get_code_string(),
			eap_packet->get_identifier(),
			eap_packet->get_length(),
			convert_eap_type_to_u32_t(eap_packet->get_type()),
			eap_packet->get_type_string()));

		EAP_TRACE_DEBUG(
			m_am_tools,
			eap_am_tools_c::eap_trace_mask_eap_messages,
			(EAPL("\n\t%s\n\tcode       = 0x%02x   = %s\n\tidentifier = 0x%02x\n\tlength     = 0x%04x = %lu\n\ttype       = 0x%08x   = %s\n"),
			(m_is_client == true) ? "client": "server",
			eap_packet->get_code(),
			eap_packet->get_code_string(),
			eap_packet->get_identifier(),
			eap_packet->get_length(),
			eap_packet->get_length(),
			convert_eap_type_to_u32_t(eap_packet->get_type()),
			eap_packet->get_type_string()));
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("%s EAP_type_GSMSIM: %s, (0x%08x), code=0x%02x=%s, identifier=0x%02x, length=0x%04x\n"),
			prefix,
			(m_is_client == true) ? "client": "server",
			this,
			eap_packet->get_code(),
			eap_packet->get_code_string(),
			eap_packet->get_identifier(),
			eap_packet->get_length()));

		EAP_TRACE_DEBUG(
			m_am_tools,
			eap_am_tools_c::eap_trace_mask_eap_messages,
			(EAPL("\n\t%s\n\tcode       = 0x%02x   = %s\n\tidentifier = 0x%02x\n\tlength     = 0x%04x = %lu\n"),
			(m_is_client == true) ? "client": "server",
			eap_packet->get_code(),
			eap_packet->get_code_string(),
			eap_packet->get_identifier(),
			eap_packet->get_length(),
			eap_packet->get_length()));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}


//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_variable_data_c * eap_type_gsmsim_c::get_nai_realm()
{
	return &m_manual_realm;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT void eap_type_gsmsim_c::update_buffer_indexes(
	const u32_t maximum_buffer_size,
	const u32_t payload_size,
	u32_t * const buffer_offset,
	u32_t * const buffer_free)
{
	EAP_UNREFERENCED_PARAMETER(maximum_buffer_size);

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT_ALWAYS(*buffer_offset + *buffer_free <= maximum_buffer_size-m_trailer_length);
	EAP_ASSERT_ALWAYS(*buffer_free >= payload_size);
	EAP_ASSERT_ALWAYS(m_gsmsim_header_offset+m_MTU == *buffer_offset + *buffer_free);

	*buffer_free -= payload_size;
	*buffer_offset += payload_size;

	EAP_ASSERT_ALWAYS(*buffer_offset + *buffer_free <= maximum_buffer_size-m_trailer_length);
	EAP_ASSERT_ALWAYS(*buffer_offset <= m_gsmsim_header_offset+m_MTU);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT void eap_type_gsmsim_c::update_payload_indexes(
	const u32_t maximum_buffer_size,
	const u32_t eap_header_size,
	const u32_t payload_size,
	u32_t * const data_offset,
	u32_t * const data_free,
	u32_t * const buffer_offset,
	u32_t * const buffer_free)
{
	EAP_UNREFERENCED_PARAMETER(eap_header_size);

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT_ALWAYS(*buffer_offset == m_gsmsim_header_offset + eap_header_size + *data_offset);
	EAP_ASSERT_ALWAYS(*buffer_free == *data_free);
	EAP_ASSERT_ALWAYS(*data_free >= payload_size);

	*data_free -= payload_size;
	*data_offset += payload_size;

	update_buffer_indexes(
		maximum_buffer_size,
		payload_size,
		buffer_offset,
		buffer_free);

	EAP_ASSERT_ALWAYS(*buffer_offset == m_gsmsim_header_offset + eap_header_size + *data_offset);
	EAP_ASSERT_ALWAYS(*buffer_free == *data_free);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT bool eap_type_gsmsim_c::get_is_client() 
{
	return m_is_client;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT void eap_type_gsmsim_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT bool eap_type_gsmsim_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT void eap_type_gsmsim_c::state_notification(
	const abs_eap_state_notification_c * const state
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::state_notification(): get_type_partner() 0x%08x\n"), 
		 get_type_partner()));

	get_type_partner()->state_notification(state);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::finish_successful_authentication(
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::finish_successful_authentication().\n")));

	if (m_is_client
		&& m_n_rands.get_is_valid_data() == true)
	{
		if (m_do_rand_uniqueness_check == true)
		{
			eap_status_e status = m_am_type_gsmsim->set_rand_is_used(
				&m_n_rands);
			if (status != eap_status_ok)
			{
				// ERROR: write to database failed..
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_data_payload);
			}
		}
	}

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());

	if (m_master_session_key.get_is_valid_data() == false
		|| m_master_session_key.get_data_length() == 0u)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	eap_status_e status = get_type_partner()->packet_data_crypto_keys(
		&send_network_id,
		&m_master_session_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_authentication_finished_successfully = true;
	set_state(eap_type_gsmsim_state_success);

	eap_state_notification_c notification(
		m_am_tools,
		&m_send_network_id,
		m_is_client,
		eap_state_notification_eap,
		eap_protocol_layer_eap,
		eap_type_gsmsim,
		eap_state_none,
		eap_state_authentication_finished_successfully,
		m_last_eap_identifier,
		true);
	state_notification(&notification);

	// Indicate GSMSIM AM authentication finish.
	m_am_type_gsmsim->authentication_finished(true, m_authentication_type, m_identity_type);


	if (m_authentication_type == GSMSIM_AUTHENTICATION_TYPE_REAUTHENTICATION)
	{
		EAP_TRACE_ALWAYS(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
			(EAPL("EAP_type_GSMSIM: %s, re-authentication EAP-SUCCESS, ")
			 EAPL("re-authentication identity\n"),
			(m_is_client == true) ? "client": "server"));
	}
	else if (m_authentication_type == GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH)
	{
		if (m_identity_type == GSMSIM_IDENTITY_TYPE_PSEUDONYM_ID)
		{
			EAP_TRACE_ALWAYS(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
				(EAPL("EAP_type_GSMSIM: %s, full authentication EAP-SUCCESS, ")
				 EAPL("pseudonym identity\n"),
				(m_is_client == true) ? "client": "server"));
		}
		else if (m_identity_type == GSMSIM_IDENTITY_TYPE_IMSI_ID)
		{
			EAP_TRACE_ALWAYS(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
				(EAPL("EAP_type_GSMSIM: %s, full authentication EAP-SUCCESS, ")
				 EAPL("IMSI identity\n"),
				(m_is_client == true) ? "client": "server"));
		}
		else if (m_identity_type == GSMSIM_IDENTITY_TYPE_RE_AUTH_ID)
		{
			EAP_TRACE_ALWAYS(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
				(EAPL("EAP_type_GSMSIM: %s, full authentication EAP-SUCCESS, ")
				 EAPL("Re-auth identity\n"),
				(m_is_client == true) ? "client": "server"));
		}
		else
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS|TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: EAP_type_GSMSIM: %s, unknown authentication EAP-SUCCESS, ")
				 EAPL("unknown identity\n"),
				(m_is_client == true) ? "client": "server"));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}
	}
	else
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS|TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: EAP_type_GSMSIM: %s, unknown authentication EAP-SUCCESS, ")
			 EAPL("unknown identity\n"),
			(m_is_client == true) ? "client": "server"));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
	}


	cancel_error_message_delay_timer();

	cancel_notification_message_delay_timer();

	status = eap_status_ok;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::packet_process(
	const eap_am_network_id_c * const receive_network_id,
	eap_header_wr_c * const received_eap,
	const u32_t eap_packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::packet_process(): receive_network_id=0x%08x is invalid.\n"),
			receive_network_id));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (received_eap == 0
		|| received_eap->get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::packet_process(): received_eap 0x%08x is invalid.\n"),
			received_eap));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	EAP_GSMSIM_PACKET_TRACE(
		EAPL("->"),
		receive_network_id,
		received_eap,
		eap_packet_length);

	if (eap_packet_length < received_eap->get_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::packet_process(): ")
			 EAPL("eap_packet_length=0x%04x < received_eap->get_length()=0x%04x.\n"),
			eap_packet_length, received_eap->get_length()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (received_eap->get_length() < eap_header_base_c::get_header_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::packet_process(): received_eap->get_length() ")
			 EAPL("< eap_header_base_c::get_header_length().\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}


	// NOTE: by disabling these calls throughput increases about 18%.
	// Disabling also decreases random seeds.
	m_am_tools->get_crypto()->add_rand_seed(
		received_eap->get_header_buffer(eap_packet_length),
		eap_packet_length);
	m_am_tools->get_crypto()->add_rand_seed_hw_ticks();

	eap_status_e status = eap_status_process_general_error;

	if ((m_is_client == true
		&& received_eap->get_code() == eap_code_request)
		|| (m_is_client == false
		&& received_eap->get_code() == eap_code_response))
	{
		if (received_eap->get_type() == eap_type_identity
			|| received_eap->get_type() == eap_type_gsmsim)
		{
			if (received_eap->get_type() == eap_type_identity
				&& received_eap->get_code() == eap_code_request
				&& received_eap->get_length() <= eap_header_base_c::get_header_length())
			{
				status = eap_status_header_corrupted;
			}
			else if (received_eap->get_type() == eap_type_identity
				&& received_eap->get_code() == eap_code_response
				&& received_eap->get_length() <= eap_header_base_c::get_header_length())
			{
				status = eap_status_header_corrupted;
			}
			else if (received_eap->get_type() == eap_type_gsmsim
				&& received_eap->get_length() < received_eap->get_header_length())
			{
				status = eap_status_header_corrupted;
			}
			else
			{
				gsmsim_header_c gsmsim_header(
					m_am_tools,
					received_eap->get_header_buffer(received_eap->get_header_buffer_length()),
					received_eap->get_header_buffer_length());

				if (gsmsim_header.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
				}

				status = gsmsim_packet_process(
					receive_network_id,
					&gsmsim_header,
					eap_packet_length,
					m_is_client);

				if (status != eap_status_ok
					&& status != eap_status_success
					&& status != eap_status_drop_packet_quietly
					&& status != eap_status_pending_request)
				{
					eap_status_string_c status_string;
					EAP_UNREFERENCED_PARAMETER(status_string);
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_GSMSIM_ERROR, 
						(EAPL("ERROR: %s=%d eap_type_gsmsim_c::gsmsim_packet_process() failed\n"),
						status_string.get_status_string(status), status));

					if (m_is_client == true)
					{
						status = initialize_error_message(
							status);
					}
					else
					{
						status = initialize_notification_message();
					}

					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
				else if (status == eap_status_ok)
				{
					EAP_GENERAL_HEADER_SET_ERROR_DETECTED(received_eap, false);
				}
			}

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else if (received_eap->get_type() == eap_type_notification)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("dropped EAP type notification: code=0x%02x, ")
				 EAPL("identifier=0x%02x, length=0x%04x, type=0x%08x\n"),
				 received_eap->get_code(),
				 received_eap->get_identifier(), 
				 received_eap->get_length(),
				 convert_eap_type_to_u32_t(received_eap->get_type())));

			status = eap_status_illegal_eap_type;

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("dropped EAP type unknown: code=0x%02x, ")
				 EAPL("identifier=0x%02x, length=0x%04x, type=0x%08x\n"),
				 received_eap->get_code(),
				 received_eap->get_identifier(), 
				 received_eap->get_length(),
				 convert_eap_type_to_u32_t(received_eap->get_type())));

			status = eap_status_illegal_eap_type;

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (m_is_client == true
		&& (received_eap->get_code() == eap_code_success
		|| received_eap->get_code() == eap_code_failure))
	{
		// Here we swap the addresses.
		eap_am_network_id_c send_network_id(m_am_tools,
			receive_network_id->get_destination_id(),
			receive_network_id->get_source_id(),
			receive_network_id->get_type());

		if (received_eap->get_code() == eap_code_success)
		{
			if (m_state == eap_type_gsmsim_state_waiting_for_success)
			{
				EAP_GENERAL_HEADER_SET_ERROR_DETECTED(received_eap, false);

				if (m_wait_eap_success_packet == false)
				{
					/**
					 * @{ Check right functionality.
					 * Here we return eap_status_ok, eap_status_success was returned after successfull
					 * EAP-Request/SIM/Challenge. This may change after EAP, 802.1X and 802.11i specifications are ready. }
					 */
					status = eap_status_ok;
				}
				else
				{
					status = finish_successful_authentication(
						receive_network_id);
				}
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("dropped EAP-Success: code=0x%02x, identifier=0x%02x, ")
					 EAPL("length=0x%04x, state %d=%s, is client %d\n"),
					received_eap->get_code(),
					received_eap->get_identifier(),
					received_eap->get_length(),
					m_state,
					get_state_string(),
					(m_is_client == true)));
				status = eap_status_drop_packet_quietly;
			}
		}
		else if (received_eap->get_code() == eap_code_failure)
		{
			// EAP is quite sloppy protocol.
			// Somebody just send a EAP-failure message and authentication is terminated.

			// Save received failure. We do not change our state yet.
			// The real correct EAP message could be received later if this failure was
			// send by nasty attacker.
			m_failure_message_received = true;
			// We handle the EAP-Request/Failure message after a timeout.

			status = eap_status_ok;
		}
		else
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("dropped EAP code unknown: code=0x%02x, ")
				 EAPL("identifier=0x%02x, length=0x%04x, is client %d\n"),
				 received_eap->get_code(), received_eap->get_identifier(), 
				 received_eap->get_length(), (m_is_client == true)));
			status = eap_status_illegal_eap_code;
		}
	}
	else
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("dropped EAP code unknown: code=0x%02x, ")
			 EAPL("identifier=0x%02x, length=0x%04x, is client %d\n"),
			 received_eap->get_code(), received_eap->get_identifier(), 
			 received_eap->get_length(), (m_is_client == true)));
		status = eap_status_illegal_eap_code;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::new_handler(
	const eap_am_network_id_c * const /* receive_network_id */,
	const bool is_client_when_true)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::new_handler(): Creating new handler 0x%08x.\n"),
		this));

	// We do not have handler yet and the message is identity EAP-message.
	// A new handler is needed.
	// Handler is selected using own address and peer address.

	m_is_client = is_client_when_true;

	if (is_client_when_true == true)
	{
		set_state(eap_type_gsmsim_state_waiting_for_identity_request);
	}
	else if (is_client_when_true == false)
	{
		set_state(eap_type_gsmsim_state_waiting_for_identity_response);
	}

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::aka_packet_process(0x%08x): New handler created.\n"),
		 this));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL(" own address"),
		m_send_network_id.get_source_id()->get_data(m_send_network_id.get_source_id()->get_data_length()),
		m_send_network_id.get_source_id()->get_data_length()));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("peer address"),
		m_send_network_id.get_destination_id()->get_data(m_send_network_id.get_destination_id()->get_data_length()),
		m_send_network_id.get_destination_id()->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::gsmsim_packet_process(
	const eap_am_network_id_c * const receive_network_id,
	gsmsim_header_c * const received_gsmsim,
	const u32_t gsmsim_packet_length,
	const bool is_client_when_true)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::gsmsim_packet_process(): ")
			 EAPL("receive_network_id=0x%08x is invalid.\n"),
			receive_network_id));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (received_gsmsim == 0
		|| received_gsmsim->get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::gsmsim_packet_process(): ")
			 EAPL("received_gsmsim 0x%08x is invalid.\n"),
			received_gsmsim));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (gsmsim_packet_length < received_gsmsim->get_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::gsmsim_packet_process(): ")
			 EAPL("gsmsim_packet_length < received_gsmsim->get_length().\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (received_gsmsim->get_type() == eap_type_gsmsim)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_gsmsim_c::gsmsim_packet_process(), GSMSIM subtype %d=%s\n"),
			received_gsmsim->get_subtype(), received_gsmsim->get_subtype_string()));
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_gsmsim_c::gsmsim_packet_process(), EAP-type 0x%08x=%s\n"),
			convert_eap_type_to_u32_t(received_gsmsim->get_type()),
			received_gsmsim->get_eap_type_string()));
	}

	eap_status_e status = eap_status_process_general_error;

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());

	if (m_state == eap_type_gsmsim_state_none)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_gsmsim_c::gsmsim_packet_process(): No handler found.\n")));

		if (is_client_when_true == false
			&& received_gsmsim->get_type() == eap_type_identity)
		{
			// The EAP-identity is plain EAP-packet without additional fields..
			eap_header_rd_c eap_header(
				m_am_tools,
				received_gsmsim->get_header_buffer(
					received_gsmsim->get_header_buffer_length()),
				received_gsmsim->get_header_buffer_length());

			// This is just to make some use in release version.
			eap_header.get_type_data_length();

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("received: EAP-identity"),
				eap_header.get_type_data(eap_header.get_type_data_length()),
				eap_header.get_type_data_length()));

			status = new_handler(
				receive_network_id,
				is_client_when_true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_GSMSIM_ERROR, 
					(EAPL("ERROR: eap_type_gsmsim_c::gsmsim_packet_process(): ")
					 EAPL("new_handler() failed, status %d.\n"),
					status));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else if (is_client_when_true == true
			&& received_gsmsim->get_code() == eap_code_request)
		{
			if (received_gsmsim->get_length() < received_gsmsim->get_header_length())
			{
				status = eap_status_process_illegal_packet_error;
				eap_status_string_c status_string;
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_GSMSIM_ERROR,
					(EAPL("ERROR: %s=%d eap_type_gsmsim_c::gsmsim_packet_process(): corrupted GSMSIM-header.\n"),
					status_string.get_status_string(status), status));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// Here we create a handler and set state to
			//  eap_type_gsmsim_state_waiting_for_start_request
			// if first EAP-Request is EAP-Request/SIM/Start.
			if (received_gsmsim->get_subtype() == gsmsim_subtype_Start)
			{
				eap_header_rd_c eap_header(
					m_am_tools,
					received_gsmsim->get_header_buffer(received_gsmsim->get_header_buffer_length()),
					received_gsmsim->get_header_buffer_length());

				EAP_UNREFERENCED_PARAMETER(eap_header);

				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("received: EAP-Request/GSMSIM/Start"),
					eap_header.get_type_data(eap_header.get_type_data_length()),
					eap_header.get_type_data_length()));

				// We must query the previous sent EAP-Identity from EAP_Core.
				// The EAP_Core saves the sent EAP-Identity when the EAP-Identity is
				// sent to the network.
				// Previous EAP-type was NOT this instance. EAP-Identity was queried from other instance.
				status = get_type_partner()->get_saved_eap_identity(&m_identity);
				if (status == eap_status_ok)
				{
					status = m_NAI.set_copy_of_buffer(&m_identity);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH;
					set_identity_type(GSMSIM_IDENTITY_TYPE_IMSI_ID);
				}

				status = new_handler(
					receive_network_id,
					is_client_when_true);
				if (status != eap_status_ok)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_GSMSIM_ERROR, 
						(EAPL("ERROR: eap_type_gsmsim_c::gsmsim_packet_process(): new_handler() failed, status %d.\n"),
						status));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				set_state(eap_type_gsmsim_state_waiting_for_start_request);
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_GSMSIM_ERROR, 
					(EAPL("ERROR: eap_type_gsmsim_c::gsmsim_packet_process(): ")
					 EAPL("Only EAP-Request/SIM/Start message in EAP-SIM client ")
					 EAPL("causes creation of new handler. This EAP-packet is dropped.\n")));

				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_GSMSIM_ERROR,
					(EAPL("ERROR: received:      source"),
					receive_network_id->get_source(),
					receive_network_id->get_source_length()));
				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_GSMSIM_ERROR,
					(EAPL("ERROR: received: destination"),
					receive_network_id->get_destination(),
					receive_network_id->get_destination_length()));

				if (received_gsmsim->get_type() == eap_type_gsmsim)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_GSMSIM_ERROR, 
						(EAPL("ERROR: erroneous EAP packet: code=0x%02x, identifier=0x%02x, ")
						 EAPL("length=0x%04x, type=0x%08x, subtype=0x%02x, client %d\n"),
						received_gsmsim->get_code(),
						received_gsmsim->get_identifier(),
						received_gsmsim->get_length(),
						convert_eap_type_to_u32_t(received_gsmsim->get_type()),
						received_gsmsim->get_subtype(),
						is_client_when_true));
				}
				else
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_GSMSIM_ERROR, 
						(EAPL("ERROR: erroneous EAP packet: code=0x%02x, identifier=0x%02x, ")
						 EAPL("length=0x%04x, type=0x%08x, client %d\n"),
						received_gsmsim->get_code(),
						received_gsmsim->get_identifier(),
						received_gsmsim->get_length(),
						convert_eap_type_to_u32_t(received_gsmsim->get_type()),
						is_client_when_true));
				}
				return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
			}
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::gsmsim_packet_process(): ")
				 EAPL("Only EAP-identity message in server causes creation ")
				 EAPL("of new handler. This EAP-packet is dropped.\n")));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_GSMSIM_ERROR,
				(EAPL("ERROR: received:      source"),
				receive_network_id->get_source(),
				receive_network_id->get_source_length()));
			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_GSMSIM_ERROR,
				(EAPL("ERROR: received: destination"),
				receive_network_id->get_destination(),
				receive_network_id->get_destination_length()));

			if (received_gsmsim->get_type() == eap_type_gsmsim)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_GSMSIM_ERROR, 
					(EAPL("ERROR: erroneous EAP packet: code=0x%02x, identifier=0x%02x, ")
					 EAPL("length=0x%04x, type=0x%08x, subtype=0x%02x, client %d\n"),
					received_gsmsim->get_code(),
					received_gsmsim->get_identifier(),
					received_gsmsim->get_length(),
					convert_eap_type_to_u32_t(received_gsmsim->get_type()),
					received_gsmsim->get_subtype(),
					is_client_when_true));
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_GSMSIM_ERROR, 
					(EAPL("ERROR: erroneous EAP packet: code=0x%02x, identifier=0x%02x, ")
					 EAPL("length=0x%04x, type=0x%08x, client %d\n"),
					received_gsmsim->get_code(),
					received_gsmsim->get_identifier(),
					received_gsmsim->get_length(),
					convert_eap_type_to_u32_t(received_gsmsim->get_type()),
					is_client_when_true));
			}
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
		}
	}

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::gsmsim_packet_process(): state %d=%s\n"),
		 m_state,
		 get_state_string()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("received: GSMSIM packet"),
		 received_gsmsim->get_header_buffer(
			 received_gsmsim->get_header_buffer_length()),
		 received_gsmsim->get_header_buffer_length()));

	if (received_gsmsim->get_type() == eap_type_identity)
	{
		if (is_client_when_true == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::gsmsim_packet_process(): ")
				 EAPL("EAP-Request/Identity is not handled here anymore.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			status = eap_status_process_general_error;
		}
#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
		else if (is_client_when_true == false)
		{
			eap_header_rd_c eap_header(
				m_am_tools,
				received_gsmsim->get_header_buffer(
					received_gsmsim->get_header_buffer_length()),
				received_gsmsim->get_header_buffer_length());

			const eap_type_gsmsim_state_variable_e saved_state = m_state;

			EAP_UNREFERENCED_PARAMETER(saved_state);

			status = handle_identity_response_message(
				&eap_header,
				gsmsim_packet_length);

			if (status != eap_status_ok
				&& status != eap_status_success
				&& status != eap_status_drop_packet_quietly)
			{
				eap_status_string_c status_string;
				EAP_UNREFERENCED_PARAMETER(status_string);
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_GSMSIM_ERROR, 
					(EAPL("ERROR: %s=%d eap_type_gsmsim_c::gsmsim_packet_process(): ")
					 EAPL("handle_identity_response_message().\n"),
					 status_string.get_status_string(status), status));
			}

			if (status == eap_status_ok)
			{
				eap_state_notification_c notification(
					m_am_tools,
					&m_send_network_id,
					m_is_client,
					eap_state_notification_eap,
					eap_protocol_layer_eap,
					eap_type_gsmsim,
					eap_state_none,
					eap_state_identity_response_received,
					m_last_eap_identifier,
					false);
				state_notification(&notification);
			}
		}
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


		if (status == eap_status_ok
			|| status == eap_status_success)
		{
			// Ok, good EAP message received.
			if (m_is_client == true)
			{
				m_failure_message_received = false;
			}
		}
		else
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::gsmsim_packet_process(): ")
				 EAPL("handle_identity_response_message() failed, status %d.\n"),
				 status));
		}

		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (gsmsim_packet_length < received_gsmsim->get_header_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_GSMSIM_ERROR,
			(EAPL("ERROR: eap_type_gsmsim_c::gsmsim_packet_process(): ")
			 EAPL("gsmsim_packet_length < gsmsim_header_c::get_header_length().\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	status = received_gsmsim->check_header();
	if (status != eap_status_ok)
	{
		eap_status_string_c status_string;
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_GSMSIM_ERROR,
			(EAPL("ERROR: %s=%d eap_type_gsmsim_c::gsmsim_packet_process(): ")
			 EAPL("corrupted GSMSIM-header.\n"),
			status_string.get_status_string(status), status));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("received: GSMSIM-type %10s, %s, state %2d=%s\n"),
		 received_gsmsim->get_subtype_string(),
		 (m_is_client) ? EAPL("client") : EAPL("server"),
		 m_state,
		 get_state_string()
		 ));

	gsmsim_payloads_c * const l_gsmsim_payloads = new gsmsim_payloads_c(m_am_tools);
	eap_automatic_variable_c<gsmsim_payloads_c> l_gsmsim_payloads_automatic(
		m_am_tools,
		l_gsmsim_payloads);

	if (l_gsmsim_payloads == 0
		|| l_gsmsim_payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = handle_gsmsim_packet(
		receive_network_id,
		received_gsmsim,
		gsmsim_packet_length,
		l_gsmsim_payloads);

	if (status != eap_status_ok
		&& status != eap_status_success
		&& status != eap_status_drop_packet_quietly
		&& status != eap_status_pending_request)
	{
		eap_status_string_c status_string;
		EAP_UNREFERENCED_PARAMETER(status_string);
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: %s=%d eap_type_gsmsim_c::gsmsim_packet_process(): ")
			 EAPL("handle_gsmsim_packet().\n"),
			status_string.get_status_string(status), status));
	}

	if (status == eap_status_ok
		|| status == eap_status_success
		|| status == eap_status_pending_request)
	{
		// Ok, good EAP message received.
		if (m_is_client == true)
		{
			m_failure_message_received = false;
		}
	}

	if (status == eap_status_ok)
	{
		// Do nothing special.
	}
	else if (status == eap_status_drop_packet_quietly)
	{
		// We will drop this message quietly.
	}
	else if (status != eap_status_ok)
	{
		// EAP-Failure will be sent from shutdown().
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::cancel_error_message_delay_timer()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = cancel_timer(
		this,
		EAP_TYPE_GSMSIM_TIMER_DELAY_FAILURE_MESSAGE_SENT_ID);

	m_erroneus_packet_received = false;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: %s: EAP_TYPE_TIMER_DELAY_FAILURE_MESSAGE_SENT_ID cancelled.\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::set_error_message_delay_timer()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = set_timer(
		this,
		EAP_TYPE_GSMSIM_TIMER_DELAY_FAILURE_MESSAGE_SENT_ID,
		0,
		m_failure_message_delay_time);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: %s: EAP_TYPE_TIMER_DELAY_FAILURE_MESSAGE_SENT_ID set.\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::cancel_notification_message_delay_timer()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = cancel_timer(
		this,
		EAP_TYPE_GSMSIM_TIMER_DELAY_NOTIFICATION_MESSAGE_ID);

	m_erroneus_packet_received = false;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: %s: EAP_TYPE_TIMER_DELAY_NOTIFICATION_MESSAGE_ID cancelled.\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::set_notification_message_delay_timer()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = set_timer(
		this,
		EAP_TYPE_GSMSIM_TIMER_DELAY_NOTIFICATION_MESSAGE_ID,
		0,
		m_failure_message_delay_time);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: %s: EAP_TYPE_TIMER_DELAY_NOTIFICATION_MESSAGE_ID set.\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_error_packet()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_GSMSIM_ERROR, 
		(EAPL("ERROR: eap_type_gsmsim_c::handle_error_packet(): ")
		 EAPL("erroneus_packet_received %d, m_client_error_code %d\n"),
		 m_erroneus_packet_received,
		 m_client_error_code));

	if (m_state == eap_type_gsmsim_state_none)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (m_erroneus_packet_received == true)
	{
		set_state(eap_type_gsmsim_state_failure);

		if (m_is_client == true)
		{
			// Client will send EAP-Response/SIM/Client-Error.
			status = send_gsmsim_client_error_response();
		}
		else
		{
			// Server will send EAP-Failure.
			// Notifies the lower level of unsuccessfull authentication.
			eap_state_notification_c notification(
				m_am_tools,
				&m_send_network_id,
				m_is_client,
				eap_state_notification_eap,
				eap_protocol_layer_eap,
				eap_type_gsmsim,
				eap_state_none,
				eap_state_authentication_terminated_unsuccessfully,
				m_last_eap_identifier,
				false);

			notification.set_authentication_error(eap_status_authentication_failure);

			state_notification(&notification);

			status = eap_status_ok;
		}
	}
	else
	{
		// One erroneous packet is already received.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("WARNING: eap_type_gsmsim_c::handle_error_packet(): one erroneus packet already received. This is ignored.\n")));
		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::initialize_error_message(
	const eap_status_e error_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	eap_status_string_c status_string;
	EAP_UNREFERENCED_PARAMETER(status_string);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_GSMSIM_ERROR, 
		(EAPL("ERROR: eap_type_gsmsim_c::initialize_error_message(): erroneus_packet_received %d, error_status %s\n"),
		 m_erroneus_packet_received,
		 status_string.get_status_string(error_status)));

	if (m_erroneus_packet_received == false)
	{
		// Only the first erroneus packet is recorded.
		m_erroneus_packet_received = true;

		if (m_is_client == true)
		{
			// Client will send EAP-Response/SIM/Client-Error.
			switch(error_status)
			{
			case eap_status_no_matching_protocol_version:
				m_client_error_code = eap_gsmsim_client_error_code_unsupported_version;
				break;
			case eap_status_not_enough_challenges:
				m_client_error_code = eap_gsmsim_client_error_code_insufficient_number_of_challenges;
				break;
			case eap_status_not_fresh_challenges:
				m_client_error_code = eap_gsmsim_client_error_code_rands_are_not_fresh;
				break;
			default:
				m_client_error_code = eap_gsmsim_client_error_code_unable_to_process_packet;
				break;
			};
		}
		else
		{
			// Server will send EAP-Failure.
		}

		if (m_failure_message_delay_time > 0ul)
		{
			// First try set delay timer.
			status = set_error_message_delay_timer();
			if (status != eap_status_ok)
			{
				// ERROR: Process error packet immediately.
				status = handle_error_packet();
			}
		}
		else
		{
			// Process error packet immediately.
			status = handle_error_packet();
		}
	}
	else
	{
		// Error packet is already processed.
		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_notification_packet()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_GSMSIM_ERROR, 
		(EAPL("eap_type_gsmsim_c::handle_notification_packet(): sim_notification_packet_received %d\n"),
		 m_sim_notification_packet_received));

	if (m_state == eap_type_gsmsim_state_none)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (m_sim_notification_packet_received == true)
	{
		bool add_at_counter_attribute = false;
		if (m_authentication_type == GSMSIM_AUTHENTICATION_TYPE_REAUTHENTICATION)
		{
			add_at_counter_attribute = true;
		}

		if (m_is_client == true)
		{
			// Client will send EAP-Response/SIM/Notification.
			if (get_gsmsim_notification_code_F_bit(m_gsmsim_notification_code) == false)
			{
				// The code values with the F bit set to zero (code values 0...32767)
				// are used on unsuccessful cases.
				// The receipt of a notification code from this range implies failed EAP
				// exchange, so the peer can use the notification as a failure indication.
				set_state(eap_type_gsmsim_state_failure);
			}

			status = send_gsmsim_notification_response(
				m_gsmsim_notification_code,
				add_at_counter_attribute);
		}
#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
		else
		{
			set_state(eap_type_gsmsim_state_waiting_for_notification_response_failure);

			// Server will send EAP-Request/SIM/Notification.
			status = send_gsmsim_notification_request(
				m_gsmsim_notification_code,
				add_at_counter_attribute);
		}
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("eap_type_gsmsim_c::handle_notification_packet(): one SIM/Notification packet already received. This is ignored.\n")));

		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::initialize_notification_message()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	if (m_state == eap_type_gsmsim_state_none)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (m_sim_notification_packet_received == false)
	{
		// Only the first SIM notification packet is recorded.
		m_sim_notification_packet_received = true;

		if (m_is_client == true)
		{
			// Client will send empty EAP-Response/SIM/Notification.
		}
		else
		{
			// Server will send EAP-Request/SIM/Notification.
			if (m_gsmsim_notification_code == eap_gsmsim_notification_none)
			{
				m_gsmsim_notification_code = eap_gsmsim_notification_no_F_P_set_general_failure;
			}

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_gsmsim_c::initialize_notification_message(0x%08x), notification_code = 0x%04x, F bit %d, P bit %d.\n"),
				 this,
				 m_gsmsim_notification_code,
				 get_gsmsim_notification_code_F_bit(m_gsmsim_notification_code),
				 get_gsmsim_notification_code_P_bit(m_gsmsim_notification_code)));
		}

		if (m_failure_message_delay_time > 0ul)
		{
			// First try set delay timer.
			status = set_notification_message_delay_timer();
			if (status != eap_status_ok)
			{
				// ERROR: Process SIM notification packet immediately.
				status = handle_notification_packet();
			}
		}
		else
		{
			// Process SIM notification packet immediately.
			status = handle_notification_packet();
		}
	}
	else
	{
		// SIM notification packet is already processed.
		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u32_t eap_type_gsmsim_c::get_header_offset(
	u32_t * const MTU,
	u32_t * const trailer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	u32_t offset = get_type_partner()->get_header_offset(MTU, trailer_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return offset;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::extra_message_authentication_code_bytes(
	const gsmsim_subtype_e subtype,
	const eap_code_value_e code,
	crypto_hmac_c *hmac_sha1)
{
	eap_status_e status(eap_status_ok);

	if (code == eap_code_request)
	{
		if (subtype == gsmsim_subtype_Challenge)
		{
			status = hmac_sha1->hmac_update(
				m_nonce_mt.get_data(),
				m_nonce_mt.get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}
	else if (code == eap_code_response)
	{
		if (subtype == gsmsim_subtype_Challenge)
		{
			status = hmac_sha1->hmac_update(
				m_n_sres.get_data(),
				m_n_sres.get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else if (subtype == gsmsim_subtype_Re_authentication)
		{
			status = hmac_sha1->hmac_update(
				m_nonce_s.get_data(),
				m_nonce_s.get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}
	else
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_GSMSIM_ERROR, (EAPL("ERROR: extra_message_authentication_code_bytes(): unsupported EAP-Code %d.\n"),
			code));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::create_message_authentication_code(
	eap_type_gsmsim_MAC_attributes_c *MAC_attributes,
	const gsmsim_subtype_e subtype,
	const eap_code_value_e code,
	const eap_variable_data_c * const authentication_key
)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (MAC_attributes == 0
		|| authentication_key == 0
		|| authentication_key->get_is_valid_data() == false
		//|| MAC_attributes->get_handler() == 0
		|| MAC_attributes->get_data() == 0
		|| MAC_attributes->get_data_length() == 0u
		|| MAC_attributes->get_MAC() == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, (EAPL("authentication_key"),
		authentication_key->get_data(),
		authentication_key->get_data_length()));

	eap_status_e status = eap_status_process_general_error;

#if defined(USE_EAP_TRACE)
	{
		eap_variable_data_c buffer(m_am_tools);

		status = buffer.set_buffer_length(2048);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = buffer.set_buffer_length(buffer.get_buffer_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		u8_t * const tmpbuffer = buffer.get_data();
		if (tmpbuffer == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t offset = 0;

		m_am_tools->memmove(tmpbuffer+offset,
			(MAC_attributes->get_data()),
			MAC_attributes->get_data_length());
		offset += MAC_attributes->get_data_length();

		if (code == eap_code_request)
		{
			if (subtype == gsmsim_subtype_Challenge)
			{
				m_am_tools->memmove(tmpbuffer+offset,
					m_nonce_mt.get_data(),
					m_nonce_mt.get_data_length());
				offset += m_nonce_mt.get_data_length();
			}
		}
		else if (code == eap_code_response)
		{
			if (subtype == gsmsim_subtype_Challenge)
			{
				m_am_tools->memmove(tmpbuffer+offset,
					m_n_sres.get_data(),
					m_n_sres.get_data_length());
				offset += m_n_sres.get_data_length();
			}
			else if (subtype == gsmsim_subtype_Re_authentication)
			{
				m_am_tools->memmove(tmpbuffer+offset,
					m_nonce_s.get_data(),
					m_nonce_s.get_data_length());
				offset += m_nonce_s.get_data_length();
			}
		}
		else
		{
			EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_GSMSIM_ERROR, (EAPL("ERROR: extra_message_authentication_code_bytes(): unsupported EAP-Code %d.\n"),
				code));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
			(EAPL("create_message_authentication_code(): MAC calculated over the following bytes:\n")));
		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
			(EAPL("MAC data"),
			 tmpbuffer,
			 offset));
	}
#endif // #if defined(USE_EAP_TRACE)


	crypto_sha1_c sha1(m_am_tools);
	crypto_hmac_c hmac_sha1(m_am_tools, &sha1, false);

	if (hmac_sha1.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (hmac_sha1.hmac_set_key(
		authentication_key
		) != eap_status_ok)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_GSMSIM_ERROR, (EAPL("ERROR: create_message_authentication_code(): set_key() failed.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = hmac_sha1.hmac_update(
		MAC_attributes->get_data(),
		MAC_attributes->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = extra_message_authentication_code_bytes(subtype, code, &hmac_sha1);
	if (status != eap_status_ok)
	{
		eap_status_string_c status_string;
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_GSMSIM_ERROR,
			(EAPL("ERROR: %s=%d create_message_authentication_code(): extra_message_authentication_code_bytes().\n"),
			status_string.get_status_string(status), status));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	u32_t length = 0u;

	status = hmac_sha1.hmac_128_final(
		MAC_attributes->get_MAC(),
		&length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_ASSERT(length == EAP_TYPE_GSMSIM_MAC_SIZE);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
		(EAPL("MAC:\n")));
	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
		(EAPL("MAC"),
		 MAC_attributes->get_MAC(),
		 length));


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::check_message_authentication_code(
	const eap_variable_data_c * const authentication_key,
	gsmsim_payloads_c * const p_gsmsim_payloads,
	const gsmsim_header_c * const gsmsim_packet,
	const u32_t gsmsim_packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (authentication_key == 0
		|| authentication_key->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}
	if (p_gsmsim_payloads->get_MAC() == 0
		|| p_gsmsim_payloads->get_MAC()->get_payload_included() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}
	if (gsmsim_packet == 0
		|| gsmsim_packet_length == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, (EAPL("authentication_key"),
		authentication_key->get_data(),
		authentication_key->get_data_length()));

	crypto_sha1_c sha1(m_am_tools);
	crypto_hmac_c hmac_sha1(m_am_tools, &sha1, false);

	if (hmac_sha1.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (hmac_sha1.hmac_set_key(
		authentication_key
		) != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u8_t saved_MAC[EAP_TYPE_GSMSIM_MAC_SIZE];

	m_am_tools->memmove(
		saved_MAC,
		p_gsmsim_payloads->get_MAC()->get_data(p_gsmsim_payloads->get_MAC()->get_data_length()),
		p_gsmsim_payloads->get_MAC()->get_data_length());

	m_am_tools->memset(
		p_gsmsim_payloads->get_MAC()->get_data(p_gsmsim_payloads->get_MAC()->get_data_length()),
		0,
		p_gsmsim_payloads->get_MAC()->get_data_length());


	eap_status_e status = hmac_sha1.hmac_update(
		gsmsim_packet->get_header_buffer(gsmsim_packet_length),
		gsmsim_packet_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = extra_message_authentication_code_bytes(
		gsmsim_packet->get_subtype(),
		gsmsim_packet->get_code(),
		&hmac_sha1);
	if (status != eap_status_ok)
	{
		eap_status_string_c status_string;
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_GSMSIM_ERROR,
			(EAPL("ERROR: %s=%d check_message_authentication_code(): extra_message_authentication_code_bytes().\n"),
			status_string.get_status_string(status), status));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}


	eap_variable_data_c *end_of_authentication = 0;
	if (p_gsmsim_payloads->get_MAC()->get_payload_included() == true)
	{
		end_of_authentication = p_gsmsim_payloads->get_MAC()->get_payload_buffer();
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}


	u32_t length = 0u;

	eap_variable_data_c tmp_MAC(m_am_tools);
	status = tmp_MAC.init(EAP_TYPE_GSMSIM_MAC_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	tmp_MAC.set_is_valid();
	tmp_MAC.set_data_length(EAP_TYPE_GSMSIM_MAC_SIZE);

	u8_t * const mac_data = tmp_MAC.get_data_offset(0u, EAP_TYPE_GSMSIM_MAC_SIZE);
	if (mac_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = hmac_sha1.hmac_128_final(
		mac_data,
		&length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_ASSERT(length == EAP_TYPE_GSMSIM_MAC_SIZE);



#if defined(USE_EAP_TRACE)
	{
		eap_variable_data_c buffer(m_am_tools);

		status = buffer.set_buffer_length(2048);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = buffer.set_buffer_length(buffer.get_buffer_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		u8_t * const tmpbuffer = buffer.get_data();
		if (tmpbuffer == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t offset = 0;

		m_am_tools->memmove(tmpbuffer+offset,
			gsmsim_packet->get_header_buffer(gsmsim_packet_length),
			gsmsim_packet_length);
		offset += gsmsim_packet_length;

		if (gsmsim_packet->get_code() == eap_code_request)
		{
			if (gsmsim_packet->get_subtype() == gsmsim_subtype_Challenge)
			{
				m_am_tools->memmove(tmpbuffer+offset,
					m_nonce_mt.get_data(),
					m_nonce_mt.get_data_length());
				offset += m_nonce_mt.get_data_length();
			}
		}
		else if (gsmsim_packet->get_code() == eap_code_response)
		{
			if (gsmsim_packet->get_subtype() == gsmsim_subtype_Challenge)
			{
				m_am_tools->memmove(tmpbuffer+offset,
					m_n_sres.get_data(),
					m_n_sres.get_data_length());
				offset += m_n_sres.get_data_length();
			}
			else if (gsmsim_packet->get_subtype() == gsmsim_subtype_Re_authentication)
			{
				m_am_tools->memmove(tmpbuffer+offset,
					m_nonce_s.get_data(),
					m_nonce_s.get_data_length());
				offset += m_nonce_s.get_data_length();
			}
		}
		else
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_GSMSIM_ERROR,
				(EAPL("ERROR: extra_message_authentication_code_bytes(): unsupported EAP-Code %d.\n"),
				gsmsim_packet->get_code()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
			(EAPL("check_message_authentication_code(): MAC calculated over the following bytes:\n")));
		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
			(EAPL("MAC data"),
			 tmpbuffer,
			 offset));

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, (EAPL("MAC:\n")));
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, (EAPL("MAC"),
			tmp_MAC.get_data(),
			tmp_MAC.get_data_length()));
	}
#endif // #if defined(USE_EAP_TRACE)


	if (length != end_of_authentication->get_data_length()
		|| tmp_MAC.get_data_length()
			!= end_of_authentication->get_data_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_EAP_AM_CRYPTO|TRACE_FLAGS_GSMSIM_ERROR|TRACE_TEST_VECTORS, 
			(EAPL("ERROR: MAC differs.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}

	if (m_am_tools->memcmp(
			tmp_MAC.get_data(),
			saved_MAC,
			tmp_MAC.get_data_length()) != 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_EAP_AM_CRYPTO|TRACE_FLAGS_GSMSIM_ERROR|TRACE_TEST_VECTORS, 
			(EAPL("ERROR: MAC differs.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, (EAPL("MAC OK.\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::timer_expired(
	const u32_t id, void *data)
{
	EAP_UNREFERENCED_PARAMETER(id);
	EAP_UNREFERENCED_PARAMETER(data);

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: [0x%08x]->eap_type_gsmsim_c::timer_expired(id 0x%02x, data 0x%08x).\n"),
		this, id, data));

	eap_status_e status = eap_status_process_general_error;

	if (id == EAP_TYPE_GSMSIM_TIMER_DELAY_FAILURE_MESSAGE_SENT_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: EAP_TYPE_TIMER_DELAY_FAILURE_MESSAGE_SENT_ID elapsed.\n"),
			 (m_is_client == true) ? "client": "server"));

		if (m_state == eap_type_gsmsim_state_failure)
		{
			// Athentication is already failed.

			// We set the session timeout to zero.
			// This will terminate this session immediately.
			status = get_type_partner()->set_session_timeout(0ul);
		}
		else
		{
			status = handle_error_packet();
		}
	}
	else if (id == EAP_TYPE_GSMSIM_TIMER_DELAY_NOTIFICATION_MESSAGE_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: EAP_TYPE_TIMER_DELAY_NOTIFICATION_MESSAGE_ID elapsed.\n"),
			 (m_is_client == true) ? "client": "server"));

		status = handle_notification_packet();
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::timer_delete_data(
	const u32_t id, void *data)
{
	EAP_UNREFERENCED_PARAMETER(id);
	EAP_UNREFERENCED_PARAMETER(data);

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: [0x%08x]->eap_type_gsmsim_c::timer_delete_data(id 0x%02x, data 0x%08x).\n"),
		this, id, data));

	if (id == EAP_TYPE_GSMSIM_TIMER_DELAY_FAILURE_MESSAGE_SENT_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: EAP_TYPE_TIMER_DELAY_FAILURE_MESSAGE_SENT_ID delete data.\n"),
			 (m_is_client == true) ? "client": "server"));
	}
	else if (id == EAP_TYPE_GSMSIM_TIMER_DELAY_NOTIFICATION_MESSAGE_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: EAP_TYPE_TIMER_DELAY_NOTIFICATION_MESSAGE_ID delete data.\n"),
			 (m_is_client == true) ? "client": "server"));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::packet_send(
	const eap_am_network_id_c * const network_id,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const u32_t buffer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::packet_send().\n")));

	eap_header_wr_c eap(
		m_am_tools,
		sent_packet->get_data_offset(
			header_offset, data_length),
		data_length);
	if (eap.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	EAP_GSMSIM_PACKET_TRACE(
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

EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// NOTE this will be read from AM of GSMSIM EAP-type.
	const eap_status_e status = m_am_type_gsmsim->type_configure_read(field, data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::write_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// NOTE this will be written to AM of GSMSIM EAP-type.
	const eap_status_e status = m_am_type_gsmsim->type_configure_write(field, data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// This is commented in eap_base_type_c::configure().
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::configure(): this = 0x%08x => 0x%08x\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	eap_status_e status(eap_status_process_general_error);


	// This must be configured first.
	status = m_am_type_gsmsim->configure();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c error_message_delay_time(m_am_tools);

		status = read_configure(
			cf_str_EAP_GSMSIM_failure_message_delay_time.get_field(),
			&error_message_delay_time);
		if (status == eap_status_ok
			&& error_message_delay_time.get_is_valid_data() == true
			&& error_message_delay_time.get_data_length() == sizeof(u32_t)
			&& error_message_delay_time.get_data() != 0)
		{
			// This is optional value.
			m_failure_message_delay_time = *reinterpret_cast<u32_t *>(
				error_message_delay_time.get_data());
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c minimum_rand_count(m_am_tools);

		status = read_configure(
			cf_str_EAP_GSMSIM_minimum_rand_count.get_field(),
			&minimum_rand_count);
		if (status == eap_status_ok
			&& minimum_rand_count.get_is_valid_data() == true
			&& minimum_rand_count.get_data_length() == sizeof(u32_t)
			&& minimum_rand_count.get_data() != 0)
		{
			// This is optional value.
			m_minimum_rand_count = *reinterpret_cast<u32_t *>(
				minimum_rand_count.get_data());
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c use_manual_realm(m_am_tools);

		status = read_configure(
			cf_str_EAP_GSMSIM_use_manual_realm.get_field(),
			&use_manual_realm);
		if (status == eap_status_ok
			&& use_manual_realm.get_is_valid_data() == true
			&& use_manual_realm.get_data_length() == sizeof(u32_t))
		{
			u32_t *flag = reinterpret_cast<u32_t *>(use_manual_realm.get_data());
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_use_manual_realm = false;
				}
				else
				{
					m_use_manual_realm = true;
				}
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_GSMSIM_ERROR, 
					(EAPL("ERROR: illegal configuration value %s\n"),
					cf_str_EAP_GSMSIM_use_manual_realm.get_field()->get_field()));
			}
		}
	}

	//----------------------------------------------------------

	{
		status = read_configure(
			cf_str_EAP_GSMSIM_manual_realm.get_field(),
			get_nai_realm());
		if (status == eap_status_ok
			&& get_nai_realm()->get_is_valid_data() == true)
		{
			// OK NAI realm is configured.
		}
		else
		{
			// No configured NAI realm.
			// We will use automatic realm "wlan.mnc456.mcc123.3gppnetwork.org" as a realm.
			// Look at eap_type_gsmsim_c::generate_nai().
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c check_identifier_of_eap_identity_response(m_am_tools);

		status = read_configure(
			cf_str_EAP_GSMSIM_check_identifier_of_eap_identity_response.get_field(),
			&check_identifier_of_eap_identity_response);

		if (status == eap_status_ok
			&& check_identifier_of_eap_identity_response.get_is_valid_data() == true)
		{
			u32_t *flag = reinterpret_cast<u32_t *>(
				check_identifier_of_eap_identity_response.get_data());
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
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: illegal configuration value %s\n"),
				cf_str_EAP_GSMSIM_check_identifier_of_eap_identity_response
				 .get_field()->get_field()));
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c EAP_GSMSIM_check_nai_realm(m_am_tools);

		status = read_configure(
			cf_str_EAP_GSMSIM_check_nai_realm.get_field(),
			&EAP_GSMSIM_check_nai_realm);
		if (status == eap_status_ok
			&& EAP_GSMSIM_check_nai_realm.get_is_valid_data() == true)
		{
			u32_t *check_nai_realm = reinterpret_cast<u32_t *>(
				EAP_GSMSIM_check_nai_realm.get_data());
			if (check_nai_realm != 0
				&& *check_nai_realm != 0)
			{
				m_check_nai_realm = true;
			}
		}
	}

	//----------------------------------------------------------

#if defined(_DEBUG) && defined(USE_EAP_GSMSIM_TEST_VECTORS)
	{
		status = read_configure(
			cf_str_EAP_GSMSIM_nonce_mt_file.get_field(),
			&m_nonce_mt_file);
		if (status == eap_status_ok
			&& m_nonce_mt_file.get_is_valid_data() == true
			&& m_nonce_mt_file.get_data_length() != 0
			&& m_nonce_mt_file.get_data() != 0)
		{
			// This is optional value.
		}
	}
#endif //#if defined(_DEBUG) && defined(USE_EAP_GSMSIM_TEST_VECTORS)

	//----------------------------------------------------------

#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)
	{
		eap_variable_data_c EAP_GSMSIM_client_responds_retransmitted_packets(m_am_tools);

		status = read_configure(
			cf_str_EAP_GSMSIM_client_responds_retransmitted_packets.get_field(),
			&EAP_GSMSIM_client_responds_retransmitted_packets);
		if (status == eap_status_ok
			&& EAP_GSMSIM_client_responds_retransmitted_packets.get_is_valid_data() == true
			&& EAP_GSMSIM_client_responds_retransmitted_packets.get_data_length() == sizeof(u32_t)
			&& EAP_GSMSIM_client_responds_retransmitted_packets.get_data() != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(
				EAP_GSMSIM_client_responds_retransmitted_packets.get_data());
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_client_responds_retransmitted_packets = false;
				}
				else
				{
					m_client_responds_retransmitted_packets = true;
				}
			}
		}
	}
#endif //#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)

	//----------------------------------------------------------

	{
		eap_variable_data_c test_version(m_am_tools);

		status = read_configure(
			cf_str_EAP_GSMSIM_test_version.get_field(),
			&test_version);
		if (status == eap_status_ok
			&& test_version.get_is_valid_data() == true
			&& test_version.get_data_length() == sizeof(u32_t)
			&& test_version.get_data() != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(test_version.get_data());
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_gsmsim_test_version = false;
				}
				else
				{
					m_gsmsim_test_version = true;
				}
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c randomly_refuse_eap_identity(m_am_tools);

		status = read_configure(
			cf_str_EAP_GSMSIM_randomly_refuse_eap_identity.get_field(),
			&randomly_refuse_eap_identity);
		if (status == eap_status_ok
			&& randomly_refuse_eap_identity.get_is_valid_data() == true
			&& randomly_refuse_eap_identity.get_data_length() == sizeof(u32_t)
			&& randomly_refuse_eap_identity.get_data() != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(randomly_refuse_eap_identity.get_data());
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_gsmsim_randomly_refuse_eap_identity = false;
				}
				else
				{
					m_gsmsim_randomly_refuse_eap_identity = true;
				}
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c do_rand_uniqueness_check(m_am_tools);

		status = read_configure(
			cf_str_EAP_GSMSIM_do_rand_uniqueness_check.get_field(),
			&do_rand_uniqueness_check);

		if (status == eap_status_ok
			&& do_rand_uniqueness_check.get_is_valid_data() == true
			&& do_rand_uniqueness_check.get_data_length() == sizeof(u32_t))
		{
			u32_t *flag = reinterpret_cast<u32_t *>(do_rand_uniqueness_check.get_data());
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_do_rand_uniqueness_check = false;
				}
				else
				{
					m_do_rand_uniqueness_check = true;
				}
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c use_manual_username(m_am_tools);

		status = read_configure(
			cf_str_EAP_GSMSIM_use_manual_username.get_field(),
			&use_manual_username);
		if (status == eap_status_ok
			&& use_manual_username.get_is_valid_data() == true
			&& use_manual_username.get_data_length() == sizeof(u32_t))
		{
			u32_t *use_manual_username_flag = reinterpret_cast<u32_t *>(
				use_manual_username.get_data());
			if (use_manual_username_flag != 0
				&& *use_manual_username_flag != 0)
			{
				m_use_manual_username = true;
			}
		}
	}

	//----------------------------------------------------------

	if (m_use_manual_username == true)
	{
		status = read_configure(
			cf_str_EAP_GSMSIM_manual_username.get_field(),
			&m_manual_username);
		if (status == eap_status_ok
			&& m_manual_username.get_is_valid_data() == true)
		{
			// This is optional value.
		}
		else
		{
			// No username defined.
			m_use_manual_username = false;
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c fail_re_authentication_counter_check(m_am_tools);

		status = read_configure(
			cf_str_EAP_GSMSIM_fail_re_authentication_counter_check.get_field(),
			&fail_re_authentication_counter_check);
		if (status == eap_status_ok
			&& fail_re_authentication_counter_check.get_is_valid_data() == true
			&& fail_re_authentication_counter_check.get_data_length() == sizeof(u32_t)
			&& fail_re_authentication_counter_check.get_data() != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(
				fail_re_authentication_counter_check.get_data());
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_fail_reauthentication_counter_check = false;
				}
				else
				{
					m_fail_reauthentication_counter_check = true;
				}
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c accept_eap_identity_response(m_am_tools);

		status = read_configure(
			cf_str_EAP_GSMSIM_accept_eap_identity_response.get_field(),
			&accept_eap_identity_response);
		if (status == eap_status_ok
			&& accept_eap_identity_response.get_is_valid_data() == true
			&& accept_eap_identity_response.get_data_length() == sizeof(u32_t)
			&& accept_eap_identity_response.get_data() != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(accept_eap_identity_response.get_data());
			if (flag != 0)
			{
				if (*flag != 0)
				{
					m_accept_eap_identity_response = true;
				}
				else if (*flag == 0)
				{
					m_accept_eap_identity_response = false;
				}
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c use_random_identity_on_eap_identity_response(m_am_tools);

		status = read_configure(
			cf_str_EAP_GSMSIM_use_random_identity_on_eap_identity_response.get_field(),
			&use_random_identity_on_eap_identity_response);
		if (status == eap_status_ok
			&& use_random_identity_on_eap_identity_response.get_is_valid_data() == true
			&& use_random_identity_on_eap_identity_response.get_data_length() == sizeof(u32_t)
			&& use_random_identity_on_eap_identity_response.get_data() != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(
				use_random_identity_on_eap_identity_response.get_data());
			if (flag != 0)
			{
				if (*flag != 0)
				{
					m_use_random_identity_on_eap_identity_response = true;
				}
				else if (*flag == 0)
				{
					m_use_random_identity_on_eap_identity_response = false;
				}
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c use_pseudonym_identity(m_am_tools);

		status = read_configure(
			cf_str_EAP_GSMSIM_use_pseudonym_identity.get_field(),
			&use_pseudonym_identity);
		if (status == eap_status_ok
			&& use_pseudonym_identity.get_is_valid_data() == true
			&& use_pseudonym_identity.get_data_length() == sizeof(u32_t)
			&& use_pseudonym_identity.get_data() != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(use_pseudonym_identity.get_data());
			if (flag != 0)
			{
				if (*flag != 0)
				{
					m_use_pseudonym_identity = true;
				}
				else if (*flag == 0)
				{
					m_use_pseudonym_identity = false;
				}
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c use_reauthentication_identity(m_am_tools);

		status = read_configure(
			cf_str_EAP_GSMSIM_use_reauthentication_identity.get_field(),
			&use_reauthentication_identity);
		if (status == eap_status_ok
			&& use_reauthentication_identity.get_is_valid_data() == true
			&& use_reauthentication_identity.get_data_length() == sizeof(u32_t)
			&& use_reauthentication_identity.get_data() != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(use_reauthentication_identity.get_data());
			if (flag != 0)
			{
				if (*flag != 0)
				{
					m_use_reauthentication_identity = true;
				}
				else if (*flag == 0)
				{
					m_use_reauthentication_identity = false;
				}
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c randomly_fail_successfull_authentication(m_am_tools);

		status = read_configure(
			cf_str_EAP_GSMSIM_randomly_fail_successfull_authentication.get_field(),
			&randomly_fail_successfull_authentication);
		if (status == eap_status_ok
			&& randomly_fail_successfull_authentication.get_is_valid_data() == true
			&& randomly_fail_successfull_authentication.get_data_length() == sizeof(u32_t)
			&& randomly_fail_successfull_authentication.get_data() != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(
				randomly_fail_successfull_authentication.get_data());
			if (flag != 0)
			{
				if (*flag != 0)
				{
					m_randomly_fail_successfull_authentication = true;
				}
				else
				{
					m_randomly_fail_successfull_authentication = false;
				}
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c allow_use_result_indication(m_am_tools);

		status = read_configure(
			cf_str_EAP_GSMSIM_allow_use_result_indication.get_field(),
			&allow_use_result_indication);
		if (status == eap_status_ok
			&& allow_use_result_indication.get_is_valid_data() == true
			&& allow_use_result_indication.get_data_length() == sizeof(u32_t)
			&& allow_use_result_indication.get_data() != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(allow_use_result_indication.get_data());
			if (flag != 0)
			{
				if (*flag != 0)
				{
					m_allow_use_result_indication = true;
				}
				else
				{
					m_allow_use_result_indication = false;
				}
			}
		}
	}

	if (m_is_client == false)
	{
		eap_variable_data_c server_allow_use_result_indication(m_am_tools);

		status = read_configure(
			cf_str_EAP_GSMSIM_server_allow_use_result_indication.get_field(),
			&server_allow_use_result_indication);
		if (status == eap_status_ok
			&& server_allow_use_result_indication.get_is_valid_data() == true
			&& server_allow_use_result_indication.get_data_length() == sizeof(u32_t)
			&& server_allow_use_result_indication.get_data() != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(server_allow_use_result_indication.get_data());
			if (flag != 0)
			{
				if (*flag != 0)
				{
					m_allow_use_result_indication = true;
				}
				else
				{
					m_allow_use_result_indication = false;
				}
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c use_eap_expanded_type(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_GSMSIM_use_eap_expanded_type.get_field(),
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

	{
		(void) read_configure(
			cf_str_EAP_GSMSIM_2_digit_mnc_map_of_mcc_of_imsi_array.get_field(),
			&m_2_digit_mnc_map_of_mcc_of_imsi_array);
		// This is optional value.
	}

	{
		eap_variable_data_c use_uma_profile(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_GSMSIM_UMA_profile.get_field(),
			&use_uma_profile);
		if (status == eap_status_ok
			&& use_uma_profile.get_is_valid_data() == true
			&& use_uma_profile.get_data_length() == sizeof(u32_t))
		{
			u32_t *flag = reinterpret_cast<u32_t *>(use_uma_profile.get_data());
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_use_uma_profile = false;
				}
				else
				{
					m_use_uma_profile = true;
				}
			}
		}		
	}

	if (m_use_uma_profile == true)
	{
		(void) read_configure(
			cf_str_EAP_GSMSIM_UMA_realm_prefix.get_field(),
			&m_uma_automatic_realm_prefix);
		// m_uma_automatic_realm_prefix is optional value.

		// In the UMA we must wait EAP-Success to fullfill the state machine of mVPN.
		m_wait_eap_success_packet = true;
	}
	else
	{
		eap_variable_data_c wait_eap_success_packet(m_am_tools);

		status = read_configure(
			cf_str_EAP_GSMSIM_wait_eap_success_packet.get_field(),
			&wait_eap_success_packet);

		if (status == eap_status_ok
			&& wait_eap_success_packet.get_is_valid_data() == true)
		{
			u32_t *flag = reinterpret_cast<u32_t *>(wait_eap_success_packet.get_data());
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_wait_eap_success_packet = false;
				}
				else
				{
					m_wait_eap_success_packet = true;
				}
			}
		}

		if (get_type_partner()->get_is_tunneled_eap() == true)
		{
			// Inside the PEAP we must wait EAP-Success to fullfill the state machine of PEAP.
			m_wait_eap_success_packet = true;
		}
	}

	//----------------------------------------------------------

	m_gsmsim_header_offset = get_type_partner()->get_header_offset(
		&m_MTU, &m_trailer_length);

	if (m_gsmsim_header_offset+m_MTU+m_trailer_length
		> EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH)
	{
		EAP_ASSERT_ALWAYS(EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH
						  >= (m_gsmsim_header_offset+m_trailer_length));

		m_MTU = EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH
			- (m_gsmsim_header_offset+m_trailer_length);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

// This is commented in eap_base_type_c::shutdown().
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::shutdown(): this = 0x%08x => 0x%08x\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	if (m_shutdown_was_called == true)
	{
		// Shutdown function was called already.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_shutdown_was_called = true;

	cancel_error_message_delay_timer();
	cancel_notification_message_delay_timer();

	if (m_state != eap_type_gsmsim_state_none)
	{
		// We must cancel the pending query.
		if (m_state == eap_type_gsmsim_state_pending_identity_query)
		{
			m_am_type_gsmsim->cancel_SIM_IMSI_or_pseudonym_or_reauthentication_id_query();
		}
		else if (m_state == eap_type_gsmsim_state_pending_kc_sres_query)
		{
			m_am_type_gsmsim->cancel_SIM_kc_sres_query();
		}
		else if (m_state == eap_type_gsmsim_state_pending_pseudonym_decode_query)
		{
			m_am_type_gsmsim->cancel_imsi_from_username_query();
		}
#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
		else if (m_state == eap_type_gsmsim_state_pending_triplet_query)
		{
			m_am_type_gsmsim->cancel_SIM_triplets_query();
		}
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)

		send_final_notification();
	}

#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	if (m_triplets != 0)
	{
		delete m_triplets;
		m_triplets = 0;
	}
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)

	eap_status_e status(eap_status_ok);
	if (m_am_type_gsmsim != 0)
	{
		status = m_am_type_gsmsim->shutdown();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// This function is to allow reuse of this object.
// The whole object state must be reset.
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("GSMSIM: %s: function: eap_type_gsmsim_c::reset(): this = 0x%08x\n"),
		(m_is_client == true ? "client": "server"),
		this));

	eap_status_e status = eap_status_not_supported;

	m_reset_was_called = true;

	m_use_result_indication = false;
	m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_NONE;
	set_identity_type(GSMSIM_IDENTITY_TYPE_NONE);

#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	if (m_triplets != 0)
	{
		delete m_triplets;
		m_triplets = 0;
	}
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)

	m_state = eap_type_gsmsim_state_none;
	m_saved_previous_state = eap_type_gsmsim_state_none;
	m_gsmsim_selected_version = GSMSIM_ILLEGAL_VERSION;
	m_nonce_mt.reset();
	m_nonce_s.reset();
	m_IV.get_payload_buffer()->reset();
	m_saved_EAP_packet.reset();
	m_XKEY.reset();
	m_K_encr.reset();
	m_K_aut.reset();
	m_master_session_key.reset();
	m_automatic_realm.reset();
	m_automatic_realm_read = false;
	m_IMSI.reset();
	m_pseudonym.reset();
	m_reauthentication_identity.reset();
	m_identity.reset();
	m_NAI.reset();
	m_n_rands.reset();
	m_n_sres.reset();

	{
		cancel_error_message_delay_timer();
		m_client_error_code = eap_gsmsim_client_error_code_none;
		m_erroneus_packet_received = false;

		cancel_notification_message_delay_timer();
		m_gsmsim_notification_code = eap_gsmsim_notification_none;
		m_sim_notification_packet_received = false;
	}

	status = m_am_type_gsmsim->reset();
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
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::set_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id, 
	void * const p_data,
	const u32_t p_time_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = get_type_partner()->set_timer(
		p_initializer, 
		p_id, 
		p_data,
		p_time_ms);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::cancel_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = get_type_partner()->cancel_timer(
		p_initializer, 
		p_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

void eap_type_gsmsim_c::set_start_response_includes_identity(gsmsim_payload_AT_type_e type)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("GSMSIM: %s: eap_type_gsmsim_c::set_start_response_includes_identity(): %d=%s\n"),
		(m_is_client == true ? "client": "server"),
		type,
		gsmsim_payload_AT_header_c::get_payload_AT_string(type)));

	m_start_response_includes_identity = type;
}

//--------------------------------------------------

void eap_type_gsmsim_c::set_identity_type(eap_type_gsmsim_identity_type type)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("GSMSIM: %s: eap_type_gsmsim_c::set_identity_type(): %d=%s\n"),
		(m_is_client == true ? "client": "server"),
		type,
		get_identity_string(type)));

	m_identity_type = type;
}

//--------------------------------------------------
// End.
