/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/wapi_ethernet_core.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 15.1.1 % << Don't touch! Updated by Synergy at check-out.
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
	#define EAP_FILE_NUMBER_ENUM 20003
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_variable_data.h"
#include "eap_tools.h"
#include "wapi_ethernet_core.h"
#include "eapol_ethernet_header.h"
#include "eap_buffer.h"
#include "eapol_session_key.h"
#include "eap_automatic_variable.h"

#include "abs_eap_am_mutex.h"


//--------------------------------------------------

// 
EAP_FUNC_EXPORT wapi_ethernet_core_c::~wapi_ethernet_core_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_ethernet_core_c::~wapi_ethernet_core_c(): this = 0x%08x\n"),
		this));

	EAP_ASSERT(m_shutdown_was_called == true);

	delete m_wapi_core;
	m_wapi_core=0;


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4355 ) // 'this' : used in base member initializer list
#endif

// 
EAP_FUNC_EXPORT wapi_ethernet_core_c::wapi_ethernet_core_c(
	abs_eap_am_tools_c * const tools,
	abs_wapi_ethernet_core_c * const partner,
	const bool is_client_when_true)
: m_partner(partner)
, m_wapi_core(new wapi_session_core_c(tools, this, is_client_when_true))
, m_am_tools(tools)
, m_is_client(is_client_when_true)
, m_is_valid(false)
, m_shutdown_was_called(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_ethernet_core_c::wapi_ethernet_core_c(): %s, this = 0x%08x, compiled %s %s.\n"),
		(m_is_client == true) ? "client": "server",
		this,
		__DATE__,
		__TIME__));

	if (m_wapi_core != 0
		&& m_wapi_core->get_is_valid() == true)
	{
		set_is_valid();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::packet_process(
	const eap_am_network_id_c * const /* receive_network_id */,
	eap_general_header_base_c * const packet_data,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("####################################################################\n")));

	if (m_wapi_core == 0)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("####################################################################\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (packet_length < eapol_ethernet_header_rd_c::get_header_length())
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("####################################################################\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	eapol_ethernet_header_wr_c eth_header(
		m_am_tools,
		packet_data->get_header_buffer(packet_data->get_header_buffer_length()),
		packet_data->get_header_buffer_length());

	if (eth_header.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (packet_length < eth_header.get_data_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("-> ETHERNET: %s: type=0x%04x, packet_length 0x%04x\n"),
		 (m_is_client == true) ? "client": "server",
		 eth_header.get_type(),
		 packet_length));

	if (m_is_client == true)
	{
		EAP_TRACE_DATA_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
			(EAPL("-> ETHERNET packet client"),
			 eth_header.get_header_buffer(eth_header.get_header_buffer_length()),
			 packet_length));
	}
	else
	{
		EAP_TRACE_DATA_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
			(EAPL("-> ETHERNET packet server"),
			 eth_header.get_header_buffer(eth_header.get_header_buffer_length()),
			 packet_length));
	}

	if (eth_header.get_type() == eapol_ethernet_type_wapi)
	{
		eap_am_network_id_c receive_network_id(
			m_am_tools,
			eth_header.get_source(),
			eth_header.get_source_length(),
			eth_header.get_destination(),
			eth_header.get_destination_length(),
			eth_header.get_type(),
			false,
			false);

		eapol_header_wr_c eapol(
			m_am_tools,
			eth_header.get_eapol_header(),
			eth_header.get_data_length());
		if (eapol.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		status = m_wapi_core->packet_process(
			&receive_network_id,
			&eapol,
			packet_length-eapol_ethernet_header_rd_c::get_header_length());

		EAP_GENERAL_HEADER_COPY_ERROR_PARAMETERS(packet_data, &eapol);
	}
	else
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Not WAPI supported ethernet type 0x%04x\n"), eth_header.get_type()));
		status = eap_status_ethernet_type_not_supported;
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("####################################################################\n")));
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------


//
EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::packet_send(
	const eap_am_network_id_c * const send_network_id,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const u32_t buffer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(header_offset < sent_packet->get_data_length());
	EAP_ASSERT(data_length <= sent_packet->get_data_length());
	EAP_ASSERT(sent_packet->get_data_length() <= buffer_length);

	if (send_network_id->get_is_valid_data() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (header_offset < eapol_ethernet_header_wr_c::get_header_length())
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	// ****
	// TODO: Check these header types for WAPI
	eapol_ethernet_header_wr_c eth(
		m_am_tools,
		sent_packet->get_data_offset(
			header_offset-eapol_ethernet_header_wr_c::get_header_length(),
			eapol_ethernet_header_wr_c::get_header_length()),
		eapol_ethernet_header_wr_c::get_header_length());

	if (eth.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}


	eth.set_type(static_cast<eapol_ethernet_type_e>(send_network_id->get_type()));

	m_am_tools->memmove(
		eth.get_destination(),
		send_network_id->get_destination(),
		send_network_id->get_destination_length());

	m_am_tools->memmove(
		eth.get_source(),
		send_network_id->get_source(),
		send_network_id->get_source_length());


	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("<- ETHERNET: %s: type=0x%04x, packet_length 0x%04x\n"),
		 (m_is_client == true) ? "client": "server",
		 eth.get_type(),
		 data_length));

	if (m_is_client == true)
	{
		EAP_TRACE_DATA_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
			(EAPL("<- ETHERNET packet client"),
			 eth.get_header_buffer(eth.get_header_buffer_length()),
			 data_length+eapol_ethernet_header_wr_c::get_header_length()));
	}
	else
	{
		EAP_TRACE_DATA_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
			(EAPL("<- ETHERNET packet server"),
			 eth.get_header_buffer(eth.get_header_buffer_length()),
			 data_length+eapol_ethernet_header_wr_c::get_header_length()));
	}

	sent_packet->set_is_client(m_is_client);

	eap_status_e status = m_partner->packet_send(
		send_network_id,
		sent_packet,
		header_offset-eapol_ethernet_header_wr_c::get_header_length(),
		data_length+eapol_ethernet_header_wr_c::get_header_length(),
		buffer_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u32_t wapi_ethernet_core_c::get_header_offset(
	u32_t * const MTU,
	u32_t * const trailer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// ****
	// TODO: Check these for WAPI
	const u32_t offset = m_partner->get_header_offset(MTU, trailer_length);
	(*MTU) -= eapol_ethernet_header_wr_c::get_header_length();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return offset+eapol_ethernet_header_wr_c::get_header_length();
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::start_authentication(
	const eap_am_network_id_c * const receive_network_id,
	const bool is_client_when_true)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_wapi_core == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = m_wapi_core->restart_authentication(receive_network_id, is_client_when_true, true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::start_reassociation(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type,
	const eap_variable_data_c * const BKID)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_not_supported);

// ****
// TODO: Is this needed in WAPI?
#if 0
	status = m_eapol_core->start_reassociation(
		receive_network_id,
		authentication_type,
		BKID);
#endif

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::read_reassociation_parameters(
	const eap_am_network_id_c * const old_receive_network_id, ///< source includes remote address, destination includes local address.
	const eap_am_network_id_c * const new_receive_network_id, ///< source includes remote address, destination includes local address.
	const eapol_key_authentication_type_e authentication_type,
	eap_variable_data_c * const BKID,
	const eap_variable_data_c * const received_WAPI_ie,
	const eap_variable_data_c * const sent_WAPI_ie)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("wapi_ethernet_core_c::read_reassociation_parameters()\n")));

	if (m_wapi_core == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = m_wapi_core->read_reassociation_parameters(
		old_receive_network_id,
		new_receive_network_id,
		authentication_type,
		BKID,
		received_WAPI_ie,
		sent_WAPI_ie);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------


//
EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::complete_reassociation(
	const eapol_wlan_authentication_state_e reassociation_result,
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type,
	const eap_variable_data_c * const received_WAPI_IE,
	const eap_variable_data_c * const sent_WAPI_IE,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_not_supported);

	//***
	// TODO: Support for this needs to be added to wapi_core_c
	/*
	status = m_wapi_core->complete_reassociation(
		reassociation_result,
		receive_network_id,
		authentication_type,
		received_WAPI_IE,
		sent_WAPI_IE,
		pairwise_key_cipher_suite,
		group_key_cipher_suite);
	*/

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void wapi_ethernet_core_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool wapi_ethernet_core_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::configure()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("wapi_ethernet_core_c::configure()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_ethernet_core_c::configure()");

	eap_status_e status = m_wapi_core->configure();

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::shutdown()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: wapi_ethernet_core_c::shutdown(), m_shutdown_was_called=%d\n"),
		(m_is_client == true) ? "client": "server",
		m_shutdown_was_called));

	if (m_shutdown_was_called == true)
	{
		// Shutdown function was called already.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_shutdown_was_called = true;

	eap_status_e status(eap_status_ok);

	if (m_wapi_core != 0)
	{
		status = m_wapi_core->shutdown();
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::packet_data_session_key(
	const eap_am_network_id_c * const send_network_id,
	const eapol_session_key_c * const key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (key == 0
		|| key->get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: wapi_ethernet_core_c::packet_data_session_key(), invalid key.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_ethernet_core_c::packet_data_session_key(): key_type 0x%02x, key_index %d\n"),
		key->get_key_type(),
		key->get_key_index()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_ethernet_core_c::packet_data_session_key():"),
		key->get_key()->get_data(key->get_key()->get_data_length()),
		key->get_key()->get_data_length()));

	const eap_status_e status = m_partner->packet_data_session_key(
		send_network_id,
		key);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	const eap_status_e status = m_partner->read_configure(field, data);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::write_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	const eap_status_e status = m_partner->write_configure(field, data);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void wapi_ethernet_core_c::state_notification(
	const abs_eap_state_notification_c * const state)
{
	m_partner->state_notification(state);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::set_timer(
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
EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::cancel_timer(
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
EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::cancel_all_timers()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->cancel_all_timers();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::cancel_all_authentication_sessions()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("wapi_ethernet_core_c::cancel_all_authentication_sessions()\n")));

	eap_status_e status = m_wapi_core->cancel_all_authentication_sessions();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::check_bksa_cache(
	eap_array_c<eap_am_network_id_c> * const bssid_sta_receive_network_ids,
	const eapol_key_authentication_type_e selected_eapol_key_authentication_type,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("wapi_ethernet_core_c::check_bksa_cache()\n")));

	eap_status_e status = m_wapi_core->check_bksa_cache(
		bssid_sta_receive_network_ids,
		selected_eapol_key_authentication_type,
		pairwise_key_cipher_suite,
		group_key_cipher_suite);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/**
 * This function removes BKSA from cache.
 * @param receive_network_id carries the MAC addresses.
 * MAC address of Authenticator should be in source address.
 * MAC address of Supplicant should be in destination address.
 */
EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::remove_bksa_from_cache(
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("wapi_ethernet_core_c::remove_bksa_from_cache()\n")));

	eap_status_e status = m_wapi_core->remove_bksa_from_cache(
		receive_network_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/**
 * Function creates a state for later use. This is for optimazing 4-Way Handshake.
 * @param receive_network_id carries the MAC addresses.
 * MAC address of Authenticator should be in source address. MAC address of 
 * Supplicant should be in destination address.
 * @param authentication_type is the selected authentication type.
 */
EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::create_state(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type
	)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	status = m_wapi_core->create_state(
		receive_network_id,
		authentication_type);

	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

/**
 * @param receive_network_id carries the MAC addresses.
 * MAC address of Authenticator should be in source address. MAC address of Supplicant should be in destination address.
 * @param authenticator_RSNA_IE is RSN IE of authenticator. Authenticator sends this in Beacon or Probe message.
 * @param supplicant_RSNA_IE is RSN IE of supplicant. Supplicant sends this in (re)association request message.
 * @param eapol_pairwise_cipher is the selected pairwise cipher.
 * @param eapol_group_cipher is the selected group cipher.
 */
EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::association(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type,
	const eap_variable_data_c * const wapi_ie_ae,
	const eap_variable_data_c * const wapi_ie_asue,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_pairwise_cipher,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_group_cipher,
	const eap_variable_data_c * const pre_shared_key
	)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	status = m_wapi_core->association(
		receive_network_id,
		authentication_type,
		wapi_ie_ae,
		wapi_ie_asue,
		eapol_pairwise_cipher,
		eapol_group_cipher,
		pre_shared_key);

	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

/**
 * @param receive_network_id carries the MAC addresses.
 * MAC address of Authenticator should be in source address. MAC address of Supplicant should be in destination address.
 */
EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::disassociation(
	const eap_am_network_id_c * const receive_network_id
	)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	status = m_wapi_core->disassociation(
		receive_network_id);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::restart_authentication(
	const eap_am_network_id_c * const receive_network_id,
	const bool is_client_when_true,
	const bool force_clean_restart,
	const bool from_timer
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	

	eap_status_e status = m_wapi_core->restart_authentication(
		receive_network_id,
		is_client_when_true,
		force_clean_restart,
		from_timer);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::asynchronous_init_remove_wapi_session(
	const eap_am_network_id_c * const send_network_id
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}
//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_ethernet_core_c::set_session_timeout(
	const u32_t session_timeout_ms
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------


// End.
