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
* %version: 49 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 62 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_variable_data.h"
#include "eap_tools.h"
#include "ethernet_core.h"
#include "eapol_ethernet_header.h"
#include "eap_buffer.h"
#include "eapol_session_key.h"
#include "eap_automatic_variable.h"


//--------------------------------------------------

// 
EAP_FUNC_EXPORT ethernet_core_c::~ethernet_core_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("ethernet_core_c::~ethernet_core_c(): this = 0x%08x\n"),
		this));

	EAP_ASSERT(m_shutdown_was_called == true);

	delete m_eapol_core;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4355 ) // 'this' : used in base member initializer list
#endif

// 
EAP_FUNC_EXPORT ethernet_core_c::ethernet_core_c(
	abs_eap_am_tools_c * const tools,
	abs_ethernet_core_c * const partner,
	const bool is_client_when_true)
: m_partner(partner)
, m_eapol_core(new eapol_core_c(tools, this, is_client_when_true))
, m_am_tools(tools)
, m_is_client(is_client_when_true)
, m_is_valid(false)
, m_shutdown_was_called(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("ethernet_core_c::ethernet_core_c(): %s, this = 0x%08x, compiled %s %s.\n"),
		(m_is_client == true) ? "client": "server",
		this,
		__DATE__,
		__TIME__));

	if (m_eapol_core != 0
		&& m_eapol_core->get_is_valid() == true)
	{
		set_is_valid();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_base_type_c * ethernet_core_c::load_type(const eap_type_value_e /* type */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return 0;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::packet_process(
	const eap_am_network_id_c * const /* receive_network_id */,
	eap_general_header_base_c * const packet_data,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("####################################################################\n")));

	if (m_eapol_core == 0)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("####################################################################\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

#if defined(EAPOL_SKIP_ETHERNET_HEADER)

	{
		eapol_header_wr_c eapol(
			m_am_tools,
			packet_data->get_header_buffer(packet_data->get_header_buffer_length()),
			packet_data->get_header_buffer_length());
		if (eapol.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		status = m_eapol_core->packet_process(
			receive_network_id,
			&eapol,
			packet_length);

		EAP_GENERAL_HEADER_COPY_ERROR_PARAMETERS(packet_data, &eapol);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("####################################################################\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

#else

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

	if (eth_header.get_type() == eapol_ethernet_type_pae
		|| eth_header.get_type() == eapol_ethernet_type_preauthentication)
	{
		eap_am_network_id_c a_receive_network_id(
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

		status = m_eapol_core->packet_process(
			&a_receive_network_id,
			&eapol,
			packet_length-eapol_ethernet_header_rd_c::get_header_length());

		EAP_GENERAL_HEADER_COPY_ERROR_PARAMETERS(packet_data, &eapol);
	}
	else
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Not supported ethernet type 0x%04x\n"), eth_header.get_type()));
		status = eap_status_ethernet_type_not_supported;
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("####################################################################\n")));
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);

#endif //#if defined(EAPOL_SKIP_ETHERNET_HEADER)

}

//--------------------------------------------------


//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::packet_send(
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

#if defined(EAPOL_SKIP_ETHERNET_HEADER)

	{
		sent_packet->set_is_client(m_is_client);

		eap_status_e status = m_partner->packet_send(
			send_network_id,
			sent_packet,
			header_offset,
			data_length,
			buffer_length);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

#else

	if (header_offset < eapol_ethernet_header_wr_c::get_header_length())
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

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

#endif //#if defined(EAPOL_SKIP_ETHERNET_HEADER)

}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u32_t ethernet_core_c::get_header_offset(
	u32_t * const MTU,
	u32_t * const trailer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

#if defined(EAPOL_SKIP_ETHERNET_HEADER)

	const u32_t offset = m_partner->get_header_offset(MTU, trailer_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return offset;

#else

	const u32_t offset = m_partner->get_header_offset(MTU, trailer_length);
	(*MTU) -= eapol_ethernet_header_wr_c::get_header_length();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return offset+eapol_ethernet_header_wr_c::get_header_length();

#endif //#if defined(EAPOL_SKIP_ETHERNET_HEADER)
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::unload_module(const eap_type_value_e type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	const eap_status_e status = m_partner->unload_module(type);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::eap_acknowledge(
	const eap_am_network_id_c * const receive_network_id)
{
	// Any Network Protocol packet is accepted as a success indication.
	// This is described in RFC 2284 "PPP Extensible Authentication Protocol (EAP)".

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_eapol_core == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = m_eapol_core->eap_acknowledge(receive_network_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::load_module(
	const eap_type_value_e type,
	const eap_type_value_e tunneling_type,
	abs_eap_base_type_c * const partner,
	eap_base_type_c ** const eap_type,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = m_partner->load_module(
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

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::start_authentication(
	const eap_am_network_id_c * const receive_network_id,
	const bool is_client_when_true)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_eapol_core == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = m_eapol_core->restart_authentication(receive_network_id, is_client_when_true, true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::start_preauthentication(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ethernet_core_c::start_preauthentication()\n")));

	if (m_eapol_core == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = m_eapol_core->start_preauthentication(receive_network_id, authentication_type);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::read_reassociation_parameters(
	const eap_am_network_id_c * const old_receive_network_id, ///< source includes remote address, destination includes local address.
	const eap_am_network_id_c * const new_receive_network_id, ///< source includes remote address, destination includes local address.
	const eapol_key_authentication_type_e authentication_type,
	eap_variable_data_c * const PMKID,
	const eap_variable_data_c * const received_WPA_ie,
	const eap_variable_data_c * const sent_WPA_ie)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ethernet_core_c::read_reassociation_parameters()\n")));

	if (m_eapol_core == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = m_eapol_core->read_reassociation_parameters(
		old_receive_network_id,
		new_receive_network_id,
		authentication_type,
		PMKID,
		received_WPA_ie,
		sent_WPA_ie);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::start_reassociation(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type,
	const eap_variable_data_c * const PMKID)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_eapol_core->start_reassociation(
		receive_network_id,
		authentication_type,
		PMKID);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::complete_reassociation(
	const eapol_wlan_authentication_state_e reassociation_result,
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type,
	const eap_variable_data_c * const received_WPA_IE, // WLM must give only the WPA IE to EAPOL
	const eap_variable_data_c * const sent_WPA_IE,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	status = m_eapol_core->complete_reassociation(
		reassociation_result,
		receive_network_id,
		authentication_type,
		received_WPA_IE,
		sent_WPA_IE,
		pairwise_key_cipher_suite,
		group_key_cipher_suite);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::send_logoff(
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_eapol_core == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = m_eapol_core->send_logoff(receive_network_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void ethernet_core_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool ethernet_core_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::configure()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ethernet_core_c::configure()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ethernet_core_c::configure()");

	eap_status_e status = m_eapol_core->configure();

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::shutdown()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: ethernet_core_c::shutdown(), m_shutdown_was_called=%d\n"),
		(m_is_client == true) ? "client": "server",
		m_shutdown_was_called));

	if (m_shutdown_was_called == true)
	{
		// Shutdown function was called already.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_shutdown_was_called = true;

	eap_status_e status(eap_status_ok);

	if (m_eapol_core != 0)
	{
		status = m_eapol_core->shutdown();
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ethernet_core_c::packet_data_session_key(
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
			(EAPL("ERROR: ethernet_core_c::packet_data_session_key(), invalid key.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("ethernet_core_c::packet_data_session_key(): key_type 0x%02x=%s, key_index %d\n"),
		key->get_key_type(),
		eapol_session_key_c::get_eapol_key_type_string(key->get_key_type()),
		key->get_key_index()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("ethernet_core_c::packet_data_session_key():"),
		key->get_key()->get_data(key->get_key()->get_data_length()),
		key->get_key()->get_data_length()));

	const eap_status_e status = m_partner->packet_data_session_key(
		send_network_id,
		key);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ethernet_core_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	const eap_status_e status = m_partner->read_configure(field, data);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ethernet_core_c::write_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	const eap_status_e status = m_partner->write_configure(field, data);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void ethernet_core_c::state_notification(
	const abs_eap_state_notification_c * const state)
{
	m_partner->state_notification(state);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::set_timer(
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
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::cancel_timer(
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
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::cancel_all_timers()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->cancel_all_timers();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ethernet_core_c::check_is_valid_eap_type(const eap_type_value_e eap_type)
{
	eap_status_e status = m_partner->check_is_valid_eap_type(eap_type);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ethernet_core_c::get_eap_type_list(
	eap_array_c<eap_type_value_e> * const eap_type_list)
{
	eap_status_e status = m_partner->get_eap_type_list(eap_type_list);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::cancel_all_authentication_sessions()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ethernet_core_c::cancel_all_authentication_sessions()\n")));

	eap_status_e status = m_eapol_core->cancel_all_authentication_sessions();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::check_pmksa_cache(
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
		(EAPL("ethernet_core_c::check_pmksa_cache()\n")));

	eap_status_e status = m_eapol_core->check_pmksa_cache(
		bssid_sta_receive_network_ids,
		selected_eapol_key_authentication_type,
		pairwise_key_cipher_suite,
		group_key_cipher_suite);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/**
 * This function removes PMKSA from cache.
 * @param receive_network_id carries the MAC addresses.
 * MAC address of Authenticator should be in source address.
 * MAC address of Supplicant should be in destination address.
 */
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::remove_pmksa_from_cache(
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ethernet_core_c::remove_pmksa_from_cache()\n")));

	eap_status_e status = m_eapol_core->remove_pmksa_from_cache(
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
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::create_state(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type
	)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	status = m_eapol_core->create_state(
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
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::association(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type,
	const eap_variable_data_c * const authenticator_RSNA_IE,
	const eap_variable_data_c * const supplicant_RSNA_IE,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_pairwise_cipher,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_group_cipher,
	const eap_variable_data_c * const pre_shared_key
	)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	status = m_eapol_core->association(
		receive_network_id,
		authentication_type,
		authenticator_RSNA_IE,
		supplicant_RSNA_IE,
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
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::disassociation(
	const bool complete_to_lower_layer,
	const eap_am_network_id_c * const receive_network_id
	)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	status = m_eapol_core->disassociation(
		complete_to_lower_layer,
		receive_network_id);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ethernet_core_c::add_rogue_ap(eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = m_partner->add_rogue_ap(rogue_ap_list);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ethernet_core_c::tkip_mic_failure(
	const eap_am_network_id_c * const receive_network_id,
	const bool fatal_failure_when_true,
	const eapol_RSNA_key_header_c::eapol_tkip_mic_failure_type_e tkip_mic_failure_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = m_eapol_core->tkip_mic_failure(
		receive_network_id,
		fatal_failure_when_true,
		tkip_mic_failure_type);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ethernet_core_c::complete_check_pmksa_cache(
	EAP_TEMPLATE_CONST eap_array_c<eap_am_network_id_c> * const bssid_sta_receive_network_ids)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = m_partner->complete_check_pmksa_cache(
		bssid_sta_receive_network_ids);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e ethernet_core_c::save_simple_config_session(
	const simple_config_state_e state,
	EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
	const eap_variable_data_c * const new_password,
	const simple_config_Device_Password_ID_e Device_Password_ID,
	const simple_config_payloads_c * const other_configuration)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: ethernet_core_c::save_simple_config_session().\n"),
		 (m_is_client == true) ? "client": "server"));

	const eap_status_e status = m_partner->save_simple_config_session(
		state,
		credential_array,
		new_password,
		Device_Password_ID,
		other_configuration);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::set_eap_database_reference_values(
	const eap_variable_data_c * const reference)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ethernet_core_c::set_eap_database_reference_values()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ethernet_core_c::set_eap_database_reference_values()");

	eap_status_e status = m_eapol_core->set_eap_database_reference_values(reference);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::get_802_11_authentication_mode(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type,
	const eap_variable_data_c * const SSID,
	const eap_variable_data_c * const preshared_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ethernet_core_c::get_802_11_authentication_mode()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ethernet_core_c::get_802_11_authentication_mode()");

	eap_status_e status = m_eapol_core->get_802_11_authentication_mode(
		receive_network_id,
		authentication_type,
		SSID,
		preshared_key);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::complete_get_802_11_authentication_mode(
		const eap_status_e completion_status,
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_802_11_authentication_mode_e mode)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ethernet_core_c::complete_get_802_11_authentication_mode()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ethernet_core_c::complete_get_802_11_authentication_mode()");

	eap_status_e status(eap_status_ok);

	if (m_partner != 0)
	{
		status = m_partner->complete_get_802_11_authentication_mode(
			completion_status,
			receive_network_id,
			mode);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::complete_disassociation(
	const bool complete_to_lower_layer,
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ethernet_core_c::complete_disassociation()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ethernet_core_c::complete_disassociation()");

	eap_status_e status(eap_status_ok);

	if (m_partner != 0)
	{
		status = m_partner->complete_disassociation(
			complete_to_lower_layer,
			receive_network_id);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------
// End.
