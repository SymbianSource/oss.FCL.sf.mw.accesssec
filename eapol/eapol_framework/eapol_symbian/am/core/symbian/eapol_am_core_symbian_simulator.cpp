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
	#define EAP_FILE_NUMBER_ENUM 149 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_variable_data.h"
#include "eap_tools.h"
#include "eap_type_all.h"
#include "eapol_am_core_symbian_simulator.h"
#include "eapol_ethernet_header.h"
#include <EapType.h>


//--------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_am_core_symbian_c::~eapol_am_core_symbian_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_shutdown_was_called == true);

	m_am_tools->enter_global_mutex();
	delete m_ethernet_core;
	m_am_tools->leave_global_mutex();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_am_core_symbian_c::eapol_am_core_symbian_c(
	abs_eap_am_tools_c * const tools,
	abs_eapol_am_core_symbian_c * const partner,
	const bool is_client_when_true)
: m_partner(partner)
, m_ethernet_core(new ethernet_core_c(tools, this, is_client_when_true))
, m_am_tools(tools)
, m_own_address(tools)
, m_authentication_counter(0u)
, m_error_probability(0u)
, m_is_valid(false)
, m_is_client(is_client_when_true)
, m_enable_random_errors(false)
, m_shutdown_was_called(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
 
	m_am_tools->enter_global_mutex();
	if (m_ethernet_core != 0
		&& m_ethernet_core->get_is_valid() == true)
	{
		set_is_valid();
	}
	m_am_tools->leave_global_mutex();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_base_type_c * eapol_am_core_symbian_c::load_type(const eap_type_value_e /*type*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return 0;
}

//--------------------------------------------------

#if defined(USE_EAPOL_LLC_INTERFACE)

//
EAP_FUNC_EXPORT eap_status_e eapol_am_core_symbian_c::packet_process(
	RMBufChain& aPdu)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	const u32_t packet_length = aPdu.Length();

	if (packet_length < eapol_ethernet_header_wr_c::get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return eap_status_too_short_message;
	}

	eapol_ethernet_header_wr_c eth_header(aPdu.First()->Ptr());

	if (eth_header.get_type() == eapol_ethernet_type_pae)
	{
		u8_t packet_buffer[EAP_MEM_GUARDS(EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH)];
		eap_buf_chain_rd_c response_packet(
			eap_read_buffer, m_am_tools, packet_buffer, sizeof(packet_buffer), false);
		u32_t offset = 0u;
		RMBuf *buf = aPdu.First();

		while(buf != 0)
		{
			m_am_tools->memmove(packet_buffer+offset, buf->Ptr(), buf->Length());
			offset += buf->Length();
			buf = buf->Next();
		}

		eapol_ethernet_header_wr_c eth_header(packet_buffer);

		eap_am_network_id_c receive_network_id(
			m_am_tools,
			eth_header.get_source()->get_address(),
			eth_header.get_source()->get_address_length(),
			eth_header.get_destination()->get_address(),
			eth_header.get_destination()->get_address_length(),
			eth_header.get_type(),
			false,
			false);

		if (m_own_address.get_data_length() != receive_network_id.get_destination_id()->get_data_length()
			|| m_am_tools->memcmp(
				m_own_address.get_data(m_own_address.get_data_length()),
				receive_network_id.get_destination_id()->get_data(receive_network_id.get_destination_id()->get_data_length()),
				receive_network_id.get_destination_id()->get_data_length()))
		{
			return eap_status_wrong_network_id;
		}

		if (m_ethernet_core == 0)
		{
			return eap_status_allocation_error;
		}

		if (packet_length < eapol_ethernet_header_rd_c::get_header_length())
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return eap_status_process_illegal_packet_error;
		}

		m_am_tools->enter_global_mutex();
		status = m_ethernet_core->packet_process(
			&receive_network_id,
			&eth_header,
			packet_length,
			NULL);
		m_am_tools->leave_global_mutex();
	}
	else
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Not supported ethernet type 0x%04x\n"), eth_header.get_type()));
		status = eap_status_ethernet_type_not_supported;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
}

#endif //#if defined(USE_EAPOL_LLC_INTERFACE)

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_am_core_symbian_c::packet_process(
	const eap_am_network_id_c * const receive_network_id,
	eapol_ethernet_header_wr_c * const eth_header,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eapol_am_core_symbian_c::packet_process(): Received packet addresses:\n")));

	if (m_ethernet_core == 0)
	{
		return eap_status_allocation_error;
	}

	if (packet_length < eapol_ethernet_header_rd_c::get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return eap_status_process_illegal_packet_error;
	}

	if (eth_header->get_type() == eapol_ethernet_type_pae)
	{
		m_am_tools->enter_global_mutex();
		status = m_ethernet_core->packet_process(
			receive_network_id,
			eth_header,
			packet_length);
		m_am_tools->leave_global_mutex();
	}
	else
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Not supported ethernet type 0x%04x\n"), eth_header->get_type()));
		status = eap_status_ethernet_type_not_supported;
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
}

//--------------------------------------------------

#include "eap_crypto_api.h"

//
EAP_FUNC_EXPORT eap_status_e eapol_am_core_symbian_c::random_error(
	eap_buf_chain_wr_c * const sent_packet)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_ok;
	u32_t ind = 0u;
	u8_t *data = sent_packet->get_data(sent_packet->get_data_length());

	crypto_random_c rand(m_am_tools);
	u32_t random_guard;

	for (ind = 0u; ind < sent_packet->get_data_length(); ind++)
	{
		status = rand.get_rand_bytes(
			reinterpret_cast<u8_t *>(&random_guard,
			sizeof(random_guard));
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// This is simple limiter to the probability of an error.
		// probability = m_error_probability / (2^32)
		if (random_guard < m_error_probability)
		{
			u8_t rnd;
			u8_t previous_data;
			// Create an error.
			status = rand.get_rand_bytes(
				&rnd,
				sizeof(rnd));
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			previous_data = data[ind];
			data[ind] ^= rnd;

			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TEST: random_error() data[0x%x] changed from 0x%02x to 0x%02x.\n"),
				ind, previous_data, data[ind]));
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_am_core_symbian_c::packet_send(
	const eap_am_network_id_c * const send_network_id,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const u32_t buffer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (header_offset != 0u)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet_send: packet buffer corrupted.\n")));
		return eap_status_process_general_error;
	}
	else if (header_offset+data_length != sent_packet->get_data_length())
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: packet_send: packet buffer corrupted (data_length != sent_packet->get_data_length()).\n")));
		EAP_ASSERT_ALWAYS(data_length == sent_packet->get_buffer_length());
		return eap_status_process_general_error;
	}

	eap_status_e status = eap_status_process_general_error;

	if (m_enable_random_errors == true)
	{
		// Make a random error to the message.
		random_error(sent_packet);
	}

	status = m_partner->packet_send(
		send_network_id,
		sent_packet,
		header_offset,
		data_length,
		buffer_length,
		this,
		true,
		0ul);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u32_t eapol_am_core_symbian_c::get_header_offset(
	u32_t * const MTU,
	u32_t * const trailer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	const u32_t offset = m_partner->get_header_offset(MTU, trailer_length);
	// (*MTU)
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return offset;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_am_core_symbian_c::unload_module(const eap_type_value_e type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;
	TInt index = m_eap_type_array.Find(type);
	if (index != KErrNotFound)
	{
		delete m_plugin_if_array[index];
		m_plugin_if_array.Remove(index);
		m_eap_type_array.Remove(index);
		status = eap_status_ok;			
	}
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_am_core_symbian_c::eap_acknowledge(const eap_am_network_id_c * const receive_network_id)
{
	// Any Network Protocol packet is accepted as a success indication.
	// This is described in RFC 2284 "PPP Extensible Authentication Protocol (EAP)".

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_ethernet_core == 0)
	{
		return eap_status_allocation_error;
	}

	m_am_tools->enter_global_mutex();
	eap_status_e status = m_ethernet_core->eap_acknowledge(receive_network_id);
	m_am_tools->leave_global_mutex();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return status;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_am_core_symbian_c::load_module(
		const eap_type_value_e type,
		const eap_type_value_e /* tunneling_type */,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type_if,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eapol_am_core_symbian_c::load_module(%d)\n"), type));
	eap_status_e status = eap_status_process_general_error;
	TBuf8<3> cue;
	cue.Num(type);
	CEapType *eapType = NULL;
	TInt error;
	// NOTE: This works now only with test_eapol simulator. In the future the index & indextype parameters
	// are received from WLM.
	if (is_client_when_true)
	{
		// We must have a trap here since the EAPOL core knows nothing about Symbian.
		TRAP(error, (eapType = CEapType::NewL(cue, ELan, 666)));
	} else {
		TRAP(error, (eapType = CEapType::NewL(cue, ELan, 667)));
	}
	
	if (error != KErrNone)
	{
		// Interface not found or implementation creation function failed
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ECom could not find/initiate implementation.\n")));
		return eap_status_allocation_error;
	}
	// Create the EAP protocol interface implementation.
	TRAP(error, (*eap_type_if = eapType->GetStackInterfaceL(m_am_tools, partner, is_client_when_true, receive_network_id)));
		
	if (error != KErrNone || 
		*eap_type_if == 0 || 
		(*eap_type_if)->get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Could not create EAP type interface instance.\n")));
		status = eap_status_allocation_error;
		// Unload DLL
		delete eapType;
	}
	else
	{
		status = eap_status_ok;
		// Add plugin information to the member arrays. There is no need to store eap_type pointer because
		// the stack takes care of its deletion.
		m_plugin_if_array.Append(eapType);
		m_eap_type_array.Append(type);
	
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_am_core_symbian_c::start_authentication(
	const eap_am_network_id_c * const receive_network_id,
	const bool is_client_when_true)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_ethernet_core == 0)
	{
		return eap_status_allocation_error;
	}

	m_am_tools->enter_global_mutex();
	eap_status_e status = m_ethernet_core->start_authentication(receive_network_id, is_client_when_true);
	m_am_tools->leave_global_mutex();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_am_core_symbian_c::send_logoff(const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_ethernet_core == 0)
	{
		return eap_status_allocation_error;
	}

	m_am_tools->enter_global_mutex();
	eap_status_e status = m_ethernet_core->send_logoff(receive_network_id);
	m_am_tools->leave_global_mutex();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_core_symbian_c::configure()
{
	m_am_tools->enter_global_mutex();
	eap_status_e status = m_ethernet_core->configure();
	m_am_tools->leave_global_mutex();


	//----------------------------------------------------------

	{
		eap_variable_data_c EAP_TRACE_disable_traces(m_am_tools);

		status = read_configure(
			cf_str_EAP_TRACE_disable_traces.get_field(),
			&EAP_TRACE_disable_traces);
		if (status == eap_status_ok
			&& EAP_TRACE_disable_traces.get_is_valid() == true)
		{
			u32_t *disable_traces = reinterpret_cast<u32_t *>(EAP_TRACE_disable_traces.get_data(sizeof(u32_t));
			if (disable_traces != 0
				&& *disable_traces != 0)
			{
				m_am_tools->set_trace_mask(
					eap_am_tools_c::eap_trace_mask_always
					| eap_am_tools_c::eap_trace_mask_error
					);
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c EAP_TRACE_enable_function_traces(m_am_tools);

		status = read_configure(
			cf_str_EAP_TRACE_enable_function_traces.get_field(),
			&EAP_TRACE_enable_function_traces);
		if (status == eap_status_ok
			&& EAP_TRACE_enable_function_traces.get_is_valid() == true)
		{
			u32_t *enable_function_traces = reinterpret_cast<u32_t *>(EAP_TRACE_enable_function_traces.get_data(sizeof(u32_t));
			if (enable_function_traces != 0
				&& *enable_function_traces != 0)
			{
				m_am_tools->set_trace_mask(
					m_am_tools->get_trace_mask()
					| eap_am_tools_c::eap_trace_mask_functions
					);
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c EAP_ERROR_TEST_enable_random_errors(m_am_tools);

		status = read_configure(
			cf_str_EAP_ERROR_TEST_enable_random_errors.get_field(),
			&EAP_ERROR_TEST_enable_random_errors);
		if (status == eap_status_ok
			&& EAP_ERROR_TEST_enable_random_errors.get_is_valid() == true)
		{
			u32_t *enable_random_errors = reinterpret_cast<u32_t *>(EAP_ERROR_TEST_enable_random_errors.get_data(sizeof(u32_t));
			if (enable_random_errors != 0
				&& *enable_random_errors != 0)
			{
				m_enable_random_errors = true;
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c EAP_ERROR_TEST_error_probability(m_am_tools);

		status = read_configure(
			cf_str_EAP_ERROR_TEST_error_probability.get_field(),
			&EAP_ERROR_TEST_error_probability);
		if (status == eap_status_ok
			&& EAP_ERROR_TEST_error_probability.get_is_valid() == true)
		{
			u32_t *error_probability = reinterpret_cast<u32_t *>(EAP_ERROR_TEST_error_probability.get_data(sizeof(u32_t));
			if (error_probability != 0)
			{
				m_error_probability = *error_probability;
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c trace_output_file(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_TRACE_output_file_name.get_field(),
			&trace_output_file);
		if (status == eap_status_ok
			&& trace_output_file.get_is_valid() == true)
		{
			status = m_am_tools->set_trace_file_name(&trace_output_file);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	//----------------------------------------------------------

	{		
		eap_variable_data_c EAP_TRACE_activate_only_trace_masks_always_and_error(m_am_tools);

		status = read_configure(
			cf_str_EAP_TRACE_activate_only_trace_masks_always_and_error.get_field(),
			&EAP_TRACE_activate_only_trace_masks_always_and_error);
		if (status == eap_status_ok
			&& EAP_TRACE_activate_only_trace_masks_always_and_error.get_is_valid() == true)
		{
			u32_t *activate_trace_mask_always
				= reinterpret_cast<u32_t *>(EAP_TRACE_activate_only_trace_masks_always_and_error.get_data(sizeof(u32_t));
			if (activate_trace_mask_always != 0
				&& *activate_trace_mask_always != 0)
			{
				m_am_tools->set_trace_mask(
					eap_am_tools_c::eap_trace_mask_always
					| eap_am_tools_c::eap_trace_mask_error
					);
			}
		}
	}

	//----------------------------------------------------------

	{		
		eap_variable_data_c EAP_TRACE_activate_trace_on_error(m_am_tools);

		status = read_configure(
			cf_str_EAP_TRACE_activate_trace_on_error.get_field(),
			&EAP_TRACE_activate_trace_on_error);
		if (status == eap_status_ok
			&& EAP_TRACE_activate_trace_on_error.get_is_valid() == true)
		{
			u32_t *activate_trace_on_error = reinterpret_cast<u32_t *>(EAP_TRACE_activate_trace_on_error.get_data(sizeof(u32_t));
			if (activate_trace_on_error != 0
				&& *activate_trace_on_error != 0)
			{
				m_am_tools->set_activate_trace_on_error();
			}
		}
	}

	//----------------------------------------------------------


	return eap_status_ok;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_core_symbian_c::shutdown()
{
	m_am_tools->enter_global_mutex();
	m_ethernet_core->shutdown();
	m_am_tools->leave_global_mutex();

	// Unload all loaded plugins
	for(int i = 0; i < m_plugin_if_array.Count(); i++)
	{
		delete m_plugin_if_array[i];
	}
	m_plugin_if_array.Close();
	m_eap_type_array.Close();

	m_shutdown_was_called = true;

	return eap_status_ok;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_am_core_symbian_c::packet_data_crypto_keys(
	const eap_am_network_id_c * const send_network_id,
	const eap_master_session_key_c * const master_session_key
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->packet_data_crypto_keys(send_network_id, master_session_key);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
}

//--------------------------------------------------
eap_status_e eapol_am_core_symbian_c::packet_data_session_key(
	const eap_am_network_id_c * const /*send_network_id*/,
	const eapol_session_key_c * const /*key*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	switch (key_type)
	{
	case eapol_key_type_wep_broadcast:
		// m_partner->SetWepKey(key, key_length, key_index)
		break;
	case eapol_key_type_wep_unicast:
		//m_partner->SetWepKey(key, key_length, key_index | 0x80)
		break;
	default:
		return eap_status_not_supported;
	}
	//TInt status = m_partner->SetKey(EWepKey, master_session_length, master_session_key)
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}



//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_core_symbian_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	const eap_status_e status = m_partner->read_configure(field, data);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_core_symbian_c::write_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	const eap_status_e status = m_partner->write_configure(field, data);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_am_core_symbian_c::set_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id, 
	void * const p_data,
	const u32_t p_time_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(p_initializer);
	EAP_UNREFERENCED_PARAMETER(p_id);
	EAP_UNREFERENCED_PARAMETER(p_data);
	EAP_UNREFERENCED_PARAMETER(p_time_ms);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_am_tools->am_set_timer(
		p_initializer, 
		p_id, 
		p_data,
		p_time_ms);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_am_core_symbian_c::cancel_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(p_initializer);
	EAP_UNREFERENCED_PARAMETER(p_id);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_am_tools->am_cancel_timer(
		p_initializer, 
		p_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_am_core_symbian_c::cancel_all_timers()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_am_tools->am_cancel_all_timers();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_core_symbian_c::check_is_valid_eap_type(const eap_type_value_e /*eap_type*/)
{

#if defined(USE_EAP_TYPE_GSMSIM)
	if (eap_type == eap_type_gsmsim)
	{
		return eap_status_ok;
	}
	else
#endif
#if defined(USE_SAESIM_EAP_TYPE)
	if (eap_type == eap_type_saesim)
	{
		return eap_status_ok;
	}
	else
#endif
#if defined(USE_DUMMY_SIM_EAP_TYPE)
	if (eap_type == eap_type_sim)
	{
		return eap_status_ok;
	}
	else
#endif
	{
		return eap_status_illegal_eap_type;
	}

}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_core_symbian_c::get_eap_type_list(
	eap_array_c<eap_type_value_e> * const eap_type_list)
{
	eap_type_value_e eap_type = eap_type_none;

	eap_type_list->reset();

	eap_status_e status = eap_status_type_does_not_exists_error;

#if defined(USE_TLS_EAP_TYPE)
	{
		eap_type = eap_type_tls;
		status = eap_type_list->add_data(&eap_type, sizeof(eap_type));
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
#endif
#if defined(USE_PEAP_EAP_TYPE)
	{
		eap_type = eap_type_peap;
		status = eap_type_list->add_data(&eap_type, sizeof(eap_type));
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
#endif
#if defined(USE_EAP_TYPE_GSMSIM)
	{
		eap_type = eap_type_gsmsim;
		status = eap_type_list->add_data(&eap_type, sizeof(eap_type));
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
#endif
#if defined(USE_SAESIM_EAP_TYPE)
	{
		eap_type = eap_type_saesim;
		status = eap_type_list->add_data(&eap_type, sizeof(eap_type));
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
#endif
#if defined(USE_MSCHAPV2_EAP_TYPE)
	{
		eap_type = eap_type_mschapv2;
		status = eap_type_list->add_data(&eap_type, sizeof(eap_type));
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
#endif
#if defined(USE_DUMMY_SIM_EAP_TYPE)
	{
		eap_type = eap_type_sim;
		status = eap_type_list->add_data(&eap_type, sizeof(eap_type));
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
#endif

	if (eap_type == eap_type_none)
	{
		status = eap_type_list->add_data(&eap_type, sizeof(eap_type));
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------




// End.
