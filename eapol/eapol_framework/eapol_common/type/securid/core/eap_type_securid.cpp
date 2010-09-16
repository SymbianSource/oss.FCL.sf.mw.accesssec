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
* %version: 22.1.4 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 115 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include "eap_am_memory.h"
#include "eap_state_notification.h"
#include "eap_memory_store_variable_data.h"
#include "eap_type_securid.h"
#include "eap_type_securid_types.h"
#include "eap_buffer.h"
#include "eap_master_session_key.h"
#include "eap_config.h"

static const u32_t EAP_SECURID_EAP_HEADER_SIZE = 5;

/**
* Constructor initializes all member attributes.
*/

EAP_FUNC_EXPORT eap_type_securid_c::eap_type_securid_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_base_type_c * const partner,
	eap_am_type_securid_c * const am_type_securid,
	const bool free_am_type_securid,
	const eap_type_value_e current_eap_type, ///< This the current EAP-type (GTC or SecurID).
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id)
	: eap_base_type_c(tools, partner)
	, m_am_type_securid(am_type_securid)
	, m_is_valid(false)
	, m_is_client(is_client_when_true)
	, m_eap_type(current_eap_type)
	, m_free_am_type_securid(free_am_type_securid)
	, m_use_EAP_FAST_response(false)
	, m_am_tools(tools)
	, m_send_network_id(tools)
	, m_identity(tools)
	, m_passcode(tools)
	, m_pincode(tools)
	, m_is_first_passcode_query(true)
	, m_is_first_pincode_query(true)
	, m_identity_asked(false)
	, m_is_pending(false)
	, m_state(is_client_when_true)
	, m_is_reauthentication(false)
	, m_use_eap_expanded_type(false)
#if defined(USE_EAP_CONFIGURATION_TO_SKIP_USER_INTERACTIONS)
	, m_skip_user_interactions(false)
#endif //#if defined(USE_EAP_CONFIGURATION_TO_SKIP_USER_INTERACTIONS)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_securid_c::eap_type_securid_c(): this = 0x%08x, ")
		 EAPL("partner 0x%08x, type partner 0x%08x, compiled %s %s\n"),
		 this,
		 partner,
		 get_type_partner(),
		__DATE__,
		__TIME__));

	m_am_type_securid->set_am_partner(this);

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

//--------------------------------------------------

EAP_FUNC_EXPORT eap_type_securid_c::~eap_type_securid_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_securid_c::~eap_type_securid_c(): this = 0x%08x\n"),
		this));

	if (m_free_am_type_securid == true)
	{
		delete m_am_type_securid;
	}

	m_free_am_type_securid = false;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_securid_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_securid_c::shutdown(): this = 0x%08x\n"),
		this));

	m_am_type_securid->shutdown();

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_securid_c::shutdown(): this = 0x%08x returns\n"),
		this));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_securid_c::eap_acknowledge(
	const eap_am_network_id_c * const /* receive_network_id */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_securid_c::set_initial_eap_identifier(
	const eap_am_network_id_c * const /*receive_network_id*/,
	const u8_t /*initial_identifier*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_type_securid_c::set_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_is_valid = true;
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_type_securid_c::get_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_type_securid_c::get_is_client() 
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_client;
}

//--------------------------------------------------

eap_buf_chain_wr_c * eap_type_securid_c::create_send_packet(u32_t length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_buf_chain_wr_c * packet = new eap_buf_chain_wr_c(
		eap_write_buffer, 
		m_am_tools,
		length + m_offset + m_trailer_length);
	if (!packet)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return 0;
	}
	if (packet->get_is_valid() == false)
	{
		delete packet;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return 0;
	}
	packet->set_data_length(length + m_offset);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return packet;
}

//--------------------------------------------------

eap_status_e eap_type_securid_c::packet_send(
	eap_buf_chain_wr_c * const data,
	const u32_t data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	if (m_mtu_length < data->get_data_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (data->get_is_valid_data() == false)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = get_type_partner()->packet_send(
		&m_send_network_id,
		data,
		m_offset,
		data_length,
		data->get_buffer_length());

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_securid_c::finish_successful_authentication()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_SECURID: function: finish_successful_authentication(), EAP-SUCCESS\n")));

	eap_master_session_key_c empty_key(
		m_am_tools,
		m_eap_type);
	u8_t key[1] = "";

	eap_status_e status = empty_key.set_buffer(
		key,
		0ul,
		false,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// This needed in PEAPv2. Just an empty key is given to PEAPv2.
	status = get_type_partner()->packet_data_crypto_keys(
		&m_send_network_id,
		&empty_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_state_notification_c notification(
		m_am_tools,
		&m_send_network_id,
		m_is_client,
		eap_state_notification_eap,
		eap_protocol_layer_eap,
		m_eap_type,
		eap_state_none,
		eap_state_authentication_finished_successfully,
		m_identifier,
		true);
	get_type_partner()->state_notification(&notification);

	// Store úsername for reauthentication (client only)
	if (m_is_client)
	{
		eap_variable_data_c key(m_am_tools);
		status = m_am_type_securid->get_memory_store_key(&key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


		eap_tlv_message_data_c tlv_data(m_am_tools);

		status = tlv_data.add_message_data(
			eap_type_gtc_stored_identity,
			m_identity.get_data_length(),
			m_identity.get_data());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_am_tools->memory_store_add_data(
			&key,
			&tlv_data,
			eap_type_default_credential_timeout);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_SECURID: function: finish_successful_authentication(): cannot store credentials\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_GTC: function: finish_successful_authentication(): ")
			 EAPL("username stored if no errors\n")));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_securid_c::finish_unsuccessful_authentication(
	const bool authentication_cancelled)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_SECURID: function: finish_unsuccessful_authentication()\n")));

	if (authentication_cancelled == true)
	{
		eap_state_notification_c notification(
			m_am_tools,
			&m_send_network_id,
			m_is_client,
			eap_state_notification_eap,
			eap_protocol_layer_general, // This must be used with eap_general_state_authentication_cancelled.
			m_eap_type,
			eap_state_none,
			eap_general_state_authentication_cancelled,
			m_identifier,
			false);

		notification.set_authentication_error(eap_status_authentication_failure);

		get_type_partner()->state_notification(&notification);
	}
	else
	{		
		eap_state_notification_c notification(
			m_am_tools,
			&m_send_network_id,
			m_is_client,
			eap_state_notification_eap,
			eap_protocol_layer_eap,
			m_eap_type,
			eap_state_none,
			eap_state_authentication_terminated_unsuccessfully,
			m_identifier,
			false);

		notification.set_authentication_error(eap_status_authentication_failure);

		if (m_is_client == true)
		{
			eap_variable_data_c string(m_am_tools);
			eap_status_e status = m_am_type_securid->read_auth_failure_string(&string);
			if (status == eap_status_ok)
			{
				notification.set_notification_string(&string, true);
			}
		}
		get_type_partner()->state_notification(&notification);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_securid_c::packet_process(
	const eap_am_network_id_c * const /*receive_network_id*/,
	eap_header_wr_c * const received_eap,
	const u32_t eap_packet_length)
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	if (eap_packet_length < EAP_SECURID_EAP_HEADER_SIZE - 1) // Without type code
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	if (eap_packet_length > received_eap->get_header_buffer_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	if (received_eap->get_type() == eap_type_notification)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}


#ifdef EAP_SECURID_SERVER
	if (m_is_client) // Client
	{
#endif

		status = client_packet_process(
			received_eap,
			eap_packet_length);

#ifdef EAP_SECURID_SERVER
	}
	else // Server
	{
		status = server_packet_process(
			received_eap,
			eap_packet_length);
	}
#endif

	if (status == eap_status_ok)
	{
		EAP_GENERAL_HEADER_SET_ERROR_DETECTED(received_eap, false);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_securid_c::remove_username_store()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_type_securid_c::remove_username_store: Start\n")));
	
	eap_status_e status = eap_status_process_general_error;

	eap_variable_data_c key(m_am_tools);
	status = m_am_type_securid->get_memory_store_key(&key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_tlv_message_data_c tlv_data(m_am_tools);

	status = m_am_tools->memory_store_get_data(
		&key,
		&tlv_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_SECURID: function: remove_username_store(): cannot get credentials, status=%d\n"),
			status));
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_SECURID: function: remove_username_store(): credentials found\n")));

		// Parse read data.
		eap_array_c<eap_tlv_header_c> tlv_blocks(m_am_tools);
				
		status = tlv_data.parse_message_data(&tlv_blocks);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		for (u32_t ind = 0ul; ind < tlv_blocks.get_object_count(); ind++)
		{
			eap_tlv_header_c * const tlv = tlv_blocks.get_object(ind);
			if (tlv != 0)
			{
				if (tlv->get_type() == eap_type_gtc_stored_identity)
				{
					status = m_identity.set_copy_of_buffer(
						tlv->get_value(tlv->get_value_length()),
						tlv->get_value_length());
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					EAP_TRACE_DATA_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("EAP_type_GTC: function: eap_type_securid_c::remove_username_store(): read m_identity:"),
						 m_identity.get_data(),
						 m_identity.get_data_length()));
				}
				else
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("EAP_type_SECURID: function: unknown credential type %d, length %d\n"),
						 tlv->get_type(),
						 tlv->get_value_length()));
				}
			}
		}
		
		status = m_am_tools->memory_store_remove_data(&key);
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_SECURID: function: remove_username_store(): credentials removed from eapol\n")));
		
		m_is_reauthentication = true;
		m_identity_asked = true;

	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_securid_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_securid_c::configure(): this = 0x%08x\n"),
		this));

	eap_status_e status = eap_status_process_general_error;

	status = m_am_type_securid->configure();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_offset = get_type_partner()->get_header_offset(&m_mtu_length, &m_trailer_length);

	// Check if the case is reauthentication (client only)
	if (m_is_client)
	{
		remove_username_store();
	}

	// read configures
	if (m_eap_type == eap_type_securid)
	{
		(void) m_am_type_securid->type_configure_read(
			cf_str_EAP_SECURID_identity.get_field(),
			&m_identity);
		// Status does not matter.

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_GTC: function: eap_type_securid_c::configure(): m_identity:"),
			 m_identity.get_data(),
			 m_identity.get_data_length()));

		if (m_is_client == false)
		{
			(void) m_am_type_securid->type_configure_read(
				cf_str_EAP_SECURID_passcode.get_field(),
				&m_pincode);
		}
	}
	else
	{
		(void) m_am_type_securid->type_configure_read(
			cf_str_EAP_GTC_identity.get_field(),
			&m_identity);
		// Status does not matter.

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_GTC: function: eap_type_securid_c::configure(): m_identity:"),
			 m_identity.get_data(),
			 m_identity.get_data_length()));

		if (m_is_client == false)
		{
			(void) m_am_type_securid->type_configure_read(
				cf_str_EAP_GTC_passcode.get_field(),
				&m_passcode);
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c use_eap_expanded_type(m_am_tools);
		eap_status_e status(eap_status_process_general_error);

		if (m_eap_type == eap_type_securid)
		{
			status = m_am_type_securid->type_configure_read(
				cf_str_EAP_SECURID_use_eap_expanded_type.get_field(),
				&use_eap_expanded_type);
		}
		else
		{
			status = m_am_type_securid->type_configure_read(
				cf_str_EAP_GTC_use_eap_expanded_type.get_field(),
				&use_eap_expanded_type);
		}

		if (status != eap_status_ok)
		{
			status = m_am_type_securid->type_configure_read(
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

#if defined(USE_FAST_EAP_TYPE)
	
	{
		eap_variable_data_c use_EAP_FAST_response(m_am_tools);

		status = m_am_type_securid->type_configure_read(
			cf_str_EAP_GTC_use_EAP_FAST_response.get_field(),
			&use_EAP_FAST_response);
		if (status == eap_status_ok)
		{
			const u32_t * const flag = reinterpret_cast<u32_t *>(
				use_EAP_FAST_response.get_data(sizeof(u32_t)));
			if (flag != 0 && *flag != 0)
			{
				m_use_EAP_FAST_response = true;
			}
			else
			{
				m_use_EAP_FAST_response = false;
			}
		}
	}

#endif //#if defined(USE_FAST_EAP_TYPE)

	//----------------------------------------------------------

#if defined(USE_EAP_CONFIGURATION_TO_SKIP_USER_INTERACTIONS)
	{
		eap_variable_data_c skip_user_interactions(m_am_tools);

		status = m_am_type_securid->type_configure_read(
			cf_str_EAP_skip_user_interactions_for_testing_purposes.get_field(),
			&skip_user_interactions);
		if (status == eap_status_ok
			&& skip_user_interactions.get_is_valid_data() == true)
		{
			u32_t *skip_user_interactions_flag = reinterpret_cast<u32_t *>(
				skip_user_interactions.get_data(sizeof(u32_t)));
			if (skip_user_interactions_flag != 0)
			{
				if (*skip_user_interactions_flag != 0)
				{
					m_skip_user_interactions = true;
				}
				else
				{
					m_skip_user_interactions = false;
				}
			}
		}
	}

	if (m_skip_user_interactions == true)
	{
		(void) m_am_type_securid->type_configure_read(
			cf_str_EAP_GTC_passcode.get_field(),
			&m_passcode);
	}
#endif //#if defined(USE_EAP_CONFIGURATION_TO_SKIP_USER_INTERACTIONS)

	//----------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

// This function is to allow reuse of this object.
// The whole object state must be reset.
EAP_FUNC_EXPORT eap_status_e eap_type_securid_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_securid_c::reset(): m_is_client=%d, m_eap_type=%d\n"),
		m_is_client,
		convert_eap_type_to_u32_t(m_eap_type)));	

	if (m_is_client)
	{
		remove_username_store();
	}

	// read configures
	if (m_eap_type == eap_type_securid)
	{
		m_am_type_securid->type_configure_read(
			cf_str_EAP_SECURID_identity.get_field(),
			&m_identity);
		// Status does not matter.
	}
	else
	{
		m_am_type_securid->type_configure_read(
			cf_str_EAP_GTC_identity.get_field(),
			&m_identity);
		// Status does not matter.
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_GTC: function: eap_type_securid_c::reset(): m_identity:"),
		 m_identity.get_data(),
		 m_identity.get_data_length()));

	m_state.set_state(eap_type_securid_state_none);
	m_identity_asked = false;
	m_is_pending = false;

	eap_status_e status = m_am_type_securid->reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------


// End.
