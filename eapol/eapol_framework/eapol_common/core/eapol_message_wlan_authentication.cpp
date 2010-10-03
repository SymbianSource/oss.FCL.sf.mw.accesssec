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
* %version: 64 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 575 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eapol_message_wlan_authentication.h"
#include "eapol_wlan_database_reference.h"
#include "eap_am_memory.h"
#include "abs_eap_state_notification.h"
#include "eap_crypto_api.h"
#include "eap_header_string.h"
#include "eap_buffer.h"
#include "eapol_session_key.h"
#include "eapol_handle_tlv_message_data.h"
#include "eap_automatic_variable.h"
#include "eap_array_algorithms.h"
#include "eap_config.h"

//--------------------------------------------------

#if defined(USE_TEST_WLAN_AUTHENTICATION_MUTEX) && defined(USE_EAPOL_WLAN_AUTHENTICATION_MUTEX)
	#error "You cannot define both USE_EAPOL_WLAN_AUTHENTICATION_MUTEX and USE_TEST_WLAN_AUTHENTICATION_MUTEX."
#endif

#if !defined(USE_TEST_WLAN_AUTHENTICATION_MUTEX) && defined(USE_EAPOL_WLAN_AUTHENTICATION_MESSAGE_ASYNCRONOUS_TEST)
	#error "You must define USE_TEST_WLAN_AUTHENTICATION_MUTEX if USE_EAPOL_WLAN_AUTHENTICATION_MESSAGE_ASYNCRONOUS_TEST is used."
#endif

//--------------------------------------------------

/**
 * This is the timer ID used with abs_eap_am_tools_c::set_timer() and abs_eap_am_tools_c::cancel_timer().
 */
enum eapol_core_timer_id
{
	EAPOL_MESSAGE_TIMER_PROCESS_DATA_ID,
	EAPOL_MESSAGE_TIMER_SEND_DATA_ID,
};


//--------------------------------------------------

EAP_FUNC_EXPORT eapol_message_wlan_authentication_c::~eapol_message_wlan_authentication_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eapol_message_wlan_authentication_c::eapol_message_wlan_authentication_c(
	abs_eap_am_tools_c * const tools,
	abs_eapol_message_wlan_authentication_c * const partner)
	: m_am_tools(tools)
	, m_wauth(0)
	, m_partner(partner)
	, m_wlan_database_reference(tools)
	, m_header_offset(0ul)
	, m_MTU(0ul)
	, m_trailer_length(0ul)
	, m_error_code(wlan_eap_if_send_status_ok)
	, m_error_function(eap_tlv_message_type_function_none)
	, m_use_asyncronous_test(false)
	, m_is_valid(true)
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::configure(
	const u32_t header_offset,
	const u32_t MTU,
	const u32_t trailer_length)
{
	eap_status_e status(eap_status_ok);

	//----------------------------------------------------------

	m_header_offset = header_offset;
	m_MTU = MTU;
	m_trailer_length = trailer_length;

	//----------------------------------------------------------

	// eapol_wlan_authentication_c object uses the tools object.
	m_wauth = eapol_wlan_authentication_c::new_eapol_wlan_authentication(
		m_am_tools,
		this,
		true);
	if (m_wauth != 0
		&& m_wauth->get_is_valid() == true)
	{
		status = m_wauth->configure();
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c EAPOL_TEST_use_asyncronous_test(m_am_tools);

		eap_status_e status = m_wauth->read_configure(
			cf_str_EAPOL_TEST_use_message_asyncronous_test.get_field(),
			&EAPOL_TEST_use_asyncronous_test);
		if (status == eap_status_ok
			&& EAPOL_TEST_use_asyncronous_test.get_is_valid_data() == true)
		{
			u32_t *use_asyncronous_test = reinterpret_cast<u32_t *>(
				EAPOL_TEST_use_asyncronous_test.get_data(sizeof(u32_t)));
			if (use_asyncronous_test != 0
				&& *use_asyncronous_test != 0)
			{
				m_use_asyncronous_test = true;
			}
		}
	}

	//----------------------------------------------------------

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::shutdown()
{
	// After use the eapol_wlan_authentication_c object must be deleted first.
	if (m_wauth != 0)
	{
		m_wauth->shutdown();
		delete m_wauth;
		m_wauth = 0;
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eapol_message_wlan_authentication_c::get_is_valid()
{
	return m_is_valid;
}

// ----------------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::timer_expired(
	const u32_t id, void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: [0x%08x]->eapol_message_wlan_authentication_c::timer_expired")
		 EAPL("(id 0x%02x, data 0x%08x).\n"),
		 this, id, data));
	
#if defined(USE_EAPOL_WLAN_AUTHENTICATION_MESSAGE_ASYNCRONOUS_TEST)

	if (id == EAPOL_MESSAGE_TIMER_PROCESS_DATA_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: [0x%08x]->eapol_message_wlan_authentication_c::timer_expired: EAPOL_MESSAGE_TIMER_PROCESS_DATA_ID")
			 EAPL("(id 0x%02x, data 0x%08x).\n"),
			 this, id, data));
	
		eapol_handle_tlv_message_data_c * const message = reinterpret_cast<eapol_handle_tlv_message_data_c *>(data);
		if (message != 0)
		{
			eap_status_e status = process_message(message);

			(void) EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (id == EAPOL_MESSAGE_TIMER_SEND_DATA_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: [0x%08x]->eapol_message_wlan_authentication_c::timer_expired: EAPOL_MESSAGE_TIMER_SEND_DATA_ID")
			 EAPL("(id 0x%02x, data 0x%08x).\n"),
			 this, id, data));
	
		eapol_handle_tlv_message_data_c * const message = reinterpret_cast<eapol_handle_tlv_message_data_c *>(data);
		if (message != 0)
		{
			wlan_eap_if_send_status_e send_status = m_partner->send_data(
				message->get_message_data(),
				message->get_message_data_length());

			if (send_status != wlan_eap_if_send_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				(void) EAP_STATUS_RETURN(m_am_tools,
					wlan_eap_if_send_status_conversion_c::convert(send_status));
			}
		}
	}

#else

	EAP_UNREFERENCED_PARAMETER(id);
	EAP_UNREFERENCED_PARAMETER(data);

#endif

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

// ----------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::timer_delete_data(
	const u32_t id, void * data)
{

#if defined(USE_EAPOL_WLAN_AUTHENTICATION_MESSAGE_ASYNCRONOUS_TEST)

	if (id == EAPOL_MESSAGE_TIMER_PROCESS_DATA_ID
		|| id == EAPOL_MESSAGE_TIMER_SEND_DATA_ID)
	{
		eapol_handle_tlv_message_data_c * const message = reinterpret_cast<eapol_handle_tlv_message_data_c *>(data);
		if (message != 0)
		{
			delete message;
		}
	}

#else

	EAP_UNREFERENCED_PARAMETER(id);
	EAP_UNREFERENCED_PARAMETER(data);

#endif

	return eap_status_ok;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::packet_send(
	const eap_am_network_id_c * const send_network_id,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const u32_t buffer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	if (sent_packet->get_do_length_checks() == true)
	{
		if (header_offset != m_header_offset)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: packet_send: packet buffer corrupted (header_offset != %d).\n"),
				m_header_offset));
			EAP_ASSERT_ALWAYS(header_offset == m_header_offset);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}
		else if (header_offset+data_length != sent_packet->get_data_length())
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: packet_send: packet buffer corrupted ")
				 EAPL("(data_length %d != sent_packet->get_data_length() %d).\n"),
				 header_offset+data_length,
				 sent_packet->get_data_length()));
			EAP_ASSERT_ALWAYS(data_length == sent_packet->get_buffer_length());
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}
		else if (header_offset+data_length > buffer_length)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: packet_send: packet buffer corrupted ")
				 EAPL("(header_offset+data_length %d > buffer_length %d).\n"),
				 header_offset+data_length,
				 buffer_length));
			EAP_ASSERT_ALWAYS(header_offset+data_length <= buffer_length);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}
		else if (header_offset+data_length > m_MTU)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: packet_send: packet buffer corrupted ")
				 EAPL("(header_offset+data_length %d > m_MTU %d).\n"),
				 header_offset+data_length,
				 m_MTU));
			EAP_ASSERT_ALWAYS(header_offset+data_length <= m_MTU);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}
	}
	else
	{

#if !defined(EAPOL_SKIP_ETHERNET_HEADER)

		// Always we need at least the Ethernet header.
		if (sent_packet->get_data_length()
			< eapol_ethernet_header_wr_c::get_header_length())
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: packet_send: packet buffer corrupted ")
				 EAPL("(sent_packet->get_data_length() %d < ")
				 EAPL("eapol_ethernet_header_wr_c::get_header_length() %d).\n"),
				 sent_packet->get_data_length(),
				 eapol_ethernet_header_wr_c::get_header_length()));
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

#endif //#if !defined(EAPOL_SKIP_ETHERNET_HEADER)

	}
	
	eapol_ethernet_header_wr_c eth(
		m_am_tools,
		sent_packet->get_data_offset(header_offset, data_length),
		data_length);
	if (eth.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	
	{
		// Creates message data composed of Attribute-Value Pairs.
		eapol_handle_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_packet_send);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(send_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(sent_packet);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eapol_message_wlan_authentication_c::get_header_offset(
	u32_t * const MTU,
	u32_t * const trailer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Header of this module is in the beging of the buffer
	// no additional header are used.
	*MTU = m_MTU;
	*trailer_length = m_trailer_length;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_header_offset;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::associate(
	eapol_key_802_11_authentication_mode_e authentication_mode)
{
	eap_status_e status(eap_status_ok);

	{
		// Creates message data composed of Attribute-Value Pairs.
		eapol_handle_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_associate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(
			eap_tlv_message_type_eapol_key_802_11_authentication_mode,
			static_cast<u32_t>(authentication_mode));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::disassociate(
	const eap_am_network_id_c * const receive_network_id, ///< source includes remote address, destination includes local address.
	const bool self_disassociation)
{
	eap_status_e status(eap_status_ok);

	{
		// Creates message data composed of Attribute-Value Pairs.
		eapol_handle_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_disassociate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(receive_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(self_disassociation);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::packet_data_session_key(
	const eap_am_network_id_c * const send_network_id,
	const eapol_session_key_c * const key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	eap_status_e status(eap_status_ok);

	if (key == 0
		|| key->get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: test_eapol_c::packet_data_session_key(), invalid key.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("test_eapol_c::packet_data_session_key(): key_type 0x%02x, key_index %d\n"),
		 key->get_key_type(),
		 key->get_key_index()));
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("test_eapol_c::packet_data_session_key"), 
		 key->get_key()->get_data(key->get_key()->get_data_length()),
		 key->get_key()->get_data_length()));
	
	{
		// Creates message data composed of Attribute-Value Pairs.
		eapol_handle_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_packet_data_session_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(send_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eapol_message_wlan_authentication_c::state_notification(
	const abs_eap_state_notification_c * const state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	{
		// Creates message data composed of Attribute-Value Pairs.
		eapol_handle_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void)EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			return;
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_state_notification);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void)EAP_STATUS_RETURN(m_am_tools, status);
			return;
		}

		status = message.add_parameter_data(state);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void)EAP_STATUS_RETURN(m_am_tools, status);
			return;
		}

		status = send_message(&message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void)EAP_STATUS_RETURN(m_am_tools, status);
			return;
		}
	}
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::add_rogue_ap(eap_array_c<eap_rogue_ap_entry_c> & /* rogue_ap_list */)
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::reassociate(
	const eap_am_network_id_c * const send_network_id,
	const eapol_key_authentication_type_e authentication_type,
	const eap_variable_data_c * const PMKID)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	if (PMKID == 0
		|| PMKID->get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: eapol_message_wlan_authentication_c::reassociate(), invalid PMKID.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eapol_message_wlan_authentication_c::reassociate"), 
		 PMKID->get_data(PMKID->get_data_length()),
		 PMKID->get_data_length()));
	
	{
		// Creates message data composed of Attribute-Value Pairs.
		eapol_handle_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_reassociate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(send_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(
			eap_tlv_message_type_eapol_key_authentication_type,
			static_cast<u32_t>(authentication_type));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(PMKID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::send_error_message(
	const eap_status_e function_status,
	const eap_tlv_message_type_function_e function)
{
	wlan_eap_if_send_status_e error_code = wlan_eap_if_send_status_conversion_c::convert(function_status);

	eap_status_e status(eap_status_ok);

	{
		// Creates message data composed of Attribute-Value Pairs.
		eapol_handle_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(
			eap_tlv_message_type_error,
			static_cast<u32_t>(error_code));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(function);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

//
EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::save_simple_config_session(
	const simple_config_state_e /* state */,
	EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
	const eap_variable_data_c * const /* new_password */,
	const simple_config_Device_Password_ID_e /* Device_Password_ID */,
	const simple_config_payloads_c * const /* other_configuration */)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_message_wlan_authentication_c::save_simple_config_session()\n")));

	// Message is formatted as:
	// 0                   1                   2                   3   
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Function                            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 4                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Value = New_protected_setup_credentials    |
	// +#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+ <= start of Array of Protected setup credential
	// |                    Type = Array                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 137                               |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ <= start of Array of Protected setup credential value
	// |                    Type = Protected setup credential          |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 129                               |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Unsigned 8 bit integer              |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 1                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   u8_t value  |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Variable data                       |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 12                                |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Value = SSID string                        |
	// +-+-+-+-                                                 -+-+-+-+
	// |                                                               |
	// +-+-+-+-                                                 -+-+-+-+
	// |                                                               |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Unsigned 16 bit integer             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 2                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   u16_t Authentication type   |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Unsigned 16 bit integer             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 2                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   u16_t Encryption type       |
	// +#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+ <= start of Array of Network key
	// |                    Type = Array                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 66                                |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ <= start of Array of Network key value
	// |                    Type = Network key                         |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 25                                |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Unsigned 8 bit integer              |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 1                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   u8_t value  |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Variable data                       |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 8                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Value = Network key                        |
	// +-+-+-+-                                                 -+-+-+-+
	// |                                                               |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Network key                         |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 25                                |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Unsigned 8 bit integer              |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 1                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   u8_t value  |
	// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	// |                    Type = Variable data                       |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 8                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Value = Network key                        |
	// +-+-+-+-                                                 -+-+-+-+
	// |                                                               |
	// +#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+ <= end of Array of Network key
	// |                    Type = Variable data                       |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Length = 6                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Value = MAC address                        |
	// +-+-+-+-                        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                               |
	// +#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+#+                                 <= end of Array of Protected setup credential


	eap_status_e status(eap_status_ok);

	{
		// Creates message data composed of Attribute-Value Pairs.
		eapol_handle_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_new_protected_setup_credentials);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(credential_array);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::complete_check_pmksa_cache(
	EAP_TEMPLATE_CONST eap_array_c<eap_am_network_id_c> * const bssid_sta_receive_network_ids)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_message_wlan_authentication_c::complete_check_pmksa_cache()\n")));

	eap_status_e status(eap_status_process_general_error);

	// Creates message data composed of Attribute-Value Pairs.
	eapol_handle_tlv_message_data_c message(m_am_tools);

	if (message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = message.add_parameter_data(eap_tlv_message_type_function_complete_check_pmksa_cache);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		u32_t bssid_sta_receive_network_ids_size(0ul);
		u32_t ind(0ul);

		for (ind = 0ul; ind < bssid_sta_receive_network_ids->get_object_count(); ++ind)
		{
			const eap_am_network_id_c * const network_id = bssid_sta_receive_network_ids->get_object(ind);
			if (network_id == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			const u32_t size_of_network_id = 
				eap_tlv_header_c::get_header_length()
				+ message.get_payload_size(network_id);

			bssid_sta_receive_network_ids_size += size_of_network_id;
		} // for()

		eap_status_e status = message.add_structured_parameter_header(
			eap_tlv_message_type_array,
			bssid_sta_receive_network_ids_size);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		for (ind = 0ul; ind < bssid_sta_receive_network_ids->get_object_count(); ++ind)
		{
			status = message.add_parameter_data(
				bssid_sta_receive_network_ids->get_object(ind));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		} // for()
	}

	status = send_message(&message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::complete_disassociation(
	const eap_am_network_id_c * const receive_network_id) ///< source includes remote address, destination includes local address.
{
	eap_status_e status(eap_status_ok);

	{
		// Creates message data composed of Attribute-Value Pairs.
		eapol_handle_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_complete_disassociation);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(receive_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::process_message_type_error(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	eap_status_e status(eap_status_ok);

	eapol_handle_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e code(eap_status_process_general_error);

	// Error payload is the first in this case.
	status = message_data.read_parameter_data(parameters, eap_message_payload_index_function, eap_tlv_message_type_error, &code);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_error_code = wlan_eap_if_send_status_conversion_c::convert(code);

	// Fuction payload is the second in this case.
	status = message_data.read_parameter_data(parameters, eap_message_payload_index_first_parameter, &m_error_function);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::send_message(eapol_handle_tlv_message_data_c * const message)
{
	// Sends message data composed of Attribute-Value Pairs.

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: eapol_message_wlan_authentication_c::send_message()\n")));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eapol_message_wlan_authentication_c::send_message()");

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_NEVER,
		(EAPL("eapol_message_wlan_authentication_c::send_message()"),
		message->get_message_data(),
		message->get_message_data_length()));

#if defined(USE_EAPOL_WLAN_AUTHENTICATION_MESSAGE_ASYNCRONOUS_TEST)

	if (m_use_asyncronous_test == true)
	{
		eap_status_e status(eap_status_ok);

		eapol_handle_tlv_message_data_c * copy_message = new eapol_handle_tlv_message_data_c(m_am_tools);

		eap_automatic_variable_c<eapol_handle_tlv_message_data_c> automatic_message(m_am_tools, copy_message);

		if (copy_message == 0
			|| copy_message->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

			status = eap_status_allocation_error;

			(void) send_error_message(
				status,
				eap_tlv_message_type_function_none);

			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = copy_message->copy_message_data(
			message->get_message_data_length(),
			message->get_message_data());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

			(void) send_error_message(
				status,
				eap_tlv_message_type_function_none);

			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		automatic_message.do_not_free_variable();

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: eapol_message_wlan_authentication_c::process_data(): sets EAPOL_MESSAGE_TIMER_SEND_DATA_ID\n")));
	
		status = m_am_tools->am_set_timer(
			this,
			EAPOL_MESSAGE_TIMER_SEND_DATA_ID, 
			copy_message,
			0ul);

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else

#endif

	{
		wlan_eap_if_send_status_e send_status = m_partner->send_data(
			message->get_message_data(),
			message->get_message_data_length());
		if (send_status != wlan_eap_if_send_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools,
				wlan_eap_if_send_status_conversion_c::convert(send_status));
		}


		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools,
			wlan_eap_if_send_status_conversion_c::convert(send_status));
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT wlan_eap_if_send_status_e eapol_message_wlan_authentication_c::process_data(const void * const data, const u32_t length)
{
	// Parses message data composed of Attribute-Value Pairs.

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: eapol_message_wlan_authentication_c::process_data()\n")));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eapol_message_wlan_authentication_c::process_data()");

	eap_status_e status(eap_status_ok);

#if defined(USE_EAPOL_WLAN_AUTHENTICATION_MESSAGE_ASYNCRONOUS_TEST)

	if (m_use_asyncronous_test == true)
	{
		eapol_handle_tlv_message_data_c * message = new eapol_handle_tlv_message_data_c(m_am_tools);

		eap_automatic_variable_c<eapol_handle_tlv_message_data_c> automatic_message(m_am_tools, message);

		if (message == 0
			|| message->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

			status = eap_status_allocation_error;

			(void) send_error_message(
				status,
				eap_tlv_message_type_function_none);

			return wlan_eap_if_send_status_conversion_c::convert(
				EAP_STATUS_RETURN(m_am_tools, status));
		}

		status = message->copy_message_data(length, data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

			(void) send_error_message(
				status,
				eap_tlv_message_type_function_none);

			return wlan_eap_if_send_status_conversion_c::convert(
				EAP_STATUS_RETURN(m_am_tools, status));
		}

		automatic_message.do_not_free_variable();

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: eapol_message_wlan_authentication_c::process_data(): sets EAPOL_MESSAGE_TIMER_PROCESS_DATA_ID\n")));
	
		status = m_am_tools->am_set_timer(
			this,
			EAPOL_MESSAGE_TIMER_PROCESS_DATA_ID, 
			message,
			0ul);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return wlan_eap_if_send_status_conversion_c::convert(
				EAP_STATUS_RETURN(m_am_tools, status));
		}
	}
	else

#endif

	{
		eapol_handle_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

			status = eap_status_allocation_error;

			(void) send_error_message(
				status,
				eap_tlv_message_type_function_none);

			return wlan_eap_if_send_status_conversion_c::convert(
				EAP_STATUS_RETURN(m_am_tools, status));
		}

		status = message.set_message_data(length, data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

			(void) send_error_message(
				status,
				eap_tlv_message_type_function_none);

			return wlan_eap_if_send_status_conversion_c::convert(
				EAP_STATUS_RETURN(m_am_tools, status));
		}

		status = process_message(&message);
	}

	return wlan_eap_if_send_status_conversion_c::convert(
		EAP_STATUS_RETURN(m_am_tools, status));
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::process_message(eapol_handle_tlv_message_data_c * const message)
{
	// Parses message data composed of Attribute-Value Pairs.

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: eapol_message_wlan_authentication_c::process_message()\n")));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eapol_message_wlan_authentication_c::process_message()");

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_NEVER,
		(EAPL("eapol_message_wlan_authentication_c::process_message()"),
		message->get_message_data(),
		message->get_message_data_length()));

	eap_array_c<eap_tlv_header_c> parameters(m_am_tools);

	eap_status_e status = message->parse_message_data(&parameters);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

		(void) send_error_message(
			status,
			eap_tlv_message_type_function_none);

		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (parameters.get_object_count() == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

		status = eap_status_illegal_parameter;

		(void) send_error_message(
			status,
			eap_tlv_message_type_function_none);

		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const eap_tlv_header_c * const function_header = parameters.get_object(eap_message_payload_index_function);
	if (function_header == 0
		|| (function_header->get_type() != eap_tlv_message_type_error
			&& function_header->get_type() != eap_tlv_message_type_function))
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

		status = eap_status_illegal_parameter;

		(void) send_error_message(
			status,
			eap_tlv_message_type_function_none);

		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (function_header->get_type() == eap_tlv_message_type_error)
	{
		status = process_message_type_error(&parameters);
	}
	else // function_header->get_type() == eap_tlv_message_type_function
	{
		eap_tlv_message_type_function_e function(eap_tlv_message_type_function_none);

		status = message->get_parameter_data(function_header, &function);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

			(void) send_error_message(
				status,
				eap_tlv_message_type_function_none);

			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eapol_message_wlan_authentication_c::process_message(): this = 0x%08x, message=%d=%s\n"),
			this,
			function,
			eap_process_tlv_message_data_c::get_function_string(function)));

		switch(function)
		{
		case eap_tlv_message_type_function_check_pmksa_cache:
			status = check_pmksa_cache(&parameters);
			break;
		case eap_tlv_message_type_function_start_authentication:
			status = start_authentication(&parameters);
			break;
		case eap_tlv_message_type_function_complete_association:
			status = complete_association(&parameters);
			break;
		case eap_tlv_message_type_function_disassociation:
			status = disassociation(&parameters);
			break;
		case eap_tlv_message_type_function_start_preauthentication:
			status = start_preauthentication(&parameters);
			break;
		case eap_tlv_message_type_function_start_reassociation:
			status = start_reassociation(&parameters);
			break;
		case eap_tlv_message_type_function_complete_reassociation:
			status = complete_reassociation(&parameters);
			break;
		case eap_tlv_message_type_function_start_WPXM_reassociation:
			status = start_WPXM_reassociation(&parameters);
			break;
		case eap_tlv_message_type_function_complete_WPXM_reassociation:
			status = complete_WPXM_reassociation(&parameters);
			break;
		case eap_tlv_message_type_function_packet_process:
			status = packet_process(&parameters);
			break;
		case eap_tlv_message_type_function_tkip_mic_failure:
			status = tkip_mic_failure(&parameters);
			break;
		case eap_tlv_message_type_function_eap_acknowledge:
			status = eap_acknowledge(&parameters);
			break;
		case eap_tlv_message_type_function_update_header_offset:
			status = update_header_offset(&parameters);
			break;
		case eap_tlv_message_type_function_update_wlan_database_reference_values:
			status = update_wlan_database_reference_values(&parameters);
			break;
		default:
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: process_data(): unknown function %d.\n"),
				 function));

			status = eap_status_illegal_parameter;
		};

		if (status != eap_status_ok
			&& status != eap_status_success
			&& status != eap_status_pending_request
			&& status != eap_status_completed_request
			&& status != eap_status_drop_packet_quietly)
		{
			(void) send_error_message(
				status,
				function);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::check_pmksa_cache(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eapol_handle_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_array_c<eap_am_network_id_c> bssid_sta_receive_network_ids(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &bssid_sta_receive_network_ids);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eapol_key_authentication_type_e selected_eapol_key_authentication_type(eapol_key_authentication_type_none);

	status = message_data.read_parameter_data(parameters, parameter_index, &selected_eapol_key_authentication_type);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite(eapol_RSNA_key_header_c::eapol_RSNA_cipher_none);

	status = message_data.read_parameter_data(parameters, parameter_index, &pairwise_key_cipher_suite);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite(eapol_RSNA_key_header_c::eapol_RSNA_cipher_none);

	status = message_data.read_parameter_data(parameters, parameter_index, &group_key_cipher_suite);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_wauth->check_pmksa_cache(
		&bssid_sta_receive_network_ids,
		selected_eapol_key_authentication_type,
		pairwise_key_cipher_suite,
		group_key_cipher_suite);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if 0

	if (status == eap_status_ok
		|| status == eap_status_not_found)
	{
		// Creates message data composed of Attribute-Value Pairs.
		eapol_handle_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(
			eap_tlv_message_type_function_complete_check_pmksa_cache);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		u32_t network_id_parameters_size(0ul);
		u32_t ind = 0ul;

		// Calculates the message size.
		for (ind = 0ul; ind < bssid_sta_receive_network_ids.get_object_count(); ++ind)
		{
			const eap_am_network_id_c * const network_id = bssid_sta_receive_network_ids.get_object(ind);
			if (network_id == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			network_id_parameters_size += 
				eap_tlv_header_c::get_header_length()
				+ message.get_payload_size(network_id);
		}

		status = message.add_structured_parameter_header(
			eap_tlv_message_type_array,
			network_id_parameters_size);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		// Adds network ID array objects to message.
		for (ind = 0ul; ind < bssid_sta_receive_network_ids.get_object_count(); ++ind)
		{
			const eap_am_network_id_c * const network_id = bssid_sta_receive_network_ids.get_object(ind);
			if (network_id == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			status = message.add_parameter_data(
				network_id);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		status = send_message(&message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

#endif //#if 0

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::start_authentication(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eapol_handle_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c SSID(m_am_tools);

	if (SSID.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = message_data.read_parameter_data(parameters, parameter_index, &SSID);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eapol_key_authentication_type_e selected_eapol_key_authentication_type(eapol_key_authentication_type_none);

	status = message_data.read_parameter_data(parameters, parameter_index, &selected_eapol_key_authentication_type);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_variable_data_c wpa_preshared_key(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &wpa_preshared_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	bool WPA_override_enabled(false);

	status = message_data.read_parameter_data(parameters, parameter_index, &WPA_override_enabled);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_am_network_id_c receive_network_id(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_wauth->start_authentication(
		&SSID,
		selected_eapol_key_authentication_type,
		&wpa_preshared_key,
		WPA_override_enabled,
		&receive_network_id
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::complete_association(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eapol_handle_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eapol_wlan_authentication_state_e association_result(eapol_wlan_authentication_state_none);

	status = message_data.read_parameter_data(parameters, parameter_index, &association_result);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_am_network_id_c receive_network_id(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_variable_data_c received_WPA_IE(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &received_WPA_IE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_variable_data_c sent_WPA_IE(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &sent_WPA_IE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite(eapol_RSNA_key_header_c::eapol_RSNA_cipher_none);

	status = message_data.read_parameter_data(parameters, parameter_index, &pairwise_key_cipher_suite);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite(eapol_RSNA_key_header_c::eapol_RSNA_cipher_none);

	status = message_data.read_parameter_data(parameters, parameter_index, &group_key_cipher_suite);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_wauth->complete_association(
		association_result,
		&receive_network_id, ///< source includes remote address, destination includes local address.
		&received_WPA_IE, // WLM must give only the WPA IE to EAPOL
		&sent_WPA_IE,
		pairwise_key_cipher_suite,
		group_key_cipher_suite
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::disassociation(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eapol_handle_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_am_network_id_c receive_network_id(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_wauth->disassociation(
		&receive_network_id ///< source includes remote address, destination includes local address.
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::start_preauthentication(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eapol_handle_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_am_network_id_c receive_network_id(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_wauth->start_preauthentication(
		&receive_network_id ///< source includes remote address, destination includes local address.
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::start_reassociation(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eapol_handle_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_am_network_id_c old_receive_network_id(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &old_receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_am_network_id_c new_receive_network_id(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &new_receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eapol_key_authentication_type_e selected_eapol_key_authentication_type(eapol_key_authentication_type_none);

	status = message_data.read_parameter_data(parameters, parameter_index, &selected_eapol_key_authentication_type);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_wauth->start_reassociation(
		&old_receive_network_id,
		&new_receive_network_id,
		selected_eapol_key_authentication_type);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::complete_reassociation(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eapol_handle_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eapol_wlan_authentication_state_e association_result(eapol_wlan_authentication_state_none);

	status = message_data.read_parameter_data(parameters, parameter_index, &association_result);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_am_network_id_c receive_network_id(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_variable_data_c received_WPA_IE(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &received_WPA_IE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_variable_data_c sent_WPA_IE(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &sent_WPA_IE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite(eapol_RSNA_key_header_c::eapol_RSNA_cipher_none);

	status = message_data.read_parameter_data(parameters, parameter_index, &pairwise_key_cipher_suite);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite(eapol_RSNA_key_header_c::eapol_RSNA_cipher_none);

	status = message_data.read_parameter_data(parameters, parameter_index, &group_key_cipher_suite);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_wauth->complete_reassociation(
		association_result,
		&receive_network_id, ///< source includes remote address, destination includes local address.
		&received_WPA_IE, // WLM must give only the WPA IE to EAPOL
		&sent_WPA_IE,
		pairwise_key_cipher_suite,
		group_key_cipher_suite
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::start_WPXM_reassociation(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eapol_handle_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_am_network_id_c old_receive_network_id(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &old_receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_am_network_id_c new_receive_network_id(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &new_receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_variable_data_c send_reassociation_request_ie(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &send_reassociation_request_ie);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_variable_data_c received_WPA_ie(m_am_tools);

	if (parameters->get_object_count() > parameter_index)
	{
		status = message_data.read_parameter_data(parameters, parameter_index, &received_WPA_ie);
		if (status != eap_status_ok)
		{
			// This is optional parameter.
			(void) EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_variable_data_c sent_WPA_ie(m_am_tools);

	if (parameters->get_object_count() > parameter_index)
	{
		status = message_data.read_parameter_data(parameters, parameter_index, &sent_WPA_ie);
		if (status != eap_status_ok)
		{
			// This is optional parameter.
			(void) EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_wauth->start_WPXM_reassociation(
		&old_receive_network_id,
		&new_receive_network_id,
		&send_reassociation_request_ie,
		&received_WPA_ie, 
		&sent_WPA_ie);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (status == eap_status_ok)
	{
		// Creates message data composed of Attribute-Value Pairs.
		eapol_handle_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eap_tlv_message_type_function_complete_start_WPXM_reassociation);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(&new_receive_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(&send_reassociation_request_ie);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = send_message(&message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::complete_WPXM_reassociation(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eapol_handle_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eapol_wlan_authentication_state_e reassociation_result(eapol_wlan_authentication_state_none);

	status = message_data.read_parameter_data(parameters, parameter_index, &reassociation_result);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_am_network_id_c receive_network_id(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_variable_data_c received_reassociation_ie(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &received_reassociation_ie);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_wauth->complete_WPXM_reassociation(
		reassociation_result,
		&receive_network_id,
		&received_reassociation_ie);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::packet_process(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eapol_handle_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_am_network_id_c receive_network_id(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eap_variable_data_c packet_data_payload(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &packet_data_payload);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eapol_ethernet_header_wr_c eth(
		m_am_tools,
		packet_data_payload.get_data(),
		packet_data_payload.get_data_length());
	if (eth.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = m_wauth->packet_process(
		&receive_network_id,
		&eth,
		packet_data_payload.get_data_length()
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::tkip_mic_failure(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eapol_handle_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_am_network_id_c receive_network_id(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	bool fatal_failure_when_true(false);

	status = message_data.read_parameter_data(parameters, parameter_index, &fatal_failure_when_true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	eapol_RSNA_key_header_c::eapol_tkip_mic_failure_type_e tkip_mic_failure_type(eapol_RSNA_key_header_c::eapol_tkip_mic_failure_type_group_key);

	status = message_data.read_parameter_data(parameters, parameter_index, &tkip_mic_failure_type);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_wauth->tkip_mic_failure(
		&receive_network_id,
		fatal_failure_when_true,
		tkip_mic_failure_type
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::eap_acknowledge(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eapol_handle_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_am_network_id_c receive_network_id(m_am_tools);

	status = message_data.read_parameter_data(parameters, parameter_index, &receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_wauth->eap_acknowledge(
		&receive_network_id ///< source includes remote address, destination includes local address.
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::update_header_offset(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eapol_handle_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = message_data.read_parameter_data(parameters, parameter_index, &m_header_offset);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	status = message_data.read_parameter_data(parameters, parameter_index, &m_MTU);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++parameter_index;

	status = message_data.read_parameter_data(parameters, parameter_index, &m_trailer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_message_wlan_authentication_c::update_wlan_database_reference_values(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eap_message_payload_index_first_parameter);

	eapol_handle_tlv_message_data_c message_data(m_am_tools);

	if (message_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = message_data.read_parameter_data(parameters, parameter_index, &m_wlan_database_reference);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_wauth->set_eap_database_reference_values(&m_wlan_database_reference);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------
// End of file.
