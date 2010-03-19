/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/wapi_message_wlan_authentication.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 8.1.1 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright � 2001-2009 Nokia.  All rights reserved.
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
	#define EAP_FILE_NUMBER_ENUM 20000 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "wapi_message_wlan_authentication.h"
#include "eapol_wlan_database_reference.h"
#include "eap_am_memory.h"
#include "abs_eap_state_notification.h"
#include "eap_crypto_api.h"
// #include "eap_header_string.h"
#include "eap_buffer.h"
#include "eapol_session_key.h"
#include "eapol_handle_tlv_message_data.h"
#include "eap_automatic_variable.h"
#include "eap_array_algorithms.h"
#include "eap_config.h"


//--------------------------------------------------

EAP_FUNC_EXPORT_INTERFACE wapi_message_wlan_authentication_c::~wapi_message_wlan_authentication_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT_INTERFACE wapi_message_wlan_authentication_c::wapi_message_wlan_authentication_c(
	abs_eap_am_tools_c * const tools,
	abs_wapi_message_wlan_authentication_c * const partner)
	: m_am_tools(tools)
	, m_wauth(0)
	, m_partner(partner)
	, m_wlan_database_reference(tools)
	, m_header_offset(0ul)
	, m_MTU(0ul)
	, m_trailer_length(0ul)
	, m_error_code(wlan_eap_if_send_status_ok)
	, m_error_function(eapol_tlv_message_type_function_none)
	, m_is_valid(true)
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT_INTERFACE eap_status_e wapi_message_wlan_authentication_c::configure(
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

	// wapi_wlan_authentication_c object uses the tools object.
	m_wauth = wapi_wlan_authentication_c::new_wapi_wlan_authentication(
		m_am_tools,
		this,
		true,
		this);
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

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT_INTERFACE eap_status_e wapi_message_wlan_authentication_c::shutdown()
{
	// After use the wapi_wlan_authentication_c object must be deleted first.
	if (m_wauth != 0)
	{
		m_wauth->shutdown();
		delete m_wauth;
		m_wauth = 0;
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT_INTERFACE bool wapi_message_wlan_authentication_c::get_is_valid()
{
	return m_is_valid;
}

// ----------------------------------------------------------------

// 
EAP_FUNC_EXPORT_INTERFACE eap_status_e wapi_message_wlan_authentication_c::timer_expired(
	const u32_t id, void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: [0x%08x]->wapi_message_wlan_authentication_c::timer_expired")
		 EAPL("(id 0x%02x, data 0x%08x).\n"),
		 this, id, data));
		 
	EAP_UNREFERENCED_PARAMETER(id);
	EAP_UNREFERENCED_PARAMETER(data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

// ----------------------------------------------------------------

EAP_FUNC_EXPORT_INTERFACE eap_status_e wapi_message_wlan_authentication_c::timer_delete_data(
	const u32_t id, void * data)
{

	EAP_UNREFERENCED_PARAMETER(id);
	EAP_UNREFERENCED_PARAMETER(data);

	return eap_status_ok;
}

//--------------------------------------------------

EAP_FUNC_EXPORT_INTERFACE eap_status_e wapi_message_wlan_authentication_c::packet_send(
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
				(EAPL("ERROR: wapi_message_wlan_authentication_c::packet_send: packet buffer corrupted (header_offset != %d).\n"),
				m_header_offset));
			EAP_ASSERT_ALWAYS(header_offset == m_header_offset);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}
		else if (header_offset+data_length != sent_packet->get_data_length())
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: wapi_message_wlan_authentication_c::packet_send: packet buffer corrupted ")
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
				(EAPL("ERROR: wapi_message_wlan_authentication_c::packet_send: packet buffer corrupted ")
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
				(EAPL("ERROR: wapi_message_wlan_authentication_c::packet_send: packet buffer corrupted ")
				 EAPL("(header_offset+data_length %d > m_MTU %d).\n"),
				 header_offset+data_length,
				 m_MTU));
			EAP_ASSERT_ALWAYS(header_offset+data_length <= m_MTU);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}
	}
	else
	{
		// Always we need at least the Ethernet header.
		if (sent_packet->get_data_length()
			< eapol_ethernet_header_wr_c::get_header_length())
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: wapi_message_wlan_authentication_c::packet_send: packet buffer corrupted ")
				 EAPL("(sent_packet->get_data_length() %d < ")
				 EAPL("eapol_ethernet_header_wr_c::get_header_length() %d).\n"),
				 sent_packet->get_data_length(),
				 eapol_ethernet_header_wr_c::get_header_length()));
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}		
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

		status = message.add_parameter_data(eapol_tlv_message_type_function_packet_send);
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
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT_INTERFACE u32_t wapi_message_wlan_authentication_c::get_header_offset(
	u32_t * const MTU,
	u32_t * const trailer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Header of this module is in the beginning of the buffer
	// no additional header are used.
	*MTU = m_MTU;
	*trailer_length = m_trailer_length;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_header_offset;
}

//--------------------------------------------------

EAP_FUNC_EXPORT_INTERFACE eap_status_e wapi_message_wlan_authentication_c::associate(
	eapol_key_802_11_authentication_mode_e authentication_mode )
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

		status = message.add_parameter_data(eapol_tlv_message_type_function_associate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(
			eapol_tlv_message_type_eapol_key_802_11_authentication_mode, 
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

EAP_FUNC_EXPORT_INTERFACE eap_status_e wapi_message_wlan_authentication_c::disassociate(
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

		status = message.add_parameter_data(eapol_tlv_message_type_function_disassociate);
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

EAP_FUNC_EXPORT_INTERFACE eap_status_e wapi_message_wlan_authentication_c::packet_data_session_key(
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
			(EAPL("ERROR: wapi_message_wlan_authentication_c::packet_data_session_key(), invalid key.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("wapi_message_wlan_authentication_c::packet_data_session_key(): key_type 0x%02x, key_index %d\n"),
		 key->get_key_type(),
		 key->get_key_index()));
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("wapi_message_wlan_authentication_c::packet_data_session_key"), 
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

		status = message.add_parameter_data(eapol_tlv_message_type_function_packet_data_session_key);
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

		// ****
		// TODO: This needs to be checked for WAPI keys,
		// may need modifications
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

EAP_FUNC_EXPORT_INTERFACE void wapi_message_wlan_authentication_c::state_notification(
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

		status = message.add_parameter_data(eapol_tlv_message_type_function_state_notification);
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

EAP_FUNC_EXPORT_INTERFACE eap_status_e wapi_message_wlan_authentication_c::reassociate(
	const eap_am_network_id_c * const send_network_id,
	const eapol_key_authentication_type_e authentication_type,
	const eap_variable_data_c * const BKID)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	if (BKID == 0
		|| BKID->get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: wapi_message_wlan_authentication_c::reassociate(), invalid BKID.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("wapi_message_wlan_authentication_c::reassociate"), 
		 BKID->get_data(BKID->get_data_length()),
		 BKID->get_data_length()));
	
	{
		// Creates message data composed of Attribute-Value Pairs.
		eapol_handle_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message.add_parameter_data(eapol_tlv_message_type_function_reassociate);
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
			eapol_tlv_message_type_eapol_key_authentication_type,
			static_cast<u32_t>(authentication_type));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.add_parameter_data(BKID);
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

EAP_FUNC_EXPORT_INTERFACE eap_status_e wapi_message_wlan_authentication_c::get_wlan_database_reference_values(
	eap_variable_data_c * const reference) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_wlan_database_reference.get_is_valid_data() == true
		&& m_wlan_database_reference.get_data_length() > 0ul)
	{

		return reference->set_copy_of_buffer(&m_wlan_database_reference);
	}
	else
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: wapi_message_wlan_authentication_c::get_wlan_database_reference_values(): no complete parameters.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT)
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_message_wlan_authentication_c::send_error_message(
	const eap_status_e function_status,
	const eapol_tlv_message_type_function_e function)
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
			eapol_tlv_message_type_error,
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

EAP_FUNC_EXPORT eap_status_e wapi_message_wlan_authentication_c::process_message_type_error(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	eap_status_e status(eap_status_ok);

	{
		// Error payload is the first in this case.
		const eap_tlv_header_c * const error_header = parameters->get_object(eapol_message_payload_index_function);

		if (error_header == 0
			|| error_header->get_type() != eapol_tlv_message_type_error)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t value(0ul);

		status = message_data.get_parameter_data(error_header, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_error_code = static_cast<wlan_eap_if_send_status_e>(value);
	}

	{
		// Fuction payload is the second in this case.
		const eap_tlv_header_c * const function_header = parameters->get_object(eapol_message_payload_index_first_parameter);

		if (function_header == 0
			|| function_header->get_type() != eapol_tlv_message_type_function)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message_data.get_parameter_data(function_header, &m_error_function);
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

EAP_FUNC_EXPORT eap_status_e wapi_message_wlan_authentication_c::send_message(eapol_handle_tlv_message_data_c * const message)
{
	// Sends message data composed of Attribute-Value Pairs.

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("wapi_message_wlan_authentication_c::send_message()"),
		message->get_message_data(),
		message->get_message_data_length()));

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

EAP_FUNC_EXPORT_INTERFACE wlan_eap_if_send_status_e wapi_message_wlan_authentication_c::process_data(const void * const data, const u32_t length)
{
	// Parses message data composed of Attribute-Value Pairs.

	eap_status_e status(eap_status_ok);

	eapol_handle_tlv_message_data_c message(m_am_tools);

	if (message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

		status = eap_status_allocation_error;

		(void) send_error_message(
			status,
			eapol_tlv_message_type_function_none);

		return wlan_eap_if_send_status_conversion_c::convert(
			EAP_STATUS_RETURN(m_am_tools, status));
	}

	status = message.set_message_data(length, data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

		(void) send_error_message(
			status,
			eapol_tlv_message_type_function_none);

		return wlan_eap_if_send_status_conversion_c::convert(
			EAP_STATUS_RETURN(m_am_tools, status));
	}

	status = process_message(&message);

	return wlan_eap_if_send_status_conversion_c::convert(
		EAP_STATUS_RETURN(m_am_tools, status));
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_message_wlan_authentication_c::process_message(eapol_handle_tlv_message_data_c * const message)
{
	// Parses message data composed of Attribute-Value Pairs.

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("wapi_message_wlan_authentication_c::process_message()"),
		message->get_message_data(),
		message->get_message_data_length()));

	eap_array_c<eap_tlv_header_c> parameters(m_am_tools);

	eap_status_e status = message->parse_message_data(&parameters);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

		(void) send_error_message(
			status,
			eapol_tlv_message_type_function_none);

		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (parameters.get_object_count() == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

		status = eap_status_illegal_parameter;

		(void) send_error_message(
			status,
			eapol_tlv_message_type_function_none);

		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const eap_tlv_header_c * const function_header = parameters.get_object(eapol_message_payload_index_function);
	if (function_header == 0
		|| (function_header->get_type() != eapol_tlv_message_type_error
			&& function_header->get_type() != eapol_tlv_message_type_function))
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

		status = eap_status_illegal_parameter;

		(void) send_error_message(
			status,
			eapol_tlv_message_type_function_none);

		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (function_header->get_type() == eapol_tlv_message_type_error)
	{
		status = process_message_type_error(&parameters);
	}
	else // function_header->get_type() == eapol_tlv_message_type_function
	{
		eapol_tlv_message_type_function_e function(eapol_tlv_message_type_function_none);

		status = message->get_parameter_data(function_header, &function);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

			(void) send_error_message(
				status,
				eapol_tlv_message_type_function_none);

			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		switch(function)
		{
		// The interface uses the old EAPOL function name
		// but in WAPI we are checking BKID here
		case eapol_tlv_message_type_function_check_pmksa_cache:
			status = check_bksa_cache(&parameters);
			break;
		case eapol_tlv_message_type_function_start_authentication:
			status = start_authentication(&parameters);
			break;
		case eapol_tlv_message_type_function_complete_association:
			status = complete_association(&parameters);
			break;
		case eapol_tlv_message_type_function_disassociation:
			status = disassociation(&parameters);
			break;
		case eapol_tlv_message_type_function_start_reassociation:
			status = start_reassociation(&parameters);
			break;
		case eapol_tlv_message_type_function_complete_reassociation:
			status = complete_reassociation(&parameters);
			break;
		case eapol_tlv_message_type_function_packet_process:
			status = packet_process(&parameters);
			break;
		case eapol_tlv_message_type_function_update_header_offset:
			status = update_header_offset(&parameters);
			break;
		case eapol_tlv_message_type_function_update_wlan_database_reference_values:
			status = update_wlan_database_reference_values(&parameters);
			break;
		default:
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: wapi_message_wlan_authentication_c::process_data(): unknown function %d.\n"),
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

EAP_FUNC_EXPORT eap_status_e wapi_message_wlan_authentication_c::check_bksa_cache(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eapol_message_payload_index_first_parameter);

	eap_array_c<eap_am_network_id_c> bssid_sta_receive_network_ids(m_am_tools);

	{
		const eap_tlv_header_c * const array_of_network_ids
			= parameters->get_object(parameter_index);

		if (array_of_network_ids == 0
			|| array_of_network_ids->get_type() != eapol_tlv_message_type_array)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c array_data(m_am_tools);

		if (array_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = array_data.set_message_data(
			array_of_network_ids->get_value_length(),
			array_of_network_ids->get_value(array_of_network_ids->get_value_length()));

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_array_c<eap_tlv_header_c> network_ids(m_am_tools);

		status = array_data.parse_message_data(
			&network_ids);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		for (u32_t ind = 0ul; ind < network_ids.get_object_count(); ++ind)
		{
			const eap_tlv_header_c * const header = network_ids.get_object(ind);

			if (header == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			eap_am_network_id_c * const new_network_id = new eap_am_network_id_c(m_am_tools);
			if (new_network_id == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			eap_automatic_variable_c<eap_am_network_id_c> automatic_new_network_id(m_am_tools, new_network_id);

			status = array_data.get_parameter_data(header, new_network_id);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			automatic_new_network_id.do_not_free_variable();

			status = bssid_sta_receive_network_ids.add_object(
				new_network_id,
				true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

		} // for()
	}


	++parameter_index;

	eapol_key_authentication_type_e selected_eapol_key_authentication_type(eapol_key_authentication_type_none);

	{
		const eap_tlv_header_c * const authentication_type
			= parameters->get_object(parameter_index);

		if (authentication_type == 0
			|| authentication_type->get_type() != eapol_tlv_message_type_eapol_key_authentication_type)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t value(0ul);

		status = message_data.get_parameter_data(authentication_type, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		selected_eapol_key_authentication_type = static_cast<eapol_key_authentication_type_e>(value);
		
	}
	
	
	++parameter_index;
	
	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite(eapol_RSNA_key_header_c::eapol_RSNA_cipher_none);

	{
		const eap_tlv_header_c * const authentication_type
			= parameters->get_object(parameter_index);

		if (authentication_type == 0
			|| authentication_type->get_type() != eapol_tlv_message_type_RSNA_cipher)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t value(0ul);

		status = message_data.get_parameter_data(authentication_type, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		pairwise_key_cipher_suite = static_cast<eapol_RSNA_key_header_c::eapol_RSNA_cipher_e>(value);
	}


	++parameter_index;

	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite(eapol_RSNA_key_header_c::eapol_RSNA_cipher_none);

	{
		const eap_tlv_header_c * const authentication_type
			= parameters->get_object(parameter_index);

		if (authentication_type == 0
			|| authentication_type->get_type() != eapol_tlv_message_type_RSNA_cipher)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t value(0ul);

		status = message_data.get_parameter_data(authentication_type, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		group_key_cipher_suite = static_cast<eapol_RSNA_key_header_c::eapol_RSNA_cipher_e>(value);
	}
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	
	status = m_wauth->check_bksa_cache(
		&bssid_sta_receive_network_ids,
		selected_eapol_key_authentication_type,
		pairwise_key_cipher_suite,
		group_key_cipher_suite);
	
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

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

		// Old function name is used in the interface
		status = message.add_parameter_data(
			eapol_tlv_message_type_function_complete_check_pmksa_cache);
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
			eapol_tlv_message_type_array,
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

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_message_wlan_authentication_c::start_authentication(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eapol_message_payload_index_first_parameter);

	eap_variable_data_c SSID(m_am_tools);

	if (SSID.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		const eap_tlv_header_c * const ssid_parameter
			= parameters->get_object(parameter_index);

		if (ssid_parameter == 0
			|| ssid_parameter->get_type() != eapol_tlv_message_type_variable_data)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message_data.get_parameter_data(ssid_parameter, &SSID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	
	
	++parameter_index;

	eapol_key_authentication_type_e selected_eapol_key_authentication_type(eapol_key_authentication_type_none);

	{
		const eap_tlv_header_c * const authentication_type_parameter
			= parameters->get_object(parameter_index);

		if (authentication_type_parameter == 0
			|| authentication_type_parameter->get_type() != eapol_tlv_message_type_eapol_key_authentication_type)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t value(0ul);

		status = message_data.get_parameter_data(authentication_type_parameter, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		selected_eapol_key_authentication_type = static_cast<eapol_key_authentication_type_e>(value);
	}


	++parameter_index;

	eap_variable_data_c preshared_key(m_am_tools);

	{
		const eap_tlv_header_c * const preshared_key_parameter
			= parameters->get_object(parameter_index);

		if (preshared_key_parameter == 0
			|| preshared_key_parameter->get_type() != eapol_tlv_message_type_variable_data)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message_data.get_parameter_data(preshared_key_parameter, &preshared_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++parameter_index;

	bool WAPI_override_enabled(false);

	{
		const eap_tlv_header_c * const WAPI_override_enabled_parameter
			= parameters->get_object(parameter_index);

		if (WAPI_override_enabled_parameter == 0
			|| WAPI_override_enabled_parameter->get_type() != eapol_tlv_message_type_boolean)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t value(0ul);

		status = message_data.get_parameter_data(WAPI_override_enabled_parameter, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		WAPI_override_enabled = (value == 0) ? false: true;
	}


	++parameter_index;

	eap_am_network_id_c receive_network_id(m_am_tools);

	{
		const eap_tlv_header_c * const receive_network_id_parameter
			= parameters->get_object(parameter_index);

		if (receive_network_id_parameter == 0
			|| receive_network_id_parameter->get_type() != eapol_tlv_message_type_network_id)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message_data.get_parameter_data(receive_network_id_parameter, &receive_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_wauth->start_authentication(
		&SSID,
		selected_eapol_key_authentication_type,
		&preshared_key,
		WAPI_override_enabled, 
		&receive_network_id
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_message_wlan_authentication_c::complete_association(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eapol_message_payload_index_first_parameter);

	eapol_wlan_authentication_state_e association_result(eapol_wlan_authentication_state_none);

	{
		const eap_tlv_header_c * const association_result_parameter
			= parameters->get_object(parameter_index);

		if (association_result_parameter == 0
			|| association_result_parameter->get_type() != eapol_tlv_message_type_eapol_wlan_authentication_state)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t value(0ul);

		status = message_data.get_parameter_data(association_result_parameter, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		association_result = static_cast<eapol_wlan_authentication_state_e>(value);
	}


	++parameter_index;

	eap_am_network_id_c receive_network_id(m_am_tools);

	{
		const eap_tlv_header_c * const receive_network_id_parameter
			= parameters->get_object(parameter_index);

		if (receive_network_id_parameter == 0
			|| receive_network_id_parameter->get_type() != eapol_tlv_message_type_network_id)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message_data.get_parameter_data(receive_network_id_parameter, &receive_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++parameter_index;

	eap_variable_data_c received_WAPI_IE(m_am_tools);

	{
		const eap_tlv_header_c * const received_WAPI_IE_parameter
			= parameters->get_object(parameter_index);

		if (received_WAPI_IE_parameter == 0
			|| received_WAPI_IE_parameter->get_type() != eapol_tlv_message_type_variable_data)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message_data.get_parameter_data(received_WAPI_IE_parameter, &received_WAPI_IE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++parameter_index;

	eap_variable_data_c sent_WAPI_IE(m_am_tools);

	{
		const eap_tlv_header_c * const sent_WAPI_IE_parameter
			= parameters->get_object(parameter_index);

		if (sent_WAPI_IE_parameter == 0
			|| sent_WAPI_IE_parameter->get_type() != eapol_tlv_message_type_variable_data)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message_data.get_parameter_data(sent_WAPI_IE_parameter, &sent_WAPI_IE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++parameter_index;


	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite(eapol_RSNA_key_header_c::eapol_RSNA_cipher_none);

	{
		const eap_tlv_header_c * const pairwise_key_cipher_suite_parameter
			= parameters->get_object(parameter_index);

		if (pairwise_key_cipher_suite_parameter == 0
			|| pairwise_key_cipher_suite_parameter->get_type() != eapol_tlv_message_type_RSNA_cipher)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t value(0ul);

		status = message_data.get_parameter_data(pairwise_key_cipher_suite_parameter, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		pairwise_key_cipher_suite = static_cast<eapol_RSNA_key_header_c::eapol_RSNA_cipher_e>(value);
	}

	++parameter_index;
	

	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite(eapol_RSNA_key_header_c::eapol_RSNA_cipher_none);

	{
		const eap_tlv_header_c * const group_key_cipher_suite_parameter
			= parameters->get_object(parameter_index);

		if (group_key_cipher_suite_parameter == 0
			|| group_key_cipher_suite_parameter->get_type() != eapol_tlv_message_type_RSNA_cipher)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t value(0ul);
		
		status = message_data.get_parameter_data(group_key_cipher_suite_parameter, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		group_key_cipher_suite = static_cast<eapol_RSNA_key_header_c::eapol_RSNA_cipher_e>(value);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_wauth->complete_association(
		association_result,
		&receive_network_id, ///< source includes remote address, destination includes local address.
		&received_WAPI_IE,
		&sent_WAPI_IE,
		pairwise_key_cipher_suite,
		group_key_cipher_suite
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_message_wlan_authentication_c::disassociation(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eapol_message_payload_index_first_parameter);

	eap_am_network_id_c receive_network_id(m_am_tools);

	{
		const eap_tlv_header_c * const receive_network_id_parameter
			= parameters->get_object(parameter_index);

		if (receive_network_id_parameter == 0
			|| receive_network_id_parameter->get_type() != eapol_tlv_message_type_network_id)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message_data.get_parameter_data(receive_network_id_parameter, &receive_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
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

EAP_FUNC_EXPORT eap_status_e wapi_message_wlan_authentication_c::start_reassociation(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eapol_message_payload_index_first_parameter);

	eap_am_network_id_c old_receive_network_id(m_am_tools);

	{
		const eap_tlv_header_c * const old_receive_network_id_parameter
			= parameters->get_object(parameter_index);

		if (old_receive_network_id_parameter == 0
			|| old_receive_network_id_parameter->get_type() != eapol_tlv_message_type_network_id)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message_data.get_parameter_data(old_receive_network_id_parameter, &old_receive_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	++parameter_index;

	eap_am_network_id_c new_receive_network_id(m_am_tools);

	{
		const eap_tlv_header_c * const new_receive_network_id_parameter
			= parameters->get_object(parameter_index);

		if (new_receive_network_id_parameter == 0
			|| new_receive_network_id_parameter->get_type() != eapol_tlv_message_type_network_id)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message_data.get_parameter_data(new_receive_network_id_parameter, &new_receive_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++parameter_index;

	eapol_key_authentication_type_e selected_eapol_key_authentication_type(eapol_key_authentication_type_none);

	{
		const eap_tlv_header_c * const authentication_type
			= parameters->get_object(parameter_index);

		if (authentication_type == 0
			|| authentication_type->get_type() != eapol_tlv_message_type_eapol_key_authentication_type)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t value(0ul);

		status = message_data.get_parameter_data(authentication_type, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		selected_eapol_key_authentication_type = static_cast<eapol_key_authentication_type_e>(value);
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

EAP_FUNC_EXPORT eap_status_e wapi_message_wlan_authentication_c::complete_reassociation(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eapol_message_payload_index_first_parameter);

	eapol_wlan_authentication_state_e association_result(eapol_wlan_authentication_state_none);

	{
		const eap_tlv_header_c * const association_result_parameter
			= parameters->get_object(parameter_index);

		if (association_result_parameter == 0
			|| association_result_parameter->get_type() != eapol_tlv_message_type_eapol_wlan_authentication_state)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t value(0ul);

		status = message_data.get_parameter_data(association_result_parameter, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		association_result = static_cast<eapol_wlan_authentication_state_e>(value);
	}


	++parameter_index;

	eap_am_network_id_c receive_network_id(m_am_tools);

	{
		const eap_tlv_header_c * const receive_network_id_parameter
			= parameters->get_object(parameter_index);

		if (receive_network_id_parameter == 0
			|| receive_network_id_parameter->get_type() != eapol_tlv_message_type_network_id)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message_data.get_parameter_data(receive_network_id_parameter, &receive_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++parameter_index;

	eap_variable_data_c received_WAPI_IE(m_am_tools);

	{
		const eap_tlv_header_c * const received_WAPI_IE_parameter
			= parameters->get_object(parameter_index);

		if (received_WAPI_IE_parameter == 0
			|| received_WAPI_IE_parameter->get_type() != eapol_tlv_message_type_variable_data)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message_data.get_parameter_data(received_WAPI_IE_parameter, &received_WAPI_IE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++parameter_index;

	eap_variable_data_c sent_WAPI_IE(m_am_tools);

	{
		const eap_tlv_header_c * const sent_WAPI_IE_parameter
			= parameters->get_object(parameter_index);

		if (sent_WAPI_IE_parameter == 0
			|| sent_WAPI_IE_parameter->get_type() != eapol_tlv_message_type_variable_data)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message_data.get_parameter_data(sent_WAPI_IE_parameter, &sent_WAPI_IE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++parameter_index;


	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite(eapol_RSNA_key_header_c::eapol_RSNA_cipher_none);

	{
		const eap_tlv_header_c * const pairwise_key_cipher_suite_parameter
			= parameters->get_object(parameter_index);

		if (pairwise_key_cipher_suite_parameter == 0
			|| pairwise_key_cipher_suite_parameter->get_type() != eapol_tlv_message_type_RSNA_cipher)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t value(0ul);

		status = message_data.get_parameter_data(pairwise_key_cipher_suite_parameter, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		pairwise_key_cipher_suite = static_cast<eapol_RSNA_key_header_c::eapol_RSNA_cipher_e>(value);
	}

	++parameter_index;


	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite(eapol_RSNA_key_header_c::eapol_RSNA_cipher_none);

	{
		const eap_tlv_header_c * const group_key_cipher_suite_parameter
			= parameters->get_object(parameter_index);

		if (group_key_cipher_suite_parameter == 0
			|| group_key_cipher_suite_parameter->get_type() != eapol_tlv_message_type_RSNA_cipher)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t value(0ul);

		status = message_data.get_parameter_data(group_key_cipher_suite_parameter, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		group_key_cipher_suite = static_cast<eapol_RSNA_key_header_c::eapol_RSNA_cipher_e>(value);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_wauth->complete_reassociation(
		association_result,
		&receive_network_id, ///< source includes remote address, destination includes local address.
		&received_WAPI_IE,
		&sent_WAPI_IE,
		pairwise_key_cipher_suite,
		group_key_cipher_suite
		);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_message_wlan_authentication_c::packet_process(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eapol_message_payload_index_first_parameter);

	eap_am_network_id_c receive_network_id(m_am_tools);

	{
		const eap_tlv_header_c * const receive_network_id_parameter
			= parameters->get_object(parameter_index);

		if (receive_network_id_parameter == 0
			|| receive_network_id_parameter->get_type() != eapol_tlv_message_type_network_id)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message_data.get_parameter_data(receive_network_id_parameter, &receive_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++parameter_index;

	eap_variable_data_c packet_data_payload(m_am_tools);

	{
		const eap_tlv_header_c * const packet_data_parameter
			= parameters->get_object(parameter_index);

		if (packet_data_parameter == 0
			|| packet_data_parameter->get_type() != eapol_tlv_message_type_variable_data)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message_data.get_parameter_data(packet_data_parameter, &packet_data_payload);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
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

EAP_FUNC_EXPORT eap_status_e wapi_message_wlan_authentication_c::update_header_offset(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eapol_message_payload_index_first_parameter);

	{
		const eap_tlv_header_c * const header_offset_value_parameter
			= parameters->get_object(parameter_index);

		if (header_offset_value_parameter == 0
			|| header_offset_value_parameter->get_type() != eapol_tlv_message_type_u32_t)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message_data.get_parameter_data(header_offset_value_parameter, &m_header_offset);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++parameter_index;

	{
		const eap_tlv_header_c * const MTU_value_parameter
			= parameters->get_object(parameter_index);

		if (MTU_value_parameter == 0
			|| MTU_value_parameter->get_type() != eapol_tlv_message_type_u32_t)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message_data.get_parameter_data(MTU_value_parameter, &m_MTU);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++parameter_index;

	{
		const eap_tlv_header_c * const trailer_length_parameter
			= parameters->get_object(parameter_index);

		if (trailer_length_parameter == 0
			|| trailer_length_parameter->get_type() != eapol_tlv_message_type_u32_t)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message_data.get_parameter_data(trailer_length_parameter, &m_trailer_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_message_wlan_authentication_c::update_wlan_database_reference_values(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	u32_t parameter_index(eapol_message_payload_index_first_parameter);

	{
		const eap_tlv_header_c * const reference_parameter
			= parameters->get_object(parameter_index);

		if (reference_parameter == 0
			|| reference_parameter->get_type() != eapol_tlv_message_type_variable_data)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eapol_handle_tlv_message_data_c message_data(m_am_tools);

		if (message_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = message_data.get_parameter_data(reference_parameter, &m_wlan_database_reference);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------
// End of file.
