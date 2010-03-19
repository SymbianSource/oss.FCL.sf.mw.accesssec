/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/wai_message_payloads.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 35 % << Don't touch! Updated by Synergy at check-out.
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
	#define EAP_FILE_NUMBER_ENUM 709 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#if defined(USE_WAPI_CORE)


#include "eap_am_memory.h"
#include "wai_message_payloads.h"
#include "wai_message.h"
#include "abs_eap_am_tools.h"
#include "eap_tools.h"
#include "eap_array_algorithms.h"
#include "eap_automatic_variable.h"
#include "eap_crypto_api.h"
#include "wapi_strings.h"

//--------------------------------------------------

EAP_FUNC_EXPORT wai_message_payloads_c::~wai_message_payloads_c()
{
}

//--------------------------------------------------

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4355 ) // 'this' : used in base member initializer list
#endif

EAP_FUNC_EXPORT wai_message_payloads_c::wai_message_payloads_c(
	abs_eap_am_tools_c * const tools,
	const bool true_when_is_client)
	: m_am_tools(tools)
	, m_message(tools)
	, m_wai_protocol_packet_header(tools, 0, 0ul)
	, m_payload_map(tools, this)
	, m_read_payloads(tools)
	, m_payload_index(0ul)
	, m_is_client(true_when_is_client)
	, m_is_valid(false)
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_message_payloads_c::initialise_header()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAI:     message_function: wai_message_payloads_c::initialise_header()\n")));

	eap_status_e status = m_message.init(m_wai_protocol_packet_header.get_header_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_message.set_data_length(m_wai_protocol_packet_header.get_header_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_wai_protocol_packet_header.set_header_buffer(
		m_message.get_data(),
		m_message.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_wai_protocol_packet_header.reset_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT const wai_protocol_packet_header_c * wai_message_payloads_c::get_wai_protocol_packet_header() const
{
	EAP_ASSERT_TOOLS(m_am_tools, (m_message.get_is_valid_data() == true));

	return &m_wai_protocol_packet_header;
}

//--------------------------------------------------

EAP_FUNC_EXPORT wai_protocol_packet_header_c * wai_message_payloads_c::get_wai_protocol_packet_header_writable()
{
	EAP_ASSERT_TOOLS(m_am_tools, (m_message.get_is_valid_data() == true));

	return &m_wai_protocol_packet_header;
}

//--------------------------------------------------

EAP_FUNC_EXPORT wai_variable_data_c * wai_message_payloads_c::get_tlv_pointer(
	const wai_payload_type_e current_payload,
	u32_t index) const
{
	eap_variable_data_c selector(m_am_tools);

	if (selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return 0;
	}

	selector.set_buffer(
		&current_payload,
		sizeof(current_payload),
		false,
		false);

	wai_variable_data_c *payload = m_payload_map.get_handler(&selector);

	while (index != 0ul && payload != 0)
	{
		--index;
		payload = payload->get_next_payload_with_same_tlv_type();
	}

	return payload;
}

//--------------------------------------------------

EAP_FUNC_EXPORT wai_variable_data_c * wai_message_payloads_c::get_tlv_pointer(
	const wai_payload_type_e current_payload) const
{
	return get_tlv_pointer(current_payload, 0ul);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t wai_message_payloads_c::get_tlv_count() const
{
	return m_read_payloads.get_object_count();
}

//--------------------------------------------------

EAP_FUNC_EXPORT wai_variable_data_c * wai_message_payloads_c::get_tlv(
	const u32_t tlv_index) const
{
	wai_variable_data_c *payload = m_read_payloads.get_object(tlv_index);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAI:     message_function: wai_message_payloads_c::get_tlv(index %d, count %d) = %s\n"),
		tlv_index,
		m_read_payloads.get_object_count(),
		payload->get_wai_payload_type_string()));

	return payload;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_message_payloads_c::insert_payload(
	const wai_variable_data_c * const new_payload)
{
	wai_variable_data_c * const copy_payload = new_payload->copy();
	if (copy_payload == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	return m_read_payloads.add_object(copy_payload, true);
}

//--------------------------------------------------

#if 0

EAP_FUNC_EXPORT eap_status_e wai_message_payloads_c::check_payloads_existense(
	const wai_payload_type_e * const needed_payloads,
	const u32_t count_of_needed_payloads) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAI:     message_function: wai_message_payloads_c::check_payloads_existense()\n")));

	for (u32_t ind = 0ul; ind < count_of_needed_payloads; ind++)
	{
		const wai_payload_type_e required_avp_code = needed_payloads[ind];
		if (required_avp_code == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (get_tlv_pointer(required_avp_code) == 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("not received TLV 0x%08x.\n"),
				 required_avp_code));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_not_found);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif

//--------------------------------------------------

#if 0

EAP_FUNC_EXPORT eap_status_e wai_message_payloads_c::check_payloads_existense(
	EAP_TEMPLATE_CONST eap_array_c<wai_payload_type_e> * const needed_payloads) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAI:     message_function: wai_message_payloads_c::check_payloads_existense()\n")));

	for (u32_t ind = 0ul; ind < needed_payloads->get_object_count(); ind++)
	{
		const wai_payload_type_e * const required_avp_code = needed_payloads->get_object(ind);
		if (required_avp_code == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (get_tlv_pointer(*required_avp_code) == 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("not received TLV 0x%08x.\n"),
				 *required_avp_code));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_not_found);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_message_payloads_c::copy_tlv(
	const wai_message_payloads_c * const source,
	const wai_payload_type_e tlv)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAI:     message_function: wai_message_payloads_c::copy_tlv(TLV 0x%08x)\n"),
		tlv));

	const wai_variable_data_c * const payload
		= source->get_tlv_pointer(tlv, 0ul);
	if (payload == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
	}

	eap_status_e status = add_tlv(
		payload->copy());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_message_payloads_c::add_tlv(
	wai_variable_data_c * const new_payload)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAI:     message_function: wai_message_payloads_c::add_tlv(): %s\n"),
		wapi_strings_c::get_wai_payload_type_string(new_payload->get_payload_type())));

	if (new_payload == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	WAI_VARIABLE_DATA_TRACE(m_am_tools, "wai_message_payloads_c::add_tlv()", new_payload, m_is_client);

	wai_variable_data_c * const copy_payload = new_payload->copy();
	if (copy_payload == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	WAI_VARIABLE_DATA_TRACE(m_am_tools, "wai_message_payloads_c::add_tlv() copy", copy_payload, m_is_client);

	eap_status_e status(eap_status_process_general_error);

	eap_automatic_variable_c<wai_variable_data_c>
		automatic_new_payload(m_am_tools, copy_payload);

	const wai_payload_type_e new_payload_type(copy_payload->get_payload_type());
		
	wai_variable_data_c *old_payload = get_tlv_pointer(
		new_payload_type);

	{
		eap_variable_data_c selector(m_am_tools);

		if (selector.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = selector.set_copy_of_buffer(
			&new_payload_type,
			sizeof(new_payload_type));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		if (old_payload == 0)
		{
			status = m_payload_map.add_handler(&selector, copy_payload);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			// Cannot add dublicate payload to m_payload_map.
			// Instead we add apointer to the next payload with the same tlv type.
			old_payload->add_next_payload_with_same_tlv_type(copy_payload);
		}

		automatic_new_payload.do_not_free_variable();

		// Note the same payload object is added to m_read_payloads as to m_payload_map.
		status = m_read_payloads.add_object(copy_payload, false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = m_wai_protocol_packet_header.set_length(m_wai_protocol_packet_header.get_length() + copy_payload->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_message_payloads_c::copy_tlv_data(
	const wai_payload_type_e current_payload,
	const void * const data,
	const u32_t data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAI:     message_function: wai_message_payloads_c::copy_tlv_data(TLV 0x%08x)\n"),
		current_payload));

	eap_status_e status(eap_status_process_general_error);

	wai_variable_data_c new_payload(m_am_tools);
	if (new_payload.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = new_payload.set_copy_of_buffer(
		current_payload,
		data,
		data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	status = add_tlv(&new_payload);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool wai_message_payloads_c::get_is_valid() const
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_message_payloads_c::parse_generic_payload(
	const wai_payload_type_e payload_type,
	const wai_variable_data_c * const wai_data,
	u32_t * const prev_payload_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	if (wai_data == 0
		|| wai_data->get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("ERROR: wai_message_payloads_c::parse_generic_payload(): illegal wai_data=0x%08x")
			 EAPL("current header 0x%08x=%s.\n"),
			 wai_data,
			 payload_type,
			 wapi_strings_c::get_wai_payload_type_string(payload_type)));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u32_t data_length(wai_data->get_data_length());
	const u32_t type_length(wai_data->get_type_header_length() + wai_data->get_type_data_length());
	const u8_t * const data = wai_data->get_data(type_length);

	*prev_payload_length = 0ul;

	if (data_length < type_length)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("ERROR: wai_message_payloads_c::parse_generic_payload(0x%08x): wai_data=0x%08x")
			 EAPL("current header 0x%08x=%s, required length 0x%08x, packet length too less 0x%08x.\n"),
			 data,
			 wai_data,
			 payload_type,
			 wapi_strings_c::get_wai_payload_type_string(payload_type),
			 type_length,
			 data_length));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	if (data == 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_ERROR, 
			(EAPL("ERROR: wai_message_payloads_c::parse_generic_payload(0x%08x): wai_data=0x%08x")
			 EAPL("current header 0x%08x=%s, type length 0x%04x, data buffer incorrect.\n"),
			 data,
			 wai_data,
			 payload_type,
			 wapi_strings_c::get_wai_payload_type_string(payload_type),
			 type_length));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	WAI_VARIABLE_DATA_TRACE(m_am_tools, "Parse WAI-TLV payload", wai_data, m_is_client);

	status = copy_tlv_data(
		wai_data->get_payload_type(),
		data,
		data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	*prev_payload_length = type_length;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wai_message_payloads_c::parse_wai_payloads(
	void * const message_buffer,
	const u32_t buffer_length,
	u32_t * const padding_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAI:     message_function: wai_message_payloads_c::parse_wai_payloads()\n")));

	eap_status_e status = eap_status_header_corrupted;

	*padding_length = 0ul;

	if (buffer_length == 0)
	{
		// Empty payload.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	u32_t remaining_data_length(buffer_length);
	u32_t remaining_data_offset(0ul);


	status = m_message.set_copy_of_buffer(message_buffer, remaining_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_wai_protocol_packet_header.set_header_buffer(
		m_message.get_data(),
		m_message.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_wai_protocol_packet_header.check_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	remaining_data_length -= m_wai_protocol_packet_header.get_header_length();
	remaining_data_offset += m_wai_protocol_packet_header.get_header_length();

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("parse_wai_payloads"),
		 m_message.get_data(),
		 m_message.get_data_length()));

	const wai_payload_type_e * required_payloads = 0;

	switch(m_wai_protocol_packet_header.get_subtype())
	{

	case wai_protocol_subtype_pre_authentication_start:
	case wai_protocol_subtype_stakey_request:
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);

	case wai_protocol_subtype_authentication_activation:
		required_payloads = required_payloads_authentication_activation;
		break;
	case wai_protocol_subtype_access_authentication_request:
		required_payloads = required_payloads_access_authentication_request;
		break;
	case wai_protocol_subtype_access_authentication_response:
		required_payloads = required_payloads_access_authentication_response;
		break;
	case wai_protocol_subtype_certificate_authentication_request:
		required_payloads = required_payloads_certificate_authentication_request;
		break;
	case wai_protocol_subtype_certificate_authentication_response:
		required_payloads = required_payloads_certificate_authentication_response;
		break;
	case wai_protocol_subtype_unicast_key_negotiation_request:
		required_payloads = required_payloads_unicast_key_negotiation_request;
		break;
	case wai_protocol_subtype_unicast_key_negotiation_response:
		required_payloads = required_payloads_unicast_key_negotiation_response;
		break;
	case wai_protocol_subtype_unicast_key_negotiation_confirmation:
		required_payloads = required_payloads_unicast_key_negotiation_confirmation;
		break;
	case wai_protocol_subtype_multicast_key_announcement:
		required_payloads = required_payloads_multicast_key_announcement;
		break;
	case wai_protocol_subtype_multicast_key_announcement_response:
		required_payloads = required_payloads_multicast_key_announcement_response;
		break;
	default:
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);

	}; // switch()


	u32_t payload_index(0ul);

	wai_variable_data_c payload(
		m_am_tools);

	status = payload.set_buffer(
		required_payloads[payload_index],
		m_wai_protocol_packet_header.get_data(m_wai_protocol_packet_header.get_data_length()),
		m_wai_protocol_packet_header.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	if (payload.get_is_valid() == true
		&& required_payloads[payload_index] >= wai_tlv_type_first_known
		&& required_payloads[payload_index] <= wai_tlv_type_last_known)
	{
		if (remaining_data_length < payload.get_data_length())
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("ERROR: wai_message_payloads_c::parse_wai_payloads(0x%08x): ")
				 EAPL("current payload 0x%08x=%s, buffer length 0x%04x.\n"),
				 payload.get_data(0ul),
				 required_payloads[payload_index],
				 wapi_strings_c::get_wai_payload_type_string(required_payloads[payload_index]),
				 remaining_data_length));
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("ERROR: wai_message_payloads_c::parse_wai_payloads(): ")
				 EAPL("WAI-payload header is corrupted.\n")));
			EAP_TRACE_DATA_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("payload"),
				payload.get_data(remaining_data_length),
				remaining_data_length));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u32_t prev_payload_length(0ul);

		status = parse_generic_payload(
			required_payloads[payload_index],
			&payload,
			&prev_payload_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		bool optional_payload_is_included(false);

		{
			// Check whether the optional payload is included.

			const u8_t * const flag = payload.get_data(sizeof(*flag));
			if (flag == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			if (((*flag) & wai_data_flag_mask_Optional_Field) != 0)
			{
				optional_payload_is_included = true;
			}
		}

		if (remaining_data_length < prev_payload_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		remaining_data_length -= prev_payload_length;
		remaining_data_offset += prev_payload_length;

		++payload_index;
		if (required_payloads[payload_index] == wai_payload_type_terminator)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (optional_payload_is_included == false
			&& required_payloads[payload_index] == wai_payload_type_optional)
		{
			++payload_index;
			if (required_payloads[payload_index] == wai_payload_type_terminator)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}
		}

		status = payload.set_buffer(
			required_payloads[payload_index],
			m_message.get_data_offset(remaining_data_offset, remaining_data_length),
			remaining_data_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		u32_t type_length(payload.get_type_header_length() + payload.get_type_data_length());

		while(remaining_data_length > 0ul
			&& remaining_data_length >= type_length
			&& payload.get_is_valid() == true)
		{
			status = parse_generic_payload(
				required_payloads[payload_index],
				&payload,
				&prev_payload_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (remaining_data_length < prev_payload_length
				|| prev_payload_length == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			remaining_data_length -= prev_payload_length;
			remaining_data_offset += prev_payload_length;

#if 1
			if (required_payloads[payload_index] != wai_payload_type_optional)
			{
				++payload_index;
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("WAI:     message_function: wai_message_payloads_c::parse_wai_payloads(): parse optional payload.\n")));
			}
#else
			if (optional_payload_is_included == false
				|| required_payloads[payload_index] != wai_payload_type_optional)
			{
				++payload_index;
				if (required_payloads[payload_index] == wai_payload_type_terminator)
				{
					break;
				}

				if (optional_payload_is_included == false
					&& required_payloads[payload_index] == wai_payload_type_optional)
				{
					++payload_index;
					if (required_payloads[payload_index] == wai_payload_type_terminator)
					{
						break;
					}
				}
			}
#endif

			status = payload.set_buffer(
				required_payloads[payload_index],
				m_message.get_data_offset(remaining_data_offset, remaining_data_length),
				remaining_data_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			type_length = (payload.get_type_header_length() + payload.get_type_data_length());

		} // while()


		if (remaining_data_length != 0u)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("ERROR: wai_message_payloads_c::parse_wai_payloads(): ")
				 EAPL("WAI-header is corrupted. Buffer length and payload ")
				 EAPL("length does not match. %lu illegal bytes.\n"),
				 remaining_data_length));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_message_payloads_c::create_wai_tlv_message(
	wai_message_c * const new_wai_message_data,
	const bool add_payloads) const
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAI:     message_function: wai_message_payloads_c::create_wai_tlv_message()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wai_message_payloads_c::create_wai_tlv_message()");

	eap_status_e status(eap_status_process_general_error);

	if (add_payloads == false)
	{
		status = new_wai_message_data->reset();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = new_wai_message_data->get_wai_message_data_writable()->add_data(
			m_wai_protocol_packet_header.get_header_buffer(m_wai_protocol_packet_header.get_header_length()),
			m_wai_protocol_packet_header.get_header_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	const u32_t tlv_count(get_tlv_count());
	u32_t tlv_index(0ul);

	while (tlv_index < tlv_count)
	{
		wai_variable_data_c * wai_data = get_tlv(tlv_index);
		if (wai_data == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		status = new_wai_message_data->get_wai_message_data_writable()->add_data(wai_data->get_full_tlv_buffer());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		WAI_VARIABLE_DATA_TRACE(m_am_tools, "Added WAI-TLV payload", wai_data, m_is_client);

		++tlv_index;

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WAI:     message_function: wai_message_payloads_c::create_wai_tlv_message(): index %d\n"),
			tlv_index));

	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_message_payloads_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_message.reset_start_offset_and_data_length();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
		
	status = m_payload_map.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_read_payloads.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT wai_message_payloads_c * wai_message_payloads_c::copy() const
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAI:     message_function: wai_message_payloads_c::copy()\n")));

	wai_message_payloads_c * copy_payloads = new wai_message_payloads_c(m_am_tools, m_is_client);

	if (copy_payloads == 0
		|| copy_payloads->get_is_valid() == false)
	{
		delete copy_payloads;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return 0;
	}

	eap_status_e status(eap_status_process_general_error);

	const u32_t tlv_count(get_tlv_count());
	u32_t tlv_index(0ul);

	while (tlv_index < tlv_count)
	{
		wai_variable_data_c * wai_data = get_tlv(tlv_index);
		if (wai_data == 0)
		{
			delete copy_payloads;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		status = copy_payloads->add_tlv(
			wai_data->copy());

		if (status != eap_status_ok)
		{
			delete copy_payloads;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		++tlv_index;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return copy_payloads;
}

//--------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

// End.
