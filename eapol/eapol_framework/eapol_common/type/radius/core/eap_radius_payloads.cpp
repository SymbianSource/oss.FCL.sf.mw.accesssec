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
	#define EAP_FILE_NUMBER_ENUM 109 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_radius_payloads.h"
#include "abs_eap_am_tools.h"
#include "eap_tools.h"



EAP_FUNC_EXPORT eap_radius_variable_data_c::~eap_radius_variable_data_c()
{
}

EAP_FUNC_EXPORT eap_radius_variable_data_c::eap_radius_variable_data_c(abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_data(tools)
	, m_payload_type(eap_diameter_avp_code_none)
{
}

EAP_FUNC_EXPORT eap_status_e eap_radius_variable_data_c::set_buffer(
	const eap_diameter_avp_code_c current_payload,
	const u8_t * const buffer,
	const u32_t buffer_length,
	const bool free_buffer,
	const bool is_writable)
{
	eap_status_e status = m_data.set_buffer(
		buffer,
		buffer_length,
		free_buffer,
		is_writable);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_payload_type = current_payload;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT eap_status_e eap_radius_variable_data_c::add_data(
	const u8_t * const buffer,
	const u32_t buffer_length)
{
	eap_status_e status = m_data.add_data(
		buffer,
		buffer_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT u32_t eap_radius_variable_data_c::get_data_length() const
{
	return m_data.get_data_length();
}

EAP_FUNC_EXPORT u8_t * eap_radius_variable_data_c::get_data(const u32_t data_length) const
{
	return m_data.get_data(data_length);
}

EAP_FUNC_EXPORT eap_variable_data_c * eap_radius_variable_data_c::get_payload_buffer()
{
	return &m_data;
}

EAP_FUNC_EXPORT eap_diameter_avp_code_c eap_radius_variable_data_c::get_payload_type() const
{
	return m_payload_type;
}

EAP_FUNC_EXPORT void eap_radius_variable_data_c::set_payload_type(const eap_diameter_avp_code_c type)
{
	m_payload_type = type;
}

EAP_FUNC_EXPORT eap_radius_variable_data_c * eap_radius_variable_data_c::copy() const
{
	eap_radius_variable_data_c * new_data = new eap_radius_variable_data_c(m_am_tools);

	if (new_data != 0)
	{
		eap_status_e status = new_data->get_payload_buffer()->add_data(&m_data);
		if (status != eap_status_ok)
		{
			delete new_data;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			return 0;
		}

		new_data->set_payload_type(get_payload_type());
	}

	return new_data;
}

EAP_FUNC_EXPORT  void eap_radius_variable_data_c::object_increase_reference_count()
{
}



EAP_FUNC_EXPORT eap_radius_payloads_c::~eap_radius_payloads_c()
{
}

EAP_FUNC_EXPORT eap_radius_payloads_c::eap_radius_payloads_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	  , m_payload_map(tools, this)
	  , m_is_valid(false)
{
	m_is_valid = true;
}

EAP_FUNC_EXPORT eap_radius_variable_data_c * eap_radius_payloads_c::get_payload(
	const eap_diameter_avp_code_c current_payload)
{
	eap_variable_data_c selector(m_am_tools);

	selector.set_buffer(
		&current_payload,
		sizeof(current_payload),
		false,
		false);

	eap_radius_variable_data_c *payload = m_payload_map.get_handler(&selector);

	return payload;
}


EAP_FUNC_EXPORT eap_status_e eap_radius_payloads_c::add_payload(
	const eap_diameter_avp_code_c current_payload,
	const u8_t * const data,
	const u32_t data_length,
	const bool free_buffer,
	const bool is_writable,
	const bool fragments_allowed)
{
	eap_status_e status(eap_status_process_general_error);

	eap_radius_variable_data_c *payload = get_payload(
		current_payload);
	if (payload != 0)
	{
		if (fragments_allowed == true)
		{
			// Add fragment to the end of the existing payload.
			status = payload->add_data(data, data_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			// Caanot add fragment.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}
	else
	{
		eap_variable_data_c selector(m_am_tools);

		selector.set_buffer(
			&current_payload,
			sizeof(current_payload),
			false,
			false);
		
		eap_radius_variable_data_c *payload = new eap_radius_variable_data_c(
			m_am_tools);
		if (payload == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = payload->set_buffer(
			current_payload,
			data,
			data_length,
			free_buffer,
			is_writable);
		if (status != eap_status_ok)
		{
			delete payload;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		status = m_payload_map.add_handler(&selector, payload);
		if (status != eap_status_ok)
		{
			delete payload;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


EAP_FUNC_EXPORT bool eap_radius_payloads_c::get_is_valid() const
{
	return m_is_valid;
}


//--------------------------------------------------

//eap_radius_payloads_c
EAP_FUNC_EXPORT eap_status_e eap_radius_payloads_c::parse_generic_payload(
	const eap_diameter_avp_code_c payload_type,
	const eap_radius_attribute_header_c * const payload)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_RADIUS_TRACE_PAYLOAD("Parsing payload", payload);

	eap_status_e status(eap_status_process_general_error);

	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |     Type      |    Length     |   Data ...
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	if (payload->get_data_length() < eap_radius_attribute_header_c::get_header_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_RADIUS_ERROR,
			(EAPL("ERROR: eap_radius_payloads_c::parse_generic_payload(0x%08x): ")
			 EAPL("current payload 0x%08x=%s, length 0x%04x, data length incorrect 0x%04x.\n"),
			 payload,
			 payload_type.get_vendor_code(),
			 payload->get_payload_type_string(),
			 payload->get_length(),
			 payload->get_data_length()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	u32_t data_length = payload->get_data_length();

	u8_t * const data
		= static_cast<u8_t *>(payload->get_data_offset(0ul, data_length));

	if (data == 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_RADIUS_ERROR, 
			(EAPL("ERROR: eap_radius_payloads_c::parse_generic_payload(0x%08x): ")
			 EAPL("current payload 0x%08x=%s, length 0x%04x, data buffer incorrect.\n"),
			 payload,
			 payload_type.get_vendor_code(),
			 payload->get_payload_type_string(),
			 payload->get_length()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	status = add_payload(
		payload_type,
		data,
		data_length,
		false,
		false,
		true); // This can be fragmented.

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_payloads_c::parse_radius_payload(
	const eap_radius_attribute_header_c * const p_payload,
	u32_t * const buffer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_radius_attribute_header_c payload(
		m_am_tools,
		p_payload->get_header_buffer(*buffer_length),
		*buffer_length); // Const correctness is gone.

	eap_diameter_avp_code_c current_payload = payload.get_current_payload();

	eap_status_e status = eap_status_header_corrupted;

	if (payload.get_is_valid() == true
		&& current_payload != eap_diameter_avp_code_none)
	{
		if (*buffer_length < payload.get_header_length()+payload.get_data_length())
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_RADIUS_ERROR,
				(EAPL("ERROR: eap_radius_payloads_c::parse_radius_payload(0x%08x): current payload 0x%08x=%s, data length 0x%04x, buffer length 0x%04x.\n"),
				payload.get_header_buffer(0ul),
				 current_payload.get_vendor_code(),
				 payload.get_payload_type_string(),
				 payload.get_data_length(),
				 *buffer_length));
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_RADIUS_ERROR,
				(EAPL("ERROR: eap_radius_payloads_c::parse_radius_payload(): RADIUS-payload header is corrupted.\n")));
			EAP_TRACE_DATA_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("payload"),
				payload.get_header_buffer(*buffer_length),
				*buffer_length));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		status = parse_generic_payload(current_payload, &payload);
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
					TRACE_FLAGS_RADIUS_ERROR,
					(EAPL("ERROR: eap_radius_payloads_c::parse_radius_payload(0x%08x): current payload 0x%08x=%s, data length 0x%04x, buffer length 0x%04x.\n"),
					 payload.get_header_buffer(0ul),
					 current_payload.get_vendor_code(),
					 payload.get_payload_type_string(),
					 payload.get_data_length(),
					 *buffer_length));
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_RADIUS_ERROR,
					(EAPL("ERROR: eap_radius_payloads_c::parse_radius_payload(): RADIUS-payload header is corrupted.\n")));
				EAP_TRACE_DATA_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("payload"),
					payload.get_header_buffer(*buffer_length),
					*buffer_length));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}

			status = parse_generic_payload(current_payload, &payload);
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
			TRACE_FLAGS_RADIUS_ERROR,
			(EAPL("ERROR: eap_radius_payloads_c::parse_radius_payload(): ")
			 EAPL("RADIUS-header is corrupted. Buffer length and payload length does not match. %lu illegal bytes.\n"),
			 *buffer_length));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------



// End.
