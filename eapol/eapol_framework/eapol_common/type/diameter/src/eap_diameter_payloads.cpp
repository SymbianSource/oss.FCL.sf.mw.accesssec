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
	#define EAP_FILE_NUMBER_ENUM 588 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_diameter_payloads.h"
#include "eap_diameter_avp_header.h"
#include "abs_eap_am_tools.h"
#include "eap_tools.h"
#include "eap_array_algorithms.h"


EAP_FUNC_EXPORT eap_diameter_variable_data_c::~eap_diameter_variable_data_c()
{
}

EAP_FUNC_EXPORT eap_diameter_variable_data_c::eap_diameter_variable_data_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_data(tools)
	, m_payload_code(eap_diameter_avp_code_none)
	, m_is_mandatory(false)
{
}

EAP_FUNC_EXPORT eap_status_e eap_diameter_variable_data_c::set_buffer(
	const eap_diameter_avp_code_c current_payload,
	const bool is_mandatory,
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

	m_payload_code = current_payload;

	m_is_mandatory = is_mandatory;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT eap_status_e eap_diameter_variable_data_c::add_data(
	const u8_t * const buffer,
	const u32_t buffer_length)
{
	eap_status_e status = m_data.add_data(
		buffer,
		buffer_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT u32_t eap_diameter_variable_data_c::get_data_length() const
{
	return m_data.get_data_length();
}

EAP_FUNC_EXPORT u8_t * eap_diameter_variable_data_c::get_data(
	const u32_t data_length) const
{
	return m_data.get_data(data_length);
}

EAP_FUNC_EXPORT eap_variable_data_c * eap_diameter_variable_data_c::get_payload_buffer()
{
	return &m_data;
}

EAP_FUNC_EXPORT eap_diameter_avp_code_c eap_diameter_variable_data_c::get_payload_code() const
{
	return m_payload_code;
}

EAP_FUNC_EXPORT bool eap_diameter_variable_data_c::get_is_mandatory() const
{
	return m_is_mandatory;
}

EAP_FUNC_EXPORT void eap_diameter_variable_data_c::set_payload_code(
	const eap_diameter_avp_code_c code)
{
	m_payload_code = code;
}

EAP_FUNC_EXPORT eap_diameter_variable_data_c * eap_diameter_variable_data_c::copy() const
{
	eap_diameter_variable_data_c * new_data = new eap_diameter_variable_data_c(m_am_tools);

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

		new_data->set_payload_code(get_payload_code());
	}

	return new_data;
}

EAP_FUNC_EXPORT  void eap_diameter_variable_data_c::object_increase_reference_count()
{
}



EAP_FUNC_EXPORT eap_diameter_payloads_c::~eap_diameter_payloads_c()
{
}

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4355 ) // 'this' : used in base member initializer list
#endif

EAP_FUNC_EXPORT eap_diameter_payloads_c::eap_diameter_payloads_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	  , m_payload_map(tools, this)
	  , m_read_payloads(tools)
	  , m_is_valid(false)
{
	m_is_valid = true;
}

EAP_FUNC_EXPORT eap_diameter_variable_data_c * eap_diameter_payloads_c::get_payload(
	const eap_diameter_avp_code_c current_payload)
{
	eap_variable_data_c selector(m_am_tools);

	eap_status_e status = selector.set_buffer(
		&current_payload,
		sizeof(current_payload),
		false,
		false);
	if (status != eap_status_ok)
	{
		return 0;
	}

	eap_diameter_variable_data_c *payload = m_payload_map.get_handler(&selector);

	return payload;
}


EAP_FUNC_EXPORT eap_status_e eap_diameter_payloads_c::check_payloads_existense(
	EAP_TEMPLATE_CONST eap_array_c<eap_diameter_avp_code_c> * const needed_payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	for (u32_t ind = 0ul; ind < needed_payloads->get_object_count(); ind++)
	{
		const eap_diameter_avp_code_c * const required_avp_code = needed_payloads->get_object(ind);
		if (required_avp_code == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (get_payload(*required_avp_code) == 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("not received AVP 0x%08x:0x%08x.\n"),
				 required_avp_code->get_vendor_id(),
				 required_avp_code->get_vendor_code()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_not_found);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}


EAP_FUNC_EXPORT eap_status_e eap_diameter_payloads_c::check_mandatory_payloads(
	EAP_TEMPLATE_CONST eap_array_c<eap_diameter_avp_code_c> * const used_payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	for (u32_t ind = 0ul; ind < m_read_payloads.get_object_count(); ind++)
	{
		const eap_diameter_variable_data_c * const read_payload = m_read_payloads.get_object(ind);
		if (read_payload == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (read_payload->get_is_mandatory() == true)
		{
			eap_diameter_avp_code_c code = read_payload->get_payload_code();

			i32_t index = find_simple<eap_diameter_avp_code_c>(
				used_payloads,
				&code,
				m_am_tools);
			if (index < 0ul)
			{
				// ERROR: not used mandatory AVP.
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_DIAMETER_ERROR, 
					(EAPL("ERROR: not used mandatory AVP 0x%08x:0x%08x.\n"),
					 code.get_vendor_id(),
					 code.get_vendor_code()));

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_unsupported_payload);
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}


EAP_FUNC_EXPORT eap_status_e eap_diameter_payloads_c::add_payload(
	const eap_diameter_avp_code_c current_payload,
	const bool is_mandatory,
	const u8_t * const data,
	const u32_t data_length,
	const bool free_buffer,
	const bool is_writable,
	const bool fragments_allowed)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	eap_diameter_variable_data_c *payload = get_payload(
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
			// Cannot add fragment.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}
	else
	{
		eap_variable_data_c selector(m_am_tools);

		status = selector.set_buffer(
			&current_payload,
			sizeof(current_payload),
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		eap_diameter_variable_data_c *payload = new eap_diameter_variable_data_c(
			m_am_tools);
		if (payload == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = payload->set_buffer(
			current_payload,
			is_mandatory,
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

		// Note the same payload object is added to m_read_payloads as to m_payload_map.
		status = m_read_payloads.add_object(payload, false);
		if (status != eap_status_ok)
		{
			// Note we do not delete payload here, because it has been added alredy to m_payload_map.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


EAP_FUNC_EXPORT bool eap_diameter_payloads_c::get_is_valid() const
{
	return m_is_valid;
}


//--------------------------------------------------

//eap_diameter_payloads_c
EAP_FUNC_EXPORT eap_status_e eap_diameter_payloads_c::parse_generic_payload(
	const eap_diameter_avp_code_c payload_type,
	const eap_diameter_avp_header_c * const payload)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_DIAMETER_TRACE_PAYLOAD("Parsing payload", payload);

	eap_status_e status(eap_status_process_general_error);

	/*
	 *  AVP-header:
	 *  0                   1                   2                   3   
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                           AVP Code                            |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |V|M|r r r r r r|                  AVP Length                   |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                      Vendor-ID (optional)                     |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                             Data ....
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	if (payload->get_length() < payload->get_header_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DIAMETER_ERROR,
			(EAPL("ERROR: eap_diameter_payloads_c::parse_generic_payload(0x%08x): ")
			 EAPL("current payload 0x%08x:0x%08x=%s, required length 0x%08x, packet length too less 0x%08x.\n"),
			 payload,
			 payload_type.get_vendor_id(),
			 payload_type.get_vendor_code(),
			 payload->get_avp_code_string(),
			 payload->get_header_length(),
			 payload->get_length()));
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
			TRACE_FLAGS_DIAMETER_ERROR, 
			(EAPL("ERROR: eap_diameter_payloads_c::parse_generic_payload(0x%08x): ")
			 EAPL("current payload 0x%08x:0x%08x=%s, length 0x%04x, data buffer incorrect.\n"),
			 payload,
			 payload_type.get_vendor_id(),
			 payload_type.get_vendor_code(),
			 payload->get_avp_code_string(),
			 payload->get_data_length()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	status = add_payload(
		payload_type,
		payload->get_avp_flag_mandatory_avp(),
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
EAP_FUNC_EXPORT eap_status_e eap_diameter_payloads_c::parse_diameter_payloads(
	const eap_diameter_avp_header_c * const p_payload,
	u32_t * const buffer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_diameter_avp_header_c payload(
		m_am_tools,
		p_payload->get_header_buffer(*buffer_length),
		*buffer_length); // Const correctness is gone.

	eap_diameter_avp_code_c current_payload = payload.get_avp_code();

	eap_status_e status = eap_status_header_corrupted;

	if (payload.get_is_valid() == true
		&& current_payload != eap_diameter_avp_code_none)
	{
		if (*buffer_length < payload.get_length())
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DIAMETER_ERROR,
				(EAPL("ERROR: eap_diameter_payloads_c::parse_diameter_payloads(0x%08x): ")
				 EAPL("current payload 0x%08x:0x%08x=%s, data length 0x%04x, buffer length 0x%04x.\n"),
				 payload.get_header_buffer(0ul),
				 current_payload.get_vendor_id(),
				 current_payload.get_vendor_code(),
				 payload.get_avp_code_string(),
				 payload.get_data_length(),
				 *buffer_length));
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DIAMETER_ERROR,
				(EAPL("ERROR: eap_diameter_payloads_c::parse_diameter_payloads(): ")
				 EAPL("DIAMETER-payload header is corrupted.\n")));
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

		u32_t prev_avp_length = payload.get_length() + payload.get_padding_length();
		if (*buffer_length < prev_avp_length)
		{
			// We do have only the current payload. So not padding is included.
			prev_avp_length = payload.get_length();
		}

		EAP_ASSERT_ALWAYS(*buffer_length >= prev_avp_length);
		*buffer_length -= prev_avp_length;

		while(*buffer_length >= payload.get_header_length()
			&& payload.get_is_valid() == true
			&& payload.get_header_buffer_length() >= payload.get_length())
		{
			payload.set_header_buffer(
					payload.get_next_header(),
					payload.get_header_buffer_length() - prev_avp_length);
			if (payload.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}

			current_payload = payload.get_avp_code();

			if (*buffer_length < payload.get_length())
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_DIAMETER_ERROR,
					(EAPL("ERROR: eap_diameter_payloads_c::parse_diameter_payloads(0x%08x): ")
					 EAPL("current payload 0x%08x:0x%08x=%s, payload data length 0x%04x, payload length 0x%04x, buffer length 0x%04x.\n"),
					 payload.get_header_buffer(0ul),
					 current_payload.get_vendor_id(),
					 current_payload.get_vendor_code(),
					 payload.get_avp_code_string(),
					 payload.get_data_length(),
					 payload.get_length(),
					 *buffer_length));
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_DIAMETER_ERROR,
					(EAPL("ERROR: eap_diameter_payloads_c::parse_diameter_payloads(): ")
					 EAPL("DIAMETER-payload header is corrupted.\n")));
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

			prev_avp_length = payload.get_length() + payload.get_padding_length();
			if (*buffer_length < prev_avp_length)
			{
				// We do have only the current payload. So not padding is included.
				prev_avp_length = payload.get_length();
			}

			EAP_ASSERT_ALWAYS(*buffer_length >= prev_avp_length);
			*buffer_length -= prev_avp_length;
		}
	}

	if (*buffer_length != 0u)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DIAMETER_ERROR,
			(EAPL("ERROR: eap_diameter_payloads_c::parse_diameter_payloads(): ")
			 EAPL("DIAMETER-header is corrupted. Buffer length and payload ")
			 EAPL("length does not match. %lu illegal bytes.\n"),
			 *buffer_length));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_diameter_payloads_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_payload_map.reset();
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
// End.
