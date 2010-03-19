/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/wai_variable_data.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 20 % << Don't touch! Updated by Synergy at check-out.
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
	#define EAP_FILE_NUMBER_ENUM 710 
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

EAP_FUNC_EXPORT wai_variable_data_c::~wai_variable_data_c()
{
	delete get_next_payload_with_same_tlv_type();
	set_next_payload_with_same_tlv_type(0);
}

//--------------------------------------------------

EAP_FUNC_EXPORT wai_variable_data_c::wai_variable_data_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	  , m_data(tools)
	  , m_wai_tlv_header(tools, 0, 0ul)
	  , m_ec_cs_tlv_header(tools, 0, 0ul)
	  , m_payload_type(wai_payload_type_none)
	  , m_next_payload_with_same_tlv_type(0)
	  , m_is_valid(false)
{
	if (m_data.get_is_valid() == false)
	{
		return;
	}

	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool wai_variable_data_c::get_is_valid() const
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool wai_variable_data_c::get_is_valid_data() const
{
	return get_is_valid() && m_data.get_is_valid_data();
}

//--------------------------------------------------

EAP_FUNC_EXPORT wai_payload_type_e wai_variable_data_c::convert_to_wai_payload_type(const wai_tlv_type_e tlv_type)
{
	switch(tlv_type)
	{
	case wai_tlv_type_signature_attribute:
		return wai_payload_type_signature_attributes;
	case wai_tlv_type_result_of_certificate_validation:
		return wai_payload_type_result_of_certificate_verification;
	case wai_tlv_type_identity_list:
		return wai_payload_type_identity_list;
	default:
		return wai_payload_type_none;
	};
}

//--------------------------------------------------

EAP_FUNC_EXPORT wai_tlv_type_e wai_variable_data_c::convert_to_wai_tlv_type(const wai_payload_type_e payload_type)
{
	switch(payload_type)
	{
	case wai_payload_type_signature_attributes:
		return wai_tlv_type_signature_attribute;
	case wai_payload_type_result_of_certificate_verification:
		return wai_tlv_type_result_of_certificate_validation;
	case wai_payload_type_identity_list:
		return wai_tlv_type_identity_list;
	case wai_payload_type_echd_parameter:
		return wai_tlv_type_echd_parameter;
	default:
		return wai_tlv_type_none;
	};
}

//--------------------------------------------------

EAP_FUNC_EXPORT wai_certificate_identifier_e wai_variable_data_c::convert_to_wai_certificate_identifier(const wai_payload_type_e payload_type)
{
	switch(payload_type)
	{
	case wai_payload_type_certificate:
	case wai_payload_type_identity:
		return wai_certificate_identifier_x_509_v3;
	default:
		return wai_certificate_identifier_none;
	};
}

//--------------------------------------------------

EAP_FUNC_EXPORT ec_cs_tlv_type_e wai_variable_data_c::convert_to_ec_cs_tlv_type(const wai_payload_type_e payload_type)
{
	switch(payload_type)
	{
	case wai_payload_type_certificate:
	case wai_payload_type_identity:
		return static_cast<ec_cs_tlv_type_e>(convert_to_wai_certificate_identifier(payload_type));
	default:
		return static_cast<ec_cs_tlv_type_e>(payload_type);
	};
}

//--------------------------------------------------

eap_status_e wai_variable_data_c::set_header_buffer(
	const wai_payload_type_e current_payload,
	const bool write_header)
{
	if (m_data.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	switch (get_type_class())
	{
	case wai_payload_type_size_ec_cs_tlv_header:
		{
			m_ec_cs_tlv_header.set_header_buffer(
				m_data.get_buffer(m_data.get_buffer_length()),
				m_data.get_buffer_length());

			if (write_header == true)
			{
				eap_status_e status = m_ec_cs_tlv_header.reset_header();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = m_ec_cs_tlv_header.set_type(convert_to_ec_cs_tlv_type(current_payload));
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
		break;
	case wai_payload_type_size_wai_tlv_header:
		{
			m_wai_tlv_header.set_header_buffer(
				m_data.get_buffer(m_data.get_buffer_length()),
				m_data.get_buffer_length());

			if (current_payload == wai_payload_type_optional)
			{
				m_payload_type = convert_to_wai_payload_type(m_wai_tlv_header.get_type());
			}
			else if (write_header == true)
			{
				eap_status_e status = m_wai_tlv_header.reset_header();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = m_wai_tlv_header.set_type(convert_to_wai_tlv_type(current_payload));
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
		break;
	default:
		;
	}; // switch

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

eap_status_e wai_variable_data_c::set_header_buffer(
	const wai_payload_type_e current_payload,
	const bool write_header,
	const u32_t data_length)
{
	eap_status_e status = set_header_buffer(
		current_payload,
		write_header);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	switch (get_type_class())
	{
	case wai_payload_type_size_ec_cs_tlv_header:
		m_ec_cs_tlv_header.set_data_length(static_cast<u16_t>(data_length));
		break;
	case wai_payload_type_size_wai_tlv_header:
		m_wai_tlv_header.set_data_length(static_cast<u16_t>(data_length));
		break;
	case wai_payload_type_size_1_octet_length_field:
		{
			u8_t * data = m_data.get_data(sizeof(u8_t));
			if (data == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			if (data_length > 0xff)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
			}

			data[0ul] = static_cast<u8_t>(data_length);

		}
		break;
	default:
		;
	}; // switch

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_variable_data_c::init_header(
	const wai_payload_type_e current_payload,
	const u32_t default_buffer_length)
{
	if (default_buffer_length > 0xffff)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = set_payload_type(current_payload);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_data.set_buffer_length(
		default_buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	switch (get_type_class())
	{
	case wai_payload_type_size_wai_tlv_header:
		{
			status = m_data.set_data_length(
				wai_tlv_header_c::get_header_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_wai_tlv_header.reset();
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		break;
	case wai_payload_type_size_ec_cs_tlv_header:
		{
			status = m_data.set_data_length(
				ec_cs_tlv_header_c::get_header_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_ec_cs_tlv_header.reset();
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		break;
	case wai_payload_type_size_1_octet_length_field:
		{
			status = m_data.set_data_length(sizeof(u8_t));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			u8_t * data = m_data.get_data(sizeof(u8_t));
			if (data == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			data[0ul] = 0u;

		}
		break;
	default:
		break;
	}; // switch


	status = set_header_buffer(current_payload, true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_variable_data_c::reset()
{
	(void) m_data.reset();

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_variable_data_c::set_buffer(
	const wai_payload_type_e current_payload,
	const void * const buffer,
	const u32_t buffer_length)
{
	if (buffer_length > 0xffff)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = m_data.set_buffer(
		buffer,
		buffer_length,
		false,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_payload_type(current_payload);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_wai_tlv_header.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_ec_cs_tlv_header.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_header_buffer(current_payload, false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

u32_t wai_variable_data_c::get_header_length(
	const wai_payload_type_e current_payload) const
{
	switch (get_type_class(current_payload))
	{
	case wai_payload_type_size_ec_cs_tlv_header:
		{
			return m_ec_cs_tlv_header.get_header_length();
		}
	case wai_payload_type_size_wai_tlv_header:
		{
			return m_wai_tlv_header.get_header_length();
		}
	case wai_payload_type_size_1_octet_length_field:
		{
			return sizeof(u8_t);
		}
	case wai_payload_type_size_wie:
		{
			return WIE_HEADER_LENGTH;
		}
	default:
		{
			return 0ul;
		}
	}; // switch
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_variable_data_c::create(
	const wai_payload_type_e current_payload,
	const void * const buffer, // Buffer includes only data.
	const u32_t buffer_length) // Buffer_length includes only data.
{
	eap_status_e status = init_header(
		current_payload,
		get_header_length(current_payload) + buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_data.add_data(buffer, buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	switch (get_type_class())
	{
	case wai_payload_type_size_ec_cs_tlv_header:
		m_ec_cs_tlv_header.set_data_length(static_cast<u16_t>(buffer_length));
		break;
	case wai_payload_type_size_wai_tlv_header:
		m_wai_tlv_header.set_data_length(static_cast<u16_t>(buffer_length));
		break;
	case wai_payload_type_size_1_octet_length_field:
		{
			u8_t * data = m_data.get_data(sizeof(u8_t));
			if (data == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			if (buffer_length > 0xff)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
			}

			data[0ul] = static_cast<u8_t>(buffer_length);

		}
		break;
	default:
		;
	}; // switch

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_variable_data_c::create(
	const wai_payload_type_e current_payload,
	const eap_variable_data_c * const buffer) // Buffer includes only data.
{
	eap_status_e status = create(
		current_payload,
		buffer->get_data(),
		buffer->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_variable_data_c::set_copy_of_buffer(
	const wai_payload_type_e current_payload,
	const void * const buffer, // Buffer does include header and data.
	const u32_t buffer_length) // Buffer_length does include header and data.
{
	eap_status_e status = init_header(
		current_payload,
		buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_data.set_copy_of_buffer(buffer, buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	switch (get_type_class())
	{
	case wai_payload_type_size_ec_cs_tlv_header:
		m_ec_cs_tlv_header.set_data_length(static_cast<u16_t>(buffer_length - get_type_header_length()));
		break;
	case wai_payload_type_size_wai_tlv_header:
		m_wai_tlv_header.set_data_length(static_cast<u16_t>(buffer_length - get_type_header_length()));
		break;
	case wai_payload_type_size_1_octet_length_field:
		{
			u8_t * data = m_data.get_data(sizeof(u8_t));
			if (data == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			if (buffer_length > 0xff)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
			}

			data[0ul] = static_cast<u8_t>(buffer_length - get_type_header_length());

		}
		break;
	default:
		;
	}; // switch

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_variable_data_c::set_copy_of_buffer(
	const wai_payload_type_e current_payload,
	const eap_variable_data_c * const buffer)
{
	eap_status_e status = set_copy_of_buffer(
		current_payload,
		buffer->get_data(),
		buffer->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_variable_data_c::set_copy_of_buffer(
	const wai_variable_data_c * const source)
{
	eap_status_e status = set_copy_of_buffer(
			source->get_payload_type(),
			source->get_data(source->get_data_length()),
			source->get_data_length());

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	delete get_next_payload_with_same_tlv_type();
	set_next_payload_with_same_tlv_type(0);

	wai_variable_data_c * previous = this;

	const wai_variable_data_c * next = source->get_next_payload_with_same_tlv_type();

	while (next != 0)
	{
		// Copy the next payload in a list too.
		wai_variable_data_c * const new_payload = next->copy();
		if (new_payload == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		previous->set_next_payload_with_same_tlv_type(new_payload);

		previous = new_payload;

		next = next->get_next_payload_with_same_tlv_type();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_variable_data_c::add_data(
	const wai_payload_type_e new_payload,
	const void * const buffer,
	const u32_t buffer_length)
{
	const wai_payload_type_e current_payload = get_payload_type();

	if (new_payload != current_payload)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	const u32_t type_data_length(get_type_data_length());

	eap_status_e status = m_data.add_data(
		buffer,
		buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_header_buffer(current_payload, true, (type_data_length + buffer_length));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_variable_data_c::add_data(
	const wai_payload_type_e new_payload,
	const eap_variable_data_c * const buffer)
{
	eap_status_e status = add_data(
		new_payload,
		buffer->get_data(),
		buffer->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_variable_data_c::add_data(
	const wai_variable_data_c * const data)
{
	eap_status_e status = add_data(
		data->get_payload_type(),
		data->get_full_tlv_buffer()->get_data(),
		data->get_full_tlv_buffer()->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

wai_payload_type_size_e wai_variable_data_c::get_type_class(const wai_payload_type_e current_payload) const
{
	if (current_payload <= wai_payload_type_last_known
		&& current_payload == wai_payload_type_to_class_map[current_payload].m_type)
	{
		return wai_payload_type_to_class_map[current_payload].m_size;
	}
	else
	{
		return wai_payload_type_size_none;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT wai_payload_type_size_e wai_variable_data_c::get_type_class() const
{
	const wai_payload_type_e current_payload(get_payload_type());

	return get_type_class(current_payload);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t wai_variable_data_c::get_type_data_length() const
{
	switch (get_type_class())
	{
	case wai_payload_type_size_ec_cs_tlv_header:
		{
			if (m_data.get_data_length() >= m_ec_cs_tlv_header.get_header_length())
			{
				return m_ec_cs_tlv_header.get_data_length();
			}
			else
			{
				return 0ul;
			}
		}
	case wai_payload_type_size_wai_tlv_header:
		{
			if (m_data.get_data_length() >= m_wai_tlv_header.get_header_length())
			{
				return m_wai_tlv_header.get_data_length();
			}
			else
			{
				return 0ul;
			}
		}
	case wai_payload_type_size_1_octet_length_field:
		{
			if (m_data.get_data_length() >= sizeof(u8_t))
			{
				const u8_t * data = m_data.get_data(sizeof(u8_t));
				return data[0ul];
			}
			else
			{
				return 0ul;
			}
		}
	case wai_payload_type_size_wie:
		{
			if (m_data.get_data_length() >= WIE_HEADER_LENGTH)
			{
				const u8_t * data = m_data.get_data(WIE_HEADER_LENGTH);
				return data[1ul];
			}
			else
			{
				return 0ul;
			}
		}
	default:
		{
			if (m_data.get_data_length() >= static_cast<u32_t>(get_type_class()))
			{
				return get_type_class();
			}
			else
			{
				return 0ul;
			}
		}
	}; // switch
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t wai_variable_data_c::get_type_header_length() const
{
	switch (get_type_class())
	{
	case wai_payload_type_size_ec_cs_tlv_header:
		{
			if (m_data.get_data_length() >= m_ec_cs_tlv_header.get_header_length())
			{
				return m_ec_cs_tlv_header.get_header_length();
			}
			else
			{
				return 0ul;
			}
		}
	case wai_payload_type_size_wai_tlv_header:
		{
			if (m_data.get_data_length() >= m_wai_tlv_header.get_header_length())
			{
				return m_wai_tlv_header.get_header_length();
			}
			else
			{
				return 0ul;
			}
		}
	case wai_payload_type_size_1_octet_length_field:
		{
			if (m_data.get_data_length() >= sizeof(u8_t))
			{
				return sizeof(u8_t);
			}
			else
			{
				return 0ul;
			}
		}
	case wai_payload_type_size_wie:
		{
			if (m_data.get_data_length() >= WIE_HEADER_LENGTH)
			{
				return WIE_HEADER_LENGTH;
			}
			else
			{
				return 0ul;
			}
		}
	default:
		{
			return 0ul;
		}
	}; // switch
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * wai_variable_data_c::get_type_data_offset(
	const u32_t offset,
	const u32_t data_length) const
{
	return m_data.get_data_offset(get_type_header_length()+offset, data_length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * wai_variable_data_c::get_type_data(
	const u32_t data_length) const
{
	return get_type_data_offset(0ul, data_length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t wai_variable_data_c::get_data_length() const
{
	return get_type_header_length() + get_type_data_length();
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * wai_variable_data_c::get_data(
	const u32_t data_length) const
{
#if 1

	return m_data.get_data(data_length);

#else

	switch (get_type_class())
	{
	case wai_payload_type_size_ec_cs_tlv_header:
		{
			return m_ec_cs_tlv_header.get_data(data_length);
		}
	case wai_payload_type_size_wai_tlv_header:
		{
			return m_wai_tlv_header.get_data(data_length);
		}
	case wai_payload_type_size_1_octet_length_field:
		{
			if (m_data.get_data_length() >= (sizeof(u8_t) + data_length))
			{
				return m_data.get_data_offset(sizeof(u8_t), data_length);
			}
			else
			{
				return 0;
			}
		}
	case wai_payload_type_size_wie:
		{
			if (m_data.get_data_length() >= (WIE_HEADER_LENGTH + data_length))
			{
				return m_data.get_data(data_length);
			}
			else
			{
				return 0;
			}
		}
	case wai_payload_type_size_1_octet:
	case wai_payload_type_size_12_octets:
	case wai_payload_type_size_16_octets:
	case wai_payload_type_size_20_octets:
	case wai_payload_type_size_32_octets:
		{
			return m_data.get_data(data_length);
		}
	default:
		{
			return 0;
		}
	}; // switch

#endif

}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * wai_variable_data_c::get_data_offset(const u32_t offset, const u32_t data_length) const
{

#if 1

	return m_data.get_data_offset(offset, data_length);

#else

	switch (get_type_class())
	{
	case wai_payload_type_size_ec_cs_tlv_header:
		{
			return m_ec_cs_tlv_header.get_data_offset(offset, data_length);
		}
	case wai_payload_type_size_wai_tlv_header:
		{
			return m_wai_tlv_header.get_data_offset(offset, data_length);
		}
	case wai_payload_type_size_1_octet_length_field:
		{
			if (m_data.get_data_length() >= (sizeof(u8_t) + offset + data_length))
			{
				return m_data.get_data_offset(offset + sizeof(u8_t), data_length);
			}
			else
			{
				return 0;
			}
		}
	case wai_payload_type_size_wie:
		{
			if (m_data.get_data_length() >= (WIE_HEADER_LENGTH + offset + data_length))
			{
				return m_data.get_data_offset(offset + WIE_HEADER_LENGTH, data_length);
			}
			else
			{
				return 0;
			}
		}
	case wai_payload_type_size_1_octet:
	case wai_payload_type_size_12_octets:
	case wai_payload_type_size_16_octets:
	case wai_payload_type_size_20_octets:
	case wai_payload_type_size_32_octets:
		{
			return m_data.get_data_offset(offset, data_length);
		}
	default:
		{
			return 0;
		}
	}; // switch

#endif

}

//--------------------------------------------------

EAP_FUNC_EXPORT const eap_variable_data_c * wai_variable_data_c::get_full_tlv_buffer() const
{
	return &m_data;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * wai_variable_data_c::get_writable_full_tlv_buffer()
{
	return &m_data;
}

//--------------------------------------------------

EAP_FUNC_EXPORT const wai_tlv_header_c * wai_variable_data_c::get_wai_tlv_header() const
{
	if (get_type_class() == wai_payload_type_size_wai_tlv_header)
	{
		return &m_wai_tlv_header;
	}
	else
	{
		return 0;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT const ec_cs_tlv_header_c * wai_variable_data_c::get_ec_cs_tlv_header() const
{
	if (get_type_class() == wai_payload_type_size_ec_cs_tlv_header)
	{
		return &m_ec_cs_tlv_header;
	}
	else
	{
		return 0;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT wai_payload_type_e wai_variable_data_c::get_payload_type() const
{
	return m_payload_type;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_variable_data_c::set_payload_type(
	const wai_payload_type_e payload_type)
{
	eap_status_e status(eap_status_ok);

	m_payload_type = payload_type;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void wai_variable_data_c::set_next_payload_with_same_tlv_type(
	wai_variable_data_c * const tlv)
{
	m_next_payload_with_same_tlv_type = tlv;
}

//--------------------------------------------------

EAP_FUNC_EXPORT wai_variable_data_c * wai_variable_data_c::get_next_payload_with_same_tlv_type() const
{
	return m_next_payload_with_same_tlv_type;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void wai_variable_data_c::add_next_payload_with_same_tlv_type(
	wai_variable_data_c * const tlv)
{
	wai_variable_data_c *payload = get_next_payload_with_same_tlv_type();
	wai_variable_data_c *prev_payload = this;

	while (payload != 0)
	{
		prev_payload = payload;
		payload = payload->get_next_payload_with_same_tlv_type();
	}

	if (prev_payload != 0)
	{
		prev_payload->set_next_payload_with_same_tlv_type(tlv);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT wai_variable_data_c * wai_variable_data_c::copy() const
{
	wai_variable_data_c * new_data = new wai_variable_data_c(m_am_tools);

	if (new_data != 0)
	{
		eap_status_e status = new_data->set_copy_of_buffer(
			get_payload_type(),
			get_data(get_data_length()),
			get_data_length());
		if (status != eap_status_ok)
		{
			delete new_data;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			return 0;
		}
	}

	return new_data;
}

//--------------------------------------------------

EAP_FUNC_EXPORT  void wai_variable_data_c::object_increase_reference_count()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT i32_t wai_variable_data_c::compare(const wai_variable_data_c * right) const
{
	if (get_payload_type() != right->get_payload_type())
	{
		return -1;
	}
	else if (get_data_length() != right->get_data_length())
	{
		return -1;
	}
	else
	{
		// Compares the (possible) header and data.
		return m_am_tools->memcmp(get_data(get_data_length()), right->get_data(right->get_data_length()), get_data_length());
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string wai_variable_data_c::get_wai_payload_type_string() const
{
	return wapi_strings_c::get_wai_payload_type_string(get_payload_type());
}

//--------------------------------------------------

void wai_variable_data_c::wai_variable_data_trace(abs_eap_am_tools_c * const tools, eap_format_string prefix, const wai_variable_data_c * const wai_data, const bool when_true_is_client)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v \n")));

	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("- %s %s (0x%08x): TLV type 0x%04x=%s, data length 0x%04x.\n"),
		prefix,
		((when_true_is_client) == true ? "client" : "server"),
		(wai_data)->get_data((wai_data)->get_data_length()),
		(wai_data)->get_payload_type(),
		wapi_strings_c::get_wai_payload_type_string((wai_data)->get_payload_type()),
		(wai_data)->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(wapi_strings_c::get_wai_payload_type_string((wai_data)->get_payload_type()),
		(wai_data)->get_data((wai_data)->get_data_length()),
		(wai_data)->get_data_length()));

	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ \n")));
}

//--------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

// End.
