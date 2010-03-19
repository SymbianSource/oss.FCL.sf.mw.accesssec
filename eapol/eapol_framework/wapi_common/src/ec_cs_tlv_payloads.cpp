/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/ec_cs_tlv_payloads.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 12 % << Don't touch! Updated by Synergy at check-out.
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
	#define EAP_FILE_NUMBER_ENUM 703 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#if defined(USE_WAPI_CORE)


#include "eap_am_memory.h"
#include "ec_cs_tlv_payloads.h"
#include "ec_cs_tlv_message.h"
#include "abs_eap_am_tools.h"
#include "eap_tools.h"
#include "eap_array_algorithms.h"
#include "eap_automatic_variable.h"
#include "eap_crypto_api.h"


//--------------------------------------------------

EAP_FUNC_EXPORT ec_cs_variable_data_c::~ec_cs_variable_data_c()
{
	delete m_next_payload_with_same_tlv_type;
	m_next_payload_with_same_tlv_type = 0;
}

//--------------------------------------------------

EAP_FUNC_EXPORT ec_cs_variable_data_c::ec_cs_variable_data_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	  , m_data(tools)
	  , m_header(tools, 0, 0ul)
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

EAP_FUNC_EXPORT bool ec_cs_variable_data_c::get_is_valid() const
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool ec_cs_variable_data_c::get_is_valid_data() const
{
	return get_is_valid() && m_data.get_is_valid_data() && m_header.get_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_variable_data_c::init_header(
	const ec_cs_tlv_type_e current_payload,
	const u32_t default_buffer_length)
{
	if (default_buffer_length > 0xffff)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = m_data.set_buffer_length(
		ec_cs_tlv_header_c::get_header_length() + default_buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_data.set_data_length(
		ec_cs_tlv_header_c::get_header_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_header.set_header_buffer(
		m_data.get_buffer(m_data.get_buffer_length()),
		m_data.get_buffer_length());

	status = m_header.reset_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_header.set_type(current_payload);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_variable_data_c::reset()
{
	(void) m_data.reset();

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_variable_data_c::set_copy_of_buffer(
	const ec_cs_tlv_type_e current_payload,
	const void * const buffer,
	const u32_t buffer_length)
{
	eap_status_e status = init_header(
		current_payload,
		buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_header.set_data_length(static_cast<u16_t>(buffer_length));

	status = m_data.add_data(buffer, buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_variable_data_c::set_copy_of_buffer(
	const ec_cs_variable_data_c * const source)
{
	eap_status_e status = set_copy_of_buffer(
			source->get_type(),
			source->get_data(source->get_data_length()),
			source->get_data_length());

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	ec_cs_variable_data_c * previous = this;

	const ec_cs_variable_data_c * next = source->get_next_payload_with_same_tlv_type();

	while (next != 0)
	{
		// Copy the next payload in a list too.
		ec_cs_variable_data_c * const new_payload = next->copy();
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

EAP_FUNC_EXPORT eap_status_e ec_cs_variable_data_c::add_data(
	const void * const buffer,
	const u32_t buffer_length)
{
	const ec_cs_tlv_type_e current_payload = m_header.get_type();

	eap_status_e status = m_data.add_data(
		buffer,
		buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_header.set_header_buffer(
		m_data.get_buffer(m_data.get_buffer_length()),
		m_data.get_buffer_length());

	status = m_header.set_type(current_payload);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if ((m_header.get_data_length() + buffer_length) > 0xffff)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	m_header.set_data_length(static_cast<u16_t>(m_header.get_data_length() + buffer_length));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_variable_data_c::add_data(
	const ec_cs_variable_data_c * const data)
{
	eap_status_e status = add_data(
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

EAP_FUNC_EXPORT eap_status_e ec_cs_variable_data_c::set_copy_of_buffer(
	const void * const buffer,
	const u32_t buffer_length)
{
	eap_status_e status = m_data.set_copy_of_buffer(buffer, buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_header.set_header_buffer(
		m_data.get_buffer(m_data.get_buffer_length()),
		m_data.get_buffer_length());

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t ec_cs_variable_data_c::get_data_length() const
{
	return m_header.get_data_length();
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * ec_cs_variable_data_c::get_data(
	const u32_t data_length) const
{
	return m_header.get_data(data_length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * ec_cs_variable_data_c::get_data_offset(const u32_t offset, const u32_t data_length) const
{
	return m_header.get_data_offset(offset, data_length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT const eap_variable_data_c * ec_cs_variable_data_c::get_full_tlv_buffer() const
{
	return &m_data;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * ec_cs_variable_data_c::get_writable_full_tlv_buffer()
{
	return &m_data;
}

//--------------------------------------------------

EAP_FUNC_EXPORT const ec_cs_tlv_header_c * ec_cs_variable_data_c::get_header() const
{
	return &m_header;
}

//--------------------------------------------------

EAP_FUNC_EXPORT ec_cs_tlv_type_e ec_cs_variable_data_c::get_type() const
{
	return m_header.get_type();
}

//--------------------------------------------------

EAP_FUNC_EXPORT void ec_cs_variable_data_c::set_type(
	const ec_cs_tlv_type_e type)
{
	m_header.set_type(type);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void ec_cs_variable_data_c::set_next_payload_with_same_tlv_type(
	ec_cs_variable_data_c * const tlv)
{
	m_next_payload_with_same_tlv_type = tlv;
}

//--------------------------------------------------

EAP_FUNC_EXPORT ec_cs_variable_data_c * ec_cs_variable_data_c::get_next_payload_with_same_tlv_type() const
{
	return m_next_payload_with_same_tlv_type;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void ec_cs_variable_data_c::add_next_payload_with_same_tlv_type(
	ec_cs_variable_data_c * const tlv)
{
	ec_cs_variable_data_c *payload = get_next_payload_with_same_tlv_type();
	ec_cs_variable_data_c *prev_payload = this;

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

EAP_FUNC_EXPORT ec_cs_variable_data_c * ec_cs_variable_data_c::copy() const
{
	ec_cs_variable_data_c * new_data = new ec_cs_variable_data_c(m_am_tools);

	if (new_data != 0)
	{
		eap_status_e status = new_data->set_copy_of_buffer(
			get_type(),
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

EAP_FUNC_EXPORT  void ec_cs_variable_data_c::object_increase_reference_count()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT i32_t ec_cs_variable_data_c::compare(const ec_cs_variable_data_c * right) const
{
	if (get_type() != right->get_type())
	{
		return -1;
	}
	else if (get_data_length() != right->get_data_length())
	{
		return -1;
	}
	else
	{
		return m_am_tools->memcmp(get_data(get_data_length()), right->get_data(right->get_data_length()), get_data_length());
	}
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------


EAP_FUNC_EXPORT ec_cs_tlv_payloads_c::~ec_cs_tlv_payloads_c()
{
}

//--------------------------------------------------

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4355 ) // 'this' : used in base member initializer list
#endif

EAP_FUNC_EXPORT ec_cs_tlv_payloads_c::ec_cs_tlv_payloads_c(
	abs_eap_am_tools_c * const tools,
	const bool true_when_is_client)
	: m_am_tools(tools)
	  , m_payload_map(tools, this)
	  , m_read_payloads(tools)
	  , m_payload_index(0ul)
	  , m_is_client(true_when_is_client)
	  , m_is_valid(false)
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT ec_cs_variable_data_c * ec_cs_tlv_payloads_c::get_tlv_pointer(
	const ec_cs_tlv_type_e current_payload,
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

	ec_cs_variable_data_c *payload = m_payload_map.get_handler(&selector);

	while (index != 0ul && payload != 0)
	{
		--index;
		payload = payload->get_next_payload_with_same_tlv_type();
	}

	return payload;
}

//--------------------------------------------------

EAP_FUNC_EXPORT ec_cs_variable_data_c * ec_cs_tlv_payloads_c::get_tlv_pointer(
	const ec_cs_tlv_type_e current_payload) const
{
	return get_tlv_pointer(current_payload, 0ul);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t ec_cs_tlv_payloads_c::get_tlv_count() const
{
	return m_read_payloads.get_object_count();
}

//--------------------------------------------------

EAP_FUNC_EXPORT ec_cs_variable_data_c * ec_cs_tlv_payloads_c::get_tlv(
	const u32_t tlv_index) const
{
	ec_cs_variable_data_c *payload = m_read_payloads.get_object(tlv_index);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC-CS:     message_function: ec_cs_tlv_payloads_c::get_tlv(index %d, max %d) = %s\n"),
		tlv_index,
		m_read_payloads.get_object_count(),
		payload->get_header()->get_tlv_string()));

	return payload;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_payloads_c::check_payloads_existense(
	const ec_cs_tlv_type_e * const needed_payloads,
	const u32_t count_of_needed_payloads) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC-CS:     message_function: ec_cs_tlv_payloads_c::check_payloads_existense()\n")));

	for (u32_t ind = 0ul; ind < count_of_needed_payloads; ind++)
	{
		const ec_cs_tlv_type_e required_avp_code = needed_payloads[ind];
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

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_payloads_c::check_payloads_existense(
	EAP_TEMPLATE_CONST eap_array_c<ec_cs_tlv_type_e> * const needed_payloads) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC-CS:     message_function: ec_cs_tlv_payloads_c::check_payloads_existense()\n")));

	for (u32_t ind = 0ul; ind < needed_payloads->get_object_count(); ind++)
	{
		const ec_cs_tlv_type_e * const required_avp_code = needed_payloads->get_object(ind);
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

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_payloads_c::copy_tlv(
	const ec_cs_tlv_payloads_c * const source,
	const ec_cs_tlv_type_e tlv)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC-CS:     message_function: ec_cs_tlv_payloads_c::copy_tlv(TLV 0x%08x)\n"),
		tlv));

	const ec_cs_variable_data_c * const payload
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

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_payloads_c::add_tlv(
	ec_cs_variable_data_c * const new_payload)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC-CS:     message_function: ec_cs_tlv_payloads_c::add_tlv()\n")));

	if (new_payload == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status(eap_status_process_general_error);

	eap_automatic_variable_c<ec_cs_variable_data_c>
		automatic_new_payload(m_am_tools, new_payload);

	const ec_cs_tlv_type_e new_payload_type(new_payload->get_type());
		
	ec_cs_variable_data_c *old_payload = get_tlv_pointer(
		new_payload_type);

	{
		eap_variable_data_c selector(m_am_tools);

		if (selector.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		selector.set_copy_of_buffer(
			&new_payload_type,
			sizeof(new_payload_type));
		
		if (old_payload == 0)
		{
			status = m_payload_map.add_handler(&selector, new_payload);
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
			old_payload->add_next_payload_with_same_tlv_type(new_payload);
		}

		automatic_new_payload.do_not_free_variable();

		// Note the same payload object is added to m_read_payloads as to m_payload_map.
		status = m_read_payloads.add_object(new_payload, false);
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

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_payloads_c::copy_tlv_data(
	const ec_cs_tlv_type_e current_payload,
	const void * const data,
	const u32_t data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC-CS:     message_function: ec_cs_tlv_payloads_c::copy_tlv_data(TLV 0x%08x)\n"),
		current_payload));

	eap_status_e status(eap_status_process_general_error);

	ec_cs_variable_data_c *new_payload = new ec_cs_variable_data_c(
		m_am_tools);
	if (new_payload == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_automatic_variable_c<ec_cs_variable_data_c>
		automatic_new_payload(m_am_tools, new_payload);

	status = new_payload->set_copy_of_buffer(
		current_payload,
		data,
		data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	automatic_new_payload.do_not_free_variable();

	status = add_tlv(new_payload);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool ec_cs_tlv_payloads_c::get_is_valid() const
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_payloads_c::parse_generic_payload(
	const ec_cs_tlv_type_e tlv_type,
	const ec_cs_tlv_header_c * const header)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	/*
	 *  TLV-header:
	 *  0                   1                   2                   3   
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |M|R|   TLV Type                |         Data Length           |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |         Data ... 
	 * +-+-+-+-+-+-+-+-+-+-
	 */
	if (header->get_header_buffer_length() < header->get_header_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("ERROR: ec_cs_tlv_payloads_c::parse_generic_payload(0x%08x): ")
			 EAPL("current header 0x%08x=%s, required length 0x%08x, packet length too less 0x%08x.\n"),
			 header,
			 tlv_type,
			 header->get_tlv_string(),
			 header->get_header_length(),
			 header->get_header_buffer_length()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	u32_t data_length = header->get_data_length();

	u8_t * const data
		= static_cast<u8_t *>(header->get_data_offset(0ul, data_length));

	if (data == 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_ERROR, 
			(EAPL("ERROR: ec_cs_tlv_payloads_c::parse_generic_payload(0x%08x): ")
			 EAPL("current header 0x%08x=%s, length 0x%04x, data buffer incorrect.\n"),
			 header,
			 tlv_type,
			 header->get_tlv_string(),
			 header->get_data_length()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EC_CS_TLV_TRACE_PAYLOAD("Parse EC-CS-TLV", header, m_is_client);

	status = copy_tlv_data(
		tlv_type,
		data,
		data_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_payloads_c::verify_padding(
	const u8_t * const possible_padding,
	const u32_t possible_padding_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC-CS:     message_function: ec_cs_tlv_payloads_c::verify_padding()\n")));

	const u8_t padding_byte = static_cast<u8_t>(possible_padding_length);

	for (u32_t ind = 0ul; ind < possible_padding_length; ind++)
	{
		if (possible_padding[ind] != padding_byte)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_padding);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_payloads_c::parse_ec_cs_payloads(
	void * const message_buffer,
	u32_t * const buffer_length,
	u32_t * const padding_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC-CS:     message_function: ec_cs_tlv_payloads_c::parse_ec_cs_payloads()\n")));

	*padding_length = 0ul;

	if (*buffer_length == 0)
	{
		// Empty payload.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("parse_ec_cs_payloads"),
		 message_buffer,
		 *buffer_length));

	ec_cs_tlv_header_c payload(
		m_am_tools,
		message_buffer,
		*buffer_length); // Const correctness is gone.

	ec_cs_tlv_type_e current_payload = payload.get_type();

	eap_status_e status = eap_status_header_corrupted;

	if (payload.get_is_valid() == true
		&& current_payload >= ec_cs_tlv_type_first_known
		&& current_payload <= ec_cs_tlv_type_last_known)
	{
		if (*buffer_length < payload.get_header_buffer_length())
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("ERROR: ec_cs_tlv_payloads_c::parse_ec_cs_payloads(0x%08x): ")
				 EAPL("current payload 0x%08x=%s, data length 0x%04x, buffer length 0x%04x.\n"),
				 payload.get_header_buffer(0ul),
				 current_payload,
				 payload.get_tlv_string(),
				 payload.get_data_length(),
				 *buffer_length));
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("ERROR: ec_cs_tlv_payloads_c::parse_ec_cs_payloads(): ")
				 EAPL("EC-CS-payload header is corrupted.\n")));
			EAP_TRACE_DATA_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("payload"),
				payload.get_header_buffer(*buffer_length),
				*buffer_length));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		status = parse_generic_payload(
			current_payload,
			&payload);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		u32_t prev_avp_length = payload.get_header_length() + payload.get_data_length();
		if (*buffer_length < prev_avp_length)
		{
			// We do have only the current payload. So not padding is included.
			prev_avp_length = payload.get_header_length() + payload.get_data_length();
		}

		EAP_ASSERT_ALWAYS(*buffer_length >= prev_avp_length);
		*buffer_length -= prev_avp_length;

		u32_t remaining_data_length(0ul);

		remaining_data_length = payload.get_header_buffer_length() - prev_avp_length;

		payload.set_header_buffer(
			payload.get_header_offset(prev_avp_length, remaining_data_length),
			remaining_data_length);

		while(*buffer_length >= payload.get_header_length()
			&& payload.get_is_valid() == true
			&& payload.get_header_buffer_length() >= payload.get_header_buffer_length())
		{
			current_payload = payload.get_type();
			if (current_payload == ec_cs_tlv_type_none)
			{
				// This might be padding in the end of the message.
				break;
			}

			if (*buffer_length < payload.get_header_buffer_length())
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_ERROR,
					(EAPL("ERROR: ec_cs_tlv_payloads_c::parse_ec_cs_payloads(0x%08x): ")
					 EAPL("current payload 0x%08x=%s, payload data length 0x%04x, payload length 0x%04x, buffer length 0x%04x.\n"),
					 payload.get_header_buffer(0ul),
					 current_payload,
					 payload.get_tlv_string(),
					 payload.get_data_length(),
					 payload.get_data_length(),
					 *buffer_length));
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_ERROR,
					(EAPL("ERROR: ec_cs_tlv_payloads_c::parse_ec_cs_payloads(): ")
					 EAPL("EC-CS-payload header is corrupted.\n")));
				EAP_TRACE_DATA_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("payload"),
					payload.get_header_buffer(*buffer_length),
					*buffer_length));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}

			status = parse_generic_payload(
				current_payload,
				&payload);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			prev_avp_length = payload.get_header_length() + payload.get_data_length();
			if (*buffer_length < prev_avp_length)
			{
				// We do have only the current payload. So not padding is included.
				prev_avp_length = payload.get_header_length() + payload.get_data_length();
			}

			EAP_ASSERT_ALWAYS(*buffer_length >= prev_avp_length);
			*buffer_length -= prev_avp_length;

			remaining_data_length = payload.get_header_buffer_length() - prev_avp_length;

			payload.set_header_buffer(
				payload.get_header_offset(prev_avp_length, remaining_data_length),
				remaining_data_length);
		} // while()

		if (*buffer_length != 0u)
		{
			const u8_t * const possible_padding = payload.get_header_buffer(remaining_data_length);
					
			// First check is this padding
			if (possible_padding == 0
				|| remaining_data_length != *buffer_length
				|| verify_padding(possible_padding, remaining_data_length) != eap_status_ok)
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_ERROR,
					(EAPL("ERROR: ec_cs_tlv_payloads_c::parse_ec_cs_payloads(): ")
					 EAPL("EC-CS-header is corrupted. Buffer length and payload ")
					 EAPL("length does not match. %lu illegal bytes.\n"),
					 *buffer_length));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}
			else
			{
				// OK, we get correct padding.
				*padding_length = remaining_data_length;
			}
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

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_payloads_c::create_ec_cs_tlv_message(
	ec_cs_tlv_message_c * const new_ec_cs_tlv_message_data,
	const bool add_payloads) const
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC-CS:     message_function: ec_cs_tlv_payloads_c::create_ec_cs_tlv_message()\n")));

	eap_status_e status(eap_status_process_general_error);

	if (add_payloads == false)
	{
		status = new_ec_cs_tlv_message_data->reset();
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
		ec_cs_variable_data_c * tlv = get_tlv(tlv_index);
		if (tlv == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		status = new_ec_cs_tlv_message_data->get_ec_cs_message_data()->add_data(tlv->get_full_tlv_buffer());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EC_CS_TLV_TRACE_PAYLOAD("Added EC-CS-TLV payload", tlv->get_header(), m_is_client);

		++tlv_index;

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EC-CS:     message_function: ec_cs_tlv_payloads_c::create_ec_cs_tlv_message(): index %d\n"),
			tlv_index));

	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC-CS:     message_function: ec_cs_tlv_payloads_c::create_ec_cs_tlv_message() returns\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_payloads_c::reset()
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

EAP_FUNC_EXPORT ec_cs_tlv_payloads_c * ec_cs_tlv_payloads_c::copy() const
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC-CS:     message_function: ec_cs_tlv_payloads_c::copy()\n")));

	ec_cs_tlv_payloads_c * copy_payloads = new ec_cs_tlv_payloads_c(m_am_tools, m_is_client);

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
		ec_cs_variable_data_c * tlv = get_tlv(tlv_index);
		if (tlv == 0)
		{
			delete copy_payloads;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		status = copy_payloads->add_tlv(
			tlv->copy());

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
