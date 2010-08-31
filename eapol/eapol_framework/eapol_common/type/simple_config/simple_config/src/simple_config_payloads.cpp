/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  Defines payloads of protected setup message.
*
*/

/*
* %version: 33.1.3 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 589 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "simple_config_payloads.h"
#include "simple_config_tlv_header.h"
#include "simple_config_message.h"
#include "abs_eap_am_tools.h"
#include "eap_tools.h"
#include "eap_array_algorithms.h"
#include "eap_automatic_variable.h"
#include "eap_crypto_api.h"


//--------------------------------------------------

EAP_FUNC_EXPORT simple_config_variable_data_c::~simple_config_variable_data_c()
{
	delete m_next_payload_with_same_attribute_type;
	m_next_payload_with_same_attribute_type = 0;
}

//--------------------------------------------------

EAP_FUNC_EXPORT simple_config_variable_data_c::simple_config_variable_data_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	  , m_data(tools)
	  , m_header(tools, 0, 0ul)
	  , m_next_payload_with_same_attribute_type(0)
	  , m_is_mandatory(false)
	  , m_is_valid(false)
{
	if (m_data.get_is_valid() == false)
	{
		return;
	}

	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool simple_config_variable_data_c::get_is_valid() const
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_variable_data_c::set_copy_of_buffer(
	const simple_config_Attribute_Type_e current_payload,
	const bool is_mandatory,
	const void * const buffer,
	const u32_t buffer_length)
{
	eap_status_e status = m_data.set_buffer_length(
		simple_config_tlv_header_c::get_header_length() + buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_data.set_data_length(
		simple_config_tlv_header_c::get_header_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_header.set_header_buffer(
		m_data.get_buffer(m_data.get_buffer_length()),
		m_data.get_buffer_length());

	m_header.set_tlv_type(current_payload);

	if (buffer_length > 0xffff)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	m_header.set_data_length(static_cast<u16_t>(buffer_length));

	status = m_data.add_data(buffer, buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_is_mandatory = is_mandatory;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_variable_data_c::add_data(
	const void * const buffer,
	const u32_t buffer_length)
{
	const simple_config_Attribute_Type_e current_payload = m_header.get_tlv_type();

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

	m_header.set_tlv_type(current_payload);

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

EAP_FUNC_EXPORT u32_t simple_config_variable_data_c::get_data_length() const
{
	return m_header.get_data_length();
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * simple_config_variable_data_c::get_data(
	const u32_t data_length) const
{
	return m_header.get_data(data_length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * simple_config_variable_data_c::get_full_attribute_buffer()
{
	return &m_data;
}

//--------------------------------------------------

EAP_FUNC_EXPORT simple_config_tlv_header_c * simple_config_variable_data_c::get_header()
{
	return &m_header;
}

//--------------------------------------------------

EAP_FUNC_EXPORT simple_config_Attribute_Type_e simple_config_variable_data_c::get_attribute_type() const
{
	return m_header.get_tlv_type();
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool simple_config_variable_data_c::get_is_mandatory() const
{
	return m_is_mandatory;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void simple_config_variable_data_c::set_attribute_type(
	const simple_config_Attribute_Type_e type)
{
	m_header.set_tlv_type(type);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void simple_config_variable_data_c::set_next_payload_with_same_attribute_type(
	simple_config_variable_data_c * const attribute)
{
	m_next_payload_with_same_attribute_type = attribute;
}

//--------------------------------------------------

EAP_FUNC_EXPORT simple_config_variable_data_c * simple_config_variable_data_c::get_next_payload_with_same_attribute_type()
{
	return m_next_payload_with_same_attribute_type;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void simple_config_variable_data_c::add_next_payload_with_same_attribute_type(
	simple_config_variable_data_c * const attribute)
{
	simple_config_variable_data_c *payload = get_next_payload_with_same_attribute_type();
	simple_config_variable_data_c *prev_payload = this;

	while (payload != 0)
	{
		prev_payload = payload;
		payload = payload->get_next_payload_with_same_attribute_type();
	}

	if (prev_payload != 0)
	{
		prev_payload->set_next_payload_with_same_attribute_type(attribute);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT simple_config_variable_data_c * simple_config_variable_data_c::copy() const
{
	simple_config_variable_data_c * new_data = new simple_config_variable_data_c(m_am_tools);

	if (new_data != 0)
	{
		eap_status_e status = new_data->set_copy_of_buffer(
			get_attribute_type(),
			get_is_mandatory(),
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

EAP_FUNC_EXPORT  void simple_config_variable_data_c::object_increase_reference_count()
{
}


//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------


EAP_FUNC_EXPORT simple_config_payloads_c::~simple_config_payloads_c()
{
}

//--------------------------------------------------

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4355 ) // 'this' : used in base member initializer list
#endif

EAP_FUNC_EXPORT simple_config_payloads_c::simple_config_payloads_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	  , m_payload_map(tools, this)
	  , m_read_payloads(tools)
	  , m_payload_index(0ul)
	  , m_is_valid(false)
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT simple_config_variable_data_c * simple_config_payloads_c::get_attribute_pointer(
	const simple_config_Attribute_Type_e current_payload,
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

	simple_config_variable_data_c *payload = m_payload_map.get_handler(&selector);

	while (index != 0ul && payload != 0)
	{
		--index;
		payload = payload->get_next_payload_with_same_attribute_type();
	}

	return payload;
}

//--------------------------------------------------

EAP_FUNC_EXPORT simple_config_variable_data_c * simple_config_payloads_c::get_attribute_pointer(
	const simple_config_Attribute_Type_e current_payload) const
{
	return get_attribute_pointer(current_payload, 0ul);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t simple_config_payloads_c::get_attribute_count() const
{
	return m_read_payloads.get_object_count();
}

//--------------------------------------------------

EAP_FUNC_EXPORT simple_config_variable_data_c * simple_config_payloads_c::get_attribute(
	const u32_t attribute_index) const
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::get_attribute(index %d, max %d)\n"),
		attribute_index,
		m_read_payloads.get_object_count()));

	simple_config_variable_data_c *payload = m_read_payloads.get_object(attribute_index);

	return payload;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_payloads_c::check_payloads_existense(
	const simple_config_Attribute_Type_e * const needed_payloads,
	const u32_t count_of_needed_payloads) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::check_payloads_existense()\n")));

	for (u32_t ind = 0ul; ind < count_of_needed_payloads; ind++)
	{
		const simple_config_Attribute_Type_e required_avp_code = needed_payloads[ind];
		if (required_avp_code == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (get_attribute_pointer(required_avp_code) == 0)
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

EAP_FUNC_EXPORT eap_status_e simple_config_payloads_c::check_payloads_existense(
	EAP_TEMPLATE_CONST eap_array_c<simple_config_Attribute_Type_e> * const needed_payloads) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::check_payloads_existense()\n")));

	for (u32_t ind = 0ul; ind < needed_payloads->get_object_count(); ind++)
	{
		const simple_config_Attribute_Type_e * const required_avp_code = needed_payloads->get_object(ind);
		if (required_avp_code == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (get_attribute_pointer(*required_avp_code) == 0)
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

EAP_FUNC_EXPORT eap_status_e simple_config_payloads_c::check_mandatory_payloads(
	EAP_TEMPLATE_CONST eap_array_c<simple_config_Attribute_Type_e> * const used_payloads) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::check_mandatory_payloads()\n")));

	for (u32_t ind = 0ul; ind < m_read_payloads.get_object_count(); ind++)
	{
		const simple_config_variable_data_c * const read_payload = m_read_payloads.get_object(ind);
		if (read_payload == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (read_payload->get_is_mandatory() == true)
		{
			simple_config_Attribute_Type_e attribute_type = read_payload->get_attribute_type();

			i32_t index = find_simple<simple_config_Attribute_Type_e>(
				used_payloads,
				&attribute_type,
				m_am_tools);
			if (index < 0)
			{
				// ERROR: not used mandatory TLV.
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_ERROR, 
					(EAPL("ERROR: not used mandatory TLV 0x%08x.\n"),
					 attribute_type));

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_unsupported_payload);
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_payloads_c::copy_attribute(
	const simple_config_payloads_c * const source,
	const simple_config_Attribute_Type_e attribute)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::copy_attribute(TLV 0x%08x)\n"),
		attribute));

	const simple_config_variable_data_c * const payload
		= source->get_attribute_pointer(attribute, 0ul);
	if (payload == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
	}

	eap_status_e status = add_attribute(
		payload->copy());

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_payloads_c::add_attribute(
	simple_config_variable_data_c * const new_payload)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::add_attribute()\n")));

	if (new_payload == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status(eap_status_process_general_error);

	eap_automatic_variable_c<simple_config_variable_data_c>
		automatic_new_payload(m_am_tools, new_payload);

	const simple_config_Attribute_Type_e new_payload_type(new_payload->get_attribute_type());
		
	simple_config_variable_data_c *old_payload = get_attribute_pointer(
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
			// Instead we add apointer to the next payload with the same attribute type.
			old_payload->add_next_payload_with_same_attribute_type(new_payload);
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

EAP_FUNC_EXPORT eap_status_e simple_config_payloads_c::copy_attribute_data(
	const simple_config_Attribute_Type_e current_payload,
	const bool is_mandatory,
	const void * const data,
	const u32_t data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::copy_attribute_data(TLV 0x%08x)\n"),
		current_payload));

	eap_status_e status(eap_status_process_general_error);

	simple_config_variable_data_c *new_payload = new simple_config_variable_data_c(
		m_am_tools);
	if (new_payload == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_automatic_variable_c<simple_config_variable_data_c>
		automatic_new_payload(m_am_tools, new_payload);

	status = new_payload->set_copy_of_buffer(
		current_payload,
		is_mandatory,
		data,
		data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	automatic_new_payload.do_not_free_variable();

	status = add_attribute(new_payload);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_payloads_c::get_attribute_data(
	const simple_config_Attribute_Type_e copied_attribute_type,
	eap_variable_data_c * const data) const
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::get_attribute_data(eap_variable_data_c *)\n")));

	if (data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	simple_config_variable_data_c * const found_attribute = get_attribute_pointer(
		copied_attribute_type);
	if (found_attribute == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
	}

	u32_t attribute_data_length = found_attribute->get_header()->get_data_length();

	if (attribute_data_length > 0ul)
	{
		const u8_t * const attribute_data = found_attribute->get_header()->get_data(attribute_data_length);
		if (attribute_data == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
		}
		
		eap_status_e status = data->set_copy_of_buffer(attribute_data, attribute_data_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		data->reset();
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_payloads_c::get_attribute_data(
	const simple_config_Attribute_Type_e copied_attribute_type,
	void * const data,
	const u32_t data_length) const
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::get_attribute_data(void *)\n")));

	if (data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	simple_config_variable_data_c * const found_attribute = get_attribute_pointer(
		copied_attribute_type);
	if (found_attribute == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
	}

	u32_t attribute_data_length = found_attribute->get_header()->get_data_length();

	if (attribute_data_length == data_length)
	{
		const u8_t * const attribute_data = found_attribute->get_header()->get_data(attribute_data_length);
		if (attribute_data == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
		}
		
		m_am_tools->memmove(data, attribute_data, attribute_data_length);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		m_am_tools->memset(data, 0, data_length);

		if (attribute_data_length < data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_long_message);
		}
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_payloads_c::get_attribute_data(
	const simple_config_Attribute_Type_e copied_attribute_type,
	u8_t * const data) const
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::get_attribute_data(u8_t *)\n")));

	return get_attribute_data(
		copied_attribute_type,
		data,
		sizeof(u8_t));
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_payloads_c::get_attribute_data(
	const simple_config_Attribute_Type_e copied_attribute_type,
	u16_t * const data) const
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::get_attribute_data(u16_t *)\n")));

	if (data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u16_t data_in_network_order(0ul);

	eap_status_e status = get_attribute_data(
		copied_attribute_type,
		&data_in_network_order,
		sizeof(data_in_network_order));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	*data = eap_ntohs(data_in_network_order);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_payloads_c::get_attribute_data(
	const simple_config_Attribute_Type_e copied_attribute_type,
	u32_t * const data) const
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::get_attribute_data(u32_t *)\n")));

	if (data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u32_t data_in_network_order(0ul);

	eap_status_e status = get_attribute_data(
		copied_attribute_type,
		&data_in_network_order,
		sizeof(data_in_network_order));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	*data = eap_ntohl(data_in_network_order);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_payloads_c::get_attribute_data(
	const simple_config_Attribute_Type_e copied_attribute_type,
	u64_t * const data) const
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::get_attribute_data(u64_t *)\n")));

	if (data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u64_t data_in_network_order(0ul);

	eap_status_e status = get_attribute_data(
		copied_attribute_type,
		&data_in_network_order,
		sizeof(data_in_network_order));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	*data = eap_ntohll(data_in_network_order);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool simple_config_payloads_c::get_is_valid() const
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_payloads_c::parse_generic_payload(
	const simple_config_Attribute_Type_e attribute_type,
	const simple_config_tlv_header_c * const header)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	SIMPLE_CONFIG_TLV_TRACE_PAYLOAD("Parsing attribute", header);

	eap_status_e status(eap_status_process_general_error);

	/*
	 *  TLV-header:
	 *  0                   1                   2                   3   
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |       Attribute Type          |         Data Length           |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |         Data ... 
	 * +-+-+-+-+-+-+-+-+-+-
	 */
	if (header->get_header_buffer_length() < header->get_header_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("ERROR: simple_config_payloads_c::parse_generic_payload(0x%08x): ")
			 EAPL("current header 0x%08x=%s, required length 0x%08x, packet length too less 0x%08x.\n"),
			 header,
			 attribute_type,
			 header->get_tlv_type_string(),
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
			(EAPL("ERROR: simple_config_payloads_c::parse_generic_payload(0x%08x): ")
			 EAPL("current header 0x%08x=%s, length 0x%04x, data buffer incorrect.\n"),
			 header,
			 attribute_type,
			 header->get_tlv_type_string(),
			 header->get_data_length()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	status = copy_attribute_data(
		attribute_type,
		true,
		data,
		data_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e simple_config_payloads_c::verify_padding(
	const u8_t * const possible_padding,
	const u32_t possible_padding_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::verify_padding()\n")));

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
EAP_FUNC_EXPORT eap_status_e simple_config_payloads_c::parse_simple_config_payloads(
	void * const message_buffer,
	u32_t * const buffer_length,
	u32_t * const padding_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::parse_simple_config_payloads()\n")));

	*padding_length = 0ul;

	simple_config_tlv_header_c payload(
		m_am_tools,
		message_buffer,
		*buffer_length); // Const correctness is gone.

	simple_config_Attribute_Type_e current_payload = payload.get_tlv_type();

	eap_status_e status = eap_status_header_corrupted;

	if (payload.get_is_valid() == true
		&& current_payload != simple_config_Attribute_Type_None)
	{
		if (*buffer_length < payload.get_length())
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("ERROR: simple_config_payloads_c::parse_simple_config_payloads(0x%08x): ")
				 EAPL("current payload 0x%08x=%s, data length 0x%04x, buffer length 0x%04x.\n"),
				 payload.get_header_buffer(0ul),
				 current_payload,
				 payload.get_tlv_type_string(),
				 payload.get_data_length(),
				 *buffer_length));
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("ERROR: simple_config_payloads_c::parse_simple_config_payloads(): ")
				 EAPL("SIMPLE_CONFIG-payload header is corrupted.\n")));
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

		u32_t prev_avp_length = payload.get_length();
		if (*buffer_length < prev_avp_length)
		{
			// We do have only the current payload. So not padding is included.
			prev_avp_length = payload.get_length();
		}

		EAP_ASSERT_ALWAYS(*buffer_length >= prev_avp_length);
		*buffer_length -= prev_avp_length;

		u32_t remaining_data_length(0ul);

		remaining_data_length = payload.get_header_buffer_length() - prev_avp_length;

		payload.set_header_buffer(
			payload.get_header_offset(prev_avp_length, remaining_data_length),
			remaining_data_length);
		if (payload.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		while(*buffer_length >= payload.get_header_length()
			&& payload.get_is_valid() == true
			&& payload.get_header_buffer_length() >= payload.get_length())
		{
			current_payload = payload.get_tlv_type();
			if (current_payload == simple_config_Attribute_Type_None)
			{
				// This might be padding in the end of the message.
				break;
			}

			if (*buffer_length < payload.get_length())
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_ERROR,
					(EAPL("ERROR: simple_config_payloads_c::parse_simple_config_payloads(0x%08x): ")
					 EAPL("current payload 0x%08x=%s, payload data length 0x%04x, payload length 0x%04x, buffer length 0x%04x.\n"),
					 payload.get_header_buffer(0ul),
					 current_payload,
					 payload.get_tlv_type_string(),
					 payload.get_data_length(),
					 payload.get_length(),
					 *buffer_length));
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_ERROR,
					(EAPL("ERROR: simple_config_payloads_c::parse_simple_config_payloads(): ")
					 EAPL("SIMPLE_CONFIG-payload header is corrupted.\n")));
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

			prev_avp_length = payload.get_length();
			if (*buffer_length < prev_avp_length)
			{
				// We do have only the current payload. So not padding is included.
				prev_avp_length = payload.get_length();
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
					(EAPL("ERROR: simple_config_payloads_c::parse_simple_config_payloads(): ")
					 EAPL("SIMPLE_CONFIG-header is corrupted. Buffer length and payload ")
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

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_payloads_c::create_simple_config_message(
	simple_config_message_c * const new_simple_config_message_data,
	const bool add_payloads) const
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::create_simple_config_message()\n")));

	eap_status_e status(eap_status_process_general_error);

	if (add_payloads == false)
	{
		status = new_simple_config_message_data->reset();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	const u32_t attribute_count(get_attribute_count());
	u32_t attribute_index(0ul);

	while (attribute_index < attribute_count)
	{
		simple_config_variable_data_c * attribute = get_attribute(attribute_index);
		if (attribute == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		status = new_simple_config_message_data->get_simple_config_message_data()->add_data(attribute->get_full_attribute_buffer());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		SIMPLE_CONFIG_TLV_TRACE_PAYLOAD("Added attribute", attribute->get_header());

		++attribute_index;

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::create_simple_config_message(): index %d\n"),
			attribute_index));

	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::create_simple_config_message() returns\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_payloads_c::add_payloads_to_simple_config_authenticator(
	crypto_hmac_c * const hmac_sha_256,
	const bool include_authenticator_attribute) const
{
	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::add_payloads_to_simple_config_authenticator()\n")));

	const u32_t attribute_count(get_attribute_count());
	u32_t attribute_index(0ul);

	while (attribute_index < attribute_count)
	{
		simple_config_variable_data_c * attribute = get_attribute(attribute_index);
		if (attribute == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (include_authenticator_attribute == false
			&& attribute->get_header()->get_tlv_type() == simple_config_Attribute_Type_Authenticator)
		{
			break;
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			EAP_TRACE_FLAGS_MESSAGE_DATA, 
			(EAPL("SIMPLE_CONFIG authenticator data"),
			 attribute->get_full_attribute_buffer()->get_data(),
			 attribute->get_full_attribute_buffer()->get_data_length()));

		status = hmac_sha_256->hmac_update(
			attribute->get_full_attribute_buffer()->get_data(),
			attribute->get_full_attribute_buffer()->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		++attribute_index;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_payloads_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_payload_map.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_read_payloads.reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT simple_config_payloads_c * simple_config_payloads_c::copy() const
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG:     message_function: simple_config_payloads_c::copy()\n")));

	simple_config_payloads_c * copy_payloads = new simple_config_payloads_c(m_am_tools);

	if (copy_payloads == 0
		|| copy_payloads->get_is_valid() == false)
	{
		delete copy_payloads;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return 0;
	}

	eap_status_e status(eap_status_process_general_error);

	const u32_t attribute_count(get_attribute_count());
	u32_t attribute_index(0ul);

	while (attribute_index < attribute_count)
	{
		simple_config_variable_data_c * attribute = get_attribute(attribute_index);
		if (attribute == 0)
		{
			delete copy_payloads;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		status = copy_payloads->add_attribute(
			attribute->copy());

		if (status != eap_status_ok)
		{
			delete copy_payloads;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		++attribute_index;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return copy_payloads;
}

//--------------------------------------------------
// End.
