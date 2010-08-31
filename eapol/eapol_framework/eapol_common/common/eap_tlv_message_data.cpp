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
* %version: 19.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 579 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_automatic_variable.h"
#include "eap_tlv_message_data.h"

/** @file */


//--------------------------------------------------

EAP_FUNC_EXPORT eap_tlv_message_data_c::~eap_tlv_message_data_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_tlv_message_data_c::eap_tlv_message_data_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_message_data(tools)
{
}

//-------------------------------------------------------------------

/**
 * This function should increase reference count.
 */
EAP_FUNC_EXPORT void eap_tlv_message_data_c::object_increase_reference_count()
{
}

//-------------------------------------------------------------------

/**
 * This function should first decrease reference count
 * and second return the remaining reference count.
 * Reference count must not be decreased when it is zero.
 */
EAP_FUNC_EXPORT u32_t eap_tlv_message_data_c::object_decrease_reference_count()
{
	return 0;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void * eap_tlv_message_data_c::get_message_data() const
{
	return m_message_data.get_data(m_message_data.get_data_length());
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_tlv_message_data_c::get_message_data_length() const
{
	return m_message_data.get_data_length();
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_tlv_message_data_c::allocate_message_data_buffer(
	const u32_t approximate_buffer_requirement)
{
	if (m_message_data.get_is_valid() == true)
	{
		return m_message_data.set_buffer_length(m_message_data.get_buffer_length()+approximate_buffer_requirement);
	}
	else
	{
		return m_message_data.set_buffer_length(approximate_buffer_requirement);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_tlv_message_data_c::copy_message_data(
	const u32_t length,
	const void * const value)
{
	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("copy_message_data()"),
		value,
		length));

	status = m_message_data.set_copy_of_buffer(
		value,
		length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_tlv_message_data_c::set_message_data(
	const u32_t length,
	const void * const value)
{
	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_NEVER,
		(EAPL("set_message_data()"),
		value,
		length));

	status = m_message_data.set_buffer(
		value,
		length,
		false,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_tlv_message_data_c::add_message_data(
	const eap_tlv_type_t type,
	const u32_t length,
	const void * const value)
{
	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_tlv_message_data_c::add_message_data():   type %2d=0x%08x, length %3d=0x%08x\n"),
		 type,
		 type,
		 length,
		 length));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("add_message_data()"),
		value,
		length));

	u32_t tlv_header_offset(0ul);

	if (m_message_data.get_is_valid() == true)
	{
		tlv_header_offset = m_message_data.get_data_length();
	}
	else
	{
		tlv_header_offset = 0ul;
	}

	// This will allocate space for eap_tlv_header_c too.
	status = m_message_data.add_data_to_offset(
		tlv_header_offset+eap_tlv_header_c::get_header_length(),
		value,
		length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Add eap_tlv_header_c to message.
	eap_tlv_header_c header(
		m_am_tools,
		m_message_data.get_data_offset(tlv_header_offset, eap_tlv_header_c::get_header_length()+length),
		eap_tlv_header_c::get_header_length()+length);

	if (header.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = header.reset_header(type, length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_tlv_message_data_c::add_message_data_array(
	const eap_tlv_type_t type,
	const u32_t length_of_each_data_block,
	eap_array_c<eap_variable_data_c> * const data_array)
{
	eap_status_e status(eap_status_process_general_error);

	u32_t tlv_header_offset(0ul);

	if (m_message_data.get_is_valid() == true)
	{
		tlv_header_offset = m_message_data.get_data_length();
	}
	else
	{
		tlv_header_offset = 0ul;
	}

	if (data_array->get_object_count() != 0ul)
	{
		for (u32_t ind = 0ul; ind < data_array->get_object_count(); ind++)
		{
			eap_variable_data_c * const data = data_array->get_object(ind);
			if (data == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			if (data->get_data_length() != length_of_each_data_block)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			// This will allocate space for eap_tlv_header_c too.
			status = m_message_data.add_data_to_offset(
				tlv_header_offset+eap_tlv_header_c::get_header_length()+(ind*length_of_each_data_block),
				data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		} // for()
	}
	else
	{
		// This will allocate space for eap_tlv_header_c only.
		status = m_message_data.add_data_to_offset(
			tlv_header_offset+eap_tlv_header_c::get_header_length(),
			0,
			0ul);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	u32_t length = data_array->get_object_count() * length_of_each_data_block;

	// Add eap_tlv_header_c to message.
	eap_tlv_header_c header(
		m_am_tools,
		m_message_data.get_data_offset(tlv_header_offset, eap_tlv_header_c::get_header_length()+length),
		eap_tlv_header_c::get_header_length()+length);

	if (header.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = header.reset_header(type, length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_tlv_message_data_c::parse_message_data(
	eap_array_c<eap_tlv_header_c> * const tlv_blocks)
{
	eap_status_e status(eap_status_ok);

	tlv_blocks->reset();

	u8_t *next_header_begins = m_message_data.get_data();
	u32_t remaining_message_data_length = m_message_data.get_data_length();

	if (next_header_begins == 0
		|| remaining_message_data_length == 0)
	{
		// TLV is empty.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	// This is reference to the first eap_tlv_header_c in the message_data.
	eap_tlv_header_c header(
		m_am_tools,
		next_header_begins,
		remaining_message_data_length);

	while (header.get_is_valid() == true)
	{
		const u32_t payload_length(header.get_header_length()+header.get_value_length());

		status = header.check_header();
		if (status != eap_status_ok)
		{
			EAP_TRACE_DATA_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("ERROR: illegal payload"),
				header.get_header_buffer(header.get_header_buffer_length()),
				header.get_header_buffer_length()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("payload"),
				header.get_header_buffer(payload_length),
				payload_length));
		}


		if (remaining_message_data_length < payload_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		{
			eap_tlv_header_c * const tlv = new eap_tlv_header_c(
				m_am_tools,
				header.get_header_buffer(payload_length),
				payload_length);

			eap_automatic_variable_c<eap_tlv_header_c> automatic_tlv(m_am_tools, tlv);

			if (tlv == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
			
			if (tlv->get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			automatic_tlv.do_not_free_variable();

			status = tlv_blocks->add_object(tlv, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}


			u32_t tlv_length = tlv->get_header_length()+tlv->get_value_length();
			next_header_begins += tlv_length;
			remaining_message_data_length -= tlv_length;

			if (next_header_begins >= (m_message_data.get_data()+m_message_data.get_data_length())
				|| remaining_message_data_length == 0)
			{
				// No next header.
				break;
			}
		}

		header.set_header_buffer(
			next_header_begins,
			remaining_message_data_length);
		if (header.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	} // while()

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_tlv_message_data_c::add_message_header(
	const eap_tlv_type_t type,
	const u32_t length)
{
	// This will allocate space for eap_tlv_header_c without any value.

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_tlv_message_data_c::add_message_header(): type %2d=0x%08x, length %3d=0x%08x\n"),
		 type,
		 type,
		 length,
		 length));

	u32_t network_order_type(eap_htonl(type));

	eap_status_e status = m_message_data.add_data(
		&network_order_type,
		sizeof(network_order_type));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t network_order_length(eap_htonl(length));

	status = m_message_data.add_data(
		&network_order_length,
		sizeof(network_order_length));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_tlv_message_data_c::allocate_message_buffer(
	const eap_tlv_type_t type,
	const u32_t length,
	void * * const buffer)
{
	eap_status_e status(eap_status_process_general_error);

	*buffer = 0;

	u32_t tlv_header_offset(0ul);

	if (m_message_data.get_is_valid() == true)
	{
		tlv_header_offset = m_message_data.get_data_length();
	}
	else
	{
		tlv_header_offset = 0ul;
	}

	// This will allocate space for eap_tlv_header_c only.
	status = m_message_data.add_data_to_offset(
		tlv_header_offset+eap_tlv_header_c::get_header_length()+length,
		0,
		0ul);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Add eap_tlv_header_c to message.
	eap_tlv_header_c header(
		m_am_tools,
		m_message_data.get_data_offset(tlv_header_offset, eap_tlv_header_c::get_header_length()+length),
		eap_tlv_header_c::get_header_length()+length);

	if (header.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = header.reset_header(type, length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	*buffer = header.get_value(length);

	if ((*buffer) == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_tlv_message_data_c::get_is_valid()
{
	return m_message_data.get_is_valid();
}

//--------------------------------------------------



// End.
