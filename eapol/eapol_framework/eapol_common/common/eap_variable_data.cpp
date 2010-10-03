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
	#define EAP_FILE_NUMBER_ENUM 42 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_variable_data.h"
#include "abs_eap_am_tools.h"
#include "eap_am_tools.h"

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_variable_data_c::initialize_members()
{
	m_data = new eap_variable_data_impl_str;
	if (m_data == 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_variable_data_c::initialize_members(): Cannot allocate %d bytes.\n"),
			sizeof(eap_variable_data_impl_str)));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	m_data->m_buffer = 0;
	m_data->m_buffer_length = 0ul;
	m_data->m_real_data_start_index = 0ul;
	m_data->m_real_data_length = 0ul;
	m_data->m_free_buffer = false;
	m_data->m_is_writable = false;

	m_data->m_is_valid = true;

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c::~eap_variable_data_c()
{
	if (m_data != 0)
	{
		if (m_data->m_free_buffer == true)
		{
			// Buffer was allocated.

#if !defined(NO_EAP_VARIABLE_DATA_MEMORY_ZERO)
			if (m_am_tools != 0)
			{
				m_am_tools->memset(m_data->m_buffer, 0, m_data->m_buffer_length);
			}
#endif //#if !defined(NO_EAP_VARIABLE_DATA_MEMORY_ZERO)

			delete [] m_data->m_buffer;
			m_data->m_buffer = 0;
		}
		m_data->m_buffer = 0;
		m_data->m_buffer_length = 0ul;
		m_data->m_real_data_start_index = 0ul;
		m_data->m_real_data_length = 0ul;
		m_data->m_free_buffer = false;

		m_data->m_is_valid = false;

		delete m_data;
		m_data = 0;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c::eap_variable_data_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_data(0)
{
	eap_status_e status = initialize_members();
	if (status != eap_status_ok)
	{
		// ERROR.
		return;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c::eap_variable_data_c(
	abs_eap_am_tools_c * const tools,
	const void * const buffer,
	const u32_t buffer_length,
	bool free_buffer,
	bool is_writable)
	: m_am_tools(tools)
	, m_data(0)
{
	eap_status_e status = initialize_members();
	if (status != eap_status_ok)
	{
		// ERROR.
		return;
	}

	status = set_buffer(
		buffer,
		buffer_length,
		free_buffer,
		is_writable);
	if (status != eap_status_ok)
	{
		// ERROR.
		set_is_invalid();
		return;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_variable_data_c::get_is_valid() const
{
	if (m_data == 0)
	{
		return false;
	}

	return m_data->m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_variable_data_c::get_is_valid_data() const
{
	if (m_data == 0)
	{
		return false;
	}

	if (m_data->m_is_valid == false)
	{
		return false;
	}

	// Note the data length could be zero.
	if (m_data->m_buffer == 0)
	{
		return false;
	}

	return true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_variable_data_c::set_is_valid()
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0)
	{
		return;
	}

	m_data->m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_variable_data_c::set_is_invalid()
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0)
	{
		return;
	}

	m_data->m_is_valid = false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_variable_data_c::get_is_writable() const
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0)
	{
		return false;
	}

	return m_data->m_is_writable;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * eap_variable_data_c::get_buffer_offset(
	const u32_t offset,
	const u32_t buffer_length) const
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data != 0
		&& m_data->m_is_valid == true
		&& m_data->m_buffer_length >= (m_data->m_real_data_start_index+offset+buffer_length))
	{
		return m_data->m_buffer + (m_data->m_real_data_start_index + offset);
	}
	else
	{
		EAP_ASSERT_TOOLS(
			m_am_tools,
			m_data != 0
			&& m_data->m_is_valid == true
			&& m_data->m_buffer_length
			>= (m_data->m_real_data_start_index+offset+buffer_length));
		return 0;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * eap_variable_data_c::get_buffer(const u32_t buffer_length) const
{
	return get_buffer_offset(0u, buffer_length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * eap_variable_data_c::get_data_offset(
	const u32_t offset,
	const u32_t data_length) const
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data != 0
		&& m_data->m_is_valid == true
		&& m_data->m_real_data_length >= (offset+data_length))
	{
		return get_buffer_offset(offset, data_length);
	}
	else
	{
		EAP_ASSERT_TOOLS(
			m_am_tools,
			m_data != 0
			&& m_data->m_is_valid == true
			&& m_data->m_real_data_length >= (offset+data_length));
		return 0;
	}
}

//--------------------------------------------------

#if !defined(USE_EAP_INLINE_FUNCTIONS)

EAP_FUNC_EXPORT u8_t * eap_variable_data_c::get_data() const
{
	return get_data(get_data_length());
}

#endif //#if !defined(USE_EAP_INLINE_FUNCTIONS)


//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * eap_variable_data_c::get_data(const u32_t data_length) const
{
	return get_data_offset(0u, data_length);
}

//--------------------------------------------------

#if !defined(USE_EAP_INLINE_FUNCTIONS)

EAP_FUNC_EXPORT u32_t eap_variable_data_c::get_data_length() const
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data != 0
		&& m_data->m_is_valid == true)
	{
		return m_data->m_real_data_length;
	}
	else
	{
		return 0u;
	}
}

#endif //#if !defined(USE_EAP_INLINE_FUNCTIONS)

//--------------------------------------------------

#if !defined(USE_EAP_INLINE_FUNCTIONS)

EAP_FUNC_EXPORT u32_t eap_variable_data_c::get_buffer_length() const
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data != 0
		&& m_data->m_is_valid == true)
	{
		return m_data->m_buffer_length;
	}
	else
	{
		return 0u;
	}
}

#endif //#if !defined(USE_EAP_INLINE_FUNCTIONS)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_variable_data_c::reset_start_offset_and_data_length()
{
	if (m_data != 0
		&& m_data->m_is_valid == true)
	{
		m_data->m_real_data_start_index = 0ul;
		m_data->m_real_data_length = 0ul;

		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		EAP_ASSERT_TOOLS(
			m_am_tools,
			m_data != 0
			&& m_data->m_is_valid == true);
		
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_variable_data_c::set_start_offset(const u32_t index)
{
	if (m_data != 0
		&& m_data->m_is_valid == true
		&& m_data->m_real_data_length >= index)
	{
		m_data->m_real_data_start_index += index;
		m_data->m_real_data_length -= index;

		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		EAP_ASSERT_TOOLS(
			m_am_tools,
			m_data != 0
			&& m_data->m_is_valid == true
			&& m_data->m_real_data_length >= index);
		
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_variable_data_c::set_data_length(
	const u32_t length)
{
	if (m_data != 0
		&& m_data->m_is_valid == true
		&& m_data->m_buffer_length >= (m_data->m_real_data_start_index + length))
	{
		m_data->m_real_data_length = length;

		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		EAP_ASSERT_TOOLS(
			m_am_tools,
			m_data != 0
			&& m_data->m_is_valid == true
			&& m_data->m_buffer_length >= (m_data->m_real_data_start_index + length));

		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_variable_data_c::reset()
{
	if (m_data == 0)
	{
		eap_status_e status = initialize_members();
		if (status != eap_status_ok)
		{
			// ERROR.
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}
	else
	{
		if (m_data->m_free_buffer == true)
		{

#if !defined(NO_EAP_VARIABLE_DATA_MEMORY_ZERO)
			m_am_tools->memset(m_data->m_buffer, 0, m_data->m_buffer_length);
#endif //#if !defined(NO_EAP_VARIABLE_DATA_MEMORY_ZERO)

			delete [] m_data->m_buffer;
			m_data->m_buffer = 0;
			m_data->m_free_buffer = false;
		}
		m_data->m_buffer = 0;
		m_data->m_buffer_length = 0u;
		m_data->m_real_data_start_index = 0ul;
		m_data->m_real_data_length = 0u;
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_variable_data_c::set_buffer(
	const void * const p_buffer,
	const u32_t buffer_length,
	bool free_buffer,
	bool is_writable)
{
	return set_buffer(
		const_cast<void *>(p_buffer),
		buffer_length,
		free_buffer,
		is_writable);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_variable_data_c::set_buffer(
	void * const p_buffer,
	const u32_t buffer_length,
	bool free_buffer,
	bool is_writable)
{
	if (m_data == 0)
	{
		eap_status_e status = initialize_members();
		if (status != eap_status_ok)
		{
			// ERROR.
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}

	if (p_buffer == 0
		&& buffer_length != 0UL)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	reset();

	m_data->m_free_buffer = free_buffer;
	m_data->m_is_writable = is_writable;
	m_data->m_buffer = static_cast<u8_t *>(p_buffer);
	m_data->m_buffer_length = buffer_length;
	m_data->m_real_data_start_index = 0ul;
	m_data->m_real_data_length = buffer_length;

	// This cannot fail.
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_variable_data_c::set_buffer(
	const eap_variable_data_c * const buffer)
{
	if (m_data == 0)
	{
		eap_status_e status = initialize_members();
		if (status != eap_status_ok)
		{
			// ERROR.
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}

	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (buffer == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (buffer == this)
	{
		// Here we are setting buffer from from itself.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	return EAP_STATUS_RETURN(m_am_tools, set_buffer(
		buffer->get_data(),
		buffer->get_data_length(),
		false,
		true));
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_variable_data_c::set_copy_of_buffer(
	const void * const buffer,
	const u32_t buffer_length)
{
	if (m_data == 0)
	{
		eap_status_e status = initialize_members();
		if (status != eap_status_ok)
		{
			// ERROR.
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}

	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (buffer == m_data->m_buffer)
	{
		// Here we are copying from itself.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	if (buffer == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = init(buffer_length);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	set_is_valid();

	if (buffer_length > 0u)
	{
		m_am_tools->memmove(m_data->m_buffer, buffer, buffer_length);
	}

	set_data_length(buffer_length);

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_variable_data_c::set_copy_of_buffer(
	const eap_variable_data_c * const buffer)
{
	if (m_data == 0)
	{
		eap_status_e status = initialize_members();
		if (status != eap_status_ok)
		{
			// ERROR.
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}

	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (buffer == 0
		|| buffer->get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (buffer == this)
	{
		// Here we are copying from itself.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	return EAP_STATUS_RETURN(m_am_tools, set_copy_of_buffer(
		buffer->get_data(),
		buffer->get_data_length()));
}


//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_variable_data_c::allocate_buffer(
	const u32_t required_buffer_length)
{
	u8_t *tmp_buffer = new u8_t[required_buffer_length];
	if (tmp_buffer == 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_variable_data_c::allocate_buffer(): Cannot allocate %d bytes.\n"),
			required_buffer_length));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// This is for testing. It is better leave buffer uninitialized.
	// Memory checking programs could track use of uninitialized data.
	
	if (m_data->m_real_data_length > 0u)
	{
		// Note the data is copied from start index of original buffer
		// to the begin of the new buffer.
		m_am_tools->memmove(
			tmp_buffer,
			m_data->m_buffer + m_data->m_real_data_start_index,
			m_data->m_real_data_length);
	}
	
	if (m_data->m_free_buffer == true)
	{

#if !defined(NO_EAP_VARIABLE_DATA_MEMORY_ZERO)
		m_am_tools->memset(m_data->m_buffer, 0, m_data->m_buffer_length);
#endif //#if !defined(NO_EAP_VARIABLE_DATA_MEMORY_ZERO)

		delete [] m_data->m_buffer;
		m_data->m_buffer = 0;
	}
	
	m_data->m_buffer = tmp_buffer;
	m_data->m_buffer_length = required_buffer_length;
	m_data->m_real_data_start_index = 0ul; // Data is now in the begin of the new buffer.
	m_data->m_free_buffer = true;
	m_data->m_is_writable = true;
	set_is_valid();

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_variable_data_c::set_buffer_length(
	const u32_t p_buffer_length)
{
	if (m_data == 0)
	{
		eap_status_e status = initialize_members();
		if (status != eap_status_ok)
		{
			// ERROR.
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}

	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	u32_t required_buffer_length = p_buffer_length;
	if (required_buffer_length < 1ul)
	{
		required_buffer_length = 1ul;
	}

	if (m_data->m_buffer_length < required_buffer_length)
	{
		eap_status_e status = allocate_buffer(required_buffer_length);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_variable_data_c::add_data_to_offset(
	const u32_t offset,
	const void * const buffer,
	const u32_t buffer_length)
{
	if (m_data == 0)
	{
		eap_status_e status = initialize_members();
		if (status != eap_status_ok)
		{
			// ERROR.
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}

	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);
	EAP_ASSERT_TOOLS(m_am_tools, m_data->m_is_valid == true);

	const u32_t offset_and_buffer_length = offset + buffer_length;

	u32_t required_buffer_length
		= m_data->m_real_data_start_index;

	if (m_data->m_real_data_length > offset_and_buffer_length)
	{
		required_buffer_length
			+= m_data->m_real_data_length;
	}
	else
	{
		required_buffer_length
			+= offset_and_buffer_length;

		if (required_buffer_length == 0ul)
		{
			++required_buffer_length;
		}
	}

	if (m_data->m_buffer_length < required_buffer_length)
	{
		eap_status_e status = allocate_buffer(required_buffer_length);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (buffer_length != 0u
		&& buffer != 0)
	{
		m_am_tools->memmove(
			m_data->m_buffer
			+ (m_data->m_real_data_start_index
			   + offset),
			buffer,
			buffer_length);
	}

	if (offset_and_buffer_length > m_data->m_real_data_length)
	{
		m_data->m_real_data_length = offset_and_buffer_length;
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_variable_data_c::add_data_to_offset(
	const u32_t offset,
	const eap_variable_data_c * const buffer)
{
	if (get_is_valid() == false)
	{
		// ERROR.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	return EAP_STATUS_RETURN(m_am_tools, add_data_to_offset(
		offset,		
		buffer->get_data(),
		buffer->get_data_length()));	
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_variable_data_c::add_data(
	const void * const buffer,
	const u32_t buffer_length)
{
	if (get_is_valid() == false)
	{
		// ERROR.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	return EAP_STATUS_RETURN(
		m_am_tools,
		add_data_to_offset(
			get_data_length(),
			buffer,
			buffer_length));
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_variable_data_c::add_data(
	const eap_variable_data_c * const buffer)
{
	if (buffer == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	return EAP_STATUS_RETURN(m_am_tools, add_data(
		buffer->get_data(),
		buffer->get_data_length()));
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_variable_data_c::add_end_null()
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	u16_t zero(0ul);
	eap_status_e status = add_data(&zero, sizeof(zero));
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// This removes the null from data length.
	set_data_length(get_data_length() - sizeof(zero));

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_variable_data_c::init(
	const u32_t length)
{
	if (m_data == 0)
	{
		eap_status_e status = initialize_members();
		if (status != eap_status_ok)
		{
			// ERROR.
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}

	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	u32_t required_buffer_length = length;
	if (length == 0u)
	{
		required_buffer_length = 1ul;
	}

	if (required_buffer_length > m_data->m_buffer_length // Too small buffer.
		|| m_data->m_is_writable == false) // Old buffer is read only.
	{
		// Must allocate a new m_buffer.

		reset();

		m_data->m_buffer = new u8_t[required_buffer_length];
		if (m_data->m_buffer == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_variable_data_c::init(): Cannot allocate %d bytes.\n"),
				required_buffer_length));
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// This is for testing. It is better leave buffer uninitialized.
		// Memory checking programs could track use of uninitialized data.

		m_data->m_free_buffer = true;
		m_data->m_is_writable = true;
		m_data->m_buffer_length = required_buffer_length;
	}

	m_data->m_real_data_start_index = 0ul;
	m_data->m_real_data_length = 0u;

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * eap_variable_data_c::copy() const
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0)
	{
		// ERROR.
		return 0;
	}

	eap_variable_data_c *new_data = new eap_variable_data_c(m_am_tools);

	if (new_data == 0
		|| new_data->get_is_valid() == false)
	{
		delete new_data;
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_variable_data_c::copy(): Cannot allocate %d bytes.\n"),
			sizeof(eap_variable_data_c)));
		return 0;
	}

	eap_status_e status = new_data->set_copy_of_buffer(this);
	if (status != eap_status_ok)
	{
		delete new_data;
		return 0;
	}

	return new_data;
}

//--------------------------------------------------

EAP_FUNC_EXPORT i32_t eap_variable_data_c::compare_length(
	const void * const data,
	const u32_t data_length,
	const u32_t compare_length_of_data) const
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0)
	{
		return -1;
	}

	if (get_data_length() < compare_length_of_data)
	{
		// Different length, cannot match.
		return -1;
	}
	else if (data_length < compare_length_of_data)
	{
		// Different length, cannot match.
		return 1;
	}

	return m_am_tools->memcmp(
		get_data(),
		data,
		compare_length_of_data);
}


//--------------------------------------------------

EAP_FUNC_EXPORT i32_t eap_variable_data_c::compare_length(
	const eap_variable_data_c * const data,
	const u32_t compare_length_of_data) const
{
	return compare_length(
		data->get_data(),
		data->get_data_length(),
		compare_length_of_data);
}


//--------------------------------------------------

EAP_FUNC_EXPORT i32_t eap_variable_data_c::compare(
	const void * const data,
	const u32_t data_length) const
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0)
	{
		return -1;
	}

	if (get_data_length() < data_length)
	{
		// Different length, cannot match.
		return -1;
	}
	else if (get_data_length() > data_length)
	{
		// Different length, cannot match.
		return 1;
	}

	return m_am_tools->memcmp(
		get_data(),
		data,
		data_length);
}


//--------------------------------------------------

EAP_FUNC_EXPORT i32_t eap_variable_data_c::compare(
	const eap_variable_data_c * const data) const
{
	return compare(
		data->get_data(),
		data->get_data_length());
}


//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_variable_data_c::hash(
	const u32_t size) const
{
	if (m_data == 0)
	{
		return 0ul;
	}

	u32_t ihash = 0x55555555;
	const u32_t length = get_data_length();
	const u8_t * const id = get_data(length);

	if (id == 0)
	{
		return 0ul;
	}

	for(u32_t ind = 0u; ind < length; ind++)
	{
		ihash += static_cast<u32_t>(id[ind]) + static_cast<u32_t>((~ind) << 15);
	}

	return ihash % size;
}

//--------------------------------------------------



// End.
