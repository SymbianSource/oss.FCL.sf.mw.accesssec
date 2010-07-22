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
	#define EAP_FILE_NUMBER_ENUM 21 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_buffer.h"
#include "eap_am_assert.h"
#include "eap_am_tools.h"
#include "eapol_ethernet_header.h"

static const bool EAP_BUFFER_DO_PACKET_RETRANSMISSION_INIT_VALUE = true;

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT bool eap_buf_chain_base_c::check_guard_bytes(const u8_t * const guard) const
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0)
	{
		return false;
	}

	u32_t ind = 0;
	for (ind = 0; ind < m_data->m_mem_guard_length; ind++)
	{
		if (guard[ind] != EAP_MEM_GUARD_BYTE)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: check_guard_bytes(): buffer overflow in byte %d."),
				ind));
			EAP_ASSERT_ANYWAY_TOOLS(m_am_tools);
			return false;
		}
	}
	return true;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT abs_eap_am_tools_c * eap_buf_chain_base_c::get_am_tools()
{
	return m_am_tools;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT bool eap_buf_chain_base_c::check_guards() const
{

#if defined(_DEBUG)
	if (m_data == 0
		|| m_data->m_buffer == 0)
	{
		return false;
	}

	if (m_data->m_buffer->get_is_writable() == true)
	{
		const u8_t * const buffer = m_data->m_buffer->get_data(
			m_data->m_buffer->get_data_length());

		if (buffer == 0)
		{
			return true;
		}

		if (check_guard_bytes(buffer) == false
			|| check_guard_bytes(
				buffer+(m_data->m_buffer->get_buffer_length()
						- m_data->m_mem_guard_length)) == false
			/* || check_guard_bytes(buffer+(m_data->m_real_data_length
			   - m_data->m_mem_guard_length)) == false */)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: check_guard_bytes(): buffer overflow, buffer 0x%08x."),
				buffer - m_data->m_mem_guard_length));
			EAP_ASSERT_ANYWAY_TOOLS(m_am_tools);
			return false;
		}
	}
#endif //#if defined(_DEBUG)

	return true;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_buf_chain_base_c::~eap_buf_chain_base_c()
{
	if (m_data != 0)
	{
		check_guards();

		delete m_data->m_buffer;
		m_data->m_buffer = 0;
	}

	delete m_data;
	m_data = 0;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_buf_chain_base_c::eap_buf_chain_base_c(
	const eap_write_buffer_e, 
	abs_eap_am_tools_c * const tools,
	u8_t * const data, 
	const u32_t data_length, 
	const bool reset_data,
	const bool free_buffer, 
	const u32_t mem_guard_length)
		: m_am_tools(tools)
		, m_data(0)
{
	eap_status_e status = initialize(mem_guard_length);
	if (status != eap_status_ok)
	{
		if (free_buffer == true)
		{
			delete [] data;
		}
		return;
	}

	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0
		|| m_data->m_buffer == 0)
	{
		if (free_buffer == true)
		{
			delete [] data;
		}
		return;
	}

	status = m_data->m_buffer->set_buffer(
		data,
		data_length,
		free_buffer,
		true);
	if (status != eap_status_ok)
	{
		if (free_buffer == true)
		{
			delete [] data;
		}
		m_data->m_is_valid = false;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	EAP_ASSERT_TOOLS(m_am_tools, data_length >= m_data->m_mem_guard_length);
	m_data->m_buffer->set_data_length(data_length - m_data->m_mem_guard_length);

	set_mem_guard_bytes();

	if (reset_data == true)
	{
		reset_data_buffer();
	}
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_buf_chain_base_c::eap_buf_chain_base_c(
	const eap_read_buffer_e,
	abs_eap_am_tools_c * const tools,
	const u8_t * const data, 
	const u32_t data_length,
	const bool free_buffer)
		: m_am_tools(tools)
		, m_data(0)
{
	eap_status_e status = initialize(0ul);
	if (status != eap_status_ok)
	{
		return;
	}

	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0
		|| m_data->m_buffer == 0)
	{
		return;
	}

	status = m_data->m_buffer->set_buffer(
		data,
		data_length,
		free_buffer,
		false);
	if (status != eap_status_ok)
	{
		m_data->m_is_valid = false;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_buf_chain_base_c::eap_buf_chain_base_c(
	const eap_write_buffer_e,
	abs_eap_am_tools_c * const tools,
	const u32_t data_length)
		: m_am_tools(tools)
		, m_data(0)
{
	eap_status_e status = initialize(EAP_MEM_GUARD_LENGTH);
	if (status != eap_status_ok)
	{
		return;
	}

	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0
		|| m_data->m_buffer == 0)
	{
		return;
	}

	status = m_data->m_buffer->init(data_length+2*m_data->m_mem_guard_length);
	if (status == eap_status_ok)
	{
		m_data->m_buffer->set_is_valid();
		m_data->m_buffer->set_data_length(m_data->m_mem_guard_length);
		set_mem_guard_bytes();
	}
	else
	{
		m_data->m_is_valid = false;
	}
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_buf_chain_base_c::eap_buf_chain_base_c(
	const eap_read_buffer_e,
	abs_eap_am_tools_c * const tools,
	const u32_t data_length)
		: m_am_tools(tools)
		, m_data(0)
{
	eap_status_e status = initialize(EAP_MEM_GUARD_LENGTH);
	if (status != eap_status_ok)
	{
		return;
	}

	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0
		|| m_data->m_buffer == 0)
	{
		return;
	}

	if (data_length > 0ul)
	{
		status = m_data->m_buffer->init(data_length+2*m_data->m_mem_guard_length);
		if (status == eap_status_ok)
		{
			m_data->m_buffer->set_is_valid();
			m_data->m_buffer->set_data_length(m_data->m_mem_guard_length);
			set_mem_guard_bytes();
		}
		else
		{
			m_data->m_is_valid = false;
		}
	}
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_buf_chain_base_c::initialize(
	const u32_t mem_guard_length)
{
	m_data = new eap_buf_chain_base_impl_str;
	if (m_data == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	m_data->m_mem_guard_length = mem_guard_length;
	m_data->m_buffer = 0;
	m_data->m_next_buffer = 0;
	m_data->m_random_error_type = eap_random_error_type_none_keep_this_last_case;
	m_data->m_send_packet_index = 0ul;
	m_data->m_stack_address = 0;
	m_data->m_is_valid = false;
	m_data->m_is_manipulated = false;
	m_data->m_do_packet_retransmission = EAP_BUFFER_DO_PACKET_RETRANSMISSION_INIT_VALUE;
	m_data->m_is_client = true;
	m_data->m_do_length_checks = false;
	m_data->m_encrypt = false;

	m_data->m_buffer = new eap_variable_data_c(m_am_tools);
	if (m_data->m_buffer == 0
		|| m_data->m_buffer->get_is_valid() == false)
	{
		delete m_data;
		m_data = 0;
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	m_data->m_is_valid = true;

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT void eap_buf_chain_base_c::reset_data_buffer()
{
	if (m_data == 0
		|| m_data->m_buffer == 0)
	{
		return;
	}

	m_am_tools->memset(
		get_data(get_data_length()),
		0,
		get_data_length());
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT void eap_buf_chain_base_c::set_mem_guard_bytes()
{
	EAP_ASSERT_TOOLS(
		m_am_tools,
		m_data != 0);
	EAP_ASSERT_TOOLS(
		m_am_tools,
		m_data->m_buffer->get_buffer_length()
		>= m_data->m_mem_guard_length);
	EAP_ASSERT_TOOLS(
		m_am_tools,
		m_data->m_buffer->get_data_length()
		>= m_data->m_mem_guard_length);

	if (m_data == 0
		|| m_data->m_buffer == 0)
	{
		return;
	}

	u8_t * const buffer = m_data->m_buffer->get_data(m_data->m_buffer->get_data_length());

	m_am_tools->memset(
		buffer,
		EAP_MEM_GUARD_BYTE,
		m_data->m_mem_guard_length);

	m_am_tools->memset(
		buffer+(m_data->m_buffer->get_buffer_length() - m_data->m_mem_guard_length),
		EAP_MEM_GUARD_BYTE,
		m_data->m_mem_guard_length);

	m_am_tools->memset(
		buffer+(m_data->m_buffer->get_data_length()),
		EAP_MEM_GUARD_BYTE,
		m_data->m_mem_guard_length);
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_buf_chain_base_c::get_mem_guard_length()
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0)
	{
		return 0;
	}

	return m_data->m_mem_guard_length;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_buf_chain_base_c::get_buffer_length() const
{
	EAP_ASSERT_TOOLS(
		m_am_tools,
		m_data != 0);
	EAP_ASSERT_TOOLS(
		m_am_tools,
		m_data->m_buffer->get_buffer_length()
		>= 2ul*m_data->m_mem_guard_length);

	if (m_data == 0
		|| m_data->m_buffer == 0)
	{
		return 0;
	}

	return m_data->m_buffer->get_buffer_length() - 2ul*m_data->m_mem_guard_length;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_buf_chain_base_c::get_data_length() const
{
	EAP_ASSERT_TOOLS(
		m_am_tools,
		m_data != 0);
	EAP_ASSERT_TOOLS(
		m_am_tools,
		m_data->m_buffer->get_data_length()
		>= m_data->m_mem_guard_length);

	if (m_data == 0
		|| m_data->m_buffer == 0)
	{
		return 0;
	}

	return m_data->m_buffer->get_data_length() - m_data->m_mem_guard_length;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT u8_t * eap_buf_chain_base_c::get_data_offset(
	const u32_t p_offset,
	const u32_t p_continuous_bytes) const
{
	EAP_ASSERT_TOOLS(
		m_am_tools,
		m_data != 0);
	EAP_ASSERT_TOOLS(
		m_am_tools,
		m_data->m_buffer->get_data_length() >= m_data->m_mem_guard_length);

	if (m_data == 0
		|| m_data->m_buffer == 0)
	{
		return 0;
	}

	if (p_offset+p_continuous_bytes <= get_buffer_length())
	{
		return m_data->m_buffer->get_buffer_offset(
			p_offset + m_data->m_mem_guard_length,
			p_continuous_bytes);
	}
	else
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: Fragments are not supported yet.\n")));
		EAP_ASSERT_ALWAYS_TOOLS(
			m_am_tools,
			p_offset+p_continuous_bytes <= get_data_length());
		return 0;
	}
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT u8_t * eap_buf_chain_base_c::get_data(
	const u32_t p_continuous_bytes) const
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0
		|| m_data->m_buffer == 0)
	{
		return 0;
	}

	return get_data_offset(0u, p_continuous_bytes);
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_buf_chain_base_c::set_buffer_length(
	const u32_t buffer_length)
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);
	EAP_ASSERT_TOOLS(m_am_tools, m_data->m_buffer != 0);

	if (m_data == 0
		|| m_am_tools == 0
		|| m_am_tools->get_is_valid() == false)
	{
		return eap_status_allocation_error;
	}

	if (m_data->m_buffer == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	m_data->m_buffer->reset();

	eap_status_e status = m_data->m_buffer->init(buffer_length+2*m_data->m_mem_guard_length);
	if (status == eap_status_ok)
	{
		m_data->m_buffer->set_is_valid();
		m_data->m_buffer->set_data_length(m_data->m_mem_guard_length);
		set_mem_guard_bytes();
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_buf_chain_base_c::set_data_length(
	const u32_t length)
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);
	EAP_ASSERT_TOOLS(m_am_tools, m_data->m_buffer != 0);
	EAP_ASSERT_TOOLS(m_am_tools, m_data->m_buffer->get_is_writable() == true);

	if (m_data == 0
		|| m_am_tools == 0
		|| m_am_tools->get_is_valid() == false)
	{
		return eap_status_allocation_error;
	}

	if (m_data->m_buffer == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	check_guards();

	if (get_buffer_length() > length)
	{
		// Here we must reset the memory guard bytes because not all of the buffer is used.
		EAP_ASSERT_TOOLS(
			m_am_tools,
			m_data->m_buffer->get_data_length()
			>= m_data->m_mem_guard_length);

		u8_t * const buffer = m_data->m_buffer->get_data_offset(
			m_data->m_mem_guard_length,
			m_data->m_buffer->get_data_length() - m_data->m_mem_guard_length);
		if (buffer == 0)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
		}

		m_am_tools->memset(
			buffer+length,
			EAP_MEM_GUARD_BYTE,
			m_data->m_mem_guard_length);
	}

	m_data->m_buffer->set_data_length(length + m_data->m_mem_guard_length);

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT bool eap_buf_chain_base_c::get_is_valid() const
{
	if (m_data == 0)
	{
		return false;
	}

	return m_data->m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_buf_chain_base_c::get_is_valid_data() const
{
	if (m_data == 0)
	{
		return false;
	}

	if (m_data->m_is_valid == false)
	{
		return false;
	}

	// Note the buffer could be empty.
	if (m_data->m_buffer == 0)
	{
		return false;
	}

	return true;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT void eap_buf_chain_base_c::set_is_manipulated()
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0)
	{
		return;
	}

	m_data->m_is_manipulated = true;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT bool eap_buf_chain_base_c::get_is_manipulated()
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0)
	{
		return false;
	}

	return m_data->m_is_manipulated;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT void eap_buf_chain_base_c::set_send_packet_index(const u32_t send_packet_index)
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0)
	{
		return;
	}

	m_data->m_send_packet_index = send_packet_index;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_buf_chain_base_c::get_send_packet_index()
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0)
	{
		return 0;
	}

	return m_data->m_send_packet_index;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT void eap_buf_chain_base_c::set_random_error_type(
	eap_random_error_type error_type)
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0)
	{
		return;
	}

	m_data->m_random_error_type = error_type;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_random_error_type eap_buf_chain_base_c::get_random_error_type()
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0)
	{
		return eap_random_error_type_manipulate_byte;
	}

	return m_data->m_random_error_type;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT void eap_buf_chain_base_c::set_do_packet_retransmission(
	const bool do_packet_retransmission_when_true)
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0)
	{
		return;
	}

	m_data->m_do_packet_retransmission = do_packet_retransmission_when_true;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT bool eap_buf_chain_base_c::get_do_packet_retransmission()
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0)
	{
		return false;
	}

	return m_data->m_do_packet_retransmission;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT void eap_buf_chain_base_c::set_is_client(const bool is_client_when_true)
{
	m_data->m_is_client = is_client_when_true;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT bool eap_buf_chain_base_c::get_is_client() const
{
	return m_data->m_is_client;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT void eap_buf_chain_base_c::set_do_length_checks(const bool do_length_checks)
{
	m_data->m_do_length_checks = do_length_checks;
}

EAP_FUNC_EXPORT bool eap_buf_chain_base_c::get_do_length_checks() const
{
	return m_data->m_do_length_checks;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT void eap_buf_chain_base_c::set_encrypt(const bool encrypt_when_true)
{
	m_data->m_encrypt = encrypt_when_true;
}

EAP_FUNC_EXPORT bool eap_buf_chain_base_c::get_encrypt() const
{
	return m_data->m_encrypt;
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT void eap_buf_chain_base_c::set_stack_address(const void * const stack_address)
{
	m_data->m_stack_address = stack_address;
}

EAP_FUNC_EXPORT const void * eap_buf_chain_base_c::get_stack_address() const
{
	return m_data->m_stack_address; 
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_buf_chain_base_c::add_data(
	const void * const buffer,
	const u32_t buffer_length)
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0
		|| m_am_tools == 0
		|| m_am_tools->get_is_valid() == false)
	{
		return eap_status_allocation_error;
	}

	eap_status_e status = add_data_to_offset(
		get_data_length(),
		buffer,
		buffer_length);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_buf_chain_base_c::add_data(
	const eap_variable_data_c * const buffer)
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0
		|| m_am_tools == 0
		|| m_am_tools->get_is_valid() == false)
	{
		return eap_status_allocation_error;
	}

	return EAP_STATUS_RETURN(m_am_tools, add_data(
		buffer->get_data(buffer->get_data_length()),
		buffer->get_data_length()));
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_buf_chain_base_c::add_data_to_offset(
	const u32_t offset,
	const void * const buffer,
	const u32_t buffer_length)
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0
		|| m_am_tools == 0
		|| m_am_tools->get_is_valid() == false)
	{
		return eap_status_allocation_error;
	}

	eap_status_e status = m_data->m_buffer->add_data_to_offset(
		m_data->m_mem_guard_length+offset,
		buffer,
		buffer_length);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_buf_chain_base_c::add_data_to_offset(
	const u32_t offset,
	const eap_variable_data_c * const buffer)
{
	EAP_ASSERT_TOOLS(m_am_tools, m_data != 0);

	if (m_data == 0
		|| m_am_tools == 0
		|| m_am_tools->get_is_valid() == false)
	{
		return eap_status_allocation_error;
	}

	eap_status_e status = m_data->m_buffer->add_data_to_offset(
		m_data->m_mem_guard_length+offset,
		buffer->get_data(buffer->get_data_length()),
		buffer->get_data_length());

	return EAP_STATUS_RETURN(m_am_tools, status);
}


//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_buf_chain_wr_c::~eap_buf_chain_wr_c()
{
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_buf_chain_wr_c::eap_buf_chain_wr_c(
	const eap_write_buffer_e,
	abs_eap_am_tools_c * const tools,
	u8_t * const data,
	const u32_t data_length,
	const bool reset_data,
	const bool free_buffer,
	const u32_t mem_guard_length)
	: eap_buf_chain_base_c(
		eap_write_buffer,
		tools,
		data,
		data_length,
		reset_data,
		free_buffer,
		mem_guard_length)
{
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_buf_chain_wr_c::eap_buf_chain_wr_c(
	const eap_write_buffer_e,
	abs_eap_am_tools_c * const tools,
	const u32_t data_length)
	: eap_buf_chain_base_c(eap_write_buffer, tools, data_length)
{
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_buf_chain_wr_c::eap_buf_chain_wr_c(
	const eap_write_buffer_e,
	abs_eap_am_tools_c * const tools)
	: eap_buf_chain_base_c(eap_write_buffer, tools, 0ul)
{
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT void eap_buf_chain_wr_c::force_inheritance()
{
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT u8_t * eap_buf_chain_wr_c::get_ethernet_header()
{
	return static_cast<u8_t *>(
		get_data(
			eapol_ethernet_header_wr_c::get_header_length()));
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_buf_chain_wr_c * eap_buf_chain_wr_c::copy()
{
	if (get_is_valid() == false)
	{
		return 0;
	}

	u8_t *new_data = new u8_t[get_buffer_length()+(2u*get_mem_guard_length())];
	
	if (new_data == 0)
	{
		return 0;
	}

	get_am_tools()->memmove(
		new_data+get_mem_guard_length(),
		get_data(get_buffer_length()),
		get_buffer_length());

	eap_buf_chain_wr_c * const new_buffer
		= new eap_buf_chain_wr_c(
			eap_write_buffer,
			get_am_tools(),
			new_data,
			get_buffer_length()+(2u*get_mem_guard_length()),
			false, // Do not init data
			true, // Free buffer on destructor
			get_mem_guard_length());

	if (new_buffer == 0
		|| new_buffer->get_is_valid_data() == false)
	{
		delete new_buffer;
		return 0;
	}

	new_buffer->set_data_length(get_data_length());

	new_buffer->set_send_packet_index(get_send_packet_index());
	new_buffer->set_random_error_type(get_random_error_type());
	new_buffer->set_stack_address(get_stack_address());
	new_buffer->set_is_client(get_is_client());

	return new_buffer;
}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_buf_chain_rd_c::~eap_buf_chain_rd_c()
{
	check_guards();
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_buf_chain_rd_c::eap_buf_chain_rd_c(
	const eap_read_buffer_e, 
	abs_eap_am_tools_c * const tools,
	const u8_t * const data, 
	const u32_t data_length,
	const bool free_buffer)
		: eap_buf_chain_base_c(
			eap_read_buffer,
			tools,
			data,
			data_length,
			free_buffer)
{
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_buf_chain_rd_c::eap_buf_chain_rd_c(
	const eap_read_buffer_e,
	abs_eap_am_tools_c * const tools,
	const u32_t data_length)
	: eap_buf_chain_base_c(eap_read_buffer, tools, data_length)
{
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT void eap_buf_chain_rd_c::force_inheritance()
{
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT const u8_t * eap_buf_chain_rd_c::get_data(
	const u32_t p_continuous_bytes) const
{
	return static_cast<const u8_t *>(
		eap_buf_chain_base_c::get_data(p_continuous_bytes));
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT const u8_t * eap_buf_chain_rd_c::get_data_offset(
	const u32_t p_offset,
	const u32_t p_continuous_bytes) const
{
	return static_cast<const u8_t *>(
		eap_buf_chain_base_c::get_data_offset(
			p_offset,
			p_continuous_bytes));
}

//-----------------------------------------------------------------------------

EAP_FUNC_EXPORT const u8_t * eap_buf_chain_rd_c::get_ethernet_header() const
{
	return static_cast<const u8_t *>(
		get_data(
			eapol_ethernet_header_rd_c::get_header_length()));
}

//-----------------------------------------------------------------------------




// End.
