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
	#define EAP_FILE_NUMBER_ENUM 13 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_am_tools.h"
#include "abs_eap_am_mutex.h"
#include "eap_crypto_api.h"
#include "eap_buffer.h"
#include "eap_configuration_field.h"

//#if !defined(NO_EAP_AM_MEMORY_STORE)
	#include "eap_am_memory_store.h"
//#endif //#if !defined(NO_EAP_AM_MEMORY_STORE)

/**
 * This is the at character used in NAI.
 */
const u8_t EAP_AT_CHARACTER = '@';

/**
 * This is the length of UUIDs.
 */
static const u32_t EAP_UUID_LENGTH = 16;

/**
 * This is the name space UUID for MAC addresses.
 */
static const u8_t EAP_MAC_ADDRESS_NAMESPACE_UUID_V5[] = 
	{ 0x35, 0x0b, 0x16, 0xfd, 
	  0x5c, 0xd8, 0x45, 0x50, 
	  0x9b, 0xb8, 0x49, 0x8f, 
	  0x95, 0x8a, 0xc9, 0x66 };


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_am_tools_c::~eap_am_tools_c()
{
	EAP_ASSERT_ALWAYS_NO_TRACE(m_shutdown_was_called == true);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_am_tools_c::eap_am_tools_c()
: 
#if !defined(NO_EAP_AM_MEMORY_STORE)
  m_memory_store(0)
, 
#endif //#if !defined(NO_EAP_AM_MEMORY_STORE)
 m_trace_mask(eap_am_tools_c::eap_trace_mask_none)
#if defined(USE_EAP_ERROR_TESTS)
, m_packet_index(0u)
#endif //#if defined(USE_EAP_ERROR_TESTS)
, m_use_seconds_timestamp_in_traces(true)
, m_thread_stopped(false)
, m_use_timer_queue(false)
, m_shutdown_was_called(false)
, m_activate_trace_on_error(false)
{
	abs_eap_am_tools_c *m_am_tools = this;
	u32_t bytes_8 = 8u;
	u32_t bytes_4 = 4u;
	u32_t bytes_2 = 2u;
	u32_t bytes_1 = 1u;

	EAP_UNREFERENCED_PARAMETER(m_am_tools);
	EAP_UNREFERENCED_PARAMETER(bytes_8);
	EAP_UNREFERENCED_PARAMETER(bytes_4);
	EAP_UNREFERENCED_PARAMETER(bytes_2);
	EAP_UNREFERENCED_PARAMETER(bytes_1);

	EAP_ASSERT_ALWAYS(sizeof(u64_t) == bytes_8);
	EAP_ASSERT_ALWAYS(sizeof(u32_t) == bytes_4);
	EAP_ASSERT_ALWAYS(sizeof(u16_t) == bytes_2);
	EAP_ASSERT_ALWAYS(sizeof(u8_t) == bytes_1);

	EAP_ASSERT_ALWAYS(sizeof(i64_t) == bytes_8);
	EAP_ASSERT_ALWAYS(sizeof(i32_t) == bytes_4);
	EAP_ASSERT_ALWAYS(sizeof(i16_t) == bytes_2);
	EAP_ASSERT_ALWAYS(sizeof(i8_t) == bytes_1);

	m_tmp_buffer[0] = 0;
	m_tmp_ascii_buffer[0] = 0;

#if !defined(NO_EAP_AM_MEMORY_STORE)
	m_memory_store = new eap_am_memory_store_c(m_am_tools);
#endif //#if !defined(NO_EAP_AM_MEMORY_STORE)
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eap_am_tools_c::get_use_seconds_timestamp_in_traces()
{
	return m_use_seconds_timestamp_in_traces;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eap_am_tools_c::get_thread_stopped()
{
	return m_thread_stopped;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_am_tools_c::set_use_timer_queue()
{
	m_use_timer_queue = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eap_am_tools_c::get_use_timer_queue()
{
	return m_use_timer_queue;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u32_t eap_am_tools_c::get_trace_mask() const
{
	return m_trace_mask;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_am_tools_c::set_trace_mask(const u32_t mask)
{
	m_trace_mask = mask;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_am_tools_c::set_activate_trace_on_error()
{
	m_activate_trace_on_error = true;

	// NOTE the always active traces are only left active.
	set_trace_mask(eap_trace_mask_always);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_am_tools_c::check_activate_trace_on_error()
{
	if (m_activate_trace_on_error == true)
	{
		set_trace_mask(
			eap_trace_mask_debug
			| eap_trace_mask_always
			| eap_trace_mask_error
			| eap_am_tools_c::eap_trace_mask_message_data);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u8_t eap_am_tools_c::octet_to_ascii(i32_t octet)
{
	if (0 <= octet && octet <= 9)
	{
		return static_cast<u8_t>('0' + octet);
	}
	else if (10 <= octet && octet <= 16)
	{
		return static_cast<u8_t>('a' + (octet-10u));
	}
	else
	{
		return 0;
	}
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT u8_t eap_am_tools_c::ascii_to_octet(i32_t character)
{
	if ('0' <= character && character <= '9')
	{
		return static_cast<u8_t>(character - '0');
	}
	else if ('a' <= character && character <= 'f')
	{
		return static_cast<u8_t>((character - 'a') + 10u);
	}
	else if ('A' <= character && character <= 'F')
	{
		return static_cast<u8_t>((character - 'A') + 10u);
	}
	else
	{
		return 0;
	}
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_am_tools_c::trace_data(
	eap_const_string prefix,
	const void * const p_data,
	const u32_t data_length)
{
	u8_t *cursor = m_tmp_buffer;
	u8_t *cursor_ascii = m_tmp_ascii_buffer;
	const u8_t *data = reinterpret_cast<const u8_t *>(p_data);
	u32_t ind;
	bool must_print = false;
	u32_t data_start = 0u;

	const u32_t EAP_DATA_TRACE_BYTE_GROUP_SIZE = 1;
	u32_t byte_group_size = EAP_DATA_TRACE_BYTE_GROUP_SIZE;

#if !defined(USE_EAP_DEBUG_TRACE)
	// This does not trace the pointer of the data.
	formatted_print(
		EAPL("%s: data begins: %d (0x%x) bytes\n"),
		prefix,
		data_length,
		data_length);
#else
	formatted_print(
		EAPL("%s: data begins 0x%08x: %d (0x%x) bytes\n"),
		prefix,
		p_data,
		data_length,
		data_length);
#endif

	if (p_data != 0)
	{
		for (ind = 0u; ind < data_length; ind++)
		{
			if ((cursor-m_tmp_buffer)+5u >= sizeof(m_tmp_buffer))
			{
				must_print = true;
				formatted_print(
					EAPL("ERROR: eap_am_tools_c::trace_data local buffer (%d bytes) too small.\n"),
					sizeof(m_tmp_buffer));
				break;
			}

			if (ind > 0u
				&& (ind % 16) == 0)
			{
				*cursor++ = 0;
				*cursor_ascii++ = 0;

				formatted_print(
					EAPL("%s: 0x%04x: %-48s |%-16s|\n"),
					prefix,
					data_start,
					m_tmp_buffer,
					m_tmp_ascii_buffer);

				cursor = m_tmp_buffer;
				cursor_ascii = m_tmp_ascii_buffer;
				must_print = false;
				data_start = ind;
			}

			*cursor_ascii++ = static_cast<u8_t>((*data >= 0x20 && *data < 0x7f) ? *data : '.');

			*cursor++ = octet_to_ascii(((*data) & 0xf0) >> 4);
			*cursor++ = octet_to_ascii(((*data) & 0x0f));
			data++;

			if ((ind > 0u
				 && ((ind+1) % byte_group_size) == 0)
				|| byte_group_size == 1ul)
			{
				*cursor++ = ' ';
			}

			must_print = true;
		}

		if (must_print == true)
		{
			*cursor++ = 0;
			*cursor_ascii = 0;
			formatted_print(
				EAPL("%s: 0x%04x: %-48s |%-16s|\n"),
				prefix,
				data_start,
				m_tmp_buffer,
				m_tmp_ascii_buffer);
		}
	}

#if !defined(USE_EAP_DEBUG_TRACE)
	// This does not trace the pointer of the data.
	formatted_print(
		EAPL("%s: data ends: %d (0x%x) bytes\n"),
		prefix,
		data_length,
		data_length);
#else
	formatted_print(
		EAPL("%s: data ends 0x%08x: %d (0x%x) bytes\n"),
		prefix,
		p_data,
		data_length,
		data_length);
#endif

}

//--------------------------------------------------

#if defined(__SYMBIAN32__) && defined(USE_MULTITHREADING)// Symbian does not have 64 bit divide operator :-(.

#include "eap_am_tools_symbian.h"
EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::timer_thread_function()
{
	EAP_TRACE_DEBUG(this, TRACE_FLAGS_DEFAULT, (EAPL("TIMER: Timer thread starts.\n")));

	u64_t start_time = get_clock_ticks();
	u64_t current_time = start_time;
	u64_t real_time = 0u;
	u64_t virtual_time = 0u;
	u64_t begin_time = 0u;
	u64_t end_time = 0u;
#if defined(_DEBUG)
	TInt64 *_begin_time = (TInt64 *)&begin_time;	
	TInt64 *_real_time = (TInt64 *)&real_time;	
	TInt64 *_end_time = (TInt64 *)&end_time;	
#endif
	u64_t hw_ticks_of_millisecond = get_clock_ticks_of_second();
	TInt64 *hw_ticks_of_millisecond_tmp = (TInt64 *)&hw_ticks_of_millisecond;
	TReal _hw_ticks_of_millisecond = hw_ticks_of_millisecond_tmp->GetTReal();	
	_hw_ticks_of_millisecond /= 1000.0;

	// Note 64-bit casted to 32-bit.
	EAP_TRACE_DEBUG(this, TRACE_FLAGS_DEFAULT, (EAPL("TIMER: get_clock_ticks_of_second() = %lu\n"),
		static_cast<u32_t>(get_clock_ticks_of_second()));


	u32_t sleep_time = get_timer_resolution_ms();
	// The mutex handle must be dublicated in Symbian operating system for each thread.
	abs_eap_am_mutex_c *mutex = get_global_mutex()->dublicate_mutex();

	if (mutex == 0
		|| mutex->get_is_valid() == false)
	{
		EAP_TRACE_ERROR(this, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Mutex dublication failed.\n")));
		m_thread_stopped =true;
		return EAP_STATUS_RETURN(this, eap_status_allocation_error);
	}

	u32_t next_sleep_time = sleep_time;

	mutex->mutex_enter();
	while(get_is_timer_thread_active())
	{
		mutex->mutex_leave(this);

		virtual_time += sleep_time;

		// Symbian sleep is more like random generator.
		// It never sleep right time.
		begin_time = get_clock_ticks();
		timer_sleep(sleep_time);
		end_time = get_clock_ticks();

		current_time = get_clock_ticks();		
		real_time = current_time - start_time;
	
		EAP_TRACE_DEBUG(
			this,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TIMER: Timer thread pulse_timer, sleep time = %d ms, ")
			 EAPL("actually %.3f ms, virtual_time %d ms, real_time %.3f ms.\n"),
			 sleep_time,
			 ((_end_time->GetTReal() - _begin_time->GetTReal()))/_hw_ticks_of_millisecond,
			 (static_cast<u32_t>(virtual_time),
			 (_real_time->GetTReal())/_hw_ticks_of_millisecond));
		
		mutex->mutex_enter();
		if (get_is_timer_thread_active())
		{
			next_sleep_time = pulse_timer(next_sleep_time);
		}
	}

	mutex->mutex_leave(this);

	delete mutex;
	EAP_TRACE_DEBUG(this, TRACE_FLAGS_DEFAULT, (EAPL("TIMER: Timer thread stops.\n")));

	m_thread_stopped =true;

	return eap_status_ok; 
}

#elif !defined(__SYMBIAN32__)

#if defined(USE_EAP_TIMER_QUEUE_TRACE)
	#define EAP_TRACE_TIMER EAP_TRACE_DEBUG
#else
	#define EAP_TRACE_TIMER(object, flags, parameters)
#endif //#if defined(USE_EAP_TIMER_QUEUE_TRACE)

EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::timer_thread_function()
{
	EAP_TRACE_DEBUG(this, TRACE_FLAGS_ALWAYS, (EAPL("TIMER: Timer thread starts.\n")));

	u32_t static_sleep_time = get_timer_resolution_ms();
	u64_t start_time = get_clock_ticks();
	u64_t current_time = start_time;
	u64_t virtual_time = 0u;
	u64_t real_sleep_time = 0ul;
	u32_t current_sleep_time = 0u;
	u64_t real_time = 0u;
	u64_t hw_ticks_of_millisecond = 0u;

	u64_t begin_time = 0u;
	u64_t end_time = 0u;

	// Note 64-bit casted to 32-bit.
	EAP_TRACE_TIMER(
		this,
		TRACE_FLAGS_TIMER, (EAPL("TIMER: get_clock_ticks_of_second() = %lu\n"),
		static_cast<u32_t>(get_clock_ticks_of_second())));

	hw_ticks_of_millisecond = get_clock_ticks_of_second();
	hw_ticks_of_millisecond /= 1000u;

	// The mutex handle must be dublicated in Symbian operating system for each thread.
	abs_eap_am_mutex_c *mutex = get_global_mutex()->dublicate_mutex();

	if (mutex == 0
		|| mutex->get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			this,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: Mutex dublication failed.\n")));
		m_thread_stopped =true;
		return EAP_STATUS_RETURN(this, eap_status_allocation_error);
	}

	u32_t next_sleep_time = static_sleep_time;
	u64_t delay_time = 0ul;


	EAP_TRACE_TIMER(
		this,
		TRACE_FLAGS_TIMER,
		(EAPL("MUTEX: eap_am_tools_c::timer_thread_function(): mutex_enter(): begin\n")));

	mutex->mutex_enter();

	EAP_TRACE_TIMER(
		this,
		TRACE_FLAGS_TIMER,
		(EAPL("MUTEX: eap_am_tools_c::timer_thread_function(): mutex_enter(): end\n")));

	while(get_is_timer_thread_active())
	{
		bool timer_queue_is_empty = get_timer_queue_is_empty();

		current_sleep_time = next_sleep_time;

		EAP_TRACE_TIMER(
			this,
			TRACE_FLAGS_TIMER,
			(EAPL("TIMER: timer_sleep(): current_sleep_time=%d\n"),
			 static_cast<u32_t>(current_sleep_time)));

		// - - - - - - - - - - - - - - - - - - - - - - - -
		begin_time = get_clock_ticks();

		EAP_TRACE_TIMER(
			this,
			TRACE_FLAGS_TIMER,
			(EAPL("MUTEX: eap_am_tools_c::timer_thread_function(): mutex_leave(): begin\n")));

		mutex->mutex_leave(this);

		EAP_TRACE_TIMER(
			this,
			TRACE_FLAGS_TIMER,
			(EAPL("MUTEX: eap_am_tools_c::timer_thread_function(): mutex_leave(): end\n")));

		// Sleep happens outside of the mutex.
		timer_sleep(current_sleep_time);

		EAP_TRACE_TIMER(
			this,
			TRACE_FLAGS_TIMER,
			(EAPL("MUTEX: eap_am_tools_c::timer_thread_function(): mutex_enter(): begin\n")));

		mutex->mutex_enter();

		EAP_TRACE_TIMER(
			this,
			TRACE_FLAGS_TIMER,
			(EAPL("MUTEX: eap_am_tools_c::timer_thread_function(): mutex_enter(): end\n")));

		end_time = get_clock_ticks();
		// - - - - - - - - - - - - - - - - - - - - - - - -

		if (timer_queue_is_empty == true)
		{
			real_sleep_time = 0ul;
			delay_time = 0ul;
			EAP_TRACE_TIMER(
				this,
				TRACE_FLAGS_TIMER,
				(EAPL("TIMER: empty timer queue\n")));
		}
		else
		{
			if (end_time < begin_time)
			{
				end_time = begin_time;
			}
			real_sleep_time = (end_time - begin_time)/hw_ticks_of_millisecond;
		}

		// - - - - - - - - - - - - - - - - - - - - - - - -
		begin_time = get_clock_ticks();
		if (get_is_timer_thread_active() == true
			&& get_use_eap_milli_second_timer() == true)
		{
			EAP_TRACE_TIMER(
				this,
				TRACE_FLAGS_TIMER,
				(EAPL("TIMER: real_sleep_time=%d, delay_time=%d\n"),
				 static_cast<u32_t>(real_sleep_time),
				 static_cast<u32_t>(delay_time)));

			next_sleep_time = pulse_timer(static_cast<u32_t>(real_sleep_time+delay_time));
		}
		else
		{
			(void) pulse_timer(static_sleep_time);
			next_sleep_time = static_sleep_time;
		}
		end_time = get_clock_ticks();
		// - - - - - - - - - - - - - - - - - - - - - - - -


		if (end_time < begin_time)
		{
			end_time = begin_time;
		}

		delay_time = (end_time - begin_time)/hw_ticks_of_millisecond;
		if (delay_time < next_sleep_time)
		{
			next_sleep_time -= static_cast<u32_t>(delay_time);
		}
		else
		{
			next_sleep_time = 0ul;
		}
		
		current_time = get_clock_ticks();
		real_time = current_time - start_time;
		real_time /= hw_ticks_of_millisecond;
		
		real_sleep_time += delay_time;
		virtual_time += real_sleep_time;


		EAP_TRACE_TIMER(
			this,
			TRACE_FLAGS_TIMER,
			(EAPL("TIMER: Timer thread pulse_timer, sleep time = %4d ms, real_sleep_time %4d ms, ")
			 EAPL("virtual_time %6d, real_time %6d, next_sleep_time %4d, delay_time %4d.\n"),
			 current_sleep_time,
			 static_cast<u32_t>(real_sleep_time),
			 static_cast<u32_t>(virtual_time),
			 static_cast<u32_t>(real_time),
			 next_sleep_time,
			 delay_time));

	} // while()

	EAP_TRACE_TIMER(
		this,
		TRACE_FLAGS_TIMER,
		(EAPL("MUTEX: eap_am_tools_c::timer_thread_function(): mutex_leave(): begin\n")));

	mutex->mutex_leave(this);

	EAP_TRACE_TIMER(
		this,
		TRACE_FLAGS_TIMER,
		(EAPL("MUTEX: eap_am_tools_c::timer_thread_function(): mutex_leave(): end\n")));

	delete mutex;

	EAP_TRACE_DEBUG(this, TRACE_FLAGS_ALWAYS, (EAPL("TIMER: Timer thread stops.\n")));

	m_thread_stopped =true;

	return eap_status_ok; 
}

#else

EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::timer_thread_function()
{
	return EAP_STATUS_RETURN(this, eap_status_not_supported); 
}

#endif

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::convert_ascii_to_uppercase(
	u8_t * const source_bytes,
	const u32_t source_bytes_length)
{
	u32_t ind;
	for (ind = 0u; ind < source_bytes_length; ind++)
	{
		if (source_bytes[ind] >= 'a' && source_bytes[ind] <= 'z')
		{
			source_bytes[ind] = static_cast<u8_t>(source_bytes[ind] - 32);
		}
	}

	return eap_status_ok;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::convert_bytes_to_hex_ascii(
	const u8_t * const source_bytes,
	const u32_t source_bytes_length,
	u8_t * const target,
	u32_t *target_length)
{
	u32_t ind;
	u32_t length = (source_bytes_length*2u < (*target_length)) ? source_bytes_length : (*target_length)/2u;
	for (ind = 0u; ind < length; ind++)
	{
		target[ind*2u] = octet_to_ascii((source_bytes[ind] >> 4) & 0x0f);
		target[(ind*2u)+1] = octet_to_ascii(source_bytes[ind] & 0x0f);
	}
	*target_length = (ind*2u);

	return eap_status_ok;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::convert_bytes_to_hex_ascii(
	const void * const source_bytes,
	const u32_t source_bytes_length,
	eap_variable_data_c * const target)
{
	if (target == 0
		|| target->get_is_valid() == false)
	{
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, eap_status_illegal_parameter);
	}

	eap_status_e status = target->set_buffer_length(source_bytes_length/2ul);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, status);
	}

	status = target->set_data_length(target->get_buffer_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, status);
	}

	u32_t byte_length(target->get_data_length());

	status = convert_bytes_to_hex_ascii(
		reinterpret_cast<const u8_t *>(source_bytes),
		source_bytes_length,
		target->get_data(),
		&byte_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, status);
	}
	else if (byte_length != target->get_data_length())
	{
		target->reset();
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, eap_status_illegal_data_payload);
	}

	EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(this, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::convert_hex_ascii_to_bytes(
	const u8_t * const source_bytes,
	const u32_t source_bytes_length,
	u8_t * const target,
	u32_t *target_length)
{
	if ((source_bytes_length % 2u) != 0)
	{
		return EAP_STATUS_RETURN(this, eap_status_data_length_not_aligned_to_block_size);
	}

	u32_t ind;
	u32_t length = (source_bytes_length/2u < (*target_length)) ? source_bytes_length/2u : (*target_length);
	for (ind = 0u; ind < length; ind++)
	{
		target[ind] = static_cast<u8_t>(ascii_to_octet(source_bytes[ind*2u]) << 4u | ascii_to_octet(source_bytes[ind*2u+1u]));
	}
	*target_length = (ind);

	return eap_status_ok;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::convert_hex_ascii_to_bytes(
	const void * const source_bytes,
	const u32_t source_bytes_length,
	eap_variable_data_c * const target)
{
	if (target == 0
		|| target->get_is_valid() == false)
	{
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, eap_status_illegal_parameter);
	}

	eap_status_e status = target->set_buffer_length(source_bytes_length/2ul);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, status);
	}

	status = target->set_data_length(source_bytes_length/2ul);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, status);
	}

	u32_t byte_length(target->get_data_length());

	status = convert_hex_ascii_to_bytes(
		reinterpret_cast<const u8_t *>(source_bytes),
		source_bytes_length,
		target->get_data(),
		&byte_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, status);
	}
	else if (byte_length != target->get_data_length())
	{
		target->reset();
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, eap_status_illegal_data_payload);
	}

	EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(this, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u8_t eap_am_tools_c::octet_to_ascii_armor(
	const u8_t source_byte)
{
	if (source_byte < 26u)
	{
		// 'A' ... 'Z'
		return static_cast<u8_t>((source_byte) + 'A');
	}
	else if (26u <= source_byte && source_byte < 52u)
	{
		// 'a' ... 'z'
		return static_cast<u8_t>((source_byte - 26u) + 'a');
	}
	else if (52u <= source_byte && source_byte < 62u)
	{
		// '0' ... '9'
		return static_cast<u8_t>(source_byte - 52u + '0');
	}
	else if (source_byte == 62u)
	{
		return static_cast<u8_t>('+');
	}
	else if (source_byte == 63u)
	{
		return static_cast<u8_t>('/');
	}
	else
	{
		return 0u;
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u8_t eap_am_tools_c::octet_from_ascii_armor(
	const u8_t source_byte)
{
	if ('A' <= source_byte && source_byte <= 'Z')
	{
		// 'A' ... 'Z'
		return static_cast<u8_t>((source_byte) - 'A');
	}
	else if ('a' <= source_byte && source_byte <= 'z')
	{
		// 'a' ... 'z'
		return static_cast<u8_t>((source_byte + 26u) - 'a');
	}
	else if ('0' <= source_byte && source_byte <= '9')
	{
		// '0' ... '9'
		return static_cast<u8_t>((source_byte + 52) - '0');
	}
	else if (source_byte == '+')
	{
		return 62;
	}
	else if (source_byte == '/')
	{
		return 63;
	}
	else
	{
		return 0u;
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_am_tools_c::convert_selected_bytes_to_ascii_armor(
	const u8_t source_byte,
	u32_t * const saved_bit_count,
	u8_t * const saved_bits,
	u8_t * const target,
	u32_t * const output_ind,
	const bool last_input_byte)
{
	u8_t value;

	if (*saved_bit_count == 0u)
	{
		/* |0 1 2 3 4 5 6 7|
		// +-+-+-+-+-+-+-+-+
		// | : : : : : : : |
		// +-+-+-+-+-+-+-+-+
		// |0 1 2 3 4 5|0 1 
		// |           +    
		// |            \   
		// |              \ 
		// |               +
		// |               |
		// |0 1 2 3 4 5 6 7|
		// +-+-+-+-+-+-+-+-+
		// | : : : : : : : |
		// +-+-+-+-+-+-+-+-+
		*/
		value = octet_to_ascii_armor(static_cast<u8_t>(source_byte >> 2u));
		*saved_bits = static_cast<u8_t>(source_byte & 0x03);
		*saved_bit_count = 2u;
		target[*output_ind] = value;
		++(*output_ind);
	}
	else if (*saved_bit_count == 2u)
	{
		/*  6 7|0 1 2 3 4 5 6 7|
		// +-+-+-+-+-+-+-+-+-+-+
		// : : | : : : : : : : |
		// +-+-+-+-+-+-+-+-+-+-+
		// |0 1 2 3 4 5|0 1 2 3 
		// |           +        
		// |            \       
		// +              \     
		//  \               \   
		//    \               \ 
		//     +               +
		//     |               |
		//  6 7|0 1 2 3 4 5 6 7|
		// +-+-+-+-+-+-+-+-+-+-+
		// : : | : : : : : : : |
		// +-+-+-+-+-+-+-+-+-+-+
		*/
		const u8_t src = static_cast<u8_t>(((*saved_bits) << 4u) | ((source_byte & 0xf0) >> 4u));
		value = octet_to_ascii_armor(src);
		*saved_bits = static_cast<u8_t>(source_byte & 0x0f);
		*saved_bit_count = 4u;
		target[*output_ind] = value;
		++(*output_ind);
	}
	else if (*saved_bit_count == 4u)
	{
		/*  4 5 6 7|0 1 2 3 4 5 6 7|
		// +-+-+-+-+-+-+-+-+-+-+-+-+
		// : : : : | : : : : : : : |
		// +-+-+-+-+-+-+-+-+-+-+-+-+
		// |0 1 2 3 4 5|0 1 2 3 4 5|
		// |           |           +
		// |           |            \               
		// |           +              \             
		// |            \               \           
		// +              \               \         
		//  \               \               \       
		//    \               \               \     
		//      \               \               \   
		//        \               \               \ 
		//         +               +               +
		//         |               |               |
		//  4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// : : : : | : : : : : : : | : : : : : : : |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		*/
		const u8_t src = static_cast<u8_t>(((*saved_bits) << 2u) | ((source_byte & 0xc0) >> 6u));
		value = octet_to_ascii_armor(src);
		target[*output_ind] = value;
		++(*output_ind);
		value = octet_to_ascii_armor(static_cast<u8_t>(source_byte & 0x3f));
		target[*output_ind] = value;
		++(*output_ind);
		*saved_bits = 0u;
		*saved_bit_count = 0u;
	}
	else
	{
		eap_am_tools_c *m_am_tools = this;
		EAP_UNREFERENCED_PARAMETER(m_am_tools);
		EAP_ASSERT(*saved_bit_count == 0u || *saved_bit_count == 2u || *saved_bit_count == 4u);
	}

	if (last_input_byte == true
		&& *saved_bit_count > 0u)
	{
		value = octet_to_ascii_armor(static_cast<u8_t>((*saved_bits) << (6u - *saved_bit_count)));
		target[*output_ind] = value;
		++(*output_ind);
		*saved_bits = 0u;
		*saved_bit_count = 0u;
	}

}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_am_tools_c::restore_selected_bytes_from_ascii_armor(
	const u8_t source_byte,
	u32_t * const missing_bit_count,
	u8_t * const target,
	u32_t * const output_ind,
	const bool last_input_byte)
{
	u8_t value;

	EAP_UNREFERENCED_PARAMETER(last_input_byte);

	if (source_byte == '=')
	{
		return;
	}

	if (*missing_bit_count == 0u)
	{
		/* |0 1 2 3 4 5 6 7|
		// +-+-+-+-+-+-+-+-+
		// | : : : : : : : |
		// +-+-+-+-+-+-+-+-+
		// |0 1 2 3 4 5|0 1 
		// |           +    
		// |            \   
		// |              \ 
		// |               +
		// |               |
		// |0 1 2 3 4 5 6 7|
		// +-+-+-+-+-+-+-+-+
		// | : : : : : : : |
		// +-+-+-+-+-+-+-+-+
		*/
		value = static_cast<u8_t>(octet_from_ascii_armor(source_byte) << 2u);
		target[*output_ind] = value;
		*missing_bit_count = 2u;
	}
	else if (*missing_bit_count == 2u)
	{
		/*  6 7|0 1 2 3 4 5 6 7|
		// +-+-+-+-+-+-+-+-+-+-+
		// : : | : : : : : : : |
		// +-+-+-+-+-+-+-+-+-+-+
		// |0 1 2 3 4 5|0 1 2 3 
		// |           +        
		// |            \       
		// +              \     
		//  \               \   
		//    \               \ 
		//     +               +
		//     |               |
		//  6 7|0 1 2 3 4 5 6 7|
		// +-+-+-+-+-+-+-+-+-+-+
		// : : | : : : : : : : |
		// +-+-+-+-+-+-+-+-+-+-+
		*/
		value = octet_from_ascii_armor(source_byte);
		target[*output_ind] = static_cast<u8_t>(target[*output_ind] | (value & 0x30) >> 4u);
		++(*output_ind);
		if (last_input_byte == false)
		{
			target[*output_ind] = static_cast<u8_t>((value & 0x0f) << 4u);
			*missing_bit_count = 4u;
		}
		else
		{
			*missing_bit_count = 0u;
		}
	}
	else if (*missing_bit_count == 4u)
	{
		/*  4 5 6 7|0 1 
		// +-+-+-+-+-+-+
		// : : : : | : :
		// +-+-+-+-+-+-+
		// |0 1 2 3 4 5|
		// |           +            
		// |            \           
		// +              \         
		//  \               \       
		//    \               \     
		//      \               \   
		//        \               \ 
		//         +               +
		//         |               |
		//  4 5 6 7|0 1 2 3 4 5 6 7|
		// +-+-+-+-+-+-+-+-+-+-+-+-+
		// : : : : | : : : : : : : |
		// +-+-+-+-+-+-+-+-+-+-+-+-+
		*/
		value = octet_from_ascii_armor(source_byte);
		target[*output_ind] = static_cast<u8_t>(target[*output_ind] | ((value >> 2u) & 0x0f));
		++(*output_ind);
		if (last_input_byte == false)
		{
			target[*output_ind] = static_cast<u8_t>((value & 0x03) << 6u);
			*missing_bit_count = 6u;
		}
		else
		{
			*missing_bit_count = 0u;
		}
	}
	else if (*missing_bit_count == 6u)
	{
		/*  2 3 4 5 6 7|
		// +-+-+-+-+-+-+
		// : : : : : : |
		// +-+-+-+-+-+-+
		// |0 1 2 3 4 5|
		// |           +                
		// |            \               
		// +              \             
		//  \               \           
		//    \               \         
		//      \               \       
		//        \               \     
		//          \               \   
		//            \               \ 
		//             +               +
		//             |               |
		//  2 3 4 5 6 7|0 1 2 3 4 5 6 7|
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// : : : : : : | : : : : : : : |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		*/
		value = octet_from_ascii_armor(source_byte);
		target[*output_ind] = static_cast<u8_t>(target[*output_ind] | value);
		++(*output_ind);
		*missing_bit_count = 0u;
	}
	else
	{
		eap_am_tools_c *m_am_tools = this;
		EAP_UNREFERENCED_PARAMETER(m_am_tools);
		EAP_ASSERT(*missing_bit_count == 0u || *missing_bit_count == 2u || *missing_bit_count == 4u || *missing_bit_count == 6u);
	}

}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::convert_bytes_to_ascii_armor(
	const u8_t * const source_bytes,
	const u32_t source_bytes_length,
	u8_t * const target,
	u32_t *target_length)
{
	if (source_bytes == 0)
	{
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, eap_status_illegal_parameter);
	}

	if (target == 0)
	{
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, eap_status_illegal_parameter);
	}

	if (target_length == 0)
	{
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, eap_status_illegal_parameter);
	}

	/* 8-bit ascii values are converted to binary 6-bit blocks. Ascii values can easily represent 2^6=64 values.
	// If length of source array is not module 3, missing bits are padded with zero bits.

	// |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|                                
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                        
	// | : : : : : : : | : : : : : : : | : : : : : : : | : : : : : : : |0:0:0:0|                        
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                        
	// |0 1 2 3 4 5|0 1 2 3 4 5|0 1 2 3 4 5|0 1 2 3 4 5|0 1 2 3 4 5|0 1 2 3 4 5|                        
	// |           |           |           |           |           |           +                        
	// |           |           |           |           |           |            \                       
	// |           |           |           |           |           +              \                     
	// |           |           |           |           |            \               \                   
	// |           |           |           |           +              \               \                 
	// |           |           |           |            \               \               \                
	// |           |           |           +              \               \               \             
	// |           |           |            \               \               \               \           
	// |           |           +              \               \               \               \         
	// |           |            \               \               \               \               \       
	// |           +              \               \               \               \               \     
	// |            \               \               \               \               \               \   
	// |              \               \               \               \               \               \ 
	// |               +               +               +               +               +               +
	// |               |               |               |               |               |               |
	// |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | : : : : : : : | : : : : : : : | : : : : : : : | : : : : : : : | : : : : : : : | : : : : : : : |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	u32_t output_ind = 0u;
	u32_t input_ind = 0u;
	u32_t input_count = (source_bytes_length*4u < (*target_length)*3u) ? source_bytes_length : (*target_length)*3u/4u;
	u8_t saved_bits = 0u;
	u32_t saved_bit_count = 0ul;

	for (input_ind = 0u; input_ind < input_count; input_ind++)
	{
		convert_selected_bytes_to_ascii_armor(source_bytes[input_ind], &saved_bit_count, &saved_bits, target, &output_ind, (input_ind+1 == input_count));
	} // for()

	u32_t remainder = output_ind % 4ul;
	if (remainder != 0ul)
	{
		u32_t padding_count(4ul - remainder);

		if (padding_count == 2ul)
		{
			// Add padding '='-characters.
			target[output_ind++] = '=';
			--padding_count;
		}
		if (padding_count == 1ul)
		{
			// Add padding '='-characters.
			target[output_ind++] = '=';
		}
	}

	*target_length = output_ind;

	return eap_status_ok;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::restore_bytes_from_ascii_armor(
	const u8_t * const source_bytes,
	const u32_t source_bytes_length,
	u8_t * const target,
	u32_t *target_length)
{
	if (source_bytes == 0)
	{
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, eap_status_illegal_parameter);
	}

	if (target == 0)
	{
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, eap_status_illegal_parameter);
	}

	if (target_length == 0)
	{
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, eap_status_illegal_parameter);
	}

	/* Binary 6-bit blocks are converted to 8-bit ascii values. Ascii values can easily represent 2^6=64 values.
	// If length of target array is not module 3, padding zero bits are ignored.

	// |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|                                
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                
	// | : : : : : : : | : : : : : : : | : : : : : : : | : : : : : : : |                                
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                
	// |0 1 2 3 4 5|0 1 2 3 4 5|0 1 2 3 4 5|0 1 2 3 4 5|0 1 2 3 4 5|0 1 2 3 4 5|                        
	// |           |           |           |           |           |           +                        
	// |           |           |           |           |           |            \                       
	// |           |           |           |           |           +              \                     
	// |           |           |           |           |            \               \                   
	// |           |           |           |           +              \               \                 
	// |           |           |           |            \               \               \                
	// |           |           |           +              \               \               \             
	// |           |           |            \               \               \               \           
	// |           |           +              \               \               \               \         
	// |           |            \               \               \               \               \       
	// |           +              \               \               \               \               \     
	// |            \               \               \               \               \               \   
	// |              \               \               \               \               \               \ 
	// |               +               +               +               +               +               +
	// |               |               |               |               |               |               |
	// |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | : : : : : : : | : : : : : : : | : : : : : : : | : : : : : : : | : : : : : : : | : : : : : : : |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	u32_t output_ind = 0u;
	u32_t input_ind = 0u;
	u32_t input_count = source_bytes_length;
	u32_t missing_bit_count = 0ul;

	for (input_ind = 0u; input_ind < input_count; input_ind++)
	{
		restore_selected_bytes_from_ascii_armor(source_bytes[input_ind], &missing_bit_count, target, &output_ind, (input_ind+1 == input_count));
	} // for()

	*target_length = output_ind;

	return eap_status_ok;
}

//-----------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::eap_status_return(
	const bool print_error_when_true,
	const eap_status_e status,
	const eap_char * const file_name,
	const i32_t line_number)
{
	if (status == eap_status_not_supported)
	{
		eap_status_string_c status_string;

		EAP_UNREFERENCED_PARAMETER(file_name);
		EAP_UNREFERENCED_PARAMETER(line_number);

		EAP_TRACE_DEBUG(
			this,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TODO: %s=%d returned from %s:%d\n"),
			status_string.get_status_string(status),
			status,
			file_name,
			line_number));
	}
	else if (status == eap_status_success)
	{
		eap_status_string_c status_string;

		EAP_TRACE_DEBUG(
			this,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SUCCESS: %s=%d returned from %s:%d\n"),
			status_string.get_status_string(status),
			status,
			file_name,
			line_number));
	}
	else if (status == eap_status_not_found
		|| status == eap_status_illegal_configure_field
		|| status == eap_status_illegal_configure_type
		|| status == eap_status_syncronization_failure)
	{
		eap_status_string_c status_string;

		EAP_TRACE_DEBUG(
			this,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: %s=%d returned from %s:%d\n"),
			status_string.get_status_string(status),
			status,
			file_name,
			line_number));
	}
	else if (status == eap_status_pending_request
		|| status == eap_status_completed_request
		|| status == eap_status_drop_packet_quietly
		|| status == eap_status_end_of_file
		|| status == eap_status_section_ends
		|| status == eap_status_end_recursion)
	{
		eap_status_string_c status_string;

		EAP_TRACE_DEBUG(
			this,
			TRACE_FLAGS_DEFAULT,
			(EAPL("INFO: %s=%d returned from %s:%d\n"),
			status_string.get_status_string(status),
			status,
			file_name,
			line_number));
	}
#if defined(_DEBUG)
	else if ((get_trace_mask() & TRACE_FLAGS_OK_RETURNS)
		&& (status == eap_status_ok
			|| status == eap_status_success
			|| status == eap_status_not_supported
			|| status == eap_status_pending_request
			|| status == eap_status_completed_request
			|| status == eap_status_drop_packet_quietly)
		)
	{
		eap_status_string_c status_string;

		EAP_TRACE_DEBUG(
			this,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EXTRA: %s=%d returned from %s:%d\n"),
			status_string.get_status_string(status),
			status,
			file_name,
			line_number));
	}
#endif
	else if (status != eap_status_ok
		&& status != eap_status_success
		&& status != eap_status_not_supported
		&& status != eap_status_pending_request
		&& status != eap_status_completed_request
		&& status != eap_status_drop_packet_quietly
		)
	{
		check_activate_trace_on_error();

		eap_status_string_c status_string;

		if (print_error_when_true == true)
		{
			EAP_TRACE_ALWAYS(
				this,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: %s=%d returned from %s:%d\n"),
				status_string.get_status_string(status),
				status,
				file_name,
				line_number));
		}
		else
		{
			EAP_TRACE_ALWAYS(
				this,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: %s=%d returned from %s:%d\n"),
				status_string.get_status_string(status),
				status,
				file_name,
				line_number));
		}
	}

	return status;
}

//-----------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::eap_status_return_file_number(
	const bool print_error_when_true,
	const eap_status_e status,
	const u32_t file_date,
	const u32_t file_number,
	const i32_t line_number)
{
	if (status == eap_status_not_supported)
	{
		eap_status_string_c status_string;

		EAP_UNREFERENCED_PARAMETER(file_date);
		EAP_UNREFERENCED_PARAMETER(file_number);
		EAP_UNREFERENCED_PARAMETER(line_number);

		EAP_TRACE_DEBUG(
			this,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TODO: %d:%d:%d:%d\n"),
			status,
			file_date,
			file_number,
			line_number));
	}
	else if (status == eap_status_success)
	{
		EAP_TRACE_DEBUG(
			this,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SUCCESS: %d:%d:%d:%d\n"),
			status,
			file_date,
			file_number,
			line_number));
	}
	else if (status == eap_status_not_found
		|| status == eap_status_illegal_configure_field
		|| status == eap_status_illegal_configure_type
		|| status == eap_status_syncronization_failure)
	{
		EAP_TRACE_DEBUG(
			this,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: %d:%d:%d:%d\n"),
			status,
			file_date,
			file_number,
			line_number));
	}
	else if (status == eap_status_pending_request
		|| status == eap_status_completed_request
		|| status == eap_status_drop_packet_quietly
		|| status == eap_status_end_of_file
		|| status == eap_status_section_ends)
	{
		EAP_TRACE_DEBUG(
			this,
			TRACE_FLAGS_DEFAULT,
			(EAPL("INFO: %d:%d:%d:%d\n"),
			status,
			file_date,
			file_number,
			line_number));
	}
	else if (status != eap_status_ok
		&& status != eap_status_success
		&& status != eap_status_not_supported
		&& status != eap_status_pending_request
		&& status != eap_status_completed_request
		&& status != eap_status_drop_packet_quietly

		)
	{
		check_activate_trace_on_error();

		if (print_error_when_true == true)
		{
			EAP_TRACE_ALWAYS(
				this,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: %d:%d:%d:%d\n"),
				status,
				file_date,
				file_number,
				line_number));
		}
		else
		{
			EAP_TRACE_ALWAYS(
				this,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: %d:%d:%d:%d\n"),
				status,
				file_date,
				file_number,
				line_number));
		}
	}

	return status;
}

//-----------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::memory_store_add_data(
	const eap_variable_data_c * const key,
	eap_tlv_message_data_c * const data,
	const u32_t timeout)
{
	EAP_TRACE_BEGIN(this, TRACE_FLAGS_DEFAULT);

#if !defined(NO_EAP_AM_MEMORY_STORE)

	if (m_memory_store == 0
		|| 	m_memory_store->get_is_valid() == false)
	{
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, eap_status_allocation_error);
	}

	eap_status_e status = m_memory_store->add_data(
		key,
		data,
		timeout);

	EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(this, status);

#else

	EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(this, eap_status_not_supported);

#endif //#if !defined(NO_EAP_AM_MEMORY_STORE)
}

//-----------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::memory_store_get_data(
	const eap_variable_data_c * const key,
	eap_tlv_message_data_c * const data)
{
	EAP_TRACE_BEGIN(this, TRACE_FLAGS_DEFAULT);

#if !defined(NO_EAP_AM_MEMORY_STORE)

	if (m_memory_store == 0
		|| 	m_memory_store->get_is_valid() == false)
	{
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, eap_status_allocation_error);
	}

	eap_status_e status = eap_status_process_general_error;

	status = m_memory_store->get_data(
		key,
		data);

	EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(this, status);

#else

	EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(this, eap_status_not_found);

#endif //#if !defined(NO_EAP_AM_MEMORY_STORE)

}

//-----------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::memory_store_remove_data(
	const eap_variable_data_c * const key)
{
	EAP_TRACE_BEGIN(this, TRACE_FLAGS_DEFAULT);

#if !defined(NO_EAP_AM_MEMORY_STORE)

	if (m_memory_store == 0
		|| 	m_memory_store->get_is_valid() == false)
	{
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, eap_status_allocation_error);
	}

	eap_status_e status = m_memory_store->remove_data(
		key);

	EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(this, status);

#else

	EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(this, eap_status_not_found);

#endif //#if !defined(NO_EAP_AM_MEMORY_STORE)
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::shutdown_am_tools()
{
	eap_status_e status = eap_status_ok;

	EAP_TRACE_DEBUG(
		this,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_tools_c::shutdown_am_tools(): this = 0x%08x\n"),
		 this));

	if (m_shutdown_was_called == false)
	{
		m_shutdown_was_called = true;
		
		// stop tracing as tools get deleted
		set_trace_mask(eap_trace_mask_none);

		#if !defined(NO_EAP_AM_MEMORY_STORE)
		(void) am_cancel_all_timers();
		if (m_memory_store != 0)
		{
			status = m_memory_store->shutdown();
		}
		delete m_memory_store;
		m_memory_store = 0;
		#endif //#if !defined(NO_EAP_AM_MEMORY_STORE)
	}

	return EAP_STATUS_RETURN(this, status);
}

//--------------------------------------------------

/// Coverts unicode string to UTF8 string.
EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::generic_convert_unicode_to_utf8(
	eap_variable_data_c & dest,
	const eap_variable_data_c & src)
{
	if (src.get_is_valid_data() == true)
	{
		u32_t len = src.get_data_length();
		u8_t * ascii = new u8_t[len / 2];
		if (!ascii)
		{
			return EAP_STATUS_RETURN(this, eap_status_allocation_error);
		}
		u8_t * src_ptr = src.get_data(len);
		u32_t dest_len = len / 2;
		u32_t i;
		for (i = 0; i < dest_len; i++)
		{
			ascii[i] = src_ptr[i * 2];
		}

		return EAP_STATUS_RETURN(this, dest.set_buffer(ascii, dest_len, true, true));
	}

	return EAP_STATUS_RETURN(this, eap_status_process_general_error);
}

//--------------------------------------------------

/// Coverts UTF8 string to unicode string. Not yet implemented.
EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::generic_convert_utf8_to_unicode(
	eap_variable_data_c & dest,
	const eap_variable_data_c & src)
{
	if (src.get_is_valid_data() == true)
	{
		u32_t len = src.get_data_length();
		u8_t * src_ptr = src.get_data(len);

		eap_status_e status = dest.set_buffer_length(2ul*len);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(this, status);
		}

		u8_t null_byte(0x00);
		u32_t i;
		for (i = 0; i < len; i++)
		{
			status = dest.add_data(&(src_ptr[i]), sizeof(u8_t));
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(this, status);
			}

			status = dest.add_data(&null_byte, sizeof(u8_t));
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(this, status);
			}
		}

		return EAP_STATUS_RETURN(this, eap_status_ok);
	}

	return EAP_STATUS_RETURN(this, eap_status_process_general_error);
}

//-----------------------------------------------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::parse_nai(
	const eap_variable_data_c * const nai,
	eap_variable_data_c * const username,
	eap_variable_data_c * const realm)
{
	if (nai == 0
		|| username == 0
		|| realm == 0)
	{
		return EAP_STATUS_RETURN(this, eap_status_illegal_parameter);
	}

	username->reset();
	realm->reset();

	if (nai->get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(this, eap_status_illegal_parameter);
	}

	EAP_TRACE_DATA_DEBUG(
		this,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_tools_c::parse_nai(): NAI"),
		nai->get_data(),
		nai->get_data_length()));


	eap_status_e status(eap_status_ok);
	u32_t username_length = nai->get_data_length();

	// We read the realm from NAI.
	const u8_t *at_character = reinterpret_cast<const u8_t *>(
		memchr(
			nai->get_data(nai->get_data_length()),
			EAP_AT_CHARACTER,
			nai->get_data_length()));
	if (at_character != 0
		&& nai->get_data_length()
		> ((1UL + reinterpret_cast<u32_t>(at_character))
		   - reinterpret_cast<u32_t>(nai->get_data(
										 nai->get_data_length()))))
	{
		u32_t realm_length = nai->get_data_length()
			- ((1UL + reinterpret_cast<u32_t>(at_character))
			   - reinterpret_cast<u32_t>(nai->get_data(
											 nai->get_data_length())));
		
		if (realm_length > 0UL)
		{
			status = realm->set_copy_of_buffer(
				at_character+1,
				realm_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(this, status);
			}

			username_length -= (realm_length + 1ul);
		}
	}
	else
	{
		// No realm.
	}

	// The begin of the NAI to '@' or the end is username.
	status = username->set_copy_of_buffer(
		nai->get_data(username_length),
		username_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, status);
	}

	EAP_TRACE_DATA_DEBUG(
		this,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_tools_c::parse_nai(): username"),
		username->get_data(),
		username->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		this,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_tools_c::parse_nai(): realm"),
		realm->get_data(),
		realm->get_data_length()));

	EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(this, status);
}

//-----------------------------------------------------------------------------------------------

#if defined(USE_EAP_ERROR_TESTS)

//
EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::generate_random_error(
	eap_buf_chain_wr_c * const sent_packet,
	const bool forse_error,
	const u32_t packet_index,
	const u32_t minimum_index,
	const u32_t error_probability,
	const u32_t minimum_packet_length)
{
	eap_status_e status(eap_status_ok);
	EAP_UNREFERENCED_PARAMETER(packet_index);

	u8_t *data = sent_packet->get_data(sent_packet->get_data_length());
	if (data == 0)
	{
		return EAP_STATUS_RETURN(this, eap_status_allocation_error);
	}

	crypto_random_c rand(this);
	u32_t random_guard = 0;
	bool error_generated = false;

	for (u32_t ind = minimum_index; ind < sent_packet->get_data_length(); ind++)
	{
		status = rand.get_rand_bytes(
			reinterpret_cast<u8_t *>(&random_guard),
			sizeof(random_guard));
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(this, status);
		}

		// This is simple limiter to the probability of an error.
		// probability = m_error_probability / (2^32)
		if (random_guard < error_probability)
		{
			u8_t rnd;
			u8_t previous_data;
			// Create an error.
			status = rand.get_rand_bytes(
				&rnd,
				sizeof(rnd));
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(this, status);
			}

			previous_data = data[ind];
			data[ind] = static_cast<u8_t>(data[ind] ^ rnd);

			if (previous_data != data[ind])
			{
				error_generated = true;
				sent_packet->set_random_error_type(eap_random_error_type_manipulate_byte);

				EAP_TRACE_DEBUG(
					this, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("TEST: random_error(): error: manipulate, packet_index 0x%08x:%lu, data[0x%04x] ")
					 EAPL("changed from 0x%02x to 0x%02x.\n"),
					this, packet_index, ind, previous_data, data[ind]));
			}
		}
	} // for()


	if (error_generated == false
		&& forse_error == true
		&& sent_packet->get_data_length() > 0ul)
	{
		// Generate one error.

		// Random error type.
		eap_random_error_type error_type = eap_random_error_type_none_keep_this_last_case;
		status = rand.get_rand_bytes(
			reinterpret_cast<u8_t *>(&error_type),
			sizeof(error_type));
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(this, status);
		}

		error_type = static_cast<eap_random_error_type>(
			static_cast<u32_t>(error_type)
			% static_cast<u32_t>(eap_random_error_type_none_keep_this_last_case));

		sent_packet->set_random_error_type(error_type);

		switch(error_type)
		{
		case eap_random_error_type_manipulate_byte:
			{
				u32_t rnd_index;
				u8_t previous_data;
				u32_t index;

				do
				{
					do
					{
						// Create an error index.
						status = rand.get_rand_bytes(
							reinterpret_cast<u8_t *>(&rnd_index),
							sizeof(rnd_index));
						if (status != eap_status_ok)
						{
							return EAP_STATUS_RETURN(this, status);
						}

						index = (rnd_index % (sent_packet->get_data_length() - minimum_index))
							+ minimum_index;
					}
					while(index < minimum_index
						|| index > sent_packet->get_buffer_length());

					u8_t rnd;
					// Create an error.
					status = rand.get_rand_bytes(
						&rnd,
						sizeof(rnd));
					if (status != eap_status_ok)
					{
						return EAP_STATUS_RETURN(this, status);
					}

					previous_data = data[index];
					data[index] = static_cast<u8_t>(data[index] ^ rnd);
				}
				while(previous_data == data[index]);

				EAP_TRACE_DEBUG(
					this, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("TEST: random_error(): error: manipulate, packet_index 0x%08x:%lu, ")
					 EAPL("data[0x%04x] changed from 0x%02x to 0x%02x.\n"),
					this, packet_index, index, previous_data, data[index]));

				error_generated = true;
			}
			break;
		case eap_random_error_type_change_packet_length_longer:
			{
				u8_t delta_length = 0;
				i32_t new_length = 0;

				do
				{
					status = rand.get_rand_bytes(
						reinterpret_cast<u8_t *>(&delta_length),
						sizeof(delta_length));
					if (status != eap_status_ok)
					{
						return EAP_STATUS_RETURN(this, status);
					}

					new_length = static_cast<i32_t>(sent_packet->get_data_length()) + static_cast<i32_t>(delta_length);
				}
				while (new_length < static_cast<i32_t>(minimum_packet_length) /*eapol_ethernet_header_wr_c::get_header_length()*/
					|| new_length > static_cast<i32_t>(sent_packet->get_buffer_length()));

				EAP_TRACE_DEBUG(
					this, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("TEST: random_error(): error: manipulate, packet_index 0x%08x:%lu, ")
					 EAPL("packet length changed from %lu to %lu.\n"),
					this,
					packet_index,
					sent_packet->get_data_length(),
					new_length));

				sent_packet->set_data_length(new_length);

				error_generated = true;
			}
			break;
		case eap_random_error_type_change_packet_length_shorter:
			{
				u8_t delta_length = 0;
				i32_t new_length = 0;

				do
				{
					status = rand.get_rand_bytes(
						reinterpret_cast<u8_t *>(&delta_length),
						sizeof(delta_length));
					if (status != eap_status_ok)
					{
						return EAP_STATUS_RETURN(this, status);
					}

					delta_length = static_cast<u8_t>(delta_length % (static_cast<i32_t>(sent_packet->get_data_length())
													- static_cast<i32_t>(minimum_packet_length)));

					if (delta_length == 0)
					{
						continue;
					}

					new_length = static_cast<i32_t>(sent_packet->get_data_length()) - static_cast<i32_t>(delta_length);
				}
				while (new_length < static_cast<i32_t>(minimum_packet_length) /*eapol_ethernet_header_wr_c::get_header_length()*/
					|| new_length > static_cast<i32_t>(sent_packet->get_buffer_length()));

				EAP_TRACE_DEBUG(
					this, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("TEST: random_error(): error: manipulate, packet_index 0x%08x:%lu, ")
					 EAPL("packet length changed from %lu to %lu.\n"),
					this,
					packet_index,
					sent_packet->get_data_length(),
					new_length));

				sent_packet->set_data_length(new_length);

				error_generated = true;
			}
			break;
		default:
			EAP_ASSERT_ANYWAY_TOOLS(this);
			break;
		}
	} // if ()


	if (error_generated == true)
	{
		sent_packet->set_is_manipulated();
	}

	EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(this, status);
}

#endif //#if defined(USE_EAP_ERROR_TESTS)

//-----------------------------------------------------------------------------------------------

#if defined(USE_EAP_ERROR_TESTS)

EAP_FUNC_EXPORT u32_t eap_am_tools_c::get_packet_index()
{
	return m_packet_index;
}

#endif //#if defined(USE_EAP_ERROR_TESTS)

//-----------------------------------------------------------------------------------------------

#if defined(USE_EAP_ERROR_TESTS)

EAP_FUNC_EXPORT void eap_am_tools_c::increase_packet_index()
{
	++m_packet_index;
}

#endif //#if defined(USE_EAP_ERROR_TESTS)

//-----------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::number_string_to_u32(
	const u8_t * const number_string,
	const u32_t number_string_length,
	u32_t * const integer)
{
	EAP_TRACE_BEGIN(this, TRACE_FLAGS_DEFAULT);

	if (number_string == 0
		|| number_string_length == 0UL
		|| integer == 0)
	{
		EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(this, eap_status_illegal_parameter);
	}

	*integer = 0UL;

	u32_t multiplier = 1UL;

	for (i32_t ind = number_string_length-1; ind >= 0; ind--)
	{
		u8_t character = number_string[ind];
		if (character < '0' || '9' < character)
		{
			EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(this, eap_status_illegal_data_payload);
		}

		u8_t digit = ascii_to_octet(static_cast<i32_t>(number_string[ind]));

		u32_t addition = static_cast<u32_t>(digit) * multiplier;
		if (((~0UL) - *integer) < addition)
		{
			EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(this, eap_status_illegal_data_payload);
		}

		*integer += addition;

		multiplier *= 10UL;
	}

	EAP_TRACE_END(this, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(this, eap_status_ok);
}

//-----------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT void eap_am_tools_c::trace_configuration(
	const eap_status_e configuration_read_status,
	const eap_configuration_field_c * const field,
	const eap_variable_data_c * const data)
{
	EAP_UNREFERENCED_PARAMETER(data);

	if (configuration_read_status != eap_status_ok)
	{
		EAP_TRACE_DATA_DEBUG(
			this,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: unknown configuration parameter"),
			field->get_field(),
			field->get_field_length()));
	}
	else
	{
		EAP_TRACE_DATA_ALWAYS(
			this,
			TRACE_FLAGS_DEFAULT,
			(EAPL("configuration parameter"),
			field->get_field(),
			field->get_field_length()));

		if (field->get_is_secret() == true)
		{
			EAP_TRACE_DEBUG(
				this, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("This is secret data. Not shown here.\n")));
		}
		else
		{
			EAP_TRACE_DATA_ALWAYS(
				this,
				TRACE_FLAGS_DEFAULT,
				(EAPL("    configuration value"),
				data->get_data(data->get_data_length()),
				data->get_data_length()));
		}
	}
}

//-----------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT u64_t eap_am_tools_c::xor_u64(
	const u64_t p_a,
	const u64_t p_b)
{

#if defined(USE_EAP_64_BIT_XOR)

	u64_t ret = p_a ^ p_b;

#else

	u64_struct a = u64_t_to_u64_struct(p_a);
	u64_struct b = u64_t_to_u64_struct(p_b);


	// Result
	u64_struct result;
	result.high = a.high ^ b.high;
	result.low = a.low ^ b.low;
	
	u64_t ret = u64_struct_to_u64_t(result);

#endif //#if defined(USE_EAP_64_BIT_XOR)

	return ret;
}

//-----------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT u64_t eap_am_tools_c::multiply_u64(
	const u64_t p_a,
	const u64_t p_b)
{

#if defined(USE_EAP_64_BIT_MULTIPLICATION)

	return p_a * p_b;

#else

	u32_t a_tmp[4];
	u32_t b_tmp[4];
	u32_t wide_tmp[8];
	u32_t tmp;
	u64_struct a = u64_t_to_u64_struct(p_a);
	u64_struct b = u64_t_to_u64_struct(p_b);

	//  <--- 32 bits ---> <--- 32 bits ---> <--- 32 bits ---> <--- 32 bits --->
	// +--------+--------+--------+--------+--------+--------+--------+--------+
	// | overf. |  0-15  | overf. |  16-31 | overf. |  32-47 | overf. |  48-63 |
	// +--------+--------+--------+--------+--------+--------+--------+--------+
	a_tmp[0] = a.low & 0xffff;
	a_tmp[1] = (a.low >> 16) & 0xffff;
	a_tmp[2] = a.high & 0xffff;
	a_tmp[3] = (a.high >> 16) & 0xffff;

	b_tmp[0] = b.low & 0xffff;
	b_tmp[1] = (b.low >> 16) & 0xffff;
	b_tmp[2] = b.high & 0xffff;
	b_tmp[3] = (b.high >> 16) & 0xffff;

	u32_t j_ind;

	for(j_ind = 0ul; j_ind < 4ul; j_ind++)
	{
		wide_tmp[j_ind]= 0ul;
	}

	for(j_ind = 0ul; j_ind < 4ul; j_ind++)
	{
		if(b_tmp[j_ind] == 0ul)
		{
			wide_tmp[j_ind+4ul] = 0ul;
		}
		else
		{
			u32_t l_ind;
			u32_t overflow = 0ul;

			for(l_ind = 0ul; l_ind < 4ul; l_ind++)
			{
				tmp = a_tmp[l_ind] * b_tmp[j_ind] + wide_tmp[l_ind+j_ind] + overflow;
				wide_tmp[l_ind+j_ind] = tmp & 0xffff;
				overflow = (tmp >> 16) & 0xffff;
			}

			wide_tmp[j_ind+4] = overflow;
		}
	}

	// Overflow
	u64_struct overflow;
	overflow.high = ((wide_tmp[7] << 16) & 0xffff0000) + wide_tmp[6];
	overflow.low = ((wide_tmp[5] << 16) & 0xffff0000) + wide_tmp[4];
	EAP_UNREFERENCED_PARAMETER(overflow);


	// Result
	u64_struct result;
	result.high = ((wide_tmp[3] << 16) & 0xffff0000) + wide_tmp[2];
	result.low = ((wide_tmp[1] << 16) & 0xffff0000) + wide_tmp[0];
	
	u64_t ret = u64_struct_to_u64_t(result);

	return ret;

#endif //#if defined(USE_EAP_64_BIT_MULTIPLICATION)

}

//-----------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT i32_t eap_am_tools_c::compare_u64(const u64_t p_a, const u64_t p_b)
{
	u64_struct a = u64_t_to_u64_struct(p_a);
	u64_struct b = u64_t_to_u64_struct(p_b);

	if (a.high > b.high)
	{
		return +1;
	}
	else if (a.high < b.high)
	{
		return -1;
	}
	else // if (a.high == b.high)
	{
		if (a.low > b.low)
		{
			return +1;
		}
		else if (a.low < b.low)
		{
			return -1;
		}
		else
		{
			return 0;
		}
	}
}

//-----------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::create_uuid_v5( 
	const void* const ns_uuid,
	const u32_t ns_uuid_length,
	const void* const name, 
	const u32_t name_length,
	eap_variable_data_c* const uuid )
{
	// check input
	if( ns_uuid == 0 || 
		ns_uuid_length != EAP_UUID_LENGTH ||
		name == 0 || name_length <= 0 || 
		uuid == 0 || uuid->get_is_valid() == false )
	{
		return EAP_STATUS_RETURN(this, eap_status_illegal_parameter); 
	}

	// make sure that uuid is empty
	uuid->reset();

	crypto_sha1_c sha( this );
	if( sha.get_is_valid() == false )
	{
		return EAP_STATUS_RETURN(this, eap_status_allocation_error); 
	}

	u32_t hash_len = sha.get_digest_length();
	// hash length must be at least the UUID length
	if( hash_len < EAP_UUID_LENGTH )
	{
		return EAP_STATUS_RETURN(this, eap_status_illegal_encryption_parameter_size); 
	}

	eap_status_e status = sha.hash_init();
	if( status != eap_status_ok )
	{
		return EAP_STATUS_RETURN(this, status); 
	}

	status = sha.hash_update( ns_uuid, ns_uuid_length );
	if( status != eap_status_ok )
	{
		return EAP_STATUS_RETURN(this, status); 
	}

	status = sha.hash_update( name, name_length );
	if( status != eap_status_ok )
	{
		return EAP_STATUS_RETURN(this, status); 
	}

	u8_t* hash = new u8_t[hash_len];
	if( hash == 0 )
	{
		return EAP_STATUS_RETURN(this, eap_status_allocation_error); 
	}

	status = sha.hash_final( hash, 0 ); // 0 - we have space for full digest in hash
	if( status != eap_status_ok )
	{
		delete[] hash;
		hash = 0;
		return EAP_STATUS_RETURN(this, status); 
	}

	// save only the needed bytes
	status = uuid->set_copy_of_buffer(hash, EAP_UUID_LENGTH );
	delete[] hash;
	if( status != eap_status_ok )
	{
		return EAP_STATUS_RETURN(this, status); 
	}

	// use hash as a temporary pointer
	hash = uuid->get_data();

	// Format according to UUID version 5 (RFC 4122).
	// MSByte                                                     LSByte
	// 0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                          time_low                             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |       time_mid                |         time_hi_and_version   |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |clk_seq_hi_res |  clk_seq_low  |         node (0-1)            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                         node (2-5)                            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	// set the four most significant bits (bits 12 through 15) of the
	// time_hi_and_version field to the appropriate 4-bit version number
	hash[6] = static_cast<u8_t>(hash[6] & 0x0F);
	hash[6] = static_cast<u8_t>(hash[6] | 0x50);

	// set the two most significant bits (bits 6 and 7) of the
    // clock_seq_hi_and_reserved to zero and one, respectively
	hash[8] = static_cast<u8_t>(hash[8] & 0x3F);
	hash[8] = static_cast<u8_t>(hash[8] | 0x80);

	return EAP_STATUS_RETURN(this, eap_status_ok);
}

//-----------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_tools_c::create_uuid_v5_from_mac_address( 
	const u8_t* const mac_address,
	const u32_t mac_address_length,
	eap_variable_data_c* const uuid )
{

	eap_status_e status = create_uuid_v5( 
		EAP_MAC_ADDRESS_NAMESPACE_UUID_V5,
		sizeof(EAP_MAC_ADDRESS_NAMESPACE_UUID_V5),
		mac_address,
		mac_address_length,
		uuid);

	return EAP_STATUS_RETURN(this, status);
}
		
//-----------------------------------------------------------------------------------------------

// End.
