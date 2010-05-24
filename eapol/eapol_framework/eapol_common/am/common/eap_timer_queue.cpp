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
	#define EAP_FILE_NUMBER_ENUM 15 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_am_memory.h"
#include "eap_timer_queue.h"

//--------------------------------------------------

#if defined(USE_EAP_TIMER_QUEUE_TRACE)
	#define EAP_TRACE_TIMER EAP_TRACE_DEBUG
#else
	#define EAP_TRACE_TIMER(object, flags, parameters)
#endif //#if defined(USE_EAP_TIMER_QUEUE_TRACE)

//--------------------------------------------------

// 
eap_timer_queue_event_c::~eap_timer_queue_event_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_initializer->timer_delete_data(m_id, m_data);
	m_initializer = 0;
	m_id = 0;
	m_data = 0;
	m_hash = 0;
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
eap_timer_queue_event_c::eap_timer_queue_event_c(
	abs_eap_am_tools_c * const tools, 
	abs_eap_base_timer_c * const initializer, 
	const u32_t id, 
	void * const data,
	const u32_t p_time_ms)
	: m_am_tools(tools)
	, m_initializer(initializer)
	, m_id(id)
	, m_data(data)
	, m_time_ms(p_time_ms)
	, m_original_time_ms(p_time_ms)
	, m_prev(0)
	, m_next(0)
	, m_hash(0)
	, m_prev_same_time(0)
	, m_next_same_time(0)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
u32_t eap_timer_queue_event_c::get_time() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_time_ms;
}

//--------------------------------------------------

// 
u32_t eap_timer_queue_event_c::get_original_time() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_original_time_ms;
}

//--------------------------------------------------

// 
eap_timer_queue_event_c *eap_timer_queue_event_c::get_prev() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_prev;
}

//--------------------------------------------------

// 
eap_timer_queue_event_c *eap_timer_queue_event_c::get_next() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_next;
}

//--------------------------------------------------

// 
eap_timer_queue_event_c *eap_timer_queue_event_c::get_prev_same_time() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_prev_same_time;
}

//--------------------------------------------------

// 
eap_timer_queue_event_c *eap_timer_queue_event_c::get_next_same_time() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_next_same_time;
}

//--------------------------------------------------

// 
eap_timer_queue_hash_c * eap_timer_queue_event_c::get_hash() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_hash;
}

//--------------------------------------------------

// 
u32_t eap_timer_queue_event_c::pulse_time(const u32_t resolution)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	if (m_time_ms >= resolution)
	{
		m_time_ms -= resolution;
		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return 0u;
	}
	else
	{
		u32_t remainder = resolution - m_time_ms;
		m_time_ms = 0u;
		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return remainder;
	}
}

//--------------------------------------------------

// 
void eap_timer_queue_event_c::decrease_time_left(const u32_t decrease_time)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_time_ms > decrease_time)
	{
		m_time_ms -= decrease_time;
	}
	else
	{
		m_time_ms = 0u;
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
void eap_timer_queue_event_c::increase_time_left(const u32_t increase_time)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_time_ms += increase_time;
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
void eap_timer_queue_event_c::set_prev(eap_timer_queue_event_c * const prev)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_prev = prev;
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
void eap_timer_queue_event_c::set_next(eap_timer_queue_event_c * const next)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_next = next;
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
void eap_timer_queue_event_c::set_prev_same_time(eap_timer_queue_event_c * const prev_same_time)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_prev_same_time = prev_same_time;
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
void eap_timer_queue_event_c::set_next_same_time(eap_timer_queue_event_c * const next_same_time)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_next_same_time = next_same_time;
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
void eap_timer_queue_event_c::set_hash(eap_timer_queue_hash_c * const hash)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_hash = hash;
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
abs_eap_base_timer_c * eap_timer_queue_event_c::get_initializer() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_initializer;
}

//--------------------------------------------------

// 
u32_t eap_timer_queue_event_c::get_id() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_id;
}

//--------------------------------------------------

// 
void * eap_timer_queue_event_c::get_data() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_data;
}

//--------------------------------------------------

// 
u32_t eap_timer_queue_event_c::get_time_ms()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_time_ms;
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

// 
eap_timer_queue_hash_c::~eap_timer_queue_hash_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_atom = 0;
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

	//--------------------------------------------------

// 
eap_timer_queue_hash_c::eap_timer_queue_hash_c(
	abs_eap_am_tools_c * const tools, 
	eap_timer_queue_event_c * const atom,
	const u32_t index)
	: m_am_tools(tools)
	, m_index(index)
	, m_atom(atom)
	, m_prev(0)
	, m_next(0)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
eap_timer_queue_hash_c *eap_timer_queue_hash_c::get_next() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_next;
}

//--------------------------------------------------

// 
eap_timer_queue_hash_c *eap_timer_queue_hash_c::get_prev() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_prev;
}

//--------------------------------------------------

// 
u32_t eap_timer_queue_hash_c::get_index() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_index;
}

//--------------------------------------------------

// 
void eap_timer_queue_hash_c::set_next(eap_timer_queue_hash_c * const next)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_next = next;
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
void eap_timer_queue_hash_c::set_prev(eap_timer_queue_hash_c * const prev)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_prev = prev;
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

eap_timer_queue_event_c * eap_timer_queue_hash_c::get_atom()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_atom;
}

//--------------------------------------------------

i32_t eap_timer_queue_hash_c::compare(
	const abs_eap_base_timer_c * const a_initializer, 
	const u32_t a_id,
	const abs_eap_base_timer_c * const b_initializer, 
	const u32_t b_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (a_id < b_id)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return -1;
	}
	else if (a_id > b_id)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return 1;
	}
	else if (a_initializer < b_initializer)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return -1;
	}
	else if (a_initializer > b_initializer)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return 1;
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return 0;
	}
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

eap_timer_queue_c::~eap_timer_queue_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	deactivate_timer_queue();

	trace_timer();

	EAP_TRACE_TIMER(
		m_am_tools,
		TRACE_FLAGS_TIMER_QUEUE,
		(EAPL("TIMER: eap_timer_queue_c::~eap_timer_queue_c(): m_timer_queue=0x%08x, m_new_event_begin=0x%08x, m_new_event_end=0x%08x\n"),
		m_timer_queue,
		m_new_event_begin,
		m_new_event_end));

	// cancel_all_timers() must be called before destructor.
	EAP_ASSERT_TOOLS(m_am_tools, m_timer_queue == 0);
	EAP_ASSERT_TOOLS(m_am_tools, m_new_event_begin == 0);
	EAP_ASSERT_TOOLS(m_am_tools, m_new_event_end == 0);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

eap_timer_queue_c::eap_timer_queue_c(
	abs_eap_am_tools_c * const tools, 
	const u32_t timer_resolution_ms)
	: m_am_tools(tools)
	, m_timer_queue(0)
	, m_new_event_begin(0)
	, m_new_event_end(0)
	, m_timer_resolution_ms(timer_resolution_ms)
	, m_is_active(false)
	, m_is_valid(false)
	, m_use_eap_millisecond_timer(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	for(u32_t ind = 0; ind < EAP_TIMER_QUEUE_HASH_SIZE; ind++)
	{
		m_map[ind] = 0;
	}
	
	m_is_active = true;
	m_is_valid = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

bool eap_timer_queue_c::get_use_eap_milli_second_timer()
{
	return m_use_eap_millisecond_timer;
}

//--------------------------------------------------

void eap_timer_queue_c::set_use_eap_milli_second_timer(const bool use_eap_millisecond_timer)
{
	m_use_eap_millisecond_timer = use_eap_millisecond_timer;
}

//--------------------------------------------------

u32_t eap_timer_queue_c::get_timer_resolution_ms()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_timer_resolution_ms;
}

//--------------------------------------------------

void eap_timer_queue_c::set_timer_resolution_ms(const u32_t timer_resolution_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_timer_resolution_ms = timer_resolution_ms;
}

//--------------------------------------------------

void eap_timer_queue_c::deactivate_timer_queue()
{
	m_is_active = false;
}

//--------------------------------------------------

// This is used in Symbian AM.
eap_status_e eap_timer_queue_c::re_activate_timer_queue()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_is_active = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

void eap_timer_queue_c::trace_timer_event(
	const eap_const_string prefix, 
	const eap_timer_queue_event_c * const event)
{

	EAP_UNREFERENCED_PARAMETER(prefix);
	EAP_UNREFERENCED_PARAMETER(event);

#if defined(USE_EAP_TIMER_QUEUE_TRACE)
#if !defined(NO_EAP_TIMER_QUEUE)

	EAP_TRACE_TIMER(
		m_am_tools,
		TRACE_FLAGS_TIMER_QUEUE,
		(EAPL("TIMER: queue: %s, %s[0x%08x], original time %8d, ")
		 EAPL("time left %8d, initializer 0x%08x, ")
		 EAPL("id 0x%02x, data 0x%08x, prev 0x%08x, ")
		 EAPL("next 0x%08x, prev same time 0x%08x, next same time 0x%08x\n"),
		 prefix,
		 ((event == m_timer_queue || event->get_time() != 0) ? "-> ": "   "),
		 event, 
		 event->get_original_time(),
		 event->get_time(), 
		 event->get_initializer(), 
		 event->get_id(), 
		 event->get_data(), 
		 event->get_prev(), 
		 event->get_next(), 
		 event->get_prev_same_time(), 
		 event->get_next_same_time()));

#endif //#if !defined(NO_EAP_TIMER_QUEUE)
#endif //#if defined(USE_EAP_TIMER_QUEUE_TRACE)
}

//--------------------------------------------------

void eap_timer_queue_c::trace_timer()
{
#if defined(USE_EAP_TIMER_QUEUE_TRACE)
#if !defined(NO_EAP_TIMER_QUEUE)

	if ( ! (m_am_tools->get_trace_mask() & (TRACE_FLAGS_TIMER_QUEUE)))
	{
		return;
	}

	eap_timer_queue_event_c *cursor = m_timer_queue;
	eap_timer_queue_event_c *prev = 0;
	EAP_UNREFERENCED_PARAMETER(prev);

	EAP_TRACE_TIMER(
		m_am_tools,
		TRACE_FLAGS_TIMER_QUEUE,
		(EAPL("-------------------------------------------------------------------------\n")));
	EAP_TRACE_TIMER(
		m_am_tools,
		TRACE_FLAGS_TIMER_QUEUE,
		(EAPL("TIMER: current timer queue:\n")));

	if (cursor == 0
		&& m_new_event_begin == 0)
	{
		EAP_TRACE_TIMER(
			m_am_tools,
			TRACE_FLAGS_TIMER_QUEUE,
			(EAPL("TIMER: queue: is empty\n")));
	}


	{
		eap_timer_queue_event_c *pending = m_new_event_begin;
		
		while(pending != 0)
		{
			trace_timer_event("new", pending);
			
			pending = pending->get_next();
		}
	}


	while(cursor != 0)
	{
		EAP_ASSERT(prev == cursor->get_prev());

		{
			eap_timer_queue_event_c *vertical = cursor;
			
			while(vertical != 0)
			{
				trace_timer_event("old", vertical);

				vertical = vertical->get_next_same_time();
			}
		}

		prev = cursor;
		cursor = cursor->get_next();

		EAP_ASSERT(prev->get_next() == cursor);
	}

	EAP_TRACE_TIMER(
		m_am_tools,
		TRACE_FLAGS_TIMER_QUEUE,
		(EAPL("-------------------------------------------------------------------------\n")));

#endif //#if !defined(NO_EAP_TIMER_QUEUE)
#endif //#if defined(USE_EAP_TIMER_QUEUE_TRACE)
}

//--------------------------------------------------

u32_t eap_timer_queue_c::pulse_timer(
	const u32_t elapsed_time_in_ms,
	const bool can_call_timer_expired_when_true)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	u32_t next_sleep_time = get_timer_resolution_ms();

#if !defined(NO_EAP_TIMER_QUEUE)

	EAP_TRACE_TIMER(
		m_am_tools,
		TRACE_FLAGS_TIMER,
		(EAPL("TIMER: pulse_timer(%u), can_call_timer_expired_when_true %d\n"),
		 elapsed_time_in_ms,
		 can_call_timer_expired_when_true));

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	trace_timer();

	if (m_timer_queue != 0)
	{
		u32_t remainder_time = m_timer_queue->pulse_time(elapsed_time_in_ms);

		if (can_call_timer_expired_when_true == true)
		{
			while (m_timer_queue != 0
				&& m_timer_queue->get_time() == 0)
			{
				eap_timer_queue_event_c *current = m_timer_queue;

				EAP_ASSERT(m_timer_queue->get_prev() == 0);
				EAP_ASSERT(current->get_time() == 0);

				if (current->get_next_same_time() != 0)
				{
					eap_timer_queue_event_c *next = current->get_next_same_time();

					EAP_ASSERT(next->get_prev() == 0 && next->get_next() == 0);

					next->set_prev_same_time(0);
					next->set_next(m_timer_queue->get_next());

					if (m_timer_queue->get_next() != 0)
					{
						m_timer_queue->get_next()->set_prev(next);
					}

					m_timer_queue = next;
				}
				else
				{
					m_timer_queue = m_timer_queue->get_next();
					if (m_timer_queue != 0)
					{
						m_timer_queue->set_prev(0);
					}
				}

				if (current != 0)
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("TIMER: eap_timer_queue_c::timer_expired(): [0x%08x]->initializer(0x%08x)->timer_expired(")
						 EAPL("id 0x%02x, data 0x%08x, original time %8d)\n"),
						 current,
						 current->get_initializer(),
						 current->get_id(),
						 current->get_data(),
						 current->get_original_time()));

					remove_hash_of_timer_event(current);

					current->set_prev_same_time(0);
					current->set_next_same_time(0);
					current->set_prev(0);
					current->set_next(0);

					current->get_initializer()->timer_expired(
						current->get_id(),
						current->get_data());

					delete current;
				}
			
				if (remainder_time != 0u
					&& m_timer_queue != 0)
				{
					remainder_time = m_timer_queue->pulse_time(remainder_time);
				}
			} // while(m_timer_queue != 0
			  //	&& m_timer_queue->get_time() == 0)
		} // if (can_call_timer_expired_when_true == true)
	}


	if (m_use_eap_millisecond_timer == true)
	{
		// New timer events are added here because the current
		// pulse might be very long, and the long pulse will
		// cause the new event expire immediately.
		// By using this function the shortest timer events in the
		// timer queue are handled and after that the new timer events
		// are added to timer queue.
		eap_status_e status = add_pending_timer();
		if (status != eap_status_ok)
		{
			next_sleep_time = get_timer_resolution_ms();

			EAP_TRACE_TIMER(
				m_am_tools,
				TRACE_FLAGS_TIMER,
				(EAPL("ERROR: TIMER: add_pending_timer() status=%d, next_sleep_time=%d\n"),
				 status,
				 next_sleep_time));
	
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return next_sleep_time;
		}
	}


	if (m_timer_queue != 0)
	{
		next_sleep_time = m_timer_queue->get_time();
	}
	else
	{
		if (m_use_eap_millisecond_timer == true)
		{
			next_sleep_time = EAP_TIMER_QUEUE_LONG_SLEEP_TIME;
		}
	}

	trace_timer();

	if (m_use_eap_millisecond_timer == false)
	{
		next_sleep_time = get_timer_resolution_ms();
	}

	EAP_TRACE_TIMER(
		m_am_tools,
		TRACE_FLAGS_TIMER,
		(EAPL("TIMER: next_sleep_time=%d\n"),
		 next_sleep_time));
	
#endif //#if !defined(NO_EAP_TIMER_QUEUE)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return next_sleep_time;
}


//--------------------------------------------------

bool eap_timer_queue_c::get_timer_queue_is_empty()
{

#if !defined(NO_EAP_TIMER_QUEUE)

	EAP_TRACE_TIMER(
		m_am_tools,
		TRACE_FLAGS_TIMER,
		(EAPL("TIMER: get_timer_queue_is_empty(): m_timer_queue=0x%08x, m_new_event_begin=0x%08x\n"),
		 m_timer_queue,
		 m_new_event_begin));

	return (m_timer_queue == 0 && m_new_event_begin == 0);

#else

	return true;

#endif //#if !defined(NO_EAP_TIMER_QUEUE)

}

//--------------------------------------------------

#if !defined(NO_EAP_TIMER_QUEUE)

eap_status_e eap_timer_queue_c::add_hash_of_timer_event(
	eap_timer_queue_event_c * const event,
	const abs_eap_base_timer_c * const initializer, 
	const u32_t id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const u32_t index = hash(EAP_TIMER_QUEUE_HASH_SIZE, initializer, id);

	if (index >= EAP_TIMER_QUEUE_HASH_SIZE)
	{
		EAP_TRACE_TIMER(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: TIMER HASH: add_handler(): initializer 0x%08x, ")
			 EAPL("id 0x%02x,  index %d >= EAP_TIMER_QUEUE_HASH_SIZE %d\n"),
			 initializer,
			 id,
			 index,
			 EAP_TIMER_QUEUE_HASH_SIZE));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_hashed_index);
	}

	eap_timer_queue_hash_c *hash = new eap_timer_queue_hash_c(m_am_tools, event, index);

	if (hash == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	event->set_hash(hash);

	eap_timer_queue_hash_c *cursor = m_map[index];
	eap_timer_queue_hash_c *last_cursor = 0;

	EAP_TRACE_TIMER(
		m_am_tools,
		TRACE_FLAGS_TIMER,
		(EAPL("TIMER HASH: add_handler(): initializer 0x%08x, id 0x%02x,  index %d\n"),
		 initializer,
		 id,
		 index));

	while (cursor != 0)
	{
		if (hash->compare(hash->get_atom()->get_initializer(),
			hash->get_atom()->get_id(),
			cursor->get_atom()->get_initializer(),
			cursor->get_atom()->get_id()) == 0)
		{
			// match
			break;
		}
		last_cursor = cursor;
		cursor = cursor->get_next();
	}

	EAP_TRACE_TIMER(
		m_am_tools,
		TRACE_FLAGS_TIMER,
		(EAPL("TIMER HASH: add_hash_of_timer_event(): hash 0x%08x\n"),
		 hash));

	EAP_ASSERT(hash->get_index() == index);

	if (last_cursor != 0)
	{
		if (last_cursor->get_next() != 0)
		{
			last_cursor->get_next()->set_prev(hash);
		}
		hash->set_next(last_cursor->get_next());
		last_cursor->set_next(hash);
		hash->set_prev(last_cursor);
	}
	else
	{
		if (m_map[index] != 0)
		{
			m_map[index]->set_prev(hash);
		}
		hash->set_next(m_map[index]);
		m_map[index] = hash;
		hash->set_prev(0);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif //#if !defined(NO_EAP_TIMER_QUEUE)

//--------------------------------------------------

#if !defined(NO_EAP_TIMER_QUEUE)

eap_timer_queue_event_c * eap_timer_queue_c::get_hashed_timer_event(
	const abs_eap_base_timer_c * const initializer, 
	const u32_t id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const u32_t index = hash(EAP_TIMER_QUEUE_HASH_SIZE, initializer, id);

	if (index >= EAP_TIMER_QUEUE_HASH_SIZE)
	{
		EAP_TRACE_TIMER(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: TIMER HASH: get_handler(): initializer 0x%08x, ")
			 EAPL("id 0x%02x,  index %d >= EAP_TIMER_QUEUE_HASH_SIZE %d\n"),
			 initializer,
			 id,
			 index,
			 EAP_TIMER_QUEUE_HASH_SIZE));
		return 0;
	}

	eap_timer_queue_hash_c *cursor = m_map[index];

	EAP_TRACE_TIMER(
		m_am_tools,
		TRACE_FLAGS_TIMER,
		(EAPL("TIMER HASH: get_handler(): initializer 0x%08x, id 0x%02x,  index %d\n"),
		 initializer,
		 id,
		 index));

	while (cursor != 0)
	{
		eap_timer_queue_event_c * const event = cursor->get_atom();

		if (cursor->compare(initializer,
			id,
			event->get_initializer(),
			event->get_id()) == 0)
		{
			// match
			EAP_TRACE_TIMER(
				m_am_tools,
				TRACE_FLAGS_TIMER,
				(EAPL("TIMER HASH: match: get_handler(): initializer 0x%08x, ")
				 EAPL("id 0x%02x,  index %d, atom 0x%08x\n"),
				 initializer,
				 id,
				 index,
				 cursor->get_atom()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return cursor->get_atom();
		}

		cursor = cursor->get_next();
	}

	EAP_TRACE_TIMER(
		m_am_tools,
		TRACE_FLAGS_TIMER,
		(EAPL("WARNING: TIMER HASH: not found: get_handler(): ")
		 EAPL("initializer 0x%08x, id 0x%02x,  index %d\n"),
		 initializer,
		 id,
		 index));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return 0;
}

#endif //#if !defined(NO_EAP_TIMER_QUEUE)

//--------------------------------------------------

#if !defined(NO_EAP_TIMER_QUEUE)

eap_status_e eap_timer_queue_c::remove_hash_of_timer_event(
	eap_timer_queue_event_c * const event)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (event == 0
		|| event->get_hash() == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	eap_timer_queue_hash_c *hash = event->get_hash();
	event->set_hash(0);

	if (hash->get_prev() != 0)
	{
		// Remove from middle.
		EAP_ASSERT(m_map[hash->get_index()] != hash);

		if (hash->get_next() != 0)
		{
			hash->get_next()->set_prev(hash->get_prev());
		}
		hash->get_prev()->set_next(hash->get_next());
	}
	else
	{
		// Remove the first item.
		EAP_ASSERT(m_map[hash->get_index()] == hash);
		EAP_ASSERT(hash->get_prev() == 0);

		if (hash->get_next() != 0)
		{
			hash->get_next()->set_prev(hash->get_prev());
		}
		m_map[hash->get_index()] = hash->get_next();
		EAP_ASSERT(m_map[hash->get_index()] == 0
			|| m_map[hash->get_index()]->get_prev() == 0);
	}

	delete hash;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif //#if !defined(NO_EAP_TIMER_QUEUE)

//--------------------------------------------------

// 
u32_t eap_timer_queue_c::hash(
	const u32_t size,
	const abs_eap_base_timer_c * const initializer, 
	const u32_t id) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	u32_t ihash = 0x55555555;

	ihash += static_cast<u32_t>(id);
	ihash += reinterpret_cast<u32_t>(initializer);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return ihash % size;
}

//--------------------------------------------------

void eap_timer_queue_c::add_end_of_vertical_list(
	eap_timer_queue_event_c * const begin,
	eap_timer_queue_event_c * const event)
{
	EAP_ASSERT(begin != 0 && event != 0);

	eap_timer_queue_event_c * previous = 0;
	eap_timer_queue_event_c * current = begin;

	while (current != 0)
	{
		previous = current;
		current = current->get_next_same_time();
	}

	// Add to the vertical list of previous time.
	event->set_next_same_time(previous->get_next_same_time());
	if (previous->get_next_same_time() != 0)
	{
		previous->get_next_same_time()->set_prev_same_time(event);
	}
	previous->set_next_same_time(event);
	event->set_prev_same_time(previous);
}

//--------------------------------------------------

eap_status_e eap_timer_queue_c::add_timer(
	eap_timer_queue_event_c *event)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

#if !defined(NO_EAP_TIMER_QUEUE)

	eap_status_e status = add_hash_of_timer_event(
		event,
		event->get_initializer(),
		event->get_id());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	if (m_timer_queue == 0)
	{
		m_timer_queue = event;

		EAP_TRACE_TIMER(
			m_am_tools,
			TRACE_FLAGS_TIMER,
			(EAPL("TIMER: [0x%08x] add_timer(initializer 0x%08x, ")
			 EAPL("id 0x%02x, data 0x%08x, time %d)\n"),
			 m_timer_queue,
			 event->get_initializer(),
			 event->get_id(),
			 event->get_data(),
			 event->get_time_ms()));
	}
	else
	{
		EAP_TRACE_TIMER(
			m_am_tools,
			TRACE_FLAGS_TIMER,
			(EAPL("TIMER: [0x%08x]\n"),
			 event));

		EAP_TRACE_TIMER(
			m_am_tools,
			TRACE_FLAGS_TIMER,
			(EAPL("TIMER: initializer 0x%08x\n"),
			 event->get_initializer()));

		EAP_TRACE_TIMER(
			m_am_tools,
			TRACE_FLAGS_TIMER,
			(EAPL("TIMER: id 0x%02x\n"),
			 event->get_id()));

		EAP_TRACE_TIMER(
			m_am_tools,
			TRACE_FLAGS_TIMER,
			(EAPL("TIMER: data 0x%08x\n"),
			 event->get_data()));

		EAP_TRACE_TIMER(
			m_am_tools,
			TRACE_FLAGS_TIMER,
			(EAPL("TIMER: time %d\n"),
			 event->get_time_ms()));

		EAP_TRACE_TIMER(
			m_am_tools,
			TRACE_FLAGS_TIMER,
			(EAPL("TIMER: [0x%08x] add_timer(initializer 0x%08x, ")
			 EAPL("id 0x%02x, data 0x%08x, time %d)\n"),
			 event,
			 event->get_initializer(),
			 event->get_id(),
			 event->get_data(),
			 event->get_time_ms()));

		eap_timer_queue_event_c *current = m_timer_queue;
		eap_timer_queue_event_c *prev = 0;
		u32_t time_ms_sum = 0u;
		u32_t tmp_time_ms = 0u;


		while(current != 0)
		{
			tmp_time_ms = current->get_time();

			time_ms_sum += tmp_time_ms;

			if (time_ms_sum >= event->get_time())
			{
				// Time segment found.
				// tmp_time_ms is decremented from time_ms_sum
				// because of we need time sum before current.
				// New event is added before current.
				if (time_ms_sum > event->get_time())
				{
					time_ms_sum -= tmp_time_ms;
				}
				else
				{
					// current points to the same time sum.
				}
				break;
			}

			prev = current;
			current = current->get_next();
		} // while(current != 0)


		if (prev == 0
			&& time_ms_sum == 0)
		{
			// Add to first.

			if (m_timer_queue != 0
				&& m_timer_queue->get_time() == event->get_time())
			{
				// Add to the first vertical list, in the end of the vertical list.
				m_timer_queue->decrease_time_left(event->get_time()); // event->get_time() == 0.
				add_end_of_vertical_list(m_timer_queue, event);
			}
			else
			{
				if (m_timer_queue != 0)
				{
					m_timer_queue->decrease_time_left(event->get_time());
				}
				event->set_next(m_timer_queue);
				m_timer_queue->set_prev(event);
				m_timer_queue = event;
			}
		}
		else if (current != 0
			&& time_ms_sum == event->get_time())
		{
			add_end_of_vertical_list(current, event);
			event->decrease_time_left(event->get_time()); // event->get_time() == 0.
		}
		else
		{
			// Add new vertical list to middle.
			EAP_ASSERT(prev != 0);

			event->decrease_time_left(time_ms_sum);

			if (prev != 0)
			{
				event->set_next(prev->get_next());
				if (prev->get_next() != 0)
				{
					prev->get_next()->set_prev(event);
					prev->get_next()->decrease_time_left(event->get_time());
				}
				prev->set_next(event);
				event->set_prev(prev);
			}
		}
	}

	trace_timer();

#endif //#if !defined(NO_EAP_TIMER_QUEUE)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

eap_status_e eap_timer_queue_c::add_new_pending_timer(
	eap_timer_queue_event_c *event)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_TIMER(
		m_am_tools,
		TRACE_FLAGS_TIMER,
		(EAPL("TIMER: [0x%08x] add_new_pending_timer(initializer 0x%08x, ")
		 EAPL("id 0x%02x, data 0x%08x, time %d)\n"),
		 m_timer_queue,
		 event->get_initializer(),
		 event->get_id(),
		 event->get_data(),
		 event->get_time_ms()));

	// Adds the new event to the end of the list to keep the order of events correct.
	EAP_ASSERT((m_new_event_begin == 0
				&& m_new_event_end == 0)
			   || (m_new_event_begin != 0
				   && m_new_event_end != 0));

	if (m_new_event_begin == 0
		&& m_new_event_end == 0)
	{
		// Adds to the begin.
		m_new_event_begin = event;
		m_new_event_end = event;
	}
	else
	{
		// Adds to the end.
		m_new_event_end->set_next(event);
		m_new_event_end = event;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

eap_status_e eap_timer_queue_c::set_timer(
	abs_eap_base_timer_c * const initializer, 
	const u32_t id, 
	void * const data,
	const u32_t time_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_STACK_TRACE(initializer);

	if (m_is_active == false)
	{
		initializer->timer_delete_data(id, data);
		EAP_TRACE_TIMER(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: TIMER: not accepted, timer queue is inactive: ")
			 EAPL("[0x%08x] set_timer(initializer 0x%08x, id 0x%02x, data 0x%08x, time %d)\n"),
			 m_timer_queue,
			 initializer,
			 id,
			 data,
			 time_ms));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
	}

#if !defined(NO_EAP_TIMER_QUEUE)

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	trace_timer();

	eap_timer_queue_event_c *event = new eap_timer_queue_event_c(
		m_am_tools,
		initializer,
		id,
		data,
		time_ms);

	if (event == 0)
	{
		initializer->timer_delete_data(id, data);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: eap_timer_queue_c::set_timer(): [0x%08x]->initializer(0x%08x)->set_timer(")
		 EAPL("id 0x%02x, data 0x%08x, original time %8d)\n"),
		 event,
		 event->get_initializer(),
		 event->get_id(),
		 event->get_data(),
		 event->get_original_time()));

	if (m_use_eap_millisecond_timer == true)
	{
		// The next pulse_timer() function call will add the event to timer queue.
		eap_status_e status = add_new_pending_timer(event);
		if (status != eap_status_ok)
		{
			delete event;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		eap_status_e status = add_timer(event);
		if (status != eap_status_ok)
		{
			delete event;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

#endif //#if !defined(NO_EAP_TIMER_QUEUE)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

eap_status_e eap_timer_queue_c::add_pending_timer()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	while (m_new_event_begin != 0)
	{
		eap_timer_queue_event_c *event = m_new_event_begin;

		m_new_event_begin = m_new_event_begin->get_next();

		if (m_new_event_begin == 0)
		{
			m_new_event_end = 0;
		}

		event->set_next(0);

		eap_status_e status = add_timer(event);
		if (status != eap_status_ok)
		{
			event->get_initializer()->timer_expired(
				event->get_id(),
				event->get_data());

			delete event;

			// Read all pending events. Even the addition failed.
			// We might have too less mamory.
		}
	} // while()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_timer_queue_c::cancel_pending_timer(
	abs_eap_base_timer_c * const initializer, 
	const u32_t id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_STACK_TRACE(initializer);

	eap_timer_queue_event_c *previous = 0;
	eap_timer_queue_event_c *event = m_new_event_begin;

	while (event != 0)
	{
		if (initializer == event->get_initializer()
			&& id == event->get_id())
		{
			// Remove this pending event.
			eap_timer_queue_event_c *remove = event;
			event = event->get_next();

			if (remove == m_new_event_end)
			{
				m_new_event_end = previous;
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TIMER: eap_timer_queue_c::cancel_pending_timer(): [0x%08x]->initializer(0x%08x)->cancel_pending_timer(")
				 EAPL("id 0x%02x, data 0x%08x, original time %8d)\n"),
				 remove,
				 remove->get_initializer(),
				 remove->get_id(),
				 remove->get_data(),
				 remove->get_original_time()));

			remove->set_next(0);
			delete remove;

			if (previous != 0)
			{
				previous->set_next(event);
			}
			else
			{
				m_new_event_begin = event;
			}
		}
		else
		{
			previous = event;
			event = event->get_next();
		}
	} // while()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

eap_status_e eap_timer_queue_c::cancel_timer(
	abs_eap_base_timer_c * const initializer, 
	const u32_t id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_STACK_TRACE(initializer);

#if !defined(NO_EAP_TIMER_QUEUE)

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);


	trace_timer();


	eap_status_e status = cancel_pending_timer(
		initializer, 
		id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	if (m_timer_queue == 0)
	{
		EAP_TRACE_TIMER(
			m_am_tools,
			TRACE_FLAGS_TIMER,
			(EAPL("TIMER: empty queue, [0x%08x] cancel_timer(initializer 0x%08x, id 0x%02x)\n"),
			 m_timer_queue,
			 initializer,
			 id));
	}
	else
	{
		eap_timer_queue_event_c * cursor = get_hashed_timer_event(initializer, id);

		while(cursor != 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TIMER: eap_timer_queue_c::cancel_timer(): [0x%08x]->initializer(0x%08x)->cancel_timer(")
				 EAPL("id 0x%02x, data 0x%08x, original time %8d)\n"),
				 cursor,
				 cursor->get_initializer(),
				 cursor->get_id(),
				 cursor->get_data(),
				 cursor->get_original_time()));

			if (cursor == m_timer_queue)
			{
				// The first event will be removed.
				EAP_ASSERT(cursor->get_prev() == 0);

				if (m_timer_queue->get_next_same_time() != 0)
				{
					eap_timer_queue_event_c * new_first = m_timer_queue->get_next_same_time();
					EAP_ASSERT(new_first->get_next() == 0 && new_first->get_prev() == 0);
					new_first->set_prev_same_time(0);
					new_first->set_next(m_timer_queue->get_next());
					if (m_timer_queue->get_next() != 0)
					{
						m_timer_queue->get_next()->set_prev(new_first);
					}
					m_timer_queue = new_first;
					m_timer_queue->increase_time_left(cursor->get_time());
				}
				else
				{
					if (cursor->get_next() != 0)
					{
						cursor->get_next()->increase_time_left(cursor->get_time());
						cursor->get_next()->set_prev(0);
					}
					m_timer_queue = cursor->get_next();
				}

				cursor->set_prev(0);
				cursor->set_next(0);
				cursor->set_prev_same_time(0);
				cursor->set_next_same_time(0);
				remove_hash_of_timer_event(cursor);
				delete cursor;
			}
			else if (cursor->get_prev_same_time() != 0)
			{
				// Event from the vertical time list will be removed.
				EAP_ASSERT(cursor->get_next() == 0 && cursor->get_prev() == 0);
				cursor->get_prev_same_time()->set_next_same_time(cursor->get_next_same_time());
				if (cursor->get_next_same_time() != 0)
				{
					cursor->get_next_same_time()->set_prev_same_time(cursor->get_prev_same_time());
				}
				cursor->set_prev(0);
				cursor->set_next(0);
				cursor->set_prev_same_time(0);
				cursor->set_next_same_time(0);
				remove_hash_of_timer_event(cursor);
				delete cursor;
			}
			else // if (cursor->get_prev_same_time() == 0)
			{
				EAP_ASSERT(cursor->get_prev() != 0);

				// Event from middle or end of the horizontal queue will be removed.
				if (cursor->get_next_same_time() != 0)
				{
					// Next on the vertical list will replace the removed timer event.
					eap_timer_queue_event_c * new_first = cursor->get_next_same_time();

					new_first->increase_time_left(cursor->get_time());

					new_first->set_next(cursor->get_next());
					if (cursor->get_next() != 0)
					{
						cursor->get_next()->set_prev(new_first);
					}
					new_first->set_prev(cursor->get_prev());
					if (cursor->get_prev() != 0)
					{
						cursor->get_prev()->set_next(new_first);
					}
					new_first->set_prev_same_time(0);
				}
				else
				{
					// No other timer events are in the vertical list.
					cursor->get_prev()->set_next(cursor->get_next());
					if (cursor->get_next() != 0)
					{
						cursor->get_next()->set_prev(cursor->get_prev());
						cursor->get_next()->increase_time_left(cursor->get_time());
					}
				}
				cursor->set_prev(0);
				cursor->set_next(0);
				cursor->set_prev_same_time(0);
				cursor->set_next_same_time(0);
				remove_hash_of_timer_event(cursor);
				delete cursor;
			}
			cursor = get_hashed_timer_event(initializer, id);
		} // while()
	}

	trace_timer();

#endif //#if !defined(NO_EAP_TIMER_QUEUE)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

eap_status_e eap_timer_queue_c::cancel_all_timers()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_STACK_TRACE(0);

	deactivate_timer_queue();

	while (m_new_event_begin != 0)
	{
		eap_timer_queue_event_c *event = m_new_event_begin;

		m_new_event_begin = m_new_event_begin->get_next();

		event->set_next(0);

		delete event;
		event = 0;
	} // while()

	m_new_event_end = 0;

#if !defined(NO_EAP_TIMER_QUEUE)

	EAP_TRACE_TIMER(
		m_am_tools,
		TRACE_FLAGS_TIMER,
		(EAPL("TIMER: [0x%08x] cancel_all_timers()\n"),
		 m_timer_queue));

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = add_pending_timer();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	trace_timer();

	if (m_timer_queue == 0)
	{
		// Nothing to do.
	}
	else
	{
		eap_timer_queue_event_c *cursor = m_timer_queue;

		while (cursor != 0)
		{
			// The first event will be removed.
			m_timer_queue = m_timer_queue->get_next();

			while (cursor != 0)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("TIMER: eap_timer_queue_c::cancel_all_timers(): [0x%08x]->initializer(0x%08x)->cancel_all_timers(")
					 EAPL("id 0x%02x, data 0x%08x, original time %8d)\n"),
					 cursor,
					 cursor->get_initializer(),
					 cursor->get_id(),
					 cursor->get_data(),
					 cursor->get_original_time()));

				eap_timer_queue_event_c *next = cursor->get_next_same_time();

				cursor->set_prev(0);
				cursor->set_next(0);

				remove_hash_of_timer_event(cursor);

				delete cursor;

				cursor = next;
			} // while()

			cursor = m_timer_queue;
		} // while()
	}

	trace_timer();

#endif //#if !defined(NO_EAP_TIMER_QUEUE)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

bool eap_timer_queue_c::get_is_valid() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_valid;
}

//--------------------------------------------------




// End.
