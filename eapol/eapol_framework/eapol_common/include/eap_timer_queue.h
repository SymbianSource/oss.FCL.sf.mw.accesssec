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

#if !defined(_EAP_TIMER_QUEU_H_)
#define _EAP_TIMER_QUEU_H_

//#include "eap_am_memory.h"
#include "eap_am_tools.h"
#include "eap_tools.h"
#include "abs_eap_am_mutex.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TIMER_QUEUE_H)
	#define EAP_CLASS_VISIBILITY_EAP_TIMER_QUEUE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TIMER_QUEUE_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TIMER_QUEUE_H 
	#define EAP_FUNC_EXPORT_EAP_TIMER_QUEUE_H 
	#define EAP_C_FUNC_EXPORT_EAP_TIMER_QUEUE_H 
#elif defined(EAP_EXPORT_EAP_TIMER_QUEUE_H)
	#define EAP_CLASS_VISIBILITY_EAP_TIMER_QUEUE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TIMER_QUEUE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TIMER_QUEUE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TIMER_QUEUE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TIMER_QUEUE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TIMER_QUEUE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TIMER_QUEUE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TIMER_QUEUE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TIMER_QUEUE_H 
	#define EAP_C_FUNC_EXPORT_EAP_TIMER_QUEUE_H 
#endif
// End: added by script change_export_macros.sh.



/** @file */

const u32_t EAP_TIMER_RESOLUTION  = 500u; ///< Timer resolution in milli seconds.

const u32_t EAP_TIMER_QUEUE_LONG_SLEEP_TIME = 86400000;  ///< Long timer sleep time of millisecond timer in milli seconds (24 hours).

class eap_timer_queue_hash_c;

// ---------------------------------------------------------------------

/// This class is one timer event stored to timer queue.
class EAP_CLASS_VISIBILITY_EAP_TIMER_QUEUE_H eap_timer_queue_event_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	abs_eap_base_timer_c *m_initializer; ///< m_initializer is the initializer of timer event. Call backs are directed to initializer.

	u32_t m_id; ///< m_id is selected by caller. Caller could separate timer events by this value.

	void *m_data; ///< m_data is pointer to any data of initializer.

	u32_t m_time_ms; ///< m_time_ms is the time after this timer event should elapse.

	u32_t m_original_time_ms; ///< m_original_time_ms is the original set time.

	eap_timer_queue_event_c *m_prev; ///< m_prev is pointer to the previous timer event in the timer queue.
	eap_timer_queue_event_c *m_next; ///< m_next is pointer to the next timer event in the timer queue.

	eap_timer_queue_hash_c *m_hash;

	eap_timer_queue_event_c *m_prev_same_time; ///< m_prev_same_time is pointer to the previous timer event with the same elapse time.
	eap_timer_queue_event_c *m_next_same_time; ///< m_next_same_time is pointer to the next timer event with the same elapse time.

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~eap_timer_queue_event_c();

	//--------------------------------------------------

	// 
	eap_timer_queue_event_c(
		abs_eap_am_tools_c * const tools, 
		abs_eap_base_timer_c * const initializer, 
		const u32_t id, 
		void * const data,
		const u32_t p_time_ms);

	//--------------------------------------------------

	// 
	u32_t get_time() const;

	//--------------------------------------------------

	// 
	u32_t get_original_time() const;

	//--------------------------------------------------

	// 
	eap_timer_queue_event_c *get_prev() const;

	//--------------------------------------------------

	// 
	eap_timer_queue_event_c *get_next() const;

	//--------------------------------------------------

	// 
	eap_timer_queue_event_c *get_prev_same_time() const;

	//--------------------------------------------------

	// 
	eap_timer_queue_event_c *get_next_same_time() const;

	//--------------------------------------------------

	// 
	eap_timer_queue_hash_c * get_hash() const;

	//--------------------------------------------------

	// 
	u32_t pulse_time(const u32_t resolution);

	//--------------------------------------------------

	// 
	void decrease_time_left(const u32_t decrease_time);

	//--------------------------------------------------

	// 
	void increase_time_left(const u32_t increase_time);

	//--------------------------------------------------

	// 
	void set_prev(eap_timer_queue_event_c * const prev);

	//--------------------------------------------------

	// 
	void set_next(eap_timer_queue_event_c * const next);

	//--------------------------------------------------

	// 
	void set_prev_same_time(eap_timer_queue_event_c * const prev_same_time);

	//--------------------------------------------------

	// 
	void set_next_same_time(eap_timer_queue_event_c * const next_same_time);

	//--------------------------------------------------

	// 
	void set_hash(eap_timer_queue_hash_c * const hash);

	//--------------------------------------------------

	// 
	abs_eap_base_timer_c * get_initializer() const;

	//--------------------------------------------------

	// 
	u32_t get_id() const;

	//--------------------------------------------------

	// 
	void * get_data() const;

	//--------------------------------------------------

	// 
	u32_t get_time_ms();

	//--------------------------------------------------
}; // class eap_timer_queue_event_c


// ---------------------------------------------------------------------

/// This class is hash to timer event stored to timer queue.
/**
 * Each timer event is stored to the timer queue (eap_timer_queue_c) with events (eap_timer_queue_event_c)
 * and to the hash array of the timer events (eap_timer_queue_c::m_map).
 */
class EAP_CLASS_VISIBILITY_EAP_TIMER_QUEUE_H eap_timer_queue_hash_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	u32_t m_index; ///< Index in the hash array.
	eap_timer_queue_event_c * m_atom; ///< Pointer to the time event.

	eap_timer_queue_hash_c *m_prev; ///< m_prev is pointer to the revious hash.
	eap_timer_queue_hash_c *m_next; ///< m_next is pointer to the next hash.

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~eap_timer_queue_hash_c();

	//--------------------------------------------------

	// 
	eap_timer_queue_hash_c(
		abs_eap_am_tools_c * const tools, 
		eap_timer_queue_event_c * const atom,
		const u32_t index);

	//--------------------------------------------------

	// 
	eap_timer_queue_hash_c *get_next() const;

	//--------------------------------------------------

	// 
	eap_timer_queue_hash_c *get_prev() const;

	//--------------------------------------------------

	// 
	u32_t get_index() const;

	//--------------------------------------------------

	// 
	void set_next(eap_timer_queue_hash_c * const next);

	// 
	void set_prev(eap_timer_queue_hash_c * const prev);

	eap_timer_queue_event_c * get_atom();

	i32_t compare(
		const abs_eap_base_timer_c * const a_initializer, 
		const u32_t a_id,
		const abs_eap_base_timer_c * const b_initializer, 
		const u32_t b_id);

	//--------------------------------------------------
}; // class eap_timer_queue_hash_c

// ---------------------------------------------------------------------

/// Size of the hash array of eap_timer_queue_hash_c elements.
/// Hash array optimizes the cancellation of timer event.
const u32_t EAP_TIMER_QUEUE_HASH_SIZE = 1024;

/// This class implements the timer queue.
/**
 * User of the timer queue must be inherited from abs_eap_base_timer_c.
 * The abs_eap_base_timer_c class is the call back interface from timer queue to the user.
 * @see Note the timer queue interface is used through abs_eap_am_tools_c.
 * Functions are abs_eap_am_tools_c::get_timer_resolution_ms(), 
 * abs_eap_am_tools_c::set_timer(), 
 * abs_eap_am_tools_c::cancel_timer(), 
 * abs_eap_am_tools_c::cancel_all_timers() and
 * abs_eap_am_tools_c::pulse_timer()
 * 
 * In the following figure m_timer_queue is pointer to the first timer event in the list.
 * The timer list is horizontal list right from m_timer_queue.
 * Each timer event in the list represents one time segment
 * that must elapse to zero before event is active. Timer event - the square box in the figure -
 * is type of eap_timer_queue_event_c.
 * Each time segment includes list of the same time values, the vertical lists.
 * 
 * Place for new timer event is found by stepping the the horizontal timer list
 * and adding the time values sum until the list ends
 * or time sum is equal or greater than time of the new timer event.
 * If time sum is equal to the time of the new timer event, the new timer event is
 * added to the second in the vertical list. If time sum is greater than the time of the new timer event,
 * the new timer event is added before the existing time event. In this case a new vertical list is created.
 * If the list ends the new time event is added to the end of the timer queue.
 * 
 * @code
 *                  +---------------+  +---------------+  +---------------+
 *   m_timer_queue->| m_time_ms 0   |->| m_time_ms 2000|->| m_time_ms 500 | // This horizontal list is the timer queue.
 *                  +---------------+  +---------------+  +---------------+
 *                          |                  |                  |        
 *                          V                  V                  V        
 *                  +---------------+  +---------------+  +---------------+
 *                  | m_time_ms 0   |  | m_time_ms 0   |  | m_time_ms 0   |
 *                  +---------------+  +---------------+  +---------------+
 *                          |                  |                           
 *                          V                  V                           
 *                  +---------------+  +---------------+                   
 *                  | m_time_ms 0   |  | m_time_ms 0   |                   
 *                  +---------------+  +---------------+                   
 *                                             |                           
 *                                             V                           
 *                                     +---------------+                   
 *                                     | m_time_ms 0   |                   
 *                                     +---------------+                   
 *   // Each vertical list includes the timer events that have the same time.
 * @endcode
 */
class EAP_CLASS_VISIBILITY_EAP_TIMER_QUEUE_H eap_timer_queue_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is pointer to the first timer event.
	eap_timer_queue_event_c *m_timer_queue;

	/// These are begin and end of the list of new events
	/// that are will be added to timer queue
	/// during the next pulse_timer() function
	/// call.
	eap_timer_queue_event_c *m_new_event_begin;
	eap_timer_queue_event_c *m_new_event_end;

	/// This is the resolution of this timer queue.
	/// Each pulse is assumed to be this length.
	/// This is also the minimum timer value.
	u32_t m_timer_resolution_ms;
	
	/// This is hash array of timer events.
	eap_timer_queue_hash_c * m_map[EAP_TIMER_QUEUE_HASH_SIZE];

	/// This indicates whether this timer queue is active. Inactive timer queue does not accept new timer events.
	bool m_is_active;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	bool m_use_eap_millisecond_timer;

	//--------------------------------------------------

	/**
	 * this function traces one timer event.
	 */
	void trace_timer_event(
		const eap_const_string prefix, 
		const eap_timer_queue_event_c * const event);

	/**
	 * This function traces all initialized timer events.
	 */
	void trace_timer();

	eap_status_e add_hash_of_timer_event(
		eap_timer_queue_event_c * const event,
		const abs_eap_base_timer_c * const initializer, 
		const u32_t id);

	eap_timer_queue_event_c * get_hashed_timer_event(
		const abs_eap_base_timer_c * const initializer, 
		const u32_t id);

	eap_status_e remove_hash_of_timer_event(
		eap_timer_queue_event_c * const event);

	//--------------------------------------------------

	// 
	u32_t hash(
		const u32_t size,
		const abs_eap_base_timer_c * const initializer, 
		const u32_t id) const;

	//--------------------------------------------------

	/**
	 * This function deactivate this timer queue.
	 * This is called before the timer queue is deleted.
	 * Inactive timer queue does not accept new timer events.
	 */
	void deactivate_timer_queue();

	/**
	 * This function adds the timer event immediately to timer queue.
	 */
	eap_status_e add_timer(
		eap_timer_queue_event_c *event);

	/**
	 * New timer events are added with this function because the next pulse might
	 * be very long, and the long pulse will cause the new event expire immediately.
	 * By using this function the shortest timer events in the
	 * timer queue are handled and after that the new timer events
	 * are added to timer queue.
	 */
	eap_status_e add_pending_timer();

	void add_end_of_vertical_list(
		eap_timer_queue_event_c *begin,
		eap_timer_queue_event_c *event);

	eap_status_e add_new_pending_timer(
		eap_timer_queue_event_c *event);

	/**
	 * This function cancels all pending timer events.
	 */
	eap_status_e cancel_pending_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id);

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * Destructor does nothing special.
	 * Note user is assumed to call cancel_all_timers()
	 * before timer queue is deleted.
	 */
	virtual ~eap_timer_queue_c();

	//--------------------------------------------------

	/**
	 * Constructor initializes the timer queue.
	 * @param timer_resolution_ms is the resolution in milli seconds of this timer.
	 * The pulse() member function is assumed to be called using 
	 * timer_resolution_ms interval.
	 */
	eap_timer_queue_c(
		abs_eap_am_tools_c * const tools, 
		const u32_t timer_resolution_ms);

	//--------------------------------------------------

	/**
	 * This function re-activates timer queue.
	 * Symbian AM call this function when AM-tools object is re-used.
	 * This can be called after cancel_all_timers() function.
	 * cancel_all_timers() function de-activated timer queue.
	 */
	eap_status_e re_activate_timer_queue();

	//--------------------------------------------------

	/**
	 * This function returns flag whether millisecond timer is in use (true) or not (false).
	 */
	bool get_use_eap_milli_second_timer();

	//--------------------------------------------------

	/**
	 * This function activates millisecond timer with true value.
	 */
	void set_use_eap_milli_second_timer(const bool use_eap_millisecond_timer);

	//--------------------------------------------------

	/**
	 * @return Returns the initialized timer resolution.
	 */
	u32_t get_timer_resolution_ms();

	//--------------------------------------------------

	/**
	 * @return Sets the timer resolution.
	 */
	void set_timer_resolution_ms(const u32_t timer_resolution_ms);

	//--------------------------------------------------

	/**
	 * The pulse() member function is assumed to be called using 
	 * timer_resolution_ms interval.
	 * This function decreases the remaining time of the first timer event.
	 * When remaining time reaches zero the timer queue calls the timer_expired() function.
	 * Function returns the next sleep time in milli seconds.
	 */
	u32_t pulse_timer(
		const u32_t elapsed_time_in_ms,
		const bool can_call_timer_expired_when_true);

	//--------------------------------------------------

	// 
	bool get_timer_queue_is_empty();

	//--------------------------------------------------

	/**
	 * This function initializes a new timer event.
	 * @param initializer is the caller of this function. Call backs are directed to initializer.
	 * @param id is selected by caller. Caller could separate timer events by this value.
	 * @param data is pointer to any data. After timer is alapsed or cancelled 
	 * timer queue calls timer_delete_data() function. The initializer could delete possible
	 * allocated data.
	 * @param p_time_ms is the time after this timer event should elapse.
	 */
	eap_status_e set_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id, 
		void * const data,
		const u32_t time_ms);

	//--------------------------------------------------

	/**
	 * This function cancels the timer event.
	 * @param initializer is the caller of this function. Call backs are directed to initializer.
	 * @param id is selected by caller. Caller could separate timer events by this value.
	 */
	eap_status_e cancel_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id);

	//--------------------------------------------------

	/**
	 * This function cancels all timer events from this timer queue.
	 * This is called before the timer queue is deleted.
	 */
	eap_status_e cancel_all_timers();

	//--------------------------------------------------

	/**
	 * The get_is_valid() function returns the status of the eap_core object.
	 * True indicates the object is initialized succesfully.
	 */
	bool get_is_valid() const;

	//--------------------------------------------------
}; // class eap_timer_queue_c


#endif //#if !defined(_EAP_TIMER_QUEU_H_)



// End.
