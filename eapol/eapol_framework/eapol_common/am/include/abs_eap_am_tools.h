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

#if !defined( _ABS_EAP_AM_TOOLS_H_ )
#define _ABS_EAP_AM_TOOLS_H_

#include "eap_am_types.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_AM_TOOLS_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_TOOLS_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_TOOLS_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_TOOLS_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_TOOLS_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_TOOLS_H 
#elif defined(EAP_EXPORT_ABS_EAP_AM_TOOLS_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_TOOLS_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_TOOLS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_TOOLS_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_TOOLS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_TOOLS_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_TOOLS_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_TOOLS_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_TOOLS_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_TOOLS_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_TOOLS_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_status.h"
#include "abs_eap_base_timer.h"
//#include "eap_am_memory_store_data.h"


#if defined(EAP_LITTLE_ENDIAN) && defined(EAP_BIG_ENDIAN)
#error Do not define both EAP_LITTLE_ENDIAN and EAP_BIG_ENDIAN
#endif

#if !defined(EAP_LITTLE_ENDIAN) && !defined(EAP_BIG_ENDIAN)
#error Do define either EAP_LITTLE_ENDIAN or EAP_BIG_ENDIAN
#endif

class abs_eap_am_crypto_c;
class eap_variable_data_c;
class abs_eap_am_mutex_c;
class eap_buf_chain_wr_c;
class eap_configuration_field_c;
class eap_tlv_message_data_c;

/// This class offers some services that are dependent of platform Y.
/**
 * Current services are timer handling, crypto library, trace functions,
 * memory manipulation and hardware tick counter. Use of eap_am_tools is through
 * abstract virtual class abs_eap_am_tools. A pointer to the abs_eap_am_tools
 * class is given to all other classes as a parameter to each constructor.
 * Adaptation module creates the eap_am_tools_Y class before it initializes the stack.
 * This prevents the need of global objects.
 */
class EAP_CLASS_VISIBILITY_ABS_EAP_AM_TOOLS_H abs_eap_am_tools_c
{

public:

	/**
	 * The destructor of the abs_eap_am_tools_c class does nothing special.
	 */
	virtual ~abs_eap_am_tools_c()
	{
	}

	/**
	 * The constructor of the abs_eap_am_tools_c does nothing special.
	 */
	abs_eap_am_tools_c()
	{
	}

	/**
	 * This function allocates platform specific tools object.
	 * Note this function calls also configure() of the allocated tools object.
	 * The platform specific module must implement this function.
	 */
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_TOOLS_H static abs_eap_am_tools_c * new_abs_eap_am_tools_c();

	/**
	 * This function deletes platform specific tools object.
	 * Note this function calls also shutdown() of the allocated tools object.
	 * The platform specific module must implement this function.
	 */
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_TOOLS_H static void delete_abs_eap_am_tools_c(abs_eap_am_tools_c * const am_tools);

	/**
	 * The configure() function is called after the constructor of the 
	 * object is successfully executed. During the function call the object 
	 * could query the configuration. Each derived class must define this function.
	 * Needed configuration depends on the implementation.
	 */
	virtual eap_status_e configure() = 0;

	/**
	 * The shutdown() function is called before the destructor of the 
	 * object is executed. During the function call the object 
	 * could shutdown the operations, for example cancel timers.
	 * Each derived class must define this function.
	 */
	virtual eap_status_e shutdown() = 0;

	/**
	 * Function converts unicode characters into UTF8 characters.
	 * @param dest is reference to destination utf8 variable data.
	 * @param src is refrence to unicode variable data.
	 * @return eap status code.
	 */
	virtual eap_status_e convert_unicode_to_utf8(
		eap_variable_data_c & dest,
		const eap_variable_data_c & src) = 0;

	/**
	 * Function converts UTF8 characters into unicode characters.
	 * @param dest is reference to destination unicode variable data.
	 * @param src is refrence to UTF8 variable data.
	 * @return eap status code.
	 */
	virtual eap_status_e convert_utf8_to_unicode(
		eap_variable_data_c & dest,
		const eap_variable_data_c & src) = 0;

	/**
	 * Function parses NAI to usename and realm.
	 * If either is missing the corresponding value will be invalid.
	 */
	virtual eap_status_e parse_nai(
		const eap_variable_data_c * const nai,
		eap_variable_data_c * const username,
		eap_variable_data_c * const realm) = 0;

	/**
	 * Function converts one octet to ascii character.
	 * @param octet is the converted octet.
	 * @return acsii byte.
	 */
	virtual u8_t octet_to_ascii(i32_t octet) = 0;

	/**
	 * Function converts one ascii character to octet.
	 * @param character is the converted ascii character.
	 * @return octet.
	 */
	virtual u8_t ascii_to_octet(i32_t character) = 0;

	/**
	 * The memmove() function copies count bytes from src to dest.
	 * The implementation must handle overlapping memory areas correctly.
	 * Check always the destination is correct memory.
	 * This function is low level and cannot check the used memory.
	 * @param dest is pointer to the destination.
	 * @param src is pointer to the source.
	 * @param count indicates the count of copied bytes.
	 */
	virtual void memmove(
		void *dest, 
		const void *src, 
		const u32_t count) = 0;

	/**
	 * The memcmp() function compares count bytes from buf1 and buf2.
	 * @return Returns zero when all count bytes are equal.
	 * @return Returns negative integer when buf1 contains smaller different byte.
	 * @return Returns positive integer when buf1 contains bigger different byte.
	 */
	virtual i32_t memcmp(
		const void * const buf1, 
		const void * const buf2, 
		const u32_t count) = 0;

	/**
	 * The memset function sets the first count bytes of dest to the character fill_byte.
	 * Check always the destination is correct memory.
	 * This function is low level and cannot check the used memory.
	 * @param dest is pointer to the destination.
	 * @param fill_byte is the fill value.
	 * @param count indicates the count of set bytes.
	 */
	virtual void memset(
		void * const dest, 
		const i32_t fill_byte, 
		const u32_t count) = 0;

	/**
	 * The memchr function searches the first occurence of character starting from buf.
	 * Maximum count bytes are searched.
	 */
	virtual void *memchr(
		const void *buf,
		u8_t character,
		u32_t count) = 0;

	/**
	 * The memchr function searches the last occurence of character starting from the enf of the buf.
	 * Maximum count bytes are searched.
	 */
	virtual void *memrchr(
		const void *buf,
		u8_t character,
		u32_t count) = 0;

	/**
	 * Get the length of a string.
	 * @return Function returns the number of characters in string,
	 * excluding the terminal NULL. No return value is reserved to indicate an error.
	 */
	virtual u32_t strlen(
		eap_const_string string) = 0;

	/**
	 * Get the length of a string.
	 * @return Function returns the number of characters in string,
	 * excluding the terminal NULL. No return value is reserved to indicate an error.
	 */
	virtual u32_t config_strlen(
		eap_config_string string) = 0;

	/**
	 * Function converts lovercase ascii characters to uppercase.
	 * @param source_bytes is pointer to the source bytes.
	 * @param source_bytes_length is length of source bytes.
	 */
	virtual eap_status_e convert_ascii_to_uppercase(
		u8_t * const source_bytes,
		const u32_t source_bytes_length) = 0;
	/**
	 * Function converts bytes to hex ascii.
	 * @param source_bytes is pointer to the source bytes.
	 * @param source_bytes_length is length of source bytes.
	 * @param target is pointer to the target bytes.
	 * @param target_length is length of target bytes.
	 */
	virtual eap_status_e convert_bytes_to_hex_ascii(
		const u8_t * const source_bytes,
		const u32_t source_bytes_length,
		u8_t * const target,
		u32_t *target_length) = 0;

	/**
	 * Function converts bytes to hex ascii.
	 * @param source_bytes is pointer to the source bytes.
	 * @param source_bytes_length is length of source bytes.
	 * @param target is pointer to the target buffer.
	 */
	virtual eap_status_e convert_bytes_to_hex_ascii(
		const void * const source_bytes,
		const u32_t source_bytes_length,
		eap_variable_data_c * const target) = 0;

	/**
	 * Function converts hex ascii to bytes.
	 * @param source_bytes is pointer to the source bytes.
	 * @param source_bytes_length is length of source bytes.
	 * @param target is pointer to the target bytes.
	 * @param target_length is length of target bytes.
	 */
	virtual eap_status_e convert_hex_ascii_to_bytes(
		const u8_t * const source_bytes,
		const u32_t source_bytes_length,
		u8_t * const target,
		u32_t *target_length) = 0;

	/**
	 * Function converts hex ascii to bytes.
	 * @param source_bytes is pointer to the source bytes.
	 * @param source_bytes_length is length of source bytes.
	 * @param target is pointer to the target bytes.
	 * @param target_length is length of target bytes.
	 */
	virtual eap_status_e convert_hex_ascii_to_bytes(
		const void * const source_bytes,
		const u32_t source_bytes_length,
		eap_variable_data_c * const target) = 0;

	/**
	 * Function converts bytes to ascii armored bytes.
	 * @param source_bytes is pointer to the source bytes.
	 * @param source_bytes_length is length of source bytes.
	 * @param target is pointer to the target bytes.
	 * @param target_length is length of target bytes.
	 * @code
	 * Binary 6-bit blocks are converted to 8-bit ascii values. Ascii values can easily represent 2^6=64 values.
	 * If length of target array is not module 3, padding zero bits are ignored.
	 *
	 * |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|                                
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                
	 * | : : : : : : : | : : : : : : : | : : : : : : : | : : : : : : : |                                
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                
	 * |0 1 2 3 4 5|0 1 2 3 4 5|0 1 2 3 4 5|0 1 2 3 4 5|0 1 2 3 4 5|0 1 2 3 4 5|                        
	 * |           |           |           |           |           |           +                        
	 * |           |           |           |           |           |            \                       
	 * |           |           |           |           |           +              \                     
	 * |           |           |           |           |            \               \                   
	 * |           |           |           |           +              \               \                 
	 * |           |           |           |            \               \               \                
	 * |           |           |           +              \               \               \             
	 * |           |           |            \               \               \               \           
	 * |           |           +              \               \               \               \         
	 * |           |            \               \               \               \               \       
	 * |           +              \               \               \               \               \     
	 * |            \               \               \               \               \               \   
	 * |              \               \               \               \               \               \ 
	 * |               +               +               +               +               +               +
	 * |               |               |               |               |               |               |
	 * |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * | : : : : : : : | : : : : : : : | : : : : : : : | : : : : : : : | : : : : : : : | : : : : : : : |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * @endcode
	 */
	virtual eap_status_e convert_bytes_to_ascii_armor(
		const u8_t * const source_bytes,
		const u32_t source_bytes_length,
		u8_t * const target,
		u32_t *target_length) = 0;

	/**
	 * Function converts ascii armored bytes to bytes.
	 * @param source_bytes is pointer to the source bytes.
	 * @param source_bytes_length is length of source bytes.
	 * @param target is pointer to the target bytes.
	 * @param target_length is length of target bytes.
	 * @code
	 * 8-bit ascii values are converted to binary 6-bit blocks. Ascii values can easily represent 2^6=64 values.
	 * If length of source array is not module 3, missing bits are padded with zero bits.
	 *
	 * |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|                                
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                        
	 * | : : : : : : : | : : : : : : : | : : : : : : : | : : : : : : : |0:0:0:0|                        
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                        
	 * |0 1 2 3 4 5|0 1 2 3 4 5|0 1 2 3 4 5|0 1 2 3 4 5|0 1 2 3 4 5|0 1 2 3 4 5|                        
	 * |           |           |           |           |           |           +                        
	 * |           |           |           |           |           |            \                       
	 * |           |           |           |           |           +              \                     
	 * |           |           |           |           |            \               \                   
	 * |           |           |           |           +              \               \                 
	 * |           |           |           |            \               \               \                
	 * |           |           |           +              \               \               \             
	 * |           |           |            \               \               \               \           
	 * |           |           +              \               \               \               \         
	 * |           |            \               \               \               \               \       
	 * |           +              \               \               \               \               \     
	 * |            \               \               \               \               \               \   
	 * |              \               \               \               \               \               \ 
	 * |               +               +               +               +               +               +
	 * |               |               |               |               |               |               |
	 * |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * | : : : : : : : | : : : : : : : | : : : : : : : | : : : : : : : | : : : : : : : | : : : : : : : |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * @endcode
	 */
	virtual eap_status_e restore_bytes_from_ascii_armor(
		const u8_t * const source_bytes,
		const u32_t source_bytes_length,
		u8_t * const target,
		u32_t *target_length) = 0;

	/**
	 * Gets the current trace mask.
	 */
	virtual u32_t get_trace_mask() const = 0;

	/**
	 * This function sets the current trace mask.
	 */
	virtual void set_trace_mask(const u32_t mask) = 0;

	/**
	 * This function sets the trace prefix string.
	 */
	virtual eap_status_e set_trace_prefix(const eap_variable_data_c * const prefix8bit) = 0;

	/**
	 * This function sets the trace output file name.
	 */
	virtual eap_status_e set_trace_file_name(const eap_variable_data_c * const trace_output_file) = 0;

	/**
	 * This function sets the maximum size of trace output file in bytes.
	 * Note this is not absolute value. New file is generated when size of trace log file
	 * exceeds this limitation.
	 */
	virtual void set_max_trace_file_size(const u32_t max_trace_file_size) = 0;

	/**
	 * This functions allows activation of trace when the error occurs.
	 * Look at the set_activate_trace_on_error() and eap_status_return()
	 * functions. NOTE the always active traces are only left active.
	 * That means set_activate_trace_on_error() function calls
	 * set_trace_mask(eap_trace_mask_always).
	 */
	virtual void set_activate_trace_on_error() = 0;

	virtual void check_activate_trace_on_error() = 0;

	/**
	 * This function formats string to buffer.
	 * Function returns number of written bytes.
	 */
	virtual u32_t snprintf(u8_t * const buffer, u32_t buffer_size, eap_format_string format, ...) = 0;

	/**
	 * The formatted_print() function traces format string and formatted parameters to file.
	 * File is set as a parameter to constructor. This is used in macros
	 * EAP_TRACE_DEBUG(object_name, _parameter_list_) and
	 * EAP_TRACE_ERROR(object_name, _parameter_list_).
	 */
	virtual void formatted_print(
		eap_format_string format, 
		...) = 0;

	/**
	 * The trace_data() function traces null terminated prefix string
	 * and data_length bytes from p_data to file. This is used in macros
	 * EAP_TRACE_DATA_DEBUG(object_name, _parameter_list_) and
	 * EAP_TRACE_DATA_ERROR(object_name, _parameter_list_).
	 */
	virtual void trace_data(
		eap_const_string prefix, 
		const void * const p_data, 
		const u32_t data_length) = 0;

	/**
	 * The get_crypto() function returns a pointer to object of type eap_am_crypto.
	 */
	virtual abs_eap_am_crypto_c * get_crypto() = 0;

	/**
	 * This function returns the current time and date in standard UNIX 32-bit format (seconds
	 * since the midnight starting Jan 1, 1970, GMT) according to the
	 * sender's internal clock. 
	 */
	virtual u32_t get_gmt_unix_time() = 0;

	/**
	 * The get_hardware_ticks() function returns current value of hardware ticks counter.
	 */
	virtual u64_t get_hardware_ticks() = 0;

	/**
	 * Function returns count of hardware ticks in one second.
	 */
	virtual u64_t get_hardware_ticks_of_second() = 0;

	/**
	 * Function returns count of clock ticks in one second.
	 */
	virtual u64_t get_clock_ticks_of_second() = 0;

	/**
	 * Function returns current value of clock ticks counter.
	 */
	virtual u64_t get_clock_ticks() = 0;

	/**
	 * Returns true when timer queue is used.
	 * Returns false when timer queue is not used.
	 */
	virtual bool get_use_timer_queue() = 0;

	/**
	 * Returns true when timer thread is stopped.
	 * Returns false when timer thread is running.
	 */
	virtual bool get_thread_stopped() = 0;

	/**
	 * The set_timer() function initializes timer to be elapsed after p_time_ms milliseconds.
	 * @param initializer is pointer to object which timer_expired() function will
	 * be called after timer elapses.
	 * @param id is identifier which will be returned in timer_expired() function.
	 * The user selects and interprets the id for this timer.
	 * @param data is pointer to any user selected data which will be returned in timer_expired() function.
	 *
	 * Adaptation module of tools includes internal attribute eap_timer_queue_c to
	 * which this call is directed.
	 */
	virtual eap_status_e am_set_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id, 
		void * const data,
		const u32_t p_time_ms) = 0;

	/**
	 * The cancel_timer() function cancels the timer id initiated by initializer.
	 *
	 * Adaptation module of tools includes internal attribute eap_timer_queue_c to
	 * which this call is directed.
	 */
	virtual eap_status_e am_cancel_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id) = 0;

	/**
	 * The cancel_all_timers() function cancels all timers.
	 * User should use this in termination of the stack before
	 * the adaptation module of tools is deleted.
	 *
	 * Adaptation module of tools includes internal attribute eap_timer_queue_c to
	 * which this call is directed.
	 *
	 * This function de-activated timer queue.
	 * You could re-activate timer queue with re_activate_timer_queue function.
	 */
	virtual eap_status_e am_cancel_all_timers() = 0;

	/**
	 * This function re-activates timer queue.
	 * Symbian AM call this function when AM-tools object is re-used.
	 * This can be called after am_cancel_all_timers() function.
	 * am_cancel_all_timers() function de-activated timer queue.
	 */
	virtual eap_status_e re_activate_timer_queue() = 0;

	/**
	 * This function sets the resolution of the timer.
	 * The default value is EAP_TIMER_RESOLUTION.
	 * Each pulse increases time by this value.
	 *
	 * Adaptation module of tools includes internal attribute eap_timer_queue_c to
	 * which this call is directed.
	 */
	virtual void set_timer_resolution_ms(const u32_t timer_resolution_ms) = 0;

	/**
	 * This function returns the resolution of the timer.
	 * Each pulse increases time by this value.
	 *
	 * Adaptation module of tools includes internal attribute eap_timer_queue_c to
	 * which this call is directed.
	 */
	virtual u32_t get_timer_resolution_ms() = 0;

	/**
	 * Pulses timer. Time is increased by get_timer_resolution_ms() milli seconds.
	 * Timer pulse is run parallel to the stack operation.
	 * This causes the use of global mutex.
	 *
	 * Adaptation module of tools includes internal attribute eap_timer_queue_c to
	 * which this call is directed.
	 * Function returns the next sleep time in milli seconds.
	 */
	virtual u32_t pulse_timer(const u32_t elapsed_time_in_ms) = 0;

	/**
	 * This function checks whether the internal timer queue is empty.
	 */
	virtual bool get_timer_queue_is_empty() = 0;

	/**
	 * Starts the thread to pulse timer.
	 * User of tools should call this after the stack is created.
	 */
	virtual eap_status_e start_timer_thread() = 0;

	/**
	 * Stops the timer thread.
	 * User of tools should call this before the stack is deleted.
	 */
	virtual eap_status_e stop_timer_thread() = 0;

	/**
	 * Function runs the timer thread loop. This function calls the pulse_timer()
	 * function to increase the elapsed time.
	 */
	virtual eap_status_e timer_thread_function() = 0;

	/**
	 * Returns the value of timer thread activity.
	 * Timer thread stops when this functions returns false.
	 */
	virtual bool get_is_timer_thread_active() = 0;

	/**
	 * This function enters the global mutex. Mutex is needed to synchronize
	 * the timer thread and stack call operations.
	 * Timer pulse is run parallel to the stack operation.
	 * This causes the use of global mutex.
	 */
	virtual void enter_global_mutex() = 0;

	/**
	 * This function leaves the global mutex.
	 * Timer pulse is run parallel to the stack operation.
	 * This causes the use of global mutex.
	 */
	virtual void leave_global_mutex() = 0;

	/**
	 * Returns the global mutex. This is used in some assertion tests.
	 */
	virtual abs_eap_am_mutex_c * get_global_mutex() = 0;

	#define ENTER_CRYPTO()
	#define LEAVE_CRYPTO()

	/**
	 * The timer_sleep function suspends the execution of the current timer thread for the specified interval. 
	 * Timer could be set any value. When timer is set to shorter timeout than the smallest current
	 * timeout is the timer_sleep() will cancel sleep and the new sleep time could be calculated.
	 * @param milli_seconds is the suspension time in milli seconds.
	 */
	virtual void timer_sleep(u32_t milli_seconds) = 0;

	/**
	 * The sleep function suspends the execution of the current thread for the specified interval. 
	 * @param milli_seconds is the suspension time in milli seconds.
	 */
	virtual void sleep(u32_t milli_seconds) = 0;

	/**
	 * The get_is_valid() function returns the status of the object.
	 * True indicates the object is initialized succesfully.
	 */
	virtual bool get_is_valid() const = 0;

#if (defined(DMALLOC) || defined(USE_EAP_CRYPTO_MEMORY_LEAK_FUNCTIONS)) && !defined(USE_EAP_LOCAL_TRACE_FILE_OPEN)
	virtual const EAP_FILE_POINTER * get_trace_file() = 0;
#endif //#if defined(DMALLOC) && !defined(USE_EAP_LOCAL_TRACE_FILE_OPEN)

	/// This function is global proxy for return values.
	virtual eap_status_e eap_status_return(
		const bool print_error_when_true,
		const eap_status_e status,
		const eap_char * const file_name,
		const i32_t line_number) = 0;

	/// This function is global proxy for return values with file name and line number.
	/// This is used in traces.
	virtual eap_status_e eap_status_return_file_number(
		const bool print_error_when_true,
		const eap_status_e status,
		const u32_t file_date,
		const u32_t file_number,
		const i32_t line_number) = 0;

	/// Memory store is visible only during the eap_am_tools_c object is alive.
	/// This function add flat data to memory store.
	/// You must format your data to eap_tlv_message_data_c object.
	/// Data is identified by key parameter.
	/// You can set timeout to data. Data will be automatically removed after timeout.
	/// Timeout value zero means no timeout is set.
	/// Serious WARNING: do use really good key values.
	/// Memory store is globally used by all EAP Core objects.
	/// Key must be good that other users do not use others data.
	/// Add the real data type as a string to the key and other identifiers
	/// that separate data between the other users that store same data type
	/// to the memory store.
	virtual eap_status_e memory_store_add_data(
		const eap_variable_data_c * const key,
		eap_tlv_message_data_c * const data,
		const u32_t timeout) = 0;

	/// Memory store is visible only during the eap_am_tools_c object is alive.
	/// This function gets data from memory store.
	/// Data is returned in eap_tlv_message_data_c object.
	/// Data is identified by key parameter.
	/// Serious WARNING: do use really good key values.
	/// Memory store is globally used by all EAP Core objects.
	/// Key must be good that other users do not use others data.
	/// Add the real data type as a string to the key and other identifiers
	/// that separate data between the other users that store same data type
	/// to the memory store.
	virtual eap_status_e memory_store_get_data(
		const eap_variable_data_c * const key,
		eap_tlv_message_data_c * const data) = 0;


	/// Memory store is visible only during the eap_am_tools_c object is alive.
	/// This function removes data from memory store.
	/// Data is identified by key parameter.
	/// Serious WARNING: do use really good key values.
	/// Memory store is globally used by all EAP Core objects.
	/// Key must be good that other users do not use others data.
	/// Add the real data type as a string to the key and other identifiers
	/// that separate data between the other users that store same data type
	/// to the memory store.
	virtual eap_status_e memory_store_remove_data(
		const eap_variable_data_c * const key) = 0;



#if defined(USE_EAP_ERROR_TESTS)
	/**
	 * This function generates random error to message.
	 * This is used in protocol testing.
	 */
	virtual eap_status_e generate_random_error(
		eap_buf_chain_wr_c * const sent_packet,
		const bool forse_error,
		const u32_t packet_index,
		const u32_t minimum_index,
		const u32_t error_probability,
		const u32_t minimum_packet_length) = 0;

	/**
	 * This function returns index of message.
	 * This is used in protocol testing.
	 */
	virtual u32_t get_packet_index() = 0;

	/**
	 * This function increases index of message.
	 * This is used in protocol testing.
	 */
	virtual void increase_packet_index() = 0;
#endif //#if defined(USE_EAP_ERROR_TESTS)


	/**
	 * Function converts AM error value to eap_status_e.
	 * @param am_error_value is the AM error value.
	 */
	virtual eap_status_e convert_am_error_to_eapol_error(const i32_t am_error_value) = 0;

	/**
	 * Function converts eap_status_e to AM error value.
	 * @param eap_error is the eap_status_e error value.
	 */
	virtual i32_t convert_eapol_error_to_am_error(eap_status_e eap_error) = 0;

	/**
	 * This function returns true when milli second timer is used.
	 */
	virtual bool get_use_eap_milli_second_timer() = 0;

	/**
	 * This function sets the flag whether to use milli second timer (true) or not (false).
	 */
	virtual void set_use_eap_milli_second_timer(
		const bool use_eap_millisecond_timer) = 0;

	/**
	 * This function reads value of environment variable.
	 * Note the all environments does not support this, for example Symbian.
	 */
	virtual eap_status_e getenv(
		const eap_variable_data_c * const environment_variable_name,
		eap_variable_data_c * const environment_variable_value) = 0;

	/**
	 * This function converts string to u32_t value.
	 */
	virtual eap_status_e number_string_to_u32(
		const u8_t * const number_string,
		const u32_t number_string_length,
		u32_t * const integer) = 0;

	/**
	 * This function checks whether the character is space.
	 */
	virtual bool isspace(const u8_t character) = 0;

	/**
	 * This function traces read configure field and data.
	 */
	virtual void trace_configuration(
		const eap_status_e configuration_read_status,
		const eap_configuration_field_c * const field,
		const eap_variable_data_c * const data) = 0;	

	/**
	 * This function converts u64_t to u64_struct type.
	 * This is used in some 64-bit calculations.
	 */
	virtual u64_struct u64_t_to_u64_struct(const u64_t value) = 0;

	/**
	 * This function converts u64_struct to u64_t type.
	 * This is used in some 64-bit calculations.
	 */
	virtual u64_t u64_struct_to_u64_t(const u64_struct value) = 0;

	/**
	 * This function xors two 64-bit integers.
	 */
	virtual u64_t xor_u64(const u64_t a, const u64_t b) = 0;

	/**
	 * This function multiplys two 64-bit integers.
	 * Returned value is remainder of 2^64, so overflow is not detected.
	 */
	virtual u64_t multiply_u64(const u64_t a, const u64_t b) = 0;

	/**
	 * This function compares two 64-bit integers.
	 * If a is bigger function returns positive integer.
	 * If b is bigger function returns negative integer.
	 * If a == b function returns zero integer.
	 */
	virtual i32_t compare_u64(const u64_t a, const u64_t b) = 0;

	/**
	 * The create_uuid_v5() method creates an UUID version 5 (SHA-1) from the 
	 * name space UUID and name (RFC 4122). The name space UUID should be in 
	 * hex format (e.g. 3d813cbb47fb52ba91df831e1593ac29). The name space UUID 
	 * and name must be in network byte order (little endiann).
	 * 
	 * @param ns_uuid pointer to the UUID of the name space in hex format.
	 * @param ns_uuid_length lenght of the name space UUID in bytes (should be 16 bytes).
	 * @param name pointer to the name (e.g. MAC address) in the name space in hex format.
	 * @param name_length length of the name in bytes.
	 * @param uuid pointer to an eap_variable_data_c instance to 
	 *  which the UUID will be created.
	 * @return status status code: eap_status_ok when successful, 
	 *  otherwise an error code.
	 */
	virtual eap_status_e create_uuid_v5( 
		const void* const ns_uuid,
		const u32_t ns_uuid_length,
		const void* const name, 
		const u32_t name_length,
		eap_variable_data_c* const uuid ) = 0;

	/**
	 * The create_uuid_v5_from_mac_address() method creates an UUID version 5
	 * from a MAC address. Uses an internally defined, fixed name space UUID
	 * allocated for EAP MAC addresses. The MAC address should be in 
	 * hex format (little endiann). 
	 * 
	 * @param mac_address pointer to the MAC address in hex format.
	 * @param mac_address_length length of the MAC address (should be 6 bytes).
	 * @param uuid pointer to an eap_variable_data_c instance to 
	 *  which the UUID will be created.
	 * @return status status code: eap_status_ok when successful, 
	 *  otherwise an error code.
	 */
	virtual eap_status_e create_uuid_v5_from_mac_address( 
		const u8_t* const mac_address, 
		const u32_t mac_address_length,
		eap_variable_data_c* const uuid ) = 0;

};


#endif //#if !defined( _ABS_EAP_AM_TOOLS_H_ )



// End.
