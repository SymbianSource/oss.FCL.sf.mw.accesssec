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
* %version: 12 %
*/

#if !defined( _EAP_TOOLS_H_ )
#define _EAP_TOOLS_H_

/** @file */

#include "eap_am_compiler_flags.h"

#include "eap_variable_data.h"
#include "eap_status.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TOOLS_H)
	#define EAP_CLASS_VISIBILITY_EAP_TOOLS_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TOOLS_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H 
	#define EAP_FUNC_EXPORT_EAP_TOOLS_H 
	#define EAP_C_FUNC_EXPORT_EAP_TOOLS_H 
#elif defined(EAP_EXPORT_EAP_TOOLS_H)
	#define EAP_CLASS_VISIBILITY_EAP_TOOLS_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TOOLS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TOOLS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TOOLS_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TOOLS_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TOOLS_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TOOLS_H 
	#define EAP_C_FUNC_EXPORT_EAP_TOOLS_H 
#endif
// End: added by script change_export_macros.sh.

#if defined(USE_EAP_STACK_TRACE) || defined(USE_EAP_ASSERT_STACK_TRACE)
	#include "eap_am_stack_trace.h"
#endif //#if defined(EAP_STACK_TRACE)


//----------------------------------------------------------------------------------

/**
 * This function changes 16-bit unsigned integer from host order to network order.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H u16_t eap_htons(const u16_t value);

/**
 * This function changes 32-bit unsigned integer from host order to network order.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H u32_t eap_htonl(const u32_t value);

/**
 * This function changes 64-bit unsigned integer from host order to network order.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H u64_t eap_htonll(const u64_t value);


/**
 * This function changes 16-bit unsigned integer from network order to host order.
 */
#define eap_ntohs(addr) eap_htons(addr)

/**
 * This function changes 32-bit unsigned integer from network order to host order.
 */
#define eap_ntohl(addr) eap_htonl(addr)

/**
 * This function changes 64-bit unsigned integer from network order to host order.
 */
#define eap_ntohll(addr) eap_htonll(addr)


/**
 * This function changes 16-bit unsigned integer from host order to little endian order.
 * This is used in some crypto algorithms.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H u16_t eap_host_to_little_endian_short(const u16_t value);

/**
 * This function changes 32-bit unsigned integer from host order to little endian order.
 * This is used in some crypto algorithms.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H u32_t eap_host_to_little_endian_long(const u32_t value);

/**
 * This function changes 64-bit unsigned integer from host order to little endian order.
 * This is used in some crypto algorithms.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H u64_t eap_host_to_little_endian_long(const u64_t value);

/**
 * This function write 16-bit unsigned integer which is in little endian order to memory.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H eap_status_e eap_write_u16_t_little_endian_order(
	void * const p_data,
	const u32_t data_length,
	const u16_t value);

/**
 * This function write 32-bit unsigned integer which is in little endian order to memory.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H eap_status_e eap_write_u32_t_little_endian_order(
	void * const p_data,
	const u32_t data_length,
	const u32_t value);

/**
 * This function write 64-bit unsigned integer which is in little endian order to memory.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H eap_status_e eap_write_u64_t_little_endian_order(
	void * const p_data,
	const u32_t data_length,
	const u64_t value);

/**
 * This function reads 16-bit unsigned integer which is in little endian order from memory
 * and returns value in host order.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H u16_t eap_read_u16_t_little_endian_order(
	const void * const data,
	const u32_t data_length);

/**
 * This function reads 32-bit unsigned integer which is in little endian order from memory
 * and returns value in host order.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H u32_t eap_read_u32_t_little_endian_order(
	const void * const p_data,
	const u32_t data_length);

/**
 * This function reads 64-bit unsigned integer which is in little endian order from memory
 * and returns value in host order.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H u64_t eap_read_u64_t_little_endian_order(
	const void * const p_data,
	const u32_t data_length);

/**
 * This function reads 16-bit unsigned integer which is in network order from memory
 * and returns value in host order.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H u16_t eap_read_u16_t_network_order(
	const void * const data,
	const u32_t data_length);

/**
 * This function reads 24-bit unsigned integer which is in network order from memory
 * and returns it in 32-bit value in host order.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H u32_t eap_read_u24_t_network_order(
	const void * const data,
	const u32_t data_length);

/**
 * This function reads 32-bit unsigned integer which is in network order from memory
 * and returns value in host order.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H u32_t eap_read_u32_t_network_order(
	const void * const data,
	const u32_t data_length);

/**
 * This function reads 64-bit unsigned integer which is in network order from memory
 * and returns value in host order.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H u64_t eap_read_u64_t_network_order(
	const void * const data,
	const u32_t data_length);


/**
 * This function writes 16-bit unsigned integer to network order to memory
 * and returns status eap_status_ok when successfull.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H eap_status_e eap_write_u16_t_network_order(
	void * const data,
	const u32_t data_length,
	const u16_t value);

/**
 * This function writes 24-bit unsigned integer to network order to memory
 * and returns status eap_status_ok when successfull.
 * Note only 24-bit least significant bits are written from 32-bit value.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H eap_status_e eap_write_u24_t_network_order(
	void * const data,
	const u32_t data_length,
	const u32_t value);

/**
 * This function writes 32-bit unsigned integer to network order to memory
 * and returns status eap_status_ok when successfull.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H eap_status_e eap_write_u32_t_network_order(
	void * const data,
	const u32_t data_length,
	const u32_t value);

/**
 * This function writes 64-bit unsigned integer to network order to memory
 * and returns status eap_status_ok when successfull.
 */
EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H eap_status_e eap_write_u64_t_network_order(
	void * const data,
	const u32_t data_length,
	const u64_t value);



EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H u64_t eap_shift_left_64_bit(u64_t value, u32_t shift);

EAP_C_FUNC_VISIBILITY_EAP_TOOLS_H u64_t eap_shift_right_64_bit(u64_t value, u32_t shift);


inline u64_t eap_read_u64_t_host_order(
	const void * const p_data,
	const u32_t data_length)
{
	#if defined(EAP_LITTLE_ENDIAN) /// byte 0 is least significant (i386)
		return eap_read_u64_t_little_endian_order(
			p_data,
			data_length);
	#elif defined(EAP_BIG_ENDIAN) /// byte 0 is most significant (mc68k)
		return eap_read_u64_t_network_order(
			p_data,
			data_length);
	#else
		#error ERROR: define EAP_LITTLE_ENDIAN (byte 0 is least significant (i386)) \
				or EAP_BIG_ENDIAN (byte 0 is most significant (mc68k)).
	#endif
}


inline eap_status_e eap_write_u64_t_host_order(
	void * const data,
	const u32_t data_length,
	const u64_t value)
{
	#if defined(EAP_LITTLE_ENDIAN) /// byte 0 is least significant (i386)
		return eap_write_u64_t_little_endian_order(
			data,
			data_length,
			value);
	#elif defined(EAP_BIG_ENDIAN) /// byte 0 is most significant (mc68k)
		return eap_write_u64_t_network_order(
			data,
			data_length,
			value);
	#else
		#error ERROR: define EAP_LITTLE_ENDIAN (byte 0 is least significant (i386)) \
				or EAP_BIG_ENDIAN (byte 0 is most significant (mc68k)).
	#endif
}

//----------------------------------------------------------------------------------

#if defined(__SYMBIAN32__)
	/// This is name of default file for EAP Core traces.
	const eap_const_string EAP_DEFAULT_TRACE_FILE = EAPL("c:\\logs\\eapol\\eap_core.log");
	#define __PRETTY_FUNCTION__ "function()"
#elif defined(__GNUC__) || defined(__arm)
	/// This is name of default file for EAP Core traces.
	const char * const EAP_DEFAULT_TRACE_FILE = "/tmp/eap_core.log";
#elif defined(_WIN32) && !defined(__GNUC__)
	#define __PRETTY_FUNCTION__ "function()"
	/// This is name of default file for EAP Core traces.
	const char * const EAP_DEFAULT_TRACE_FILE = "c:\\temp\\eap_core.log";
#endif


#define EAP_NULL_FUNCTION  /* do{}while(0) // This causes a lot of warning C4127: conditional expression is constant. */


#if defined(NO_EAP_TRACE)
#error Use of NO_EAP_TRACE is deprecated. Please, define USE_EAP_TRACE when EAP traces are needed.
#endif //defined(NO_EAP_TRACE)

#if defined(NO_EAP_DEBUG_TRACE)
#error Use of NO_EAP_DEBUG_TRACE is deprecated. Please, define USE_EAP_DEBUG_TRACE when EAP debug traces are needed.
#endif //defined(NO_EAP_DEBUG_TRACE)

#if defined(NO_EAP_TRACE_STRINGS)
#error Use of NO_EAP_TRACE_STRINGS is deprecated. Please, define USE_EAP_TRACE_STRINGS when EAP debug trace strings are needed.
#endif //defined(NO_EAP_TRACE_STRINGS)

#if defined(NO_EAP_ASSERTS)
#error Use of NO_EAP_ASSERTS is deprecated. Please, define USE_EAP_ASSERTS when EAP assertions are needed.
#endif //!defined(USE_EAP_ASSERTS)

#if defined(NO_EAP_STATUS_RETURN)
#error Use of NO_EAP_STATUS_RETURN is deprecated. Please, define USE_EAP_STATUS_RETURN when EAP status return traces are needed.
#endif //!defined(NO_EAP_STATUS_RETURN)

#if defined(NO_EAP_FUNCTION_TRACE)
#error Use of NO_EAP_FUNCTION_TRACE is deprecated. Please, define USE_EAP_FUNCTION_TRACE when heavy EAP function traces are needed.
#endif //!defined(NO_EAP_FUNCTION_TRACE)


#if !defined(USE_EAP_TRACE_ALWAYS) && !defined(USE_EAP_TRACE)

	#define EAP_TRACE_ALWAYS(object_name, flags, _parameter_list_) EAP_NULL_FUNCTION

	#define EAP_TRACE_DATA_ALWAYS(object_name, flags, _parameter_list_) EAP_NULL_FUNCTION

#else

	/**
	 * This function traces formatted string with parameters to a file.
	 * For example
	 * @code
	 * EAP_TRACE_ALWAYS(m_am_tools, TRACE_FLAGS_TIMER, (EAPL("~eap_type_gsmsim_c(): 0x%08x\n"), this));
	 * @endcode
	 *
	 */
	#define EAP_TRACE_ALWAYS(object_name, flags, _parameter_list_) \
			if (object_name != 0 && ((*(object_name)).get_trace_mask() & (flags))) \
			{ \
				(*(object_name)).formatted_print _parameter_list_ ; \
			} \

	/**
	 * This function traces data bytes to a file.
	 * For example
	 * @code
	 * EAP_TRACE_DATA_ALWAYS(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("new_nai"),
	 *	new_nai->get_data(new_nai->get_data_length()),
	 *	new_nai->get_data_length()));".
	 * @endcode
	 *
	 */
	#define EAP_TRACE_DATA_ALWAYS(object_name, flags, _parameter_list_) \
			if (object_name != 0 && ((*(object_name)).get_trace_mask() & (flags))) \
			{ \
				(*(object_name)).trace_data _parameter_list_ ; \
			} \

#endif //#if !defined(USE_EAP_TRACE_ALWAYS)


#if !defined(USE_EAP_TRACE)

	#define EAP_TRACE_ERROR(object_name, flags, _parameter_list_) EAP_NULL_FUNCTION

	#define EAP_TRACE_DEBUG(object_name, flags, _parameter_list_) EAP_NULL_FUNCTION

	#define EAP_TRACE_FORMAT(object_name, _parameter_list_) EAP_NULL_FUNCTION

	#define EAP_TRACE_RETURN_STRING(object_name, string) EAP_NULL_FUNCTION

	#define EAP_TRACE_RETURN_STRING_FLAGS(object_name, flags, string) EAP_NULL_FUNCTION

	#define EAP_TRACE_DATA_ERROR(object_name, flags, _parameter_list_) EAP_NULL_FUNCTION

	#define EAP_TRACE_DATA_DEBUG(object_name, flags, _parameter_list_) EAP_NULL_FUNCTION

	#define EAP_TRACE_BEGIN(object_name, flags) EAP_NULL_FUNCTION

	#define EAP_TRACE_END(object_name, flags) EAP_NULL_FUNCTION

#else

	/**
	 * This function traces formatted string with parameters to a file.
	 * Trace includes ERROR string, file name and line number.
	 * For example
	 * @code
	 * EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_TIMER, (EAPL("~eap_type_gsmsim_c(): 0x%08x\n"), this));
	 * @endcode
	 *
	 */
	#define EAP_TRACE_ERROR(object_name, flags, _parameter_list_) \
		if (object_name != 0) \
		{ \
			(*(object_name)).check_activate_trace_on_error(); \
			if (((*(object_name)).get_trace_mask() & ((flags) | eap_am_tools_c::eap_trace_mask_error))) \
			{ \
				(*(object_name)).formatted_print(EAPL("ERROR: source: %s:%d\n"), __FILE__, __LINE__); \
				(*(object_name)).formatted_print _parameter_list_ ; \
			} \
		} \

	/**
	 * This function traces data bytes to a file.
	 * For example
	 * @code
	 * EAP_TRACE_DATA_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("new_nai"),
	 *	new_nai->get_data(new_nai->get_data_length()),
	 *	new_nai->get_data_length()));".
	 * @endcode
	 *
	 */
	#define EAP_TRACE_DATA_ERROR(object_name, flags, _parameter_list_) \
		if (object_name != 0) \
		{ \
			(*(object_name)).check_activate_trace_on_error(); \
			if (((*(object_name)).get_trace_mask() & ((flags) | eap_am_tools_c::eap_trace_mask_error))) \
			{ \
				(*(object_name)).trace_data _parameter_list_ ; \
			} \
		} \

	/**
	 * @{ Remove debug traces in release version when appropriate. }
	 */
	//#if defined(_DEBUG) && defined(USE_EAP_DEBUG_TRACE)
	#if defined(USE_EAP_DEBUG_TRACE)

		/**
		 * This function traces formatted string with parameters to a file.
		 * This is used only in debug version.
		 * For example
		 * @code
		 * EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_TIMER, (EAPL("~eap_type_gsmsim_c(): 0x%08x\n"), this));
		 * @endcode
		 *
		 */
		#define EAP_TRACE_DEBUG(object_name, flags, _parameter_list_) \
				if (object_name != 0 && ((*(object_name)).get_trace_mask() & ((flags) | eap_am_tools_c::eap_trace_mask_error))) \
				{ \
					if (((*(object_name)).get_trace_mask() & (flags))) \
					{ \
						if (((*(object_name)).get_trace_mask() & ((flags) & eap_am_tools_c::eap_trace_mask_error))) \
						{ \
							(*(object_name)).formatted_print(EAPL("ERROR: source: %s:%d\n"), __FILE__, __LINE__); \
						} \
						(*(object_name)).formatted_print _parameter_list_ ; \
					} \
					else \
					{ \
						/* Do nothing. This else is because lint complains the missing else. */ \
					} \
				} \

		/**
		 * This function traces data bytes to a file.
		 * This is used only in debug version.
		 * For example
		 * @code
		 * EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("new_nai"),
		 *	new_nai->get_data(new_nai->get_data_length()),
		 *	new_nai->get_data_length()));".
		 * @endcode
		 *
		 */
		#define EAP_TRACE_DATA_DEBUG(object_name, flags, _parameter_list_) \
				if (object_name != 0 && ((*(object_name)).get_trace_mask() & (flags))) \
				{ \
					(*(object_name)).trace_data _parameter_list_ ; \
				} \

		/**
		 * This function formats string to a buffer.
		 * This is used only in debug version.
		 * For example
		 * @code
		 * EAP_TRACE_FORMAT(m_am_tools, (buffer, buffer_size, EAPL("new_nai %d, %s"),
		 *	foo,
		 *	EAPL("some string")));".
		 * @endcode
		 *
		 */
		#define EAP_TRACE_FORMAT(object_name, _parameter_list_) \
				if (object_name != 0 && (*(object_name)).get_trace_mask()) \
				{ \
					(*(object_name)).snprintf _parameter_list_; \
				} \

		#define EAP_TRACE_RETURN_STRING(object_name, string) \
			eap_automatic_trace_string_c __eap_trace_function_returns__(object_name, string);

		#define EAP_TRACE_RETURN_STRING_FLAGS(object_name, flags, string) \
			eap_automatic_trace_string_c __eap_trace_function_returns__(object_name, flags, string);

		/**
		 * This flag indicates that the debug traces are active.
		 * Functions can use this flag to deduce whether debug related
		 * parameters should be introduced.
		 */
		#define	EAP_DEBUG_TRACE_ACTIVE

	#else

		#define EAP_TRACE_DEBUG(object_name, flags, _parameter_list_) EAP_NULL_FUNCTION

		#define EAP_TRACE_DATA_DEBUG(object_name, flags, _parameter_list_) EAP_NULL_FUNCTION

		#define EAP_TRACE_FORMAT(object_name, _parameter_list_) EAP_NULL_FUNCTION

		#define EAP_TRACE_RETURN_STRING(object_name, string) EAP_NULL_FUNCTION

		#define EAP_TRACE_RETURN_STRING_FLAGS(object_name, flags, string) EAP_NULL_FUNCTION

	#endif


	#if !defined(USE_EAP_FUNCTION_TRACE)

		#define EAP_TRACE_BEGIN(object_name, flags) EAP_NULL_FUNCTION

		#define EAP_TRACE_END(object_name, flags) EAP_NULL_FUNCTION

	#else
		/**
		 * This function traces begin of the function with name, file and line number to a file.
		 * For example
		 * @code
		 * EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		 * @endcode
		 *
		 */
		#define EAP_TRACE_BEGIN(object_name, flags) \
				if (object_name != 0 && ((*(object_name)).get_trace_mask() & (eap_am_tools_c::eap_trace_mask_functions))) \
				{ \
					(*(object_name)).formatted_print(EAPL("-> %s:%s:%d\n"), __PRETTY_FUNCTION__, __FILE__, __LINE__); \
				} \

		/**
		 * This function traces end of the function with name, file and line number to a file.
		 * For example
		 * @code
		 * EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		 * @endcode
		 *
		 */
		#define EAP_TRACE_END(object_name, flags) \
				if (object_name != 0 && ((*(object_name)).get_trace_mask() & (eap_am_tools_c::eap_trace_mask_functions))) \
				{ \
					(*(object_name)).formatted_print(EAPL("<- %s:%s:%d\n"), __PRETTY_FUNCTION__, __FILE__, __LINE__); \
				} \

	#endif

#endif //#if !defined(USE_EAP_TRACE)



#if defined(USE_EAP_STACK_TRACE)

		#define EAP_STACK_TRACE_TOOLS(am_tools, address) \
				{ \
					stack_trace st_trace(am_tools); \
					st_trace.trace(address); \
				} \

		#define EAP_STACK_TRACE(address) \
			EAP_STACK_TRACE_TOOLS(m_am_tools, address)

#else

		#define EAP_STACK_TRACE_TOOLS(am_tools, address) EAP_NULL_FUNCTION

		#define EAP_STACK_TRACE(address) EAP_NULL_FUNCTION

#endif //#if defined(EAP_STACK_TRACE)


#if defined(USE_EAP_ASSERT_STACK_TRACE)

		#define EAP_ASSERT_STACK_TRACE_TOOLS(am_tools, address) \
				{ \
					stack_trace st_trace(am_tools); \
					st_trace.trace(address); \
				} \

		#define EAP_ASSERT_STACK_TRACE(address) \
			EAP_ASSERT_STACK_TRACE_TOOLS(m_am_tools, address)

#else

		#define EAP_ASSERT_STACK_TRACE_TOOLS(am_tools, address) EAP_NULL_FUNCTION

		#define EAP_ASSERT_STACK_TRACE(address) EAP_NULL_FUNCTION

#endif //#if defined(EAP_STACK_TRACE)



/// This defines one if case for a constant
/// that returns constant name string.
#define EAP_IF_RETURN_STRING(type, const_type) \
		if ((type) == (const_type)) \
		{ \
			return EAPL(#const_type); \
		}


#if !defined(lint)
	#if defined(__GNUC__) || defined(__ARMCC__) || defined(__arm)
		/// This prevent compiler warning of unused variable.
		#define EAP_UNREFERENCED_PARAMETER(P) \
				if ((&(P)) == (&(P))) \
					; \

	#else
		/// This prevent compiler warning of unused variable.
		#define EAP_UNREFERENCED_PARAMETER(P) (P)
	#endif
#else // lint
	// Note: lint -e530 says don't complain about uninitialized variables for
	// this varible.  Error 527 has to do with unreachable code.
	// -restore restores checking to the -save state
	/// This prevent compiler warning of unused variable.
	#define EAP_UNREFERENCED_PARAMETER(P)          \
		/*lint -save -e527 -e530 */ \
		{\
				(P) = (P); \
		} \

		/*lint -restore */
#endif // lint

//----------------------------------------------------------------------------------

#endif //#if !defined( _EAP_TOOLS_H_ )



// End.
