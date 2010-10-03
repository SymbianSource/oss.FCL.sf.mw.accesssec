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
* %version: 8.1.2 %
*/

#if !defined( _EAP_AM_TOOLS_H_ )
#define _EAP_AM_TOOLS_H_

#include "abs_eap_am_tools.h"
#include "eap_variable_data.h"
#include "eap_tools.h"
#include "eap_status.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_TOOLS_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TOOLS_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TOOLS_H 
	#define EAP_FUNC_EXPORT_EAP_AM_TOOLS_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TOOLS_H 
#elif defined(EAP_EXPORT_EAP_AM_TOOLS_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TOOLS_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TOOLS_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TOOLS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TOOLS_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_TOOLS_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TOOLS_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TOOLS_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TOOLS_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_status_string.h"
#include "abs_eap_am_memory_store_data.h"


//#if !defined(NO_EAP_AM_MEMORY_STORE)
class eap_tlv_message_data_c;
class eap_am_memory_store_c;
//#endif //#if !defined(NO_EAP_AM_MEMORY_STORE)


/// This class defines the common functions of tools.
/// These are the platform independent functions used in tools.
class EAP_CLASS_VISIBILITY_EAP_AM_TOOLS_H eap_am_tools_c
: public abs_eap_am_tools_c
//#if !defined(NO_EAP_AM_MEMORY_STORE)
, public abs_eap_am_memory_store_data_c
//#endif //#if !defined(NO_EAP_AM_MEMORY_STORE)
{
private:

#if !defined(NO_EAP_AM_MEMORY_STORE)
	eap_am_memory_store_c * m_memory_store;
#endif //#if !defined(NO_EAP_AM_MEMORY_STORE)

	/// This is trace mask. This could be changed dynamically with set_trace_mask() function.
	u32_t m_trace_mask;

#if defined(USE_EAP_ERROR_TESTS)
	u32_t m_packet_index;
#endif //#if defined(USE_EAP_ERROR_TESTS)

	bool m_use_seconds_timestamp_in_traces;

	bool m_thread_stopped;

	bool m_use_timer_queue;

	/// Function shutdown_am_tools() is called already.
	bool m_shutdown_was_called;

	/// This flag allows activation of trace when the error occurs.
	/// Look at the set_activate_trace_on_error() and eap_status_return()
	/// functions.
	bool m_activate_trace_on_error;

	u8_t m_tmp_buffer[256];
	
	u8_t m_tmp_ascii_buffer[256];


	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H u8_t octet_to_ascii_armor(
		const u8_t source_byte);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H u8_t octet_from_ascii_armor(
		const u8_t source_byte);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H void convert_selected_bytes_to_ascii_armor(
		const u8_t source_byte,
		u32_t * const saved_bit_count,
		u8_t * const saved_bits,
		u8_t * const target,
		u32_t * const output_ind,
		const bool last_input_byte);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H void restore_selected_bytes_from_ascii_armor(
		const u8_t source_byte,
		u32_t * const missing_bit_count,
		u8_t * const target,
		u32_t * const output_ind,
		const bool last_input_byte);

public:

	/// These are valid values used with set_trace_mask() function.
	enum
	{
		eap_trace_mask_none               = (0u),       ///< This value disables all traces.
		eap_trace_mask_always             = (1u << 0u), ///< This values traces all permanent traces (EAP_TRACE_ALWAYS() macro).
		eap_trace_mask_error              = (1u << 1u), ///< This values traces all errors.
		eap_trace_mask_debug              = (1u << 2u), ///< This value traces debug information. Not used in released code.
		eap_trace_mask_functions          = (1u << 3u), ///< This value traces function enters and returns.
		eap_trace_mask_crypto             = (1u << 4u), ///< This value traces crypto data. Do not use on released code. All keys and intermediate values are traced.
		eap_trace_mask_timer              = (1u << 5u), ///< This value traces the timer functions.
		eap_trace_mask_eap_messages       = (1u << 6u), ///< This value traces only the EAP messages.
		eap_trace_mask_test_vectors       = (1u << 7u), ///< This value traces only the test vectors of each EAP-type.
		eap_trace_mask_crypto_sha1        = (1u << 8u), ///< This value traces only internal state of SHA1.
		eap_trace_mask_crypto_md4         = (1u << 9u), ///< This value traces only internal state of MD4.
		eap_trace_mask_crypto_rc4         = (1u << 10u), ///< This value traces only internal state of RC4.
		eap_trace_mask_crypto_test_random = (1u << 11u), ///< This value traces only internal state of test random generator.
		eap_trace_mask_message_data       = (1u << 12u), ///< This value traces only data of the messages, this will increase trace bloat.
		eap_trace_mask_hash_map           = (1u << 13u), ///< This value traces only data of hash table. It does map data and selector.
		eap_trace_mask_timer_queue        = (1u << 14u), ///< This value traces the timer queue.
		eap_trace_mask_ok_returns         = (1u << 15u), ///< This value traces the OK return values, alot of them.
		eap_trace_mask_trace_never        = (1u << 16u), ///< This value never traces. This can disable trace always.
	};

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H u8_t octet_to_ascii(i32_t octet);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H u8_t ascii_to_octet(i32_t character);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H virtual ~eap_am_tools_c();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_am_tools_c();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H bool get_use_seconds_timestamp_in_traces();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H bool get_thread_stopped();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H void set_use_timer_queue();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H bool get_use_timer_queue();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H u32_t get_trace_mask() const;

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H void set_trace_mask(const u32_t mask);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H void set_activate_trace_on_error();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H void check_activate_trace_on_error();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H void trace_data(eap_const_string prefix, const void * const data, const u32_t data_length);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e timer_thread_function();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e convert_ascii_to_uppercase(
		u8_t * const source_bytes,
		const u32_t source_bytes_length);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e convert_bytes_to_hex_ascii(
		const u8_t * const source_bytes,
		const u32_t source_bytes_length,
		u8_t * const target,
		u32_t *target_length);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e convert_bytes_to_hex_ascii(
		const void * const source_bytes,
		const u32_t source_bytes_length,
		eap_variable_data_c * const target);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e convert_hex_ascii_to_bytes(
		const u8_t * const source_bytes,
		const u32_t source_bytes_length,
		u8_t * const target,
		u32_t *target_length);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e convert_hex_ascii_to_bytes(
		const void * const source_bytes,
		const u32_t source_bytes_length,
		eap_variable_data_c * const target);

	
	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e convert_bytes_to_ascii_armor(
		const u8_t * const source_bytes,
		const u32_t source_bytes_length,
		u8_t * const target,
		u32_t *target_length);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e restore_bytes_from_ascii_armor(
		const u8_t * const source_bytes,
		const u32_t source_bytes_length,
		u8_t * const target,
		u32_t *target_length);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e eap_status_return(
		const bool print_error_when_true,
		const eap_status_e status,
		const eap_char * const file_name,
		const i32_t line_number);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e eap_status_return_file_number(
		const bool print_error_when_true,
		const eap_status_e status,
		const u32_t file_date,
		const u32_t file_number,
		const i32_t line_number);


	// This is documented in abs_eap_am_tools_c::memory_store_add_data().
	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e memory_store_add_data(
		const eap_variable_data_c * const key,
		eap_tlv_message_data_c * const data,
		const u32_t timeout);

	// This is documented in abs_eap_am_tools_c::memory_store_get_data().
	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e memory_store_get_data(
		const eap_variable_data_c * const key,
		eap_tlv_message_data_c * const data);

	// This is documented in abs_eap_am_tools_c::memory_store_remove_data().
	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e memory_store_remove_data(
		const eap_variable_data_c * const key);


	/// This function shuts down eap_am_tools_c object.
	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e shutdown_am_tools();

	/// The implementing function must call eap_am_tools_c::shutdown_am_tools().
	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H virtual eap_status_e shutdown() = 0;

	/**
	 * Function converts unicode characters into UTF8 characters.
	 * @param dest is reference to destination utf8 variable data.
	 * @param src is refrence to unicode variable data.
	 * @return eap status code.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e generic_convert_unicode_to_utf8(
		eap_variable_data_c & dest,
		const eap_variable_data_c & src);

	/**
	 * Function converts UTF8 characters into unicode characters.
	 * @param dest is reference to destination unicode variable data.
	 * @param src is refrence to UTF8 variable data.
	 * @return eap status code.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e generic_convert_utf8_to_unicode(
		eap_variable_data_c & dest,
		const eap_variable_data_c & src);

	/**
	 * Function parses NAI to usename and realm.
	 * If either is missing the corresponding value will be invalid.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e parse_nai(
		const eap_variable_data_c * const nai,
		eap_variable_data_c * const username,
		eap_variable_data_c * const realm);


#if defined(USE_EAP_ERROR_TESTS)
	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e generate_random_error(
		eap_buf_chain_wr_c * const sent_packet,
		const bool forse_error,
		const u32_t packet_index,
		const u32_t minimum_index,
		const u32_t error_probability,
		const u32_t minimum_packet_length);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H u32_t get_packet_index();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H void increase_packet_index();
#endif //#if defined(USE_EAP_ERROR_TESTS)


	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e number_string_to_u32(
		const u8_t * const number_string,
		const u32_t number_string_length,
		u32_t * const integer);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H void trace_configuration(
		const eap_status_e configuration_read_status,
		const eap_configuration_field_c * const field,
		const eap_variable_data_c * const data);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H u64_t xor_u64(const u64_t a, const u64_t b);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H u64_t multiply_u64(const u64_t a, const u64_t b);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H i32_t compare_u64(const u64_t a, const u64_t b);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e create_uuid_v5( 
		const void* const ns_uuid,
		const u32_t ns_uuid_length,
		const void* const name, 
		const u32_t name_length,
		eap_variable_data_c* const uuid );

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_H eap_status_e create_uuid_v5_from_mac_address( 
		const u8_t* const mac_address, 
		const u32_t mac_address_length,
		eap_variable_data_c* const uuid );

};

/** @file */

//-----------------------------------------------------------------------------------------------

/// This is the default trace mask.
const u32_t TRACE_FLAGS_DEFAULT = eap_am_tools_c::eap_trace_mask_debug;
const u32_t TRACE_FLAGS_ERROR = eap_am_tools_c::eap_trace_mask_error;
const u32_t TRACE_FLAGS_ALWAYS = eap_am_tools_c::eap_trace_mask_always;

const u32_t TRACE_TEST_VECTORS = eap_am_tools_c::eap_trace_mask_test_vectors;

const u32_t EAP_TRACE_FLAGS_MESSAGE_DATA = eap_am_tools_c::eap_trace_mask_message_data;

const u32_t EAP_TRACE_MASK_HASH_MAP = eap_am_tools_c::eap_trace_mask_hash_map;

/// This mask activates an additional timer trace.
const u32_t TRACE_FLAGS_TIMER = eap_am_tools_c::eap_trace_mask_timer;
const u32_t TRACE_FLAGS_TIMER_QUEUE = eap_am_tools_c::eap_trace_mask_timer_queue;

const u32_t TRACE_FLAGS_OK_RETURNS = eap_am_tools_c::eap_trace_mask_ok_returns;

const u32_t EAP_TRACE_FLAGS_NEVER = eap_am_tools_c::eap_trace_mask_trace_never;

//-----------------------------------------------------------------------------------------------

#if !defined(USE_EAP_STATUS_RETURN)

	#define EAP_STATUS_RETURN(tools, status) (status)

	#define EAP_STATUS_RETURN_WARNING(tools, status) (status)

#else

	#if defined(USE_EAP_MINIMUM_RELEASE_TRACES) && !defined(_DEBUG) && !defined(DEBUG)
		// This is used only in release version.

		#if !defined(EAP_FILE_NUMBER_ENUM)
			#define EAP_FILE_NUMBER_ENUM 0ul
		#endif //#if defined(EAP_FILE_NUMBER_ENUM)

		#if !defined(EAP_FILE_NUMBER_DATE)
			#define EAP_FILE_NUMBER_DATE 0ul
		#endif //#if defined(EAP_FILE_NUMBER_DATE)

		#define EAP_STATUS_RETURN(tools, status) \
			((tools != 0 && (*(tools)).get_trace_mask()) \
			? (*(tools)).eap_status_return_file_number( \
				true, \
				(status), \
				EAP_FILE_NUMBER_DATE, \
				EAP_FILE_NUMBER_ENUM, \
				__LINE__) \
			 : status)

		#define EAP_STATUS_RETURN_WARNING(tools, status) \
			((tools != 0 && (*(tools)).get_trace_mask()) \
			? (*(tools)).eap_status_return_file_number( \
				false, \
				(status), \
				EAP_FILE_NUMBER_DATE, \
				EAP_FILE_NUMBER_ENUM, \
				__LINE__) \
			 : status)

	#else

		#define EAP_STATUS_RETURN(tools, status) \
			((tools != 0 && (*(tools)).get_trace_mask()) \
			? (*(tools)).eap_status_return( \
				true, \
				(status), \
				__FILE__, \
				__LINE__) \
			: status)

		#define EAP_STATUS_RETURN_WARNING(tools, status) \
			((tools != 0 && (*(tools)).get_trace_mask()) \
			? (*(tools)).eap_status_return( \
				false, \
				(status), \
				__FILE__, \
				__LINE__) \
			: status)

	#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#endif //#if !defined(USE_EAP_STATUS_RETURN)

//-----------------------------------------------------------------------------------------------

#endif //#if !defined( _EAP_AM_TOOLS_H_ )



// End.
