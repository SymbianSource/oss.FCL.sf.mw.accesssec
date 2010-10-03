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
* %version: 7 %
*/

// INCLUDES
#if !defined( _EAP_AM_TOOLS_SYMBIAN_H_ )
#define _EAP_AM_TOOLS_SYMBIAN_H_

#include <e32std.h>
#include <e32svr.h>

//#include "eap_am_memory.h"

#include "eap_am_tools.h"
#include "eap_variable_data.h"
#include "eap_tools.h"
#include "eap_status.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_TOOLS_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H 
	#define EAP_FUNC_EXPORT_EAP_AM_TOOLS_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TOOLS_SYMBIAN_H 
#elif defined(EAP_EXPORT_EAP_AM_TOOLS_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TOOLS_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TOOLS_SYMBIAN_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TOOLS_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TOOLS_SYMBIAN_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_am_crypto_symbian.h"
#include "eap_timer_queue.h"
#include "eap_am_mutex_symbian.h"
#include <f32file.h>
#include <d32dbms.h>

/// This class implements functionality of platform adaptation of Symbian.
/**
 *	See function comments on abs_eap_am_tools_c and eap_am_tools_c.
 */
class EAP_CLASS_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H eap_am_tools_symbian_c
: public eap_am_tools_c
//, public CActive
, public CTimer
{
private:

#if defined(USE_EAP_FILE_TRACE)

	/// File server used in filetrace.
	RFs m_Fs;

	/// File used in filetrace.
	RFile m_LogFile;

	/// File name used in filetrace.
	TBuf<64> m_filename;

#endif //#if defined(USE_EAP_FILE_TRACE)

	/// Prefix string used in filetrace.
	eap_variable_data_c m_prefix_string;

	u64_t m_start_ticks;

	bool m_directory_exists;

	eap_am_crypto_symbian_c m_crypto;

	eap_timer_queue_c m_timer_queue;

	eap_am_mutex_symbian_c m_global_mutex;
	
	eap_am_mutex_symbian_c m_trace_mutex;

	bool m_run_thread;

	bool m_is_valid;

	bool m_configure_called;

#if defined(USE_EAP_TRACE) || defined(USE_EAP_TRACE_ALWAYS)
	/// Bufers are used in traces.
	TBuf8<1024> m_args_buf;
#if defined(USE_EAP_HARDWARE_TRACE)
	TBuf16<1024> m_trace_buf_16;
#endif //#if defined(USE_EAP_HARDWARE_TRACE)
#endif //#if defined(USE_EAP_TRACE) || defined(USE_EAP_TRACE_ALWAYS)

	/// Buffers are used in string conversions.
	TBuf8<1024> m_format_buf;
	TBuf8<1024> m_trace_buf;

	/// These member variables are used in Symbian timer.
	TUint iInterval;
	u64_t iStartTime;
	u64_t iLastTime;

	// This flag tells whether the trace log file is open.
	bool m_logfile_open;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H void sprint(TDes& KPrintBuf, eap_const_string format, ...);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H void KFormatVArgs(TDes& aDes, const TDesC& aFmt, VA_LIST aList);

	// Member function to support active sceduler timer.
	void StartTimer(const TUint aInterval);
	void StopTimer();
	TBool TimerRunning();
	void RunL();
	void DoCancel();

	u32_t limit_microsecond_timeout(u32_t next_timeout_millisecond);

	// On purpose unimplemented constructors.
	eap_am_tools_symbian_c(eap_am_tools_symbian_c &source);

	// On purpose unimplemented operator.
	const eap_am_tools_symbian_c & operator=(const eap_am_tools_symbian_c& source);

	void set_default_trace_mask();

public:

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H virtual ~eap_am_tools_symbian_c();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H eap_am_tools_symbian_c(eap_const_string pfilename);


	/// See function comments on abs_eap_am_tools_c and eap_am_tools_c.

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H eap_status_e configure();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H bool get_use_eap_milli_second_timer();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H void set_use_eap_milli_second_timer(
		const bool use_eap_millisecond_timer);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H void enter_global_mutex();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H void leave_global_mutex();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H abs_eap_am_mutex_c * get_global_mutex();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H void enter_trace_mutex();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H void leave_trace_mutex();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H abs_eap_am_mutex_c * get_trace_mutex();


	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H void set_timer_resolution_ms(const u32_t timer_resolution_ms);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H u32_t get_timer_resolution_ms();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H u32_t pulse_timer(const u32_t elapsed_time_in_ms);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H bool get_timer_queue_is_empty();


	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H eap_status_e start_timer_thread();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H eap_status_e stop_timer_thread();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H bool get_is_timer_thread_active();


	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H eap_status_e set_trace_prefix(
		const eap_variable_data_c * const prefix8bit);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H eap_status_e set_trace_file_name(const eap_variable_data_c * const trace_output_file);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H void set_max_trace_file_size(const u32_t max_trace_file_size);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H u32_t snprintf(u8_t * const buffer, u32_t buffer_size, eap_format_string format, ...);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H void formatted_print(eap_format_string format, ...);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H void memmove(void *dest, const void *src, const u32_t count);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H i32_t memcmp(const void * const dest, const void * const src, const u32_t count);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H void memset(void * const src, const i32_t fill_byte, const u32_t count);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H void *memchr(
		const void *buf,
		u8_t character,
		u32_t count);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H void *memrchr(
		const void *buf,
		u8_t character,
		u32_t count);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H u32_t strlen(
		eap_const_string string);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H u32_t config_strlen(
		eap_config_string string);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H abs_eap_am_crypto_c * get_crypto();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H u64_t get_hardware_ticks();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H u64_t get_hardware_ticks_of_second();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H u64_t get_clock_ticks();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H u64_t get_clock_ticks_of_second();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H u32_t get_gmt_unix_time();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H eap_status_e am_set_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id, 
		void * const data,
		const u32_t p_time_ms);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H eap_status_e am_cancel_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H eap_status_e am_cancel_all_timers();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H eap_status_e re_activate_timer_queue();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H void enter_crypto_cs();
	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H void leave_crypto_cs();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H void timer_sleep(u32_t milli_seconds);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H void sleep(u32_t milli_seconds);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H bool get_is_valid() const;

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H eap_status_e begin_db_transaction(RDbNamedDatabase& aDatabase);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H eap_status_e begin_db_update(RDbView& aView);
	
	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H eap_status_e begin_db_delete(RDbView& aView);

	/// This function must call eap_am_tools_c::shutdown_am_tools().
	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H eap_status_e shutdown();

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H eap_status_e convert_unicode_to_utf8(
		eap_variable_data_c & dest,
		const eap_variable_data_c & src);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H eap_status_e convert_utf8_to_unicode(
		eap_variable_data_c & dest,
		const eap_variable_data_c & src);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H eap_status_e convert_am_error_to_eapol_error(const i32_t am_error_value);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H i32_t convert_eapol_error_to_am_error(eap_status_e aErr);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H eap_status_e getenv(
		const eap_variable_data_c * const environment_variable_name,
		eap_variable_data_c * const environment_variable_value);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H bool isspace(const u8_t character);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H u64_struct u64_t_to_u64_struct(const u64_t value);

	EAP_FUNC_VISIBILITY_EAP_AM_TOOLS_SYMBIAN_H u64_t u64_struct_to_u64_t(const u64_struct value);
};

#endif //#if !defined( _EAP_AM_TOOLS_SYMBIAN_H_ )



// End of file
