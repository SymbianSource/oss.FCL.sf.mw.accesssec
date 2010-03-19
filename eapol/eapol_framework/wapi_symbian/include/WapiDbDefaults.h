/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_symbian/include/WapiDbDefaults.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 6 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.2
*/



#if !defined(_WAPIDBDEFAULTS_H_)
#define _WAPIDBDEFAULTS_H_

// LOCAL CONSTANTS

#if !defined(USE_WAPI_FILECONFIG)
	const TInt default_WAPI_TRACE_disable_traces = 0;
	const TInt default_WAPI_TRACE_enable_function_traces = 0;
	const TInt default_WAPI_TRACE_only_trace_messages = 0;
	const TInt default_WAPI_TRACE_only_test_vectors = 0;
#endif //#if !defined(USE_WAPI_FILECONFIG)

_LIT(default_WAPI_TRACE_output_file_name, "c:\\logs\\wapi\\wapi_core.txt");

#if !defined(USE_WAPI_FILECONFIG)
	const TInt default_WAPI_CORE_session_timeout = 120000; // ms = 120 seconds = 2 minutes.
	const TInt default_WAPI_CORE_starts_max_count = 3;		
	const TInt default_WAPI_CORE_send_start_interval = 2000; // ms
	const TInt default_WAPI_ERROR_TEST_enable_random_errors = 0;
	const TInt default_WAPI_ERROR_TEST_send_original_packet_first = 0;
	const TInt default_WAPI_ERROR_TEST_generate_multiple_error_packets = 2;
	const TInt default_WAPI_ERROR_TEST_manipulate_ethernet_header = 0;
	const TInt default_WAPI_ERROR_TEST_error_probability = 8000000;
	const TInt default_WAPI_CORE_retransmission_counter = 0;
#endif //#if !defined(USE_WAPI_FILECONFIG)
		
#endif // _WAPIDBDEFAULTS_H_

// End of file
