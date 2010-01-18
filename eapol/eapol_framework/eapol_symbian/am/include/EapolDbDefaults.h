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

#if !defined(_EAPOLDBDEFAULTS_H_)
#define _EAPOLDBDEFAULTS_H_

// LOCAL CONSTANTS

#ifdef SYMBIAN_SECURE_DBMS
// For EAPOL secure database.
// Full path is not needed. The database eapol.dat will be saved in the 
// data cage path for DBMS. So it will be in "\private\100012a5\eapol.dat" in C: drive.
// The maximum length of database name is 0x40 (KDbMaxName) , which is defined in d32dbms.h.

_LIT(KDatabaseName, "c:eapol.dat");

_LIT(KSecureUIDFormat, "SECURE[102072e9]"); // For the security policy.

#else

_LIT(KDatabaseName, "c:\\system\\data\\eapol.dat");

#endif // #ifdef SYMBIAN_SECURE_DBMS

#if !defined(USE_EAP_FILECONFIG)
	const TInt default_EAP_TRACE_disable_traces = 0;
	const TInt default_EAP_TRACE_enable_function_traces = 0;
	const TInt default_EAP_TRACE_only_trace_messages = 0;
	const TInt default_EAP_TRACE_only_test_vectors = 0;
#endif //#if !defined(USE_EAP_FILECONFIG)

_LIT(default_EAP_TRACE_output_file_name, "c:\\logs\\eapol\\eap_core.txt");

#if !defined(USE_EAP_FILECONFIG)
	const TInt default_EAP_CORE_session_timeout = 120000; // ms = 120 seconds = 2 minutes.
	const TInt default_EAPOL_CORE_starts_max_count = 3;		
	const TInt default_EAPOL_CORE_send_start_interval = 2000; // ms
	const TInt default_EAP_ERROR_TEST_enable_random_errors = 0;
	const TInt default_EAP_ERROR_TEST_send_original_packet_first = 0;
	const TInt default_EAP_ERROR_TEST_generate_multiple_error_packets = 2;
	const TInt default_EAP_ERROR_TEST_manipulate_ethernet_header = 0;
	const TInt default_EAP_ERROR_TEST_error_probability = 8000000;
	const TInt default_EAP_test_default_type = 18; // EAP-SIM
	const TInt default_EAP_CORE_retransmission_counter = 0;
#endif //#if !defined(USE_EAP_FILECONFIG)
		
#endif // _EAPOLDBDEFAULTS_H_

// End of file
