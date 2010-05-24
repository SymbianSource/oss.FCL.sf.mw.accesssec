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

#if !defined(_EAP_AM_COMPILER_FLAGS_H_)
#define _EAP_AM_COMPILER_FLAGS_H_

#if defined(_DEBUG) || defined(DEBUG)

	#if !defined(USE_EAP_TRACE)
		// This macro enables most of the traces.
		#define USE_EAP_TRACE
	#endif //#if defined(USE_EAP_TRACE)

	#if !defined(USE_EAP_TRACE_ALWAYS)
		// This macro enables some traces for release error log.
		// EAP_TRACE_ALWAYS() and EAP_TRACE_DATA_ALWAYS() are left
		// active if USE_EAP_TRACE_ALWAYS is defined.
		#define USE_EAP_TRACE_ALWAYS
	#endif //#if !defined(USE_EAP_TRACE_ALWAYS)

	#if !defined(USE_EAP_DEBUG_TRACE)
		// This macro enaables debug traces.
		// Note the EAP_TRACE_ERROR() and EAP_TRACE_DATA_ERROR macroes
		// are left inactive.
		#define USE_EAP_DEBUG_TRACE
	#endif //#if defined(USE_EAP_DEBUG_TRACE)

	#if !defined(USE_EAP_TRACE_STRINGS)
		// This macro enables trace strings.
		// Traces does convert enumerations to readable string
		// if this is defined.
		#define USE_EAP_TRACE_STRINGS
	#endif //#if defined(USE_EAP_TRACE_STRINGS)

	#if !defined(USE_EAP_STATUS_RETURN)
		// This macro enables status return traces.
		// Each return does trace error status and source code file and line
		// if this is defined.
		#define USE_EAP_STATUS_RETURN
	#endif //#if defined(USE_EAP_STATUS_RETURN)

	#if !defined(USE_EAP_ASSERTS)
		// This macro enables all EAP assertions.
		#define USE_EAP_ASSERTS
	#endif //#if defined(USE_EAP_ASSERTS)

	#if !defined(USE_EAP_FILE_TRACE)
		// This macro activates file tracing.
		//#define USE_EAP_FILE_TRACE
	#endif //#if !defined(USE_EAP_FILE_TRACE)

	#if !defined(USE_EAP_HARDWARE_TRACE)
		// This macro activates hardware traces of each platform if such exists.
		#define USE_EAP_HARDWARE_TRACE
	#endif //#if !defined(USE_EAP_HARDWARE_TRACE)

	#if !defined(USE_EAP_HARDWARE_TRACE_RAW_PRINT)
		// This macro activates hardware traces RAW print of each platform if such exists.
		#define USE_EAP_HARDWARE_TRACE_RAW_PRINT
	#endif //#if !defined(USE_EAP_HARDWARE_TRACE_RAW_PRINT)

#else

	// This is release code.

	#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
		#if !defined(USE_EAP_TRACE_ALWAYS)
			// This macro enables some traces for release error log.
			// EAP_TRACE_ALWAYS() and EAP_TRACE_DATA_ALWAYS() are left
			// active if USE_EAP_TRACE_ALWAYS is defined.
			#define USE_EAP_TRACE_ALWAYS
		#endif //#if !defined(USE_EAP_TRACE_ALWAYS)
		
		#if !defined(USE_EAP_STATUS_RETURN)
			// This macro enables status return traces.
			// Each return does trace error status and source code file and line
			// if this is defined.
			#define USE_EAP_STATUS_RETURN
		#endif //#if defined(USE_EAP_STATUS_RETURN)

		#if !defined(USE_EAP_FILE_TRACE)
			// This macro activates file tracing.
			#define USE_EAP_FILE_TRACE
		#endif //#if !defined(USE_EAP_FILE_TRACE)
	#endif //#if !defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#endif

#endif //#if !defined(_EAP_AM_COMPILER_FLAGS_H_)

