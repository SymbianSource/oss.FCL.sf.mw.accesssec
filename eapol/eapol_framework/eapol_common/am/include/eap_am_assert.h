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

#if !defined(_EAP_ASSERT_H_)
#define _EAP_ASSERT_H_

#include "eap_am_compiler_flags.h"

#include "eap_tools.h"


#if defined(_DEBUG) || defined(DEBUG) || defined(USE_EAP_ASSERTS)

	#if defined(__MARM__) || defined(__THUMB__) \
		|| defined(__ARMI__) || defined(__ARM4__)
		// Works only in ARM platform.
		#define EAP_SYSTEM_DEBUG_BREAK() User::Panic(_L("EAPOL"), KErrGeneral)
	#elif defined(__GNUC__) && defined(EAP_INTEL_PROCESSOR)
		// Works only in intel platform and gcc.
		#define EAP_SYSTEM_DEBUG_BREAK()  __asm__( "int $0x03" : : )
	#elif defined(__WINSCW__)
		// For RCVT compiler
		#define EAP_SYSTEM_DEBUG_BREAK()  EAP_NULL_FUNCTION
	#elif defined(_WIN32) || defined(__WINS__)
		// Works only in intel platform and MSVC++.
		#define EAP_SYSTEM_DEBUG_BREAK() { __asm int 0x03 }
	#else
		#define EAP_SYSTEM_DEBUG_BREAK()  EAP_NULL_FUNCTION
	#endif

	#define EAP_STATIC_ASSERT(_x) do { typedef int ai[(_x) ? 1 : 0]; } while(0)

#else

	#define EAP_SYSTEM_DEBUG_BREAK() EAP_NULL_FUNCTION

	#define EAP_STATIC_ASSERT(_x)

#endif



#if !defined(USE_EAP_ASSERTS)

	#define EAP_ASSERT_TOOLS(am_tools, param) EAP_NULL_FUNCTION

	#define EAP_ASSERT(param) EAP_NULL_FUNCTION


	#define EAP_ASSERT_ALWAYS_TOOLS(am_tools, param) EAP_NULL_FUNCTION

	#define EAP_ASSERT_ALWAYS(param) EAP_NULL_FUNCTION


	#define EAP_ASSERT_ALWAYS_NO_TRACE(param) EAP_NULL_FUNCTION


	#define EAP_ASSERT_ANYWAY_TOOLS(am_tools) EAP_NULL_FUNCTION

	#define EAP_ASSERT_ANYWAY  EAP_NULL_FUNCTION

#else

#if defined(__SYMBIAN32__)

	#if defined(_DEBUG) || defined(DEBUG) || defined(USE_EAP_ASSERTS)
		#define EAP_ASSERT_TOOLS(am_tools, param)\
				if (!(param))\
				{\
					if ((am_tools) != 0) \
					{ \
						(*(am_tools)).formatted_print(EAPL("ERROR: assertion failed " #param " %s:%d.\n"), __FILE__, __LINE__); \
					} \
					EAP_ASSERT_STACK_TRACE_TOOLS(am_tools, 0); \
					EAP_SYSTEM_DEBUG_BREAK();\
				}\
				__ASSERT_ALWAYS((param), User::Panic(_L("EAPOL"), 1))

		#define EAP_ASSERT(param)\
			EAP_ASSERT_TOOLS(m_am_tools, param)

	#else
		#define EAP_ASSERT_TOOLS(am_tools, param) EAP_NULL_FUNCTION
		#define EAP_ASSERT(param) EAP_NULL_FUNCTION
	#endif


	#define EAP_ASSERT_ALWAYS_TOOLS(am_tools, param)\
			if (!(param))\
			{\
				if ((am_tools) != 0) \
				{ \
					(*(am_tools)).formatted_print(EAPL("ERROR: assertion failed " #param " %s:%d.\n"), __FILE__, __LINE__); \
				} \
				EAP_ASSERT_STACK_TRACE_TOOLS(am_tools, 0); \
				EAP_SYSTEM_DEBUG_BREAK();\
			}\
			__ASSERT_ALWAYS((param), User::Panic(_L("EAPOL"), 1))

	#define EAP_ASSERT_ALWAYS(param)\
			EAP_ASSERT_ALWAYS_TOOLS(m_am_tools, param)


	#define EAP_ASSERT_ALWAYS_NO_TRACE(param) \
			if (!(param)) \
			{ \
				EAP_SYSTEM_DEBUG_BREAK();\
			} \
			__ASSERT_ALWAYS((param), User::Panic(_L("EAPOL"), 1))


	#define EAP_ASSERT_ANYWAY_TOOLS(am_tools)\
			if ((am_tools) != 0) \
			{ \
				(*(am_tools)).formatted_print(EAPL("ERROR: assertion failed. %s:%d\n"), __FILE__, __LINE__); \
			} \
			EAP_ASSERT_STACK_TRACE_TOOLS(am_tools, 0); \
			EAP_SYSTEM_DEBUG_BREAK();\
			__ASSERT_ALWAYS(0, User::Panic(_L("EAPOL"), 1))

	#define EAP_ASSERT_ANYWAY\
			EAP_ASSERT_ANYWAY_TOOLS(m_am_tools)

#elif defined(_WIN32) || defined(__GNUC__) || defined(__arm)

	#include <assert.h>

	#if defined(_DEBUG) || defined(DEBUG) || defined(USE_EAP_ASSERTS)
		#define EAP_ASSERT_TOOLS(am_tools, param) \
				if (!(param)) \
				{ \
					if ((am_tools) != 0) \
					{ \
						(*(am_tools)).formatted_print(EAPL("ERROR: assertion failed " #param " %s:%d.\n"), __FILE__, __LINE__); \
					} \
					EAP_ASSERT_STACK_TRACE_TOOLS(am_tools, 0); \
					EAP_SYSTEM_DEBUG_BREAK();\
				} \
				assert(param)

		#define EAP_ASSERT(param) \
			EAP_ASSERT_TOOLS(m_am_tools, param)

	#else
		#define EAP_ASSERT_TOOLS(am_tools, param) EAP_NULL_FUNCTION
		#define EAP_ASSERT(param) EAP_NULL_FUNCTION
	#endif


	#define EAP_ASSERT_ALWAYS_TOOLS(am_tools, param) \
			if (!(param)) \
			{ \
				if ((am_tools) != 0) \
				{ \
					(*(am_tools)).formatted_print(EAPL("ERROR: assertion failed " #param " %s:%d.\n"), __FILE__, __LINE__); \
				} \
				EAP_ASSERT_STACK_TRACE_TOOLS(am_tools, 0); \
				EAP_SYSTEM_DEBUG_BREAK();\
			} \
			assert(param)

	#define EAP_ASSERT_ALWAYS(param) \
			EAP_ASSERT_ALWAYS_TOOLS(m_am_tools, param)


	#define EAP_ASSERT_ALWAYS_NO_TRACE(param) \
			if (!(param)) \
			{ \
				EAP_SYSTEM_DEBUG_BREAK();\
			} \
			assert(param)


	#define EAP_ASSERT_ANYWAY_TOOLS(am_tools) \
			if ((am_tools) != 0) \
			{ \
				(*(am_tools)).formatted_print(EAPL("ERROR: assertion failed. %s:%d\n"), __FILE__, __LINE__); \
			} \
			EAP_ASSERT_STACK_TRACE_TOOLS(am_tools, 0); \
			EAP_SYSTEM_DEBUG_BREAK();\
			assert(0)

	#define EAP_ASSERT_ANYWAY \
		EAP_ASSERT_ANYWAY_TOOLS(m_am_tools)

#endif //#if defined(_WIN32) || defined(__GNUC__)

#endif //#if !defined(USE_EAP_ASSERTS)

#endif //#if !defined(_EAP_ASSERT_H_)



// End.
