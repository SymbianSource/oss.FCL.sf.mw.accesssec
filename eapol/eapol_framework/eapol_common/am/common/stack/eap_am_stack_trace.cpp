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
	#define EAP_FILE_NUMBER_ENUM 17 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#if defined(unix)
	#include <unistd.h>
#endif
#if defined(WIN32)
	#include <windows.h>
#endif

#if !defined(__SYMBIAN32__)
	#include <stdlib.h>
	#include <stdio.h>
	#include <setjmp.h>
	#include <assert.h>
#endif //#if !defined(__SYMBIAN32__)

#include "eap_am_stack_trace.h"

#include "abs_eap_am_tools.h"
#include "eap_am_tools.h"

/********************************************************************/

EAP_FUNC_EXPORT stack_trace::~stack_trace()
{
}

/********************************************************************/

EAP_FUNC_EXPORT stack_trace::stack_trace(abs_eap_am_tools_c * const tools)
: m_am_tools(tools)
{
}

/********************************************************************/

EAP_FUNC_EXPORT void stack_trace::trace_frames(
	unsigned long *bp
)
{

#if !defined(__SYMBIAN32__)

	unsigned long *tmp_bp = bp;

	if (bp == 0)
	{
		return;
	}

	while ( tmp_bp != 0x0 && tmp_bp < reinterpret_cast<unsigned long *>(0xbffff8ec)
#if defined(linux)
			&& tmp_bp > reinterpret_cast<unsigned long *>(0xbf800000)
#else
			&& tmp_bp < reinterpret_cast<unsigned long *>(0x77000000)
#endif
			   )
	{

		EAP_TRACE_ALWAYS(m_am_tools, TRACE_FLAGS_DEFAULT,
						(EAPL("function: 0x%08x\n"),
						 reinterpret_cast<void *>(*(tmp_bp+1))));

		tmp_bp = reinterpret_cast<unsigned long *>(*tmp_bp);
	}

#else

	EAP_UNREFERENCED_PARAMETER(bp);

#endif //#if !defined(__SYMBIAN32__)

}

/********************************************************************/


EAP_FUNC_EXPORT void stack_trace::trace(const void * const memory_address)
{

#if defined(__SYMBIAN32__) && (defined(USE_EAP_STACK_TRACE) || defined(USE_EAP_ASSERT_STACK_TRACE))

	u32_t current_sp = 0;

#if 0
	// Thumb does not support inline assembler.
	__asm
	{
		MOV current_sp, __current_sp()
	}
#else
	current_sp = reinterpret_cast<u32_t>(&current_sp);
#endif

	if (current_sp == 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Cannot obtain current stack pointer.\n")));
	}

	TThreadStackInfo aInfo;

	RThread current_thread;
	
	if (current_thread.StackInfo(aInfo) != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Cannot obtain stack information.\n")));
	}

	if (aInfo.iBase < current_sp)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Stack start %d < current stack pointer %d.\n"),
			 aInfo.iBase,
			 current_sp));
	}

	u32_t *start_address = reinterpret_cast<u32_t *>(current_sp);
	u32_t *address = start_address;

	EAP_TRACE_ALWAYS(m_am_tools, TRACE_FLAGS_DEFAULT,
					(EAPL("address 0x%08x, accessed from:.\n"),
					 memory_address));

	while (reinterpret_cast<TLinAddr>(address) >= aInfo.iLimit)
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("stack address 0x%08x: 0x%08x\n"),
			 address,
			 *address));

		--address;
	}

	EAP_TRACE_ALWAYS(m_am_tools, TRACE_FLAGS_DEFAULT,
					(EAPL("\n")));
	EAP_TRACE_ALWAYS(m_am_tools, TRACE_FLAGS_DEFAULT,
					(EAPL("address 0x%08x, accessed from:.\n"),
					 memory_address));

	address = start_address;

	while (reinterpret_cast<TLinAddr>(address) < aInfo.iBase)
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("stack address 0x%08x: 0x%08x\n"),
			 address,
			 *address));

		++address;
	}

#elif (defined(unix) || defined(WIN32)) && (defined(USE_EAP_STACK_TRACE) || defined(USE_EAP_ASSERT_STACK_TRACE))

	jmp_buf tmp_buf;


#if defined(linux)
	_setjmp( tmp_buf );
#else
	setjmp( tmp_buf );
#endif


	EAP_TRACE_ALWAYS(m_am_tools, TRACE_FLAGS_DEFAULT,
					(EAPL("address 0x%08x, accessed from:.\n"),
					 memory_address));


	trace_frames(
		#if defined(linux)
			reinterpret_cast<unsigned long *>(tmp_buf->__jmpbuf[JB_BP])
		#elif defined(WIN32)
			reinterpret_cast<unsigned long *>(((_JUMP_BUFFER *)tmp_buf)->Ebp)
		#elif defined(cygwin)
			reinterpret_cast<unsigned long *>(tmp_buf[0].ebp)
		#else
			reinterpret_cast<unsigned long *>(tmp_buf->__ebp)
		#endif
			);

#else

	EAP_UNREFERENCED_PARAMETER(memory_address);

#endif //#if defined(unix) || defined(WIN32)

}


/********************************************************************/
/* End. */
