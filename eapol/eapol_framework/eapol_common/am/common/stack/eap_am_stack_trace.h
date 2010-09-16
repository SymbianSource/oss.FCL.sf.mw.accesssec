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

#if !defined(_STACK_OUTPUT_H_)
#define _STACK_OUTPUT_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_STACK_TRACE_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_STACK_TRACE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_STACK_TRACE_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_STACK_TRACE_H 
	#define EAP_FUNC_EXPORT_EAP_AM_STACK_TRACE_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_STACK_TRACE_H 
#elif defined(EAP_EXPORT_EAP_AM_STACK_TRACE_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_STACK_TRACE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_STACK_TRACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_STACK_TRACE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_STACK_TRACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_STACK_TRACE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_STACK_TRACE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_STACK_TRACE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_STACK_TRACE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_STACK_TRACE_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_STACK_TRACE_H 
#endif
// End: added by script change_export_macros.sh.

class abs_eap_am_tools_c;

/**
 * This class implemets a stack trace. This code is highly processor dependent.
 * Only Intel processor with gcc or MSVC is supported.
 */
class EAP_CLASS_VISIBILITY_EAP_AM_STACK_TRACE_H stack_trace
{
private:

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/**
	 * This function traces stack frames starting from bp.
	 * The bp is pointer to base of the starting stack frame.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_STACK_TRACE_H void trace_frames(
		unsigned long *bp
		);

public:

	/**
	 * Destructor does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_STACK_TRACE_H virtual ~stack_trace();

	/**
	 * Constructor does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_STACK_TRACE_H stack_trace(abs_eap_am_tools_c * const tools);

	/**
	 * This function traces stack frames starting from current frame.
	 * Value of parameter memory_address is traced in the begin.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_STACK_TRACE_H void trace(const void * const memory_address);

};

#endif //#if !defined(_STACK_OUTPUT_H_)

/* End. */
