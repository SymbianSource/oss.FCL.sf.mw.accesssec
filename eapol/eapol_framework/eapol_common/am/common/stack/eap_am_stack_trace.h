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

class abs_eap_am_tools_c;

/**
 * This class implemets a stack trace. This code is highly processor dependent.
 * Only Intel processor with gcc or MSVC is supported.
 */
class EAP_EXPORT stack_trace
{
private:

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/**
	 * This function traces stack frames starting from bp.
	 * The bp is pointer to base of the starting stack frame.
	 */
	EAP_FUNC_IMPORT void trace_frames(
		unsigned long *bp
		);

public:

	/**
	 * Destructor does nothing special.
	 */
	EAP_FUNC_IMPORT virtual ~stack_trace();

	/**
	 * Constructor does nothing special.
	 */
	EAP_FUNC_IMPORT stack_trace(abs_eap_am_tools_c * const tools);

	/**
	 * This function traces stack frames starting from current frame.
	 * Value of parameter memory_address is traced in the begin.
	 */
	EAP_FUNC_IMPORT void trace(const void * const memory_address);

};

#endif //#if !defined(_STACK_OUTPUT_H_)

/* End. */
