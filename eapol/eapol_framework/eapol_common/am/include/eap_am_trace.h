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

#error Not used any more.

#if !defined(_EAP_AM_TRACE_H_) && 0
#define _EAP_AM_TRACE_H_


#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_TRACE_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TRACE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TRACE_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TRACE_H 
	#define EAP_FUNC_EXPORT_EAP_AM_TRACE_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TRACE_H 
#elif defined(EAP_EXPORT_EAP_AM_TRACE_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TRACE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TRACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TRACE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TRACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TRACE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_TRACE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TRACE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TRACE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TRACE_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TRACE_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_variable_data.h"


class EAP_CLASS_VISIBILITY_EAP_AM_TRACE_H abs_eap_am_trace_c
{
public:

	/**
	 * Destructor does nothing special.
	 */
	virtual ~abs_eap_am_trace_c()
	{
	}

	virtual void formatted_print(eap_format_string format, ...) = 0;
};


class EAP_CLASS_VISIBILITY_EAP_AM_TRACE_H eap_am_trace_c
{
public:

	/**
	 * Destructor does nothing special.
	 */
	virtual ~eap_am_trace_c()
	{
	}

	eap_am_trace_c(const char *pfilename);

	void formatted_print(eap_format_string format, ...);

private:

	const eap_char *m_filename;
	bool m_directory_exists;
};


#endif //#if !defined(_EAP_AM_TRACE_H_)



// End.
