/*
* Copyright (c) 2001-2005 Nokia Corporation and/or its subsidiary(-ies).
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

#if !defined( _EAP_AM_TRACE_SYMBIAN_H_ )
#define _EAP_AM_TRACE_SYMBIAN_H_

#include <e32debug.h>

//------------------------------------------------------------------------

IMPORT_C void eap_trace_data_symbian(
	const char * const prefix,
	const void * const p_data,
	const TUint data_length);

//------------------------------------------------------------------------

#if defined(_DEBUG) || defined(DEBUG)

	#define EAP_TRACE_DEBUG_SYMBIAN(_parameter_list_) \
			{ \
				RDebug::Print _parameter_list_ ; \
			} \

	#define EAP_TRACE_DATA_DEBUG_SYMBIAN(_parameter_list_) \
			{ \
				eap_trace_data_symbian _parameter_list_ ; \
			} \

#else // #if defined(_DEBUG) || defined(DEBUG)

	#define EAP_TRACE_DEBUG_SYMBIAN(_parameter_list_) 

	#define EAP_TRACE_DATA_DEBUG_SYMBIAN(_parameter_list_)

#endif // #if defined(_DEBUG) || defined(DEBUG)

//------------------------------------------------------------------------

class eap_automatic_trace_string_symbian_c
{
private:

	/// This is pointer to the string that will be traced on destructor.
	const TPtrC m_string;

public:
	
	/**
	 * The destructor traces the string.
	 */	
	virtual ~eap_automatic_trace_string_symbian_c()
	{
		if (m_string.Length() > 0)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("<<< %S <<<\n"), &m_string));
		}
	}
	
	/**
	 * The constructor sets the values for the member variables
	 */	
	eap_automatic_trace_string_symbian_c(
		const TPtrC string)
		: m_string(string)
	{
	}
};

#if defined(_DEBUG) || defined(DEBUG)

	#define EAP_TRACE_RETURN_STRING_SYMBIAN(string) \
		eap_automatic_trace_string_symbian_c __eap_trace_function_returns__(string)

#else // #if defined(_DEBUG) || defined(DEBUG)

	#define EAP_TRACE_RETURN_STRING_SYMBIAN(string)

#endif // #if defined(_DEBUG) || defined(DEBUG)

//------------------------------------------------------------------------


#endif //#if !defined( _EAP_AM_TRACE_SYMBIAN_H_ )
