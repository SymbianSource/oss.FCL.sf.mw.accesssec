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
	#define EAP_FILE_NUMBER_ENUM 106 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



/** @file */

#include "eap_tools.h"
#include "eap_radius_header_string.h"

//------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_radius_header_string_c::~eap_radius_header_string_c()
{
}

EAP_FUNC_EXPORT eap_radius_header_string_c::eap_radius_header_string_c()
{
}

EAP_FUNC_EXPORT eap_const_string eap_radius_header_string_c::get_code_string(
	const eap_radius_code_value_e code)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(code, eap_radius_code_none)
	else EAP_IF_RETURN_STRING(code, eap_radius_code_access_request)
	else EAP_IF_RETURN_STRING(code, eap_radius_code_access_accept)
	else EAP_IF_RETURN_STRING(code, eap_radius_code_access_reject)
	else EAP_IF_RETURN_STRING(code, eap_radius_code_accounting_request)
	else EAP_IF_RETURN_STRING(code, eap_radius_code_accounting_response)
	else EAP_IF_RETURN_STRING(code, eap_radius_code_access_challenge)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown EAP-code");
	}
}

//------------------------------------------------------------------------------



// End.
