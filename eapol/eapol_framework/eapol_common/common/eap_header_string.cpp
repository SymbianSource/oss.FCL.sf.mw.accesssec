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
	#define EAP_FILE_NUMBER_ENUM 27 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



/** @file */

#include "eap_tools.h"
#include "eap_header_string.h"

//------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_header_string_c::~eap_header_string_c()
{
}

EAP_FUNC_EXPORT eap_header_string_c::eap_header_string_c()
{
}

EAP_FUNC_EXPORT eap_const_string eap_header_string_c::get_eap_code_string(const eap_code_value_e code)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(code, eap_code_none)
	else EAP_IF_RETURN_STRING(code, eap_code_request)
	else EAP_IF_RETURN_STRING(code, eap_code_response)
	else EAP_IF_RETURN_STRING(code, eap_code_success)
	else EAP_IF_RETURN_STRING(code, eap_code_failure)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(code);
		return EAPL("Unknown EAP-code");
	}
}

EAP_FUNC_EXPORT eap_const_string eap_header_string_c::get_eap_type_string(const eap_type_value_e type)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(type, eap_type_none)
	else EAP_IF_RETURN_STRING(type, eap_type_identity)
	else EAP_IF_RETURN_STRING(type, eap_type_notification)
	else EAP_IF_RETURN_STRING(type, eap_type_nak)
	else EAP_IF_RETURN_STRING(type, eap_type_md5_challenge)
	else EAP_IF_RETURN_STRING(type, eap_type_one_time_password)
	else EAP_IF_RETURN_STRING(type, eap_type_generic_token_card)
	else EAP_IF_RETURN_STRING(type, eap_type_tls)
	else EAP_IF_RETURN_STRING(type, eap_type_leap)
	else EAP_IF_RETURN_STRING(type, eap_type_gsmsim)
	else EAP_IF_RETURN_STRING(type, eap_type_ttls)
	else EAP_IF_RETURN_STRING(type, eap_type_aka)
	else EAP_IF_RETURN_STRING(type, eap_type_peap)
	else EAP_IF_RETURN_STRING(type, eap_type_mschapv2)
	else EAP_IF_RETURN_STRING(type, eap_type_securid)
	else EAP_IF_RETURN_STRING(type, eap_type_tlv_extensions)
#if defined(USE_FAST_EAP_TYPE)
	else EAP_IF_RETURN_STRING(type, eap_type_fast)
#endif //#if defined(USE_FAST_EAP_TYPE)
	else EAP_IF_RETURN_STRING(type, eap_type_saesim)
	else EAP_IF_RETURN_STRING(type, eap_expanded_type_simple_config.get_type())
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(type);
		return EAPL("Unknown EAP-type");
	}
}

//------------------------------------------------------------------------------



// End.
