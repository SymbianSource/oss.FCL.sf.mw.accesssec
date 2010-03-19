/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/ec_cs_completion.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 10 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.1.1
*/

// This is enumeration of WAPI source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 128 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_tools.h"
#include "eap_array.h"
#include "ec_cs_completion.h"

/** @file */


//--------------------------------------------------

EAP_FUNC_EXPORT ec_cs_completion_c::~ec_cs_completion_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT ec_cs_completion_c::ec_cs_completion_c(
	abs_eap_am_tools_c * const tools,
	ec_cs_completion_e completion_action)
: m_am_tools(tools)
, m_completion_action(completion_action)
, m_is_valid(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void ec_cs_completion_c::set_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_is_valid = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool ec_cs_completion_c::get_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void ec_cs_completion_c::set_completion_action(ec_cs_completion_e completion_action)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_completion_action = completion_action;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT ec_cs_completion_e ec_cs_completion_c::get_completion_action() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_completion_action;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string ec_cs_completion_c::get_completion_action_string(ec_cs_completion_e completion_action)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(completion_action, ec_cs_completion_none)
	else EAP_IF_RETURN_STRING(completion_action, ec_cs_completion_internal_select_certificate)
	else EAP_IF_RETURN_STRING(completion_action, ec_cs_completion_internal_select_certificate_with_identity)
	else EAP_IF_RETURN_STRING(completion_action, ec_cs_completion_internal_complete_add_imported_certificate_file)
	else EAP_IF_RETURN_STRING(completion_action, ec_cs_completion_complete_add_imported_certificate_file)
	else EAP_IF_RETURN_STRING(completion_action, ec_cs_completion_query_PAC_store_password)
	else EAP_IF_RETURN_STRING(completion_action, ec_cs_completion_add_imported_ca_certificate)
	else EAP_IF_RETURN_STRING(completion_action, ec_cs_completion_add_imported_client_certificate)
	else EAP_IF_RETURN_STRING(completion_action, ec_cs_completion_internal_create_signature_with_private_key)
	else EAP_IF_RETURN_STRING(completion_action, ec_cs_completion_complete_query_certificate_list)
	else EAP_IF_RETURN_STRING(completion_action, ec_cs_completion_internal_verify_signature_with_public_key)
	else
#else
	EAP_UNREFERENCED_PARAMETER(completion_action);
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown completion_action");
	}
}

//--------------------------------------------------

// End.
