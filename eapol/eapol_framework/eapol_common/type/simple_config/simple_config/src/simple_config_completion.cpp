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
	#define EAP_FILE_NUMBER_ENUM 595 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_tools.h"
#include "eap_array.h"
#include "simple_config_completion.h"
#include "simple_config_types.h"

/** @file */


//--------------------------------------------------

EAP_FUNC_EXPORT simple_config_completion_c::~simple_config_completion_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT simple_config_completion_c::simple_config_completion_c(
	abs_eap_am_tools_c * const tools,
	simple_config_completion_action_e completion_action)
: m_am_tools(tools)
, m_completion_action(completion_action)
, m_is_valid(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void simple_config_completion_c::set_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_is_valid = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool simple_config_completion_c::get_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void simple_config_completion_c::set_completion_action(simple_config_completion_action_e completion_action)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_completion_action = completion_action;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT simple_config_completion_action_e simple_config_completion_c::get_completion_action() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_completion_action;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string simple_config_completion_c::get_completion_action_string() const
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(m_completion_action, simple_config_completion_action_none)
	else EAP_IF_RETURN_STRING(m_completion_action, simple_config_completion_action_process_simple_config_attributes)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown completion_action");
	}
}

//--------------------------------------------------



// End.
