/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/wai_message.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 11 % << Don't touch! Updated by Synergy at check-out.
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
	#define EAP_FILE_NUMBER_ENUM 711 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#if defined(USE_WAPI_CORE)

#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_array.h"
#include "wai_message.h"

/** @file */


//--------------------------------------------------

EAP_FUNC_EXPORT wai_message_c::~wai_message_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT wai_message_c::wai_message_c(
	abs_eap_am_tools_c * const tools,
	const bool is_client)
	: m_am_tools(tools)
	, m_message_data(tools)
	, m_is_client(is_client)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_message_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_message_data.reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wai_message_c::set_wai_message_data(
	const eap_variable_data_c * const wai_message_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_message_data.set_copy_of_buffer(wai_message_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT const eap_variable_data_c * wai_message_c::get_wai_message_data() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_message_data;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * wai_message_c::get_wai_message_data_writable()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_message_data;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool wai_message_c::get_is_valid() const
{
	return m_message_data.get_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT wai_message_c * wai_message_c::copy() const
{
	wai_message_c * new_message = new wai_message_c(
		m_am_tools,
		m_is_client);
	if (new_message == 0
		|| new_message->get_is_valid() == false)
	{
		return 0;
	}

	eap_status_e status = new_message->set_wai_message_data(get_wai_message_data());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, status);
		return 0;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return new_message;
}

//--------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

// End.
