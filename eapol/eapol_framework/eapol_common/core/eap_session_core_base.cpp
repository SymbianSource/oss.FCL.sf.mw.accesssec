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
* %version: 12 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 727 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_session_core_base.h"
#include "eap_session_core.h"
#include "eap_core_client_message_if.h"
#include "eap_automatic_variable.h"


EAP_FUNC_EXPORT eap_session_core_base_c::~eap_session_core_base_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

EAP_FUNC_EXPORT eap_session_core_base_c::eap_session_core_base_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_session_core_base_c * eap_session_core_base_c::new_eap_session_core_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_session_core_c * const partner,
	const bool is_client_when_true,
	const u32_t /* MTU */)
{
	eap_session_core_c * new_session_core = new eap_session_core_c(tools, partner, is_client_when_true);

	eap_automatic_variable_c<eap_session_core_c> automatic_new_session_core(
		tools,
		new_session_core);

	if (new_session_core == 0
		|| new_session_core->get_is_valid() == false)
	{
		// ERROR.
		if (new_session_core != 0)
		{
			EAP_TRACE_DEBUG(
				tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("calls: new_eap_session_core_c(): new_session_core->shutdown(): %s.\n"),
				(is_client_when_true == true) ? "client": "server"));

			new_session_core->shutdown();
		}
		return 0;
	}

	automatic_new_session_core.do_not_free_variable();

	return new_session_core;
}

//--------------------------------------------------
// End.
