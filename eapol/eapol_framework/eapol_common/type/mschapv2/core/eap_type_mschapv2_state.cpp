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
	#define EAP_FILE_NUMBER_ENUM 100 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include "eap_am_tools.h"
#include "eap_type_mschapv2_state.h"

eap_type_mschapv2_state_c::eap_type_mschapv2_state_c(abs_eap_am_tools_c * const tools, const bool client)
: m_am_tools(tools)
, m_is_client(client)
, m_state(eap_type_mschapv2_state_none)
, m_prev_state(eap_type_mschapv2_state_none)
, m_next_state(eap_type_mschapv2_state_none)
, m_failure_message_received(false)
{
	reset();
}

EAP_FUNC_EXPORT eap_type_mschapv2_state_c::~eap_type_mschapv2_state_c()
{
}

eap_type_mschapv2_state_variable_e eap_type_mschapv2_state_c::get_state() const
{
	return m_state;
}

void eap_type_mschapv2_state_c::reset()
{
	if (m_is_client)
	{
		m_state = eap_type_mschapv2_state_none;
		m_prev_state = eap_type_mschapv2_state_none;
		m_next_state = eap_type_mschapv2_state_identity_request;
	}
	else
	{
		m_state = eap_type_mschapv2_state_none;
		m_prev_state = eap_type_mschapv2_state_none;
		m_next_state = eap_type_mschapv2_state_identity_response;
	}
}

void eap_type_mschapv2_state_c::set_state(const eap_type_mschapv2_state_variable_e new_state)
{
	set_state(new_state, eap_type_mschapv2_state_none);
}

void eap_type_mschapv2_state_c::set_state(
	const eap_type_mschapv2_state_variable_e new_state,
	const eap_type_mschapv2_state_variable_e new_next_state)

{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_state_c::set_state(): this = 0x%08x, previous state %d=%s, new state %d=%s, new next state %d=%s\n"),
		 this,
		 m_prev_state,
		 get_state_string(m_prev_state),
		 new_state,
		 get_state_string(new_state),
		 new_next_state,
		 get_state_string(m_next_state)));

	m_prev_state = m_state;
	m_state = new_state;
	m_next_state = new_next_state;
}

bool eap_type_mschapv2_state_c::is_valid_state(const eap_type_mschapv2_state_variable_e new_state) const
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_state_c::is_valid_state(): this = 0x%08x, previous state %d=%s, state %d=%s, new state %d=%s, new next state %d\n"),
		 this,
		 m_prev_state,
		 get_state_string(m_prev_state),
		 m_state,
		 get_state_string(m_state),
		 new_state,
		 get_state_string(new_state),
		 m_next_state,
		 get_state_string(m_next_state)));

	if (m_is_client) // Client
	{
		if (new_state == eap_type_mschapv2_state_identity_request)
		{
			return true;
		}

		// Check validity against (current) state.
		// If it fails then against previous state (in case of resending)

		switch (m_state)
		{
		case eap_type_mschapv2_state_none:
			if (new_state == eap_type_mschapv2_state_challenge_request)
			{
				return true;
			}
			break;

		case eap_type_mschapv2_state_identity_request:
			if (new_state == eap_type_mschapv2_state_challenge_request)
			{
				return true;
			}
			break;

		case eap_type_mschapv2_state_challenge_request:
			if (new_state == eap_type_mschapv2_state_success_request
				|| new_state == eap_type_mschapv2_state_failure_request
				|| new_state == eap_type_mschapv2_state_failure) // non-retryable error in Windows XP SP1
			{
				return true;
			}
			break;

		case eap_type_mschapv2_state_failure_request:
			if (new_state == eap_type_mschapv2_state_failure)
			{
				return true;
			}
			break;

		case eap_type_mschapv2_state_success_request:
			if (new_state == eap_type_mschapv2_state_success)
			{
				return true;
			}
			break;

		case eap_type_mschapv2_state_change_password_request:
			if (new_state == eap_type_mschapv2_state_success_request
				|| new_state == eap_type_mschapv2_state_failure_request
				|| new_state == eap_type_mschapv2_state_failure) // non-retryable error in Windows XP SP1
			{
				return true;
			}
			break;

		case eap_type_mschapv2_state_success:
		case eap_type_mschapv2_state_failure:
			// Session is ended

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WARNING: eap_type_mschapv2_state_c::is_valid_state(): returns false: this = 0x%08x, previous state %d=%s, state %d=%s, new state %d=%s, new next state %d=%s\n"),
				 this,
				 m_prev_state,
				 get_state_string(m_prev_state),
				 m_state,
				 get_state_string(m_state),
				 new_state,
				 get_state_string(new_state),
				 m_next_state,
				 get_state_string(m_next_state)));

			return false;

		default:
			;
		}

	}

	else // Server
	{
		switch (m_state)
		{
		case eap_type_mschapv2_state_none:
			if (new_state == eap_type_mschapv2_state_identity_response)
			{
				return true;
			}
			break;

		case eap_type_mschapv2_state_identity_response:
			if (new_state == eap_type_mschapv2_state_challenge_response)
			{
				return true;
			}
			break;

		case eap_type_mschapv2_state_challenge_response:
			if (m_next_state == new_state)
			{
				return true;
			}
			break;
		case eap_type_mschapv2_state_change_password_response:
			if (m_next_state == new_state)
			{
				return true;
			}
			break;

		case eap_type_mschapv2_state_success_response:
		case eap_type_mschapv2_state_failure_response:
			// Session is ended

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WARNING: eap_type_mschapv2_state_c::is_valid_state(): returns false: this = 0x%08x, previous state %d=%s, state %d=%s, new state %d=%s, new next state %d=%s\n"),
				 this,
				 m_prev_state,
				 get_state_string(m_prev_state),
				 m_state,
				 get_state_string(m_state),
				 new_state,
				 get_state_string(new_state),
				 m_next_state,
				 get_state_string(m_next_state)));

			return false;

		default:
			;
		}
	}
	return false;
}

void eap_type_mschapv2_state_c::set_failure_message_received()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_state_c::set_failure_message_received(): this = 0x%08x, previous state %d=%s, state %d=%s, new next state %d=%s\n"),
		 this,
		 m_prev_state,
		 get_state_string(m_prev_state),
		 m_state,
		 get_state_string(m_state),
		 m_next_state,
		 get_state_string(m_next_state)));

	m_failure_message_received = true;
}

void eap_type_mschapv2_state_c::unset_failure_message_received()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_state_c::unset_failure_message_received(): this = 0x%08x, previous state %d=%s, state %d=%s, new next state %d=%s\n"),
		 this,
		 m_prev_state,
		 get_state_string(m_prev_state),
		 m_state,
		 get_state_string(m_state),
		 m_next_state,
		 get_state_string(m_next_state)));

	m_failure_message_received = false;
}

void eap_type_mschapv2_state_c::cancel_eap_failure_timer()
{
}

eap_const_string eap_type_mschapv2_state_c::get_state_string(const eap_type_mschapv2_state_variable_e state)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(state, eap_type_mschapv2_state_none)
	else EAP_IF_RETURN_STRING(state, eap_type_mschapv2_state_success)
	else EAP_IF_RETURN_STRING(state, eap_type_mschapv2_state_failure)
	else EAP_IF_RETURN_STRING(state, eap_type_mschapv2_state_identity_request)
	else EAP_IF_RETURN_STRING(state, eap_type_mschapv2_state_challenge_request)
	else EAP_IF_RETURN_STRING(state, eap_type_mschapv2_state_success_request)
	else EAP_IF_RETURN_STRING(state, eap_type_mschapv2_state_failure_request)
	else EAP_IF_RETURN_STRING(state, eap_type_mschapv2_state_change_password_request)
	else EAP_IF_RETURN_STRING(state, eap_type_mschapv2_state_identity_response)
	else EAP_IF_RETURN_STRING(state, eap_type_mschapv2_state_challenge_response)
	else EAP_IF_RETURN_STRING(state, eap_type_mschapv2_state_success_response)
	else EAP_IF_RETURN_STRING(state, eap_type_mschapv2_state_failure_response)
	else EAP_IF_RETURN_STRING(state, eap_type_mschapv2_state_change_password_response)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(state);
		return EAPL("Unknown EAP-MsChapv2-state");
	}
}


// End
