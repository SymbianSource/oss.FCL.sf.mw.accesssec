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
	#define EAP_FILE_NUMBER_ENUM 117 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include "eap_type_securid_state.h"

eap_type_securid_state_c::eap_type_securid_state_c(const bool client)
{
	m_is_client = client;

	if (m_is_client)
	{
		m_state = eap_type_securid_state_none;
		m_prev_state = eap_type_securid_state_none;
		m_next_state = eap_type_securid_state_identity_query;
	}
	else
	{
		m_state = eap_type_securid_state_none;
		m_prev_state = eap_type_securid_state_none;
		m_next_state = eap_type_securid_state_identity_response;
	}
}

eap_type_securid_state_c::~eap_type_securid_state_c()
{
}

eap_type_securid_state_variable_e eap_type_securid_state_c::get_state() const
{
	return m_state;
}

void eap_type_securid_state_c::set_state(const eap_type_securid_state_variable_e new_state)
{
	set_state(new_state, eap_type_securid_state_none);
}

void eap_type_securid_state_c::set_state(
	const eap_type_securid_state_variable_e new_state,
	const eap_type_securid_state_variable_e new_next_state)

{
	m_prev_state = m_state;
	m_state = new_state;
	m_next_state = new_next_state;
}

bool eap_type_securid_state_c::is_valid_state(const eap_type_securid_state_variable_e new_state) const
{
	if (m_is_client) // Client
	{
		if (new_state == eap_type_securid_state_identity_query)
		{
			return true;
		}

		// Check validity against (current) state.
		// If it fails then against previous state (in case of resending)

		switch (m_state)
		{
		case eap_type_securid_state_none:
			if (new_state == eap_type_securid_state_identity_query
				|| new_state == eap_type_securid_state_gtc_user_input_query)
			{
				return true;
			}
			break;

		case eap_type_securid_state_identity_query:
			if (new_state == eap_type_securid_state_passcode_query)
			{
				return true;
			}
			break;

		case eap_type_securid_state_passcode_query:
			if (new_state == eap_type_securid_state_success
				|| new_state == eap_type_securid_state_failure)
			{
				return true;
			}
			break;

		case eap_type_securid_state_gtc_user_input_query:
			if (new_state == eap_type_securid_state_gtc_user_input_query
				|| new_state == eap_type_securid_state_success
				|| new_state == eap_type_securid_state_failure)
			{
				return true;
			}
			break;

		case eap_type_securid_state_success:
		case eap_type_securid_state_failure:
			// Session is ended
			return false;

		default:
			;
		}

	}

	else // Server
	{
		if (new_state == eap_type_securid_state_identity_response)
		{
			return true;
		}

		switch (m_state)
		{
		case eap_type_securid_state_none:
			//if (new_state == eap_type_securid_state_identity_response) See 8 lines up.
			//{
			//	return true;
			//}
			break;

		case eap_type_securid_state_identity_response:
			if (new_state == eap_type_securid_state_passcode_response
				|| new_state == eap_type_securid_state_gtc_response)
			{
				return true;
			}
			break;

		case eap_type_securid_state_passcode_response:
			if (m_next_state == new_state)
			{
				return true;
			}
			if (m_next_state == eap_type_securid_state_passcode_response)
			{
				return true;
			}
			break;

		case eap_type_securid_state_gtc_response:
			if (new_state == eap_type_securid_state_gtc_response)
			{
				return true;
			}
			break;

		default:
			;
		}
	}
	return false;
}

void eap_type_securid_state_c::set_failure_message_received()
{
}

void eap_type_securid_state_c::unset_failure_message_received()
{
}

void eap_type_securid_state_c::cancel_eap_failure_timer()
{
}

//--------------------------------------------------


// End.
