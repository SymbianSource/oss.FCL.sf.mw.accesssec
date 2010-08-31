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

#if !defined(_EAP_STATE_SELECTOR_H_)
#define _EAP_STATE_SELECTOR_H_

#error Do not use.

#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_export.h"
#include "eap_variable_data.h"
#include "sae_cookie.h"


//--------------------------------------------------

class EAP_EXPORT eap_state_selector_c
: public eap_variable_data_c
{
private:

	abs_eap_am_tools_c * const m_am_tools;

public:

	virtual ~eap_state_selector_c()
	{
	}

	eap_state_selector_c(
		abs_eap_am_tools_c * const tools)
		: eap_variable_data_c(tools)
		, m_am_tools(tools)
	{
	}


	eap_state_selector_c(
		abs_eap_am_tools_c * const tools,
		sae_cookie_c * const own_cookie,
		sae_cookie_c * const peer_cookie)
		: eap_variable_data_c(tools)
		, m_am_tools(tools)
	{
		eap_status_e status = set_copy_of_buffer(own_cookie->get_data(), SAE_COOKIE_LENGTH);
		if (status != eap_status_ok)
		{
			return;
		}
		status = add_data(peer_cookie->get_data(), SAE_COOKIE_LENGTH);
		if (status != eap_status_ok)
		{
			return;
		}
	}

	eap_status_e set_selector(
		sae_cookie_c * const own_cookie,
		sae_cookie_c * const peer_cookie)
	{
		eap_status_e status = eap_status_process_general_error;

		status = set_copy_of_buffer(own_cookie->get_data(), SAE_COOKIE_LENGTH);
		if (status != eap_status_ok)
		{
			return status;
		}

		status = add_data(peer_cookie->get_data(), SAE_COOKIE_LENGTH);
		if (status != eap_status_ok)
		{
			return status;
		}

		return status;
	}

	eap_state_selector_c(
		abs_eap_am_tools_c * const tools,
		const eap_state_selector_c * const selector)
		: eap_variable_data_c(tools)
		, m_am_tools(tools)
	{
		eap_status_e status = set_copy_of_buffer(
			selector->get_data(selector->get_data_length()),
			selector->get_data_length());
		if (status != eap_status_ok)
		{
			return;
		}
	}


	//
	eap_state_selector_c * const copy() const
	{
		eap_state_selector_c * const new_selector
			= new eap_state_selector_c(m_am_tools, this);

		return new_selector;
	}

};

#endif //#if !defined(_EAP_STATE_SELECTOR_H_)

//--------------------------------------------------



// End.
