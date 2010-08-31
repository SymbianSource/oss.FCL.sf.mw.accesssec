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
	#define EAP_FILE_NUMBER_ENUM 25 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#error Do not use this anymore

#include "eap_handle.h"


EAP_FUNC_EXPORT eap_handle_c::~eap_handle_c()
{
}

EAP_FUNC_EXPORT eap_handle_c::eap_handle_c(
	abs_eap_am_tools_c * const tools)
	: eap_variable_data_c(tools)
	, m_send_network_id(tools)
	, m_eap_type(eap_type_none)
{
}

EAP_FUNC_EXPORT eap_handle_c::eap_handle_c(
	abs_eap_am_tools_c * const tools,
	eap_variable_data_c * const selector,
	const eap_am_network_id_c * const network_id,
	const eap_type_value_e p_eap_type)
	: eap_variable_data_c(tools)
	, m_send_network_id(tools, network_id)
	, m_eap_type(p_eap_type)
{
	eap_status_e status = set_copy_of_buffer(selector);
	if (status != eap_status_ok)
	{
		return;
	}

	set_is_valid();
}

EAP_FUNC_EXPORT eap_status_e eap_handle_c::set_handle(
	eap_variable_data_c * const selector,
	const eap_am_network_id_c * const network_id,
	const eap_type_value_e p_eap_type)
{
	eap_status_e status = eap_status_process_general_error;

	if (selector != 0)
	{
		status = set_copy_of_buffer(selector);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (network_id != 0)
	{
		status = m_send_network_id.set_copy_of_network_id(network_id);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	m_eap_type = (p_eap_type);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT eap_am_network_id_c * eap_handle_c::get_send_network_id() const
{
	return &m_send_network_id;
}

EAP_FUNC_EXPORT eap_type_value_e eap_handle_c::get_eap_type() const
{
	return m_eap_type;
}

EAP_FUNC_EXPORT void eap_handle_c::reset()
{
	eap_variable_data_c::reset();
	m_send_network_id.reset();
	m_eap_type = eap_type_none;
}





// End.
