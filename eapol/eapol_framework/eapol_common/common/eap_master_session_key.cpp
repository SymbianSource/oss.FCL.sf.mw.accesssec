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
	#define EAP_FILE_NUMBER_ENUM 28 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_master_session_key.h"

//--------------------------------------------------

EAP_FUNC_EXPORT eap_master_session_key_c::~eap_master_session_key_c()
{
}

EAP_FUNC_EXPORT eap_master_session_key_c::eap_master_session_key_c(
	abs_eap_am_tools_c * const tools,
	const eap_type_value_e eap_type)
	: eap_variable_data_c(tools)
	  , m_am_tools(tools)
	  , m_leap_password(tools)
	  , m_eap_type(eap_type)
{
}

EAP_FUNC_EXPORT eap_type_value_e eap_master_session_key_c::get_eap_type() const
{
	return m_eap_type;
}

EAP_FUNC_EXPORT void eap_master_session_key_c::set_eap_type(eap_type_value_e type)
{
	m_eap_type = type;
}

EAP_FUNC_EXPORT eap_status_e eap_master_session_key_c::copy_leap_password(const eap_variable_data_c * const key)
{
	return m_leap_password.set_copy_of_buffer(key);
}

EAP_FUNC_EXPORT const eap_variable_data_c * eap_master_session_key_c::get_leap_password() const
{
	return &m_leap_password;
}

EAP_FUNC_EXPORT eap_status_e eap_master_session_key_c::set_copy(const eap_master_session_key_c * const msk)
{
	eap_status_e status = eap_variable_data_c::set_copy_of_buffer(msk);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (msk->get_leap_password()->get_is_valid_data() == true)
	{
		status = m_leap_password.set_copy_of_buffer(msk->get_leap_password());
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	m_eap_type = msk->get_eap_type();

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------



// End.
