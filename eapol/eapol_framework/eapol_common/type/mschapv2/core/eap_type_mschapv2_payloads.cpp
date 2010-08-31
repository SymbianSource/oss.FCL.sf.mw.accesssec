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
	#define EAP_FILE_NUMBER_ENUM 98 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

//#include "eap_tools.h"
#include "eap_type_mschapv2_payloads.h"

EAP_FUNC_EXPORT mschapv2_data_c::mschapv2_data_c(abs_eap_am_tools_c * const tools)
    : m_username(tools)
    , m_password(tools)
    , m_challenge(tools)
    , m_peer_challenge(tools)
    , m_identifier(1)
    , m_mschapv2id(1)
    , m_error_code(0)
    , m_password_prompt_enabled(eap_boolean_true)
    , m_nt_response(tools)
    , m_new_password(tools)
{
}

EAP_FUNC_EXPORT mschapv2_data_c::~mschapv2_data_c()
{
};

eap_boolean_e mschapv2_data_c::get_password_prompt_enabled() const
{
    return m_password_prompt_enabled;
}

void mschapv2_data_c::set_password_prompt_enabled(eap_boolean_e is_enabled)
{
    m_password_prompt_enabled = is_enabled;
}

eap_variable_data_c * const mschapv2_data_c::get_username()
{
	return &m_username;
}

eap_variable_data_c * const mschapv2_data_c::get_password()
{
	return &m_password;
}

eap_variable_data_c * const mschapv2_data_c::get_challenge()
{
	return &m_challenge;
}

eap_variable_data_c * const mschapv2_data_c::get_peer_challenge()
{
	return &m_peer_challenge;
}

// Client
eap_variable_data_c * const mschapv2_data_c::get_nt_response()
{
	return &m_nt_response;
}

eap_variable_data_c * const mschapv2_data_c::get_new_password()
{
	return &m_new_password;
}

u8_t mschapv2_data_c::get_identifier() const
{
    return m_identifier;
}

void mschapv2_data_c::set_identifier(u8_t identifier)
{
    m_identifier = identifier;
}

u8_t mschapv2_data_c::get_mschapv2id() const
{
    return m_mschapv2id;
}

void mschapv2_data_c::set_mschapv2id(u8_t mschapv2id)
{
    m_mschapv2id = mschapv2id;
}

u32_t mschapv2_data_c::get_error_code() const
{
    return m_error_code;
}

void mschapv2_data_c::set_error_code(u32_t error_code)
{
    m_error_code = error_code;
}
