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
* Description:  This class defines Credential attributes for protected setup (previously known as simple config).
*
*/

/*
* %version: 8 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 763 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include "eap_tools.h"
#include "simple_config_credential.h"

/** @file */


//----------------------------------------------------------------------------

EAP_FUNC_EXPORT simple_config_credential_c::~simple_config_credential_c()
{
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT simple_config_credential_c::simple_config_credential_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_network_index(1ul)
	, m_SSID(tools)
	, m_Authentication_Type(simple_config_Authentication_Type_None)
	, m_Encryption_Type(simple_config_Encryption_Type_None)
	, m_network_keys(tools)
	, m_MAC_address(tools)
	, m_is_valid(false)
{
	if (m_SSID.get_is_valid() == false)
	{
		return;
	}

	if (m_MAC_address.get_is_valid() == false)
	{
		return;
	}

	m_is_valid = true;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT void simple_config_credential_c::set_network_index(const u8_t index)
{
	m_network_index = index;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT u8_t simple_config_credential_c::get_network_index() const
{
	return m_network_index;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * simple_config_credential_c::get_SSID()
{
	return &m_SSID;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT const eap_variable_data_c * simple_config_credential_c::get_SSID_const() const
{
	return &m_SSID;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT simple_config_Authentication_Type_e simple_config_credential_c::get_Authentication_Type()
{
	return m_Authentication_Type;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT void simple_config_credential_c::set_Authentication_Type(const simple_config_Authentication_Type_e Authentication_Type)
{
	m_Authentication_Type = Authentication_Type;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT simple_config_Encryption_Type_e simple_config_credential_c::get_Encryption_Type()
{
	return m_Encryption_Type;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT void simple_config_credential_c::set_Encryption_Type(const simple_config_Encryption_Type_e Encryption_Type)
{
	m_Encryption_Type = Encryption_Type;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_array_c<network_key_and_index_c> * simple_config_credential_c::get_network_keys()
{
	return &m_network_keys;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT const eap_array_c<network_key_and_index_c> * simple_config_credential_c::get_network_keys_const() const
{
	return &m_network_keys;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * simple_config_credential_c::get_MAC_address()
{
	return &m_MAC_address;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT const eap_variable_data_c * simple_config_credential_c::get_MAC_address_const() const
{
	return &m_MAC_address;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT bool simple_config_credential_c::get_is_valid()
{
	return m_is_valid;
}

//----------------------------------------------------------------------------
// End.
