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
	#define EAP_FILE_NUMBER_ENUM 34 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eapol_session_key.h"
#include "eap_tools.h"


//--------------------------------------------------

EAP_FUNC_EXPORT eapol_session_key_c::~eapol_session_key_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eapol_session_key_c::eapol_session_key_c(
		abs_eap_am_tools_c * const tools,
		eap_variable_data_c * const key, ///< Here is the key.
		const eapol_key_type_e key_type, ///< This the type of the key.
		const u32_t key_index, ///< This is the index of the key.
		const bool key_tx_bit, ///< This is the TX bit of the key.
		const u8_t * const key_RSC, ///< This is the RSC counter
		const u32_t key_RSC_size ///< This is the size of RSC counter
		)
	: m_am_tools(tools)
	  , m_key(tools)
	  , m_sequence_number(tools)
	  , m_key_type(key_type)
	  , m_key_index(key_index)
	  , m_key_tx_bit(key_tx_bit)
	  , m_is_valid(false)
{
	eap_status_e status = m_key.set_copy_of_buffer(key);
	if (status != eap_status_ok)
	{
		return;
	}

	if (key_RSC != 0
		&& key_RSC_size > 0ul)
	{
		status = m_sequence_number.set_copy_of_buffer(
			key_RSC,
			key_RSC_size);
		if (status != eap_status_ok)
		{
			return;
		}
	}

	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eapol_session_key_c::eapol_session_key_c(
	abs_eap_am_tools_c * const tools
	)
	: m_am_tools(tools)
	  , m_key(tools)
	  , m_sequence_number(tools)
	  , m_key_type(eapol_key_type_last_type)
	  , m_key_index(0ul)
	  , m_key_tx_bit(false)
	  , m_is_valid(true)
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT const eap_variable_data_c * eapol_session_key_c::get_key() const
{
	return &m_key;
}

//--------------------------------------------------

EAP_FUNC_EXPORT const eap_variable_data_c * eapol_session_key_c::get_sequence_number() const
{
	return &m_sequence_number;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eapol_key_type_e eapol_session_key_c::get_key_type() const
{
	return m_key_type;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eapol_session_key_c::get_key_index() const
{
	return m_key_index;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eapol_session_key_c::get_key_tx_bit() const
{
	return m_key_tx_bit;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eapol_session_key_c::get_is_valid() const
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_session_key_c::set_key(const eap_variable_data_c * const key)
{
	return m_key.set_copy_of_buffer(key);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_session_key_c::set_sequence_number(eap_variable_data_c * const sequence_number)
{
	return m_sequence_number.set_copy_of_buffer(sequence_number);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eapol_session_key_c::set_key_type(const eapol_key_type_e key_type)
{
	m_key_type = key_type;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eapol_session_key_c::set_key_index(const u32_t key_index)
{
	m_key_index = key_index;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eapol_session_key_c::set_key_tx_bit(const bool key_tx_bit)
{
	m_key_tx_bit = key_tx_bit;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eapol_session_key_c::get_eapol_key_type_string(
	const eapol_key_type_e key_type)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(key_type, eapol_key_type_broadcast)
	else EAP_IF_RETURN_STRING(key_type, eapol_key_type_unicast)
#if defined(EAP_USE_WPXM)
	else EAP_IF_RETURN_STRING(key_type, eapol_key_type_wpxm_wpxk1)
	else EAP_IF_RETURN_STRING(key_type, eapol_key_type_wpxm_wpxk2)
#endif //#if defined(EAP_USE_WPXM)
	else EAP_IF_RETURN_STRING(key_type, eapol_key_type_pmkid)
	else EAP_IF_RETURN_STRING(key_type, eapol_key_type_last_type)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(key_type);

		return EAPL("Unknown EAPOL-Key type");
	}
}

//--------------------------------------------------



// End.
