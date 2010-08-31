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
	#define EAP_FILE_NUMBER_ENUM 55 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eapol_rsna_key_data_payloads.h"
#include "abs_eap_am_tools.h"
#include "eap_tools.h"



EAP_FUNC_EXPORT eapol_rsna_variable_data_c::~eapol_rsna_variable_data_c()
{
}

EAP_FUNC_EXPORT eapol_rsna_variable_data_c::eapol_rsna_variable_data_c(
	abs_eap_am_tools_c * const tools,
	const bool is_RSNA_when_true,
	const bool is_WPXM_when_true)
	: eap_variable_data_c(tools)
	, m_am_tools(tools)
	, m_original_header(tools, is_RSNA_when_true, is_WPXM_when_true, 0, 0)
{
}

EAP_FUNC_EXPORT const eapol_rsna_key_data_header_c * eapol_rsna_variable_data_c::get_original_header() const
{
	return &m_original_header;
}

EAP_FUNC_EXPORT eap_status_e eapol_rsna_variable_data_c::set_buffer(const eapol_rsna_key_data_header_c * const original_header,
	u8_t *buffer, const u32_t buffer_length,
	const bool free_buffer, const bool is_writable)
{
	m_original_header.set_header_buffer(
		original_header->get_header_buffer(original_header->get_header_buffer_length()),
		original_header->get_header_buffer_length());
	if (m_original_header.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	eap_status_e status = eap_variable_data_c::set_buffer(buffer, buffer_length, free_buffer, is_writable);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}



EAP_FUNC_EXPORT eapol_rsna_key_data_payloads_c::~eapol_rsna_key_data_payloads_c()
{
}

EAP_FUNC_EXPORT eapol_rsna_key_data_payloads_c::eapol_rsna_key_data_payloads_c(
	abs_eap_am_tools_c * const tools,
	const bool is_RSNA_when_true,
	const bool is_WPXM_when_true)
	: m_am_tools(tools)
	, m_group_key(tools, is_RSNA_when_true, is_WPXM_when_true)
	, m_group_key_id(0ul)
	, m_group_key_tx_bit(false)
	, m_STAKey(tools, is_RSNA_when_true, is_WPXM_when_true)
	, m_PMKID(tools, is_RSNA_when_true, is_WPXM_when_true)
	, m_RSN_IE(tools)
	, m_is_valid(false)
{
	m_is_valid = true;
}

EAP_FUNC_EXPORT bool eapol_rsna_key_data_payloads_c::check_one_payload(
	const eapol_rsna_key_data_payload_status_e status,
	const eapol_rsna_variable_data_c * const payload)
{
	if (status == eapol_rsna_key_data_payload_status_optional)
	{
		return true;
	}
	else if (status == eapol_rsna_key_data_payload_status_must_not_be
		&& payload->eap_variable_data_c::get_is_valid_data() == false)
	{
		return true;
	}
	else if (status == eapol_rsna_key_data_payload_status_must_be
		&& payload->eap_variable_data_c::get_is_valid_data() == true)
	{
		return true;
	}
	else
	{
		return false;
	}
}

EAP_FUNC_EXPORT bool eapol_rsna_key_data_payloads_c::check_one_payload(
	const eapol_rsna_key_data_payload_status_e status,
	const eap_array_c<eap_variable_data_c> * const payload)
{
	if (status == eapol_rsna_key_data_payload_status_optional)
	{
		return true;
	}
	else if (status == eapol_rsna_key_data_payload_status_must_not_be
		&& (payload->get_object_count() == 0ul
			|| payload->get_object(0ul) == 0
			|| payload->get_object(0ul)->get_is_valid_data() == false))
	{
		return true;
	}
	else if (status == eapol_rsna_key_data_payload_status_must_be
		&& (payload->get_object_count() != 0ul
			&& payload->get_object(0ul) != 0
			&& payload->get_object(0ul)->get_is_valid_data() == true))
	{
		return true;
	}
	else
	{
		return false;
	}
}

EAP_FUNC_EXPORT bool eapol_rsna_key_data_payloads_c::check_payloads(
	const eapol_rsna_key_data_payload_status_e key_id_and_group_key,
	const eapol_rsna_key_data_payload_status_e sta_key,
	const eapol_rsna_key_data_payload_status_e pmkid,
	const eapol_rsna_key_data_payload_status_e one_or_more_RSN_IE
	)
{
	if (check_one_payload(key_id_and_group_key, get_group_key()) == true
		&& check_one_payload(sta_key, get_STAKey()) == true
		&& check_one_payload(pmkid, get_PMKID()) == true
		&& check_one_payload(one_or_more_RSN_IE, get_RSN_IE()) == true // This will check at least one RSN IE exists if any is required.
		)
	{
		return true;
	}
	else
	{
		return false;
	}
}

u8_t eapol_rsna_key_data_payloads_c::get_group_key_id()
{
	return m_group_key_id;
}

bool eapol_rsna_key_data_payloads_c::get_group_key_tx()
{
	return m_group_key_tx_bit;
}

eapol_rsna_variable_data_c * eapol_rsna_key_data_payloads_c::get_group_key()
{
	return static_cast<eapol_rsna_variable_data_c *>(&m_group_key);
}

eapol_rsna_variable_data_c * eapol_rsna_key_data_payloads_c::get_STAKey()
{
	return static_cast<eapol_rsna_variable_data_c *>(&m_STAKey);
}

eapol_rsna_variable_data_c * eapol_rsna_key_data_payloads_c::get_PMKID()
{
	return static_cast<eapol_rsna_variable_data_c *>(&m_PMKID);
}

eap_array_c<eap_variable_data_c> * eapol_rsna_key_data_payloads_c::get_RSN_IE()
{
	return &m_RSN_IE;
}

bool eapol_rsna_key_data_payloads_c::get_is_valid() const
{
	return m_is_valid;
}


void eapol_rsna_key_data_payloads_c::set_group_key_id(const u8_t key_index)
{
	m_group_key_id = key_index;
}

void eapol_rsna_key_data_payloads_c::set_group_key_tx(const bool key_tx_bit)
{
	m_group_key_tx_bit = key_tx_bit;
}


//--------------------------------------------------



// End.
