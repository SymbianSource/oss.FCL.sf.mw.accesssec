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
* %version: 7.1.3 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 81 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_type_gsmsim_payloads.h"
#include "abs_eap_am_tools.h"
#include "eap_tools.h"


EAP_FUNC_EXPORT gsmsim_fixed_data_c::~gsmsim_fixed_data_c()
{
}

EAP_FUNC_EXPORT gsmsim_fixed_data_c::gsmsim_fixed_data_c(
	abs_eap_am_tools_c * const tools)
	: m_is_valid(false)
	, m_original_header(tools, 0, 0)
	, m_type(0)
	, m_data(0)
{
}

EAP_FUNC_EXPORT bool gsmsim_fixed_data_c::get_is_valid() const
{
	return m_is_valid;
}

EAP_FUNC_EXPORT const gsmsim_payload_AT_header_c * gsmsim_fixed_data_c::get_original_header()
{
	return &m_original_header;
}

EAP_FUNC_EXPORT u16_t gsmsim_fixed_data_c::get_type(abs_eap_am_tools_c * const m_am_tools) const
{
	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	if (m_is_valid == true)
	{
		return m_type;
	}
	else
	{
		EAP_ASSERT_ALWAYS(m_is_valid == true);
		return 0u;
	}
}

EAP_FUNC_EXPORT u16_t gsmsim_fixed_data_c::get_data(abs_eap_am_tools_c * const m_am_tools) const
{
	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	if (m_is_valid == true)
	{
		return m_data;
	}
	else
	{
		EAP_ASSERT_ALWAYS(m_is_valid == true);
		return 0u;
	}
}

EAP_FUNC_EXPORT void gsmsim_fixed_data_c::set_data(const gsmsim_payload_AT_header_c * const original_header,
	const u16_t type, const u16_t data)
{
	m_is_valid = true;
	m_original_header.set_header_buffer(
		original_header->get_header_buffer(original_header->get_header_buffer_length()),
		original_header->get_header_buffer_length());
	m_type = static_cast<u16_t>(type & 0x7FFF); // Mask out the AF bit.
	m_data = data;
}



EAP_FUNC_EXPORT gsmsim_variable_data_c::~gsmsim_variable_data_c()
{
}

EAP_FUNC_EXPORT gsmsim_variable_data_c::gsmsim_variable_data_c(abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_data(tools)
	, m_original_header(tools, 0, 0)
	, m_payload_included(false)
{
}

EAP_FUNC_EXPORT eap_status_e gsmsim_variable_data_c::reset()
{
	m_payload_included = false;
	m_original_header.reset_header(0ul);
	return m_data.reset();
}

EAP_FUNC_EXPORT const gsmsim_payload_AT_header_c * gsmsim_variable_data_c::get_original_header() const
{
	return &m_original_header;
}

EAP_FUNC_EXPORT eap_status_e gsmsim_variable_data_c::set_buffer(const gsmsim_payload_AT_header_c * const original_header,
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

	eap_status_e status = m_data.set_buffer(buffer, buffer_length, free_buffer, is_writable);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_payload_included = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT bool gsmsim_variable_data_c::get_payload_included() const
{
	return m_payload_included;
}

EAP_FUNC_EXPORT u32_t gsmsim_variable_data_c::get_data_length() const
{
	return m_data.get_data_length();
}

EAP_FUNC_EXPORT u8_t * gsmsim_variable_data_c::get_data(const u32_t data_length) const
{
	return m_data.get_data(data_length);
}

EAP_FUNC_EXPORT eap_variable_data_c * gsmsim_variable_data_c::get_payload_buffer()
{
	return &m_data;
}


EAP_FUNC_EXPORT gsmsim_payloads_c::~gsmsim_payloads_c()
{
}

EAP_FUNC_EXPORT gsmsim_payloads_c::gsmsim_payloads_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_nonce_mt(tools)
	, m_nonce_s(tools)
	, m_MAC(tools)
	, m_ENCR_DATA(tools)
	, m_IDENTITY_payload(tools)
	, m_padding_payload(tools)
	, m_n_RANDs(tools)
	, m_PERMANENT_ID_REQ(tools)
	, m_FULLAUTH_ID_REQ(tools)
	, m_ANY_ID_REQ(tools)
	, m_IV(tools)
	, m_NEXT_PSEUDONYM(tools)
	, m_NEXT_REAUTH_ID(tools)
	, m_NOTIFICATION(tools)
	, m_VERSION_LIST(tools)
	, m_SELECTED_VERSION(tools)
	, m_COUNTER(tools)
	, m_COUNTER_TOO_SMALL(tools)
	, m_CLIENT_ERROR_CODE(tools)
	, m_RESULT_IND(tools)
	, m_unknown_payload(gsmsim_payload_NONE)
	, m_includes_other_version_than_1(false)
	, m_is_valid(false)
{
	m_is_valid = true;
}

EAP_FUNC_EXPORT bool gsmsim_payloads_c::check_one_payload(
	const eap_gsmsim_payload_status_e status,
	const gsmsim_variable_data_c * const payload)
{
	if (status == eap_gsmsim_payload_status_optional)
	{
		return true;
	}
	else if (status == eap_gsmsim_payload_status_must_not_be
		&& payload->get_payload_included() == false)
	{
		return true;
	}
	else if (status == eap_gsmsim_payload_status_must_be
		&& payload->get_payload_included() == true)
	{
		return true;
	}
	else
	{
		return false;
	}
}

EAP_FUNC_EXPORT bool gsmsim_payloads_c::check_payloads(
	const eap_gsmsim_payload_status_e nonce_mt,
	const eap_gsmsim_payload_status_e nonce_s,
	const eap_gsmsim_payload_status_e MAC,
	const eap_gsmsim_payload_status_e ENCR_DATA,
	const eap_gsmsim_payload_status_e IDENTITY,
	const eap_gsmsim_payload_status_e padding,
	const eap_gsmsim_payload_status_e n_RANDs,
	const eap_gsmsim_payload_status_e PERMANENT_ID_REQ,
	const eap_gsmsim_payload_status_e FULLAUTH_ID_REQ,
	const eap_gsmsim_payload_status_e ANY_ID_REQ,
	const eap_gsmsim_payload_status_e IV,
	const eap_gsmsim_payload_status_e NEXT_PSEUDONYM,
	const eap_gsmsim_payload_status_e NEXT_REAUTH_ID,
	const eap_gsmsim_payload_status_e NOTIFICATION,
	const eap_gsmsim_payload_status_e VERSION_LIST,
	const eap_gsmsim_payload_status_e SELECTED_VERSION,
	const eap_gsmsim_payload_status_e COUNTER,
	const eap_gsmsim_payload_status_e COUNTER_TOO_SMALL,
	const eap_gsmsim_payload_status_e CLIENT_ERROR_CODE,
	const eap_gsmsim_payload_status_e RESULT_IND
	)
{
	if (check_one_payload(nonce_mt, get_NONCE_MT()) == true
		&& check_one_payload(nonce_s, get_NONCE_S()) == true
		&& check_one_payload(MAC, get_MAC()) == true
		&& check_one_payload(ENCR_DATA, get_ENCR_DATA()) == true
		&& check_one_payload(IDENTITY, get_IDENTITY_payload()) == true
		&& check_one_payload(padding, get_padding_payload()) == true
		&& check_one_payload(n_RANDs, get_n_RANDs()) == true
		&& check_one_payload(PERMANENT_ID_REQ, get_PERMANENT_ID_REQ()) == true
		&& check_one_payload(FULLAUTH_ID_REQ, get_FULLAUTH_ID_REQ()) == true
		&& check_one_payload(ANY_ID_REQ, get_ANY_ID_REQ()) == true
		&& check_one_payload(IV, get_IV()) == true
		&& check_one_payload(NEXT_PSEUDONYM, get_NEXT_PSEUDONYM()) == true
		&& check_one_payload(NEXT_REAUTH_ID, get_NEXT_REAUTH_ID()) == true
		&& check_one_payload(NOTIFICATION, get_NOTIFICATION()) == true
		&& check_one_payload(VERSION_LIST, get_VERSION_LIST()) == true
		&& check_one_payload(SELECTED_VERSION, get_SELECTED_VERSION()) == true
		&& check_one_payload(COUNTER, get_COUNTER()) == true
		&& check_one_payload(COUNTER_TOO_SMALL, get_counter_too_small()) == true
		&& check_one_payload(CLIENT_ERROR_CODE, get_CLIENT_ERROR_CODE()) == true
		&& check_one_payload(RESULT_IND, get_RESULT_IND()) == true
		)
	{
		return true;
	}
	else
	{
		return false;
	}
}


EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_NONCE_MT()
{
	return static_cast<gsmsim_variable_data_c *>(&m_nonce_mt);
}

EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_NONCE_S()
{
	return static_cast<gsmsim_variable_data_c *>(&m_nonce_s);
}

EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_MAC()
{
	return static_cast<gsmsim_variable_data_c *>(&m_MAC);
}

EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_ENCR_DATA()
{
	return static_cast<gsmsim_variable_data_c *>(&m_ENCR_DATA);
}

EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_IDENTITY_payload()
{
	return static_cast<gsmsim_variable_data_c *>(&m_IDENTITY_payload);
}

EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_padding_payload()
{
	return static_cast<gsmsim_variable_data_c *>(&m_padding_payload);
}

EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_n_RANDs()
{
	return static_cast<gsmsim_variable_data_c *>(&m_n_RANDs);
}

EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_PERMANENT_ID_REQ()
{
	return static_cast<gsmsim_variable_data_c *>(&m_PERMANENT_ID_REQ);
}

EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_FULLAUTH_ID_REQ()
{
	return static_cast<gsmsim_variable_data_c *>(&m_FULLAUTH_ID_REQ);
}

EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_ANY_ID_REQ()
{
	return static_cast<gsmsim_variable_data_c *>(&m_ANY_ID_REQ);
}

EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_IV()
{
	return static_cast<gsmsim_variable_data_c *>(&m_IV);
}

EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_NEXT_PSEUDONYM()
{
	return static_cast<gsmsim_variable_data_c *>(&m_NEXT_PSEUDONYM);
}

EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_NEXT_REAUTH_ID()
{
	return static_cast<gsmsim_variable_data_c *>(&m_NEXT_REAUTH_ID);
}

EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_NOTIFICATION()
{
	return static_cast<gsmsim_variable_data_c *>(&m_NOTIFICATION);
}

EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_RESULT_IND()
{
	return static_cast<gsmsim_variable_data_c *>(&m_RESULT_IND);
}

EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_VERSION_LIST()
{
	return static_cast<gsmsim_variable_data_c *>(&m_VERSION_LIST);
}

EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_SELECTED_VERSION()
{
	return static_cast<gsmsim_variable_data_c *>(&m_SELECTED_VERSION);
}

EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_CLIENT_ERROR_CODE()
{
	return static_cast<gsmsim_variable_data_c *>(&m_CLIENT_ERROR_CODE);
}

EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_COUNTER()
{
	return static_cast<gsmsim_variable_data_c *>(&m_COUNTER);
}

EAP_FUNC_EXPORT gsmsim_variable_data_c * gsmsim_payloads_c::get_counter_too_small()
{
	return static_cast<gsmsim_variable_data_c *>(&m_COUNTER_TOO_SMALL);
}


EAP_FUNC_EXPORT void gsmsim_payloads_c::set_includes_unknown_attribute(const gsmsim_payload_AT_type_e unknown_payload)
{
	if (m_unknown_payload == gsmsim_payload_NONE)
	{
		// Only the first one is recorded.
		m_unknown_payload = unknown_payload;
	}
}

EAP_FUNC_EXPORT gsmsim_payload_AT_type_e gsmsim_payloads_c::get_includes_unknown_attribute()
{
	return m_unknown_payload;
}

EAP_FUNC_EXPORT void gsmsim_payloads_c::set_includes_other_version_than_1(const bool includes_other_version_than_1)
{
	m_includes_other_version_than_1 = includes_other_version_than_1;
}

EAP_FUNC_EXPORT bool gsmsim_payloads_c::get_includes_other_version_than_1()
{
	return m_includes_other_version_than_1;
}

EAP_FUNC_EXPORT bool gsmsim_payloads_c::get_is_valid() const
{
	return m_is_valid;
}


//--------------------------------------------------



// End.
