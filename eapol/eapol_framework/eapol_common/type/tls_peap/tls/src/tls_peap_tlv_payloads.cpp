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
	#define EAP_FILE_NUMBER_ENUM 133 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "tls_peap_tlv_payloads.h"
#include "abs_eap_am_tools.h"
#include "eap_tools.h"



EAP_FUNC_EXPORT peap_tlv_variable_data_c::~peap_tlv_variable_data_c()
{
}

EAP_FUNC_EXPORT peap_tlv_variable_data_c::peap_tlv_variable_data_c(abs_eap_am_tools_c * const tools)
	: eap_variable_data_c(tools)
	, m_am_tools(tools)
	, m_original_header(tools, 0, 0)
	, m_header_copy(tools)
{
}

EAP_FUNC_EXPORT const tls_peap_tlv_header_c * peap_tlv_variable_data_c::get_original_header() const
{
	return &m_original_header;
}

EAP_FUNC_EXPORT eap_status_e peap_tlv_variable_data_c::set_buffer(
	const tls_peap_tlv_header_c * const original_header,
	u8_t *data_buffer,
	const u32_t data_buffer_length,
	const bool free_buffer,
	const bool is_writable)
{
	m_original_header.set_header_buffer(
		original_header->get_header_buffer(original_header->get_header_buffer_length()),
		original_header->get_header_buffer_length());

	eap_status_e status = eap_variable_data_c::set_buffer(data_buffer, data_buffer_length, free_buffer, is_writable);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT eap_status_e peap_tlv_variable_data_c::set_copy_of_buffer(
	const tls_peap_tlv_header_c * const original_header)
{
	u32_t data_length = original_header->get_header_length()+original_header->get_data_length();

	if (original_header->get_header_buffer_length() < data_length)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eap_status_e status = m_header_copy.set_copy_of_buffer(
		original_header->get_header_buffer(data_length),
		data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_original_header.set_header_buffer(
		m_header_copy.get_data(m_header_copy.get_data_length()),
		m_header_copy.get_data_length());

	tls_peap_tlv_header_c payload_copy(
		m_am_tools,
		m_header_copy.get_data(m_header_copy.get_data_length()),
		m_header_copy.get_data_length());

	status = eap_variable_data_c::set_buffer(
		payload_copy.get_data(payload_copy.get_data_length()),
		payload_copy.get_data_length(),
		false,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}



EAP_FUNC_EXPORT peap_tlv_payloads_c::~peap_tlv_payloads_c()
{
}

EAP_FUNC_EXPORT peap_tlv_payloads_c::peap_tlv_payloads_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_result_tlv(tools)
	, m_nak_tlv(tools)
	, m_crypto_binding_tlv(tools)
	, m_eap_payload_tlv(tools)
	, m_intermediate_result_tlv(tools)
	, m_is_valid(false)
{
	m_is_valid = true;
}

EAP_FUNC_EXPORT bool peap_tlv_payloads_c::check_one_payload(
	const peap_tlv_payload_status_e status,
	const peap_tlv_variable_data_c * const payload)
{
	if (status == peap_tlv_payload_status_optional)
	{
		return true;
	}
	else if (status == peap_tlv_payload_status_must_not_be
		&& payload->eap_variable_data_c::get_is_valid_data() == false)
	{
		return true;
	}
	else if (status == peap_tlv_payload_status_must_be
		&& payload->eap_variable_data_c::get_is_valid_data() == true)
	{
		return true;
	}
	else
	{
		return false;
	}
}

EAP_FUNC_EXPORT bool peap_tlv_payloads_c::check_payloads(
	const peap_tlv_payload_status_e result_tlv,
	const peap_tlv_payload_status_e nak_tlv,
	const peap_tlv_payload_status_e crypto_binding_tlv,
	const peap_tlv_payload_status_e eap_payload_tlv,
	const peap_tlv_payload_status_e intermediate_result_tlv
	)
{
	if (check_one_payload(result_tlv, get_result_tlv()) == true
		&& check_one_payload(nak_tlv, get_nak_tlv()) == true
		&& check_one_payload(crypto_binding_tlv, get_crypto_binding_tlv()) == true
		&& check_one_payload(eap_payload_tlv, get_eap_payload_tlv()) == true
		&& check_one_payload(intermediate_result_tlv, get_intermediate_result_tlv()) == true
		)
	{
		return true;
	}
	else
	{
		return false;
	}
}

EAP_FUNC_EXPORT peap_tlv_variable_data_c * peap_tlv_payloads_c::get_result_tlv()
{
	return static_cast<peap_tlv_variable_data_c *>(&m_result_tlv);
}

EAP_FUNC_EXPORT peap_tlv_variable_data_c * peap_tlv_payloads_c::get_nak_tlv()
{
	return static_cast<peap_tlv_variable_data_c *>(&m_nak_tlv);
}

EAP_FUNC_EXPORT peap_tlv_variable_data_c * peap_tlv_payloads_c::get_crypto_binding_tlv()
{
	return static_cast<peap_tlv_variable_data_c *>(&m_crypto_binding_tlv);
}

EAP_FUNC_EXPORT peap_tlv_variable_data_c * peap_tlv_payloads_c::get_eap_payload_tlv()
{
	return static_cast<peap_tlv_variable_data_c *>(&m_eap_payload_tlv);
}

EAP_FUNC_EXPORT peap_tlv_variable_data_c * peap_tlv_payloads_c::get_intermediate_result_tlv()
{
	return static_cast<peap_tlv_variable_data_c *>(&m_intermediate_result_tlv);
}

EAP_FUNC_EXPORT bool peap_tlv_payloads_c::get_is_valid() const
{
	return m_is_valid;
}

EAP_FUNC_EXPORT void peap_tlv_payloads_c::reset()
{
	m_result_tlv.reset();
	m_nak_tlv.reset();
	m_crypto_binding_tlv.reset();
	m_eap_payload_tlv.reset();
	m_intermediate_result_tlv.reset();
	m_is_valid = false;
}


//--------------------------------------------------



// End.
