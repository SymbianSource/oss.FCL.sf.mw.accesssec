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

#if !defined(_ISAKMP_RESULT_H_)
#define _ISAKMP_RESULT_H_

#include "eap_variable_data.h"

class isakmp_generic_payload_header_c;


class isakmp_fixed_data_c
{
private:
	//--------------------------------------------------

	bool m_is_valid;
	const isakmp_generic_payload_header_c * m_original_header;
	u16_t m_type;
	u16_t m_data;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~isakmp_fixed_data_c()
	{
	}

	// 
	isakmp_fixed_data_c()
		: m_is_valid(false)
	{
	}

	bool get_is_valid() const
	{
		return m_is_valid;
	}

	const isakmp_generic_payload_header_c * const get_original_header()
	{
		return m_original_header;
	}

	const u16_t get_type(abs_eap_am_tools_c * const m_am_tools) const
	{
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

	const u16_t get_data(abs_eap_am_tools_c * const m_am_tools) const
	{
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

	void set_data(const isakmp_generic_payload_header_c * const original_header,
		const u16_t type, const u16_t data)
	{
		m_is_valid = true;
		m_original_header = original_header;
		m_type = type & 0x7FFF; // Mask out the AF bit.
		m_data = data;
	}

	//--------------------------------------------------
}; // class isakmp_fixed_data_c


class isakmp_variable_data_c
: public eap_variable_data_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	const isakmp_generic_payload_header_c * m_original_header;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~isakmp_variable_data_c()
	{
	}

	// 
	isakmp_variable_data_c(abs_eap_am_tools_c * const tools)
		: eap_variable_data_c(tools)
		, m_am_tools(tools)
		, m_original_header(0)
	{
	}

	const isakmp_generic_payload_header_c * const get_original_header()
	{
		return m_original_header;
	}

	void set_buffer(const isakmp_generic_payload_header_c * const original_header,
		u8_t *buffer, const u32_t buffer_length,
		const bool free_buffer, const bool is_writable)
	{
		m_original_header = original_header;
		eap_variable_data_c::set_buffer(buffer, buffer_length, free_buffer, is_writable);
	}

	//--------------------------------------------------
}; // class isakmp_variable_data_c


//--------------------------------------------------


// 
class isakmp_payloads_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	const u32_t m_received_sequence_number;

	isakmp_fixed_data_c m_encryption_algorithm_offer;

	isakmp_variable_data_c m_dh_public_key;

	isakmp_variable_data_c m_nonce;

	isakmp_variable_data_c m_MAC;

	isakmp_variable_data_c m_L_MAC;

	isakmp_variable_data_c m_EAP_BLOB;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~isakmp_payloads_c()
	{
	}

	// 
	isakmp_payloads_c(
		abs_eap_am_tools_c * const tools
		, const u32_t received_sequence_number)
		: m_am_tools(tools)
		, m_received_sequence_number(received_sequence_number)
		, m_dh_public_key(tools)
		, m_nonce(tools)
		, m_MAC(tools)
		, m_L_MAC(tools)
		, m_EAP_BLOB(tools)
	{
	}

	const u32_t get_received_sequence_number()
	{
		return m_received_sequence_number;
	}

	isakmp_fixed_data_c * const get_encryption_algorithm_offer()
	{
		return reinterpret_cast<isakmp_fixed_data_c *>(&m_encryption_algorithm_offer);
	}

	isakmp_variable_data_c * const get_dh_public_key()
	{
		return reinterpret_cast<isakmp_variable_data_c *>(&m_dh_public_key);
	}

	isakmp_variable_data_c * const get_NONCE()
	{
		return reinterpret_cast<isakmp_variable_data_c *>(&m_nonce);
	}

	isakmp_variable_data_c * const get_MAC()
	{
		return reinterpret_cast<isakmp_variable_data_c *>(&m_MAC);
	}

	isakmp_variable_data_c * const get_L_MAC()
	{
		return reinterpret_cast<isakmp_variable_data_c *>(&m_L_MAC);
	}

	isakmp_variable_data_c * const get_EAP_BLOB()
	{
		return reinterpret_cast<isakmp_variable_data_c *>(&m_EAP_BLOB);
	}

	//--------------------------------------------------
}; // class isakmp_payloads_c


#endif //#if !defined(_ISAKMP_RESULT_H_)

//--------------------------------------------------



// End.
