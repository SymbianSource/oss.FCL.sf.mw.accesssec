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
	#define EAP_FILE_NUMBER_ENUM 132 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "tls_peap_tlv_header.h"

/** @file */


/**
 * The destructor of the tls_peap_tlv_header_c class does nothing.
 */
tls_peap_tlv_header_c::~tls_peap_tlv_header_c()
{
}

/**
 * The constructor of the tls_peap_tlv_header_c class simply initializes the attributes.
 */
tls_peap_tlv_header_c::tls_peap_tlv_header_c(
	abs_eap_am_tools_c * const tools,
	void * const header_begin,
	const u32_t header_buffer_length)
	: eap_general_header_base_c(tools, header_begin, header_buffer_length)
	, m_am_tools(tools)
{
}

/**
 * This function returns the TLV type flag.
 */
tls_peap_tlv_type_e tls_peap_tlv_header_c::get_flag_tlv_type() const
{
	const u8_t * const flag_tlv_type_data = get_header_offset(m_flags_and_tlv_type_offset, sizeof(u16_t));
	if (flag_tlv_type_data != 0)
	{
		return static_cast<tls_peap_tlv_type_e>(
			(static_cast<u16_t>(
				flag_tlv_type_data[0] & ~(m_flag_mask_mandatory_tlv|m_flag_mask_reserved)) << 8)
			| (static_cast<u16_t>(flag_tlv_type_data[1])));
	}
	else
	{
		return tls_peap_tlv_type_none;
	}
}

/**
 * This function returns the TLV mandatory flag.
 */
bool tls_peap_tlv_header_c::get_flag_mandatory_tlv() const
{
	const u8_t * const flag_tlv_type_data = get_header_offset(m_flags_and_tlv_type_offset, sizeof(u8_t));
	if (flag_tlv_type_data != 0)
	{
		u8_t flag = static_cast<u8_t>(flag_tlv_type_data[0] & m_flag_mask_mandatory_tlv);
		if (flag != 0)
		{
			return true;
		}
	}
	return false;
}

/**
 * This function returns the TLV reserved flag.
 */
bool tls_peap_tlv_header_c::get_flag_reserved() const
{
	const u8_t * const flag_tlv_type_data = get_header_offset(m_flags_and_tlv_type_offset, sizeof(u8_t));
	if (flag_tlv_type_data != 0)
	{
		u8_t flag = static_cast<u8_t>(flag_tlv_type_data[0] & m_flag_mask_reserved);
		if (flag != 0)
		{
			return true;
		}
	}
	return false;
}

/**
 * This function returns the data length of TLV.
 */
u16_t tls_peap_tlv_header_c::get_data_length() const
{
	const u8_t * const length_data = get_header_offset(m_length_offset, sizeof(u16_t));
	if (length_data != 0)
	{
		return eap_read_u16_t_network_order(length_data, sizeof(u16_t));
	}
	else
	{
		return 0ul;
	}
}

/**
 * This function returns the header length of TLV.
 */
u32_t tls_peap_tlv_header_c::get_header_length()
{
	return m_data_offset;
}

/**
 * This function returns pointer to the offset of data of TLV.
 * @param offset is the offset of queried data in bytes.
 * @param contignuous_bytes is the length of queried data in bytes.
 */
u8_t * tls_peap_tlv_header_c::get_data_offset(const u32_t offset, const u32_t contignuous_bytes) const
{
	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	u32_t data_length = get_data_length(); // Here is removed optional TLS message length.

	if (data_length >= offset+contignuous_bytes)
	{
		u8_t * const data = get_header_offset(m_data_offset, offset+contignuous_bytes);
		if (data != 0)
		{
			return &data[offset];
		}
		else
		{
			return 0;
		}
	}
	else
	{
		EAP_ASSERT_ALWAYS(data_length >= offset+contignuous_bytes);
	}
	return 0;
}


/**
 * This function returns pointer to the offset of data of TLV.
 * @param contignuous_bytes is the length of queried data in bytes.
 */
u8_t * tls_peap_tlv_header_c::get_data(const u32_t contignuous_bytes) const
{
	return get_data_offset(0u, contignuous_bytes);
}


/**
 * This function return pointer to the next TLV header in the same buffer.
 */
u8_t * tls_peap_tlv_header_c::get_next_header() const
{
	if (get_header_buffer_length() >= 2ul*get_header_length()+get_data_length())
	{
		return get_data_offset(get_data_length(), get_header_length());
	}
	else
	{
		return 0;
	}
}


/**
 * This function checks the header is valid.
 */
eap_status_e tls_peap_tlv_header_c::check_header() const
{
	if (get_flag_tlv_type() != tls_peap_tlv_type_result
		&& get_flag_tlv_type() != tls_peap_tlv_type_nak
		&& get_flag_tlv_type() != tls_peap_tlv_type_crypto_binding
		&& get_flag_tlv_type() != tls_peap_tlv_eap_payload
		&& get_flag_tlv_type() != tls_peap_tlv_type_intermediate_result)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	else if (get_flag_reserved() != 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

/**
 * This function returns debug strings of the TLV type.
 */
eap_const_string tls_peap_tlv_header_c::get_tlv_type_string() const
{

#if defined(USE_EAP_TRACE_STRINGS)
	const tls_peap_tlv_type_e protocol = get_flag_tlv_type();

	EAP_IF_RETURN_STRING(protocol, tls_peap_tlv_type_none)
	else EAP_IF_RETURN_STRING(protocol, tls_peap_tlv_type_result)
	else EAP_IF_RETURN_STRING(protocol, tls_peap_tlv_type_nak)
	else EAP_IF_RETURN_STRING(protocol, tls_peap_tlv_type_crypto_binding)
	else EAP_IF_RETURN_STRING(protocol, tls_peap_tlv_eap_payload)
	else EAP_IF_RETURN_STRING(protocol, tls_peap_tlv_type_intermediate_result)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown TLV type");
	}
}

/**
 * This function sets the TLV type flag.
 */
void tls_peap_tlv_header_c::set_flag_tlv_type(tls_peap_tlv_type_e type)
{
	u8_t * const flag_tlv_type_data = get_header_offset(m_flags_and_tlv_type_offset, sizeof(u16_t));
	
	EAP_ASSERT(flag_tlv_type_data != 0);
	
	flag_tlv_type_data[0] = static_cast<u8_t>(
		(flag_tlv_type_data[0] & (m_flag_mask_mandatory_tlv|m_flag_mask_reserved))
		| (((type & 0xff00) >> 8) & ~(m_flag_mask_mandatory_tlv|m_flag_mask_reserved)));

	flag_tlv_type_data[1] = static_cast<u8_t>(type & 0x00ff);
}

/**
 * This function sets the TLV reserved flag.
 */
void tls_peap_tlv_header_c::set_flag_reserved(bool reserved)
{
	u8_t * const flag_tlv_type_data = get_header_offset(m_flags_and_tlv_type_offset, sizeof(u16_t));
	EAP_ASSERT(flag_tlv_type_data != 0);
	
	if (reserved == true)
	{
		flag_tlv_type_data[0] = static_cast<u8_t>(flag_tlv_type_data[0] | m_flag_mask_reserved);
	}
	else
	{
		flag_tlv_type_data[0] = static_cast<u8_t>(flag_tlv_type_data[0] & ~m_flag_mask_reserved);
	}
}

/**
 * This function sets the TLV manadtory flag.
 */
void tls_peap_tlv_header_c::set_flag_mandatory_tlv(const bool mandatory_when_true)
{
	u8_t * const flag_tlv_type_data = get_header_offset(m_flags_and_tlv_type_offset, sizeof(u16_t));
	EAP_ASSERT(flag_tlv_type_data != 0);
	
	if (mandatory_when_true == true)
	{
		flag_tlv_type_data[0] = static_cast<u8_t>(flag_tlv_type_data[0] | m_flag_mask_mandatory_tlv);
	}
	else
	{
		flag_tlv_type_data[0] = static_cast<u8_t>(flag_tlv_type_data[0] & ~m_flag_mask_mandatory_tlv);
	}
}

/**
 * This function sets the TLV data length.
 */
void tls_peap_tlv_header_c::set_data_length(const u16_t p_length)
{
	u8_t * const length_data = get_header_offset(m_length_offset, sizeof(u16_t));
	
	EAP_ASSERT(length_data != 0);
	
	length_data[0] = static_cast<u8_t>((p_length & 0xff00) >> 8);
	length_data[1] = static_cast<u8_t>((p_length & 0x00ff));
}

/**
 * This function resets the TLV header.
 */
void tls_peap_tlv_header_c::reset_header(const u16_t buffer_length)
{
	set_flag_tlv_type(tls_peap_tlv_type_none);
	set_flag_reserved(0);
	set_flag_mandatory_tlv(true);
	set_data_length(buffer_length);
}




// End.
