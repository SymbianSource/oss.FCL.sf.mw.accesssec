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

#if !defined(_ISAKMP_HEADER_H_)
#define _ISAKMP_HEADER_H_

#include "eap_am_memory.h"
#include "sae_cookie.h"


enum isakmp_version_value_e
{
	isakmp_version_none = 0,
	isakmp_version_current = ((1 << 4) | (0)),
};

enum isakmp_exchange_type_value_e
{
	isakmp_exchange_type = 240, // This is in private area.
};

enum isakmp_payload_type_e
{
	isakmp_payload_NONE                =   0,
	isakmp_payload_sa                  =   1,
	isakmp_payload_proposal            =   2,
	isakmp_payload_transform           =   3,
	isakmp_payload_key_exchange        =   4,
	isakmp_payload_identification      =   5,
	isakmp_payload_certificate         =   6,
	isakmp_payload_certificate_request =   7,
	isakmp_payload_mac                 =   8,
	isakmp_payload_signature           =   9,
	isakmp_payload_nonce               =  10,
	isakmp_payload_notification        =  11,
	isakmp_payload_delete              =  12,
	isakmp_payload_vendor_id           =  13,
	isakmp_payload_EAP                 = 103, // Found from draft-ietf-ipsra-pic-01.txt.
	isakmp_payload_legacy_mac          = 128, // NOTE this is in private area.
};


enum isakmp_attribute_type_e
{
	isakmp_attribute_Encryption_Algorithm               =  1, // B
	isakmp_attribute_Hash_Algorithm                     =  2, // B
	isakmp_attribute_Authentication_Method              =  3, // B
	isakmp_attribute_Group_Description                  =  4, // B
	isakmp_attribute_Group_Type                         =  5, // B
	isakmp_attribute_Group_Prime_Irreducible_Polynomial =  6, // V
	isakmp_attribute_Group_Generator_One                =  7, // V
	isakmp_attribute_Group_Generator_Two                =  8, // V
	isakmp_attribute_Group_Curve_A                      =  9, // V
	isakmp_attribute_Group_Curve_B                      = 10, // V
	isakmp_attribute_Life_Type                          = 11, // B
	isakmp_attribute_Life_Duration                      = 12, // V
	isakmp_attribute_PRF                                = 13, // B
	isakmp_attribute_Key_Length                         = 14, // B
	isakmp_attribute_Field_Size                         = 15, // B
	isakmp_attribute_Group_Order                        = 16, // V
};

const u32_t ISAKMP_COOKIE_LENGTH = 8u;


// 
class isakmp_generic_payload_header_c
{
private:
	//--------------------------------------------------

	u8_t m_next_payload;
	u8_t m_reserved;
	u16_t m_length;
	// m_length-sizeof(isakmp_generic_payload_header_c) data octets follows isakmp_generic_payload_header_c.

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	~isakmp_generic_payload_header_c()
	{
	}

	// 
	isakmp_generic_payload_header_c()
	{
	}

	const isakmp_payload_type_e get_next_payload() const
	{
		return (isakmp_payload_type_e)m_next_payload;
	}

	const u8_t get_reserved() const
	{
		return m_reserved;
	}

	u16_t get_data_length() const
	{
		if (eap_ntohs(m_length) > static_cast<u16_t>(sizeof(isakmp_generic_payload_header_c))
			return eap_ntohs(m_length)-(u16_t)sizeof(isakmp_generic_payload_header_c);
		else
			return 0;
	}

	u16_t get_header_length() const
	{
		return sizeof(isakmp_generic_payload_header_c);
	}

	u8_t * get_data(abs_eap_am_tools_c * const m_am_tools, const u32_t contignuous_bytes) const
	{
		if (get_data_length() >= contignuous_bytes
			&& contignuous_bytes > 0)
		{
			return reinterpret_cast<u8_t *>(this+1); // Data begins after the header.
		}
		else
		{
			EAP_ASSERT_ALWAYS(get_data_length() > 0u);
		}
		return 0;
	}

	isakmp_generic_payload_header_c * const get_next_header() const
	{
		return reinterpret_cast<isakmp_generic_payload_header_c *>((reinterpret_cast<u8_t *>(this+1))+get_data_length());
	}

	void set_next_payload(abs_eap_am_tools_c * const m_am_tools, const isakmp_payload_type_e p_next_payload)
	{
		EAP_ASSERT_ALWAYS(p_next_payload == (isakmp_payload_type_e)((u8_t)p_next_payload));
		m_next_payload = static_cast<u8_t>(p_next_payload;
	}

	void set_reserved(const u8_t p_reserved)
	{
		m_reserved = p_reserved;
	}

	void set_data_length(const u16_t p_data_length)
	{
		m_length = eap_htons(p_data_length+sizeof(isakmp_generic_payload_header_c));
	}

	void reset_header(abs_eap_am_tools_c * const m_am_tools, const u16_t buffer_length)
	{
		set_next_payload(m_am_tools, isakmp_payload_NONE);
		set_reserved(0u);
		set_data_length(buffer_length);
	}

	// 
	//--------------------------------------------------
}; // class isakmp_generic_payload_header_c



// 
class isakmp_attribute_header_c
{
private:
	//--------------------------------------------------

	u16_t m_type;
	u16_t m_value_or_length;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	~isakmp_attribute_header_c()
	{
	}

	// 
	isakmp_attribute_header_c()
	{
	}

	const isakmp_attribute_type_e get_type() const
	{
		return (isakmp_attribute_type_e)(m_type && 0x7FFF);
	}

	const u16_t get_value() const
	{
		return m_value_or_length;
	}


	bool is_type_fixed() const
	{
		if ((m_type & 0x8000) != 0)
		{
			return true;
		}
		return false;
	}

	void set_type_fixed(const isakmp_attribute_type_e p_type)
	{
		m_type = p_type | 0x8000;
	}

	void set_type_variable(const isakmp_attribute_type_e p_type)
	{
		m_type = p_type | 0x0000;
	}

	void set_value_or_length(const u16_t p_value)
	{
		m_value_or_length = p_value;
	}

	// 
	//--------------------------------------------------
}; // class isakmp_attribute_header_c


const u8_t isakmp_flag_server = (1 << 3);
const u8_t isakmp_mask_server = (~(1 << 3));


// 
class isakmp_header_c
{
private:
	//--------------------------------------------------

	sae_cookie_c m_source_cookie; // m_initiator.
	sae_cookie_c m_destination_cookie; // m_responder.
	u8_t m_next_payload;
	u8_t m_version;
	u8_t m_exchange_type;
	u8_t m_flags;
	u32_t m_sequence_number; //m_message_id.
	u32_t m_length;
	// m_length-sizeof(isakmp_header_c) data octets follows isakmp_header_c.

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	~isakmp_header_c()
	{
	}

	// 
	isakmp_header_c()
	{
	}

	const isakmp_payload_type_e get_next_payload() const
	{
		return (isakmp_payload_type_e)m_next_payload;
	}

	const isakmp_version_value_e get_version() const
	{
		return (const isakmp_version_value_e)m_version;
	}

	const u8_t get_exchange_type() const
	{
		return m_exchange_type;
	}

	const u8_t get_flags() const
	{
		return m_flags;
	}

	const u32_t get_sequence_number()
	{
		return eap_ntohl(m_sequence_number);
	}

	u32_t get_data_length() const
	{
		if (eap_ntohl(m_length) > (u32_t)sizeof(isakmp_header_c))
			return eap_ntohl(m_length)-(u32_t)sizeof(isakmp_header_c);
		else
			return 0;
	}

	u32_t get_header_length() const
	{
		return sizeof(isakmp_header_c);
	}

	sae_cookie_c *get_source_cookie()
	{
		return &m_source_cookie;
	}

	sae_cookie_c *get_destination_cookie()
	{
		return &m_destination_cookie;
	}

	u8_t * get_data_offset(abs_eap_am_tools_c * const m_am_tools, const u32_t offset, const u32_t contignuous_bytes) const
	{
		u32_t data_length = get_data_length();
		if (data_length >= offset+contignuous_bytes
			&& contignuous_bytes > 0u)
		{
			return ((reinterpret_cast<u8_t *>(this+1))+offset); // Data begins after the header.
		}
		else
		{
			EAP_ASSERT_ALWAYS(get_data_length() > 0u);
		}
		return 0;
	}


	u8_t * get_data(abs_eap_am_tools_c * const m_am_tools, const u32_t contignuous_bytes) const
	{
		return get_data_offset(m_am_tools, 0u, contignuous_bytes);
	}


	void set_next_payload(const isakmp_payload_type_e p_next_payload)
	{
		m_next_payload = static_cast<u8_t>(p_next_payload;
	}

	void set_version(const isakmp_version_value_e p_version)
	{
		m_version = static_cast<u8_t>(p_version;
	}

	void set_exchange_type(const u8_t p_exchange_type)
	{
		m_exchange_type = p_exchange_type;
	}

	void set_flags(const u8_t p_flags)
	{
		m_flags = p_flags;
	}

	void set_sequence_number(const u32_t sequence_number)
	{
		m_sequence_number = eap_htonl(sequence_number);
	}

	void set_data_length(const u32_t p_data_length)
	{
		m_length = eap_htonl(p_data_length+sizeof(isakmp_header_c));
	}

	void reset_header(const u32_t buffer_length,
		const bool is_client_when_true)
	{
		set_next_payload(isakmp_payload_NONE);
		set_version(isakmp_version_current);
		set_exchange_type(isakmp_exchange_type);
		if (is_client_when_true == true)
		{
			set_flags(0u);
		}
		else
		{
			set_flags(isakmp_flag_server);
		}
		set_sequence_number(0u);
		set_data_length(buffer_length-sizeof(isakmp_header_c));
		get_source_cookie()->reset_cookie();
		get_destination_cookie()->reset_cookie();
	}

	eap_status_e check_header(const bool is_client_when_true)
	{
		if (get_version() != isakmp_version_current)
		{
			return eap_status_wrong_isakmp_header_version;
		}
		else if (get_exchange_type() != isakmp_exchange_type)
		{
			return eap_status_wrong_isakmp_exchange_type;
		}
		else if (is_client_when_true == false
			&& get_flags() != 0u)
		{
			return eap_status_wrong_isakmp_flags;
		}
		else if (is_client_when_true == true
			&& get_flags() != isakmp_flag_server)
		{
			return eap_status_wrong_isakmp_flags;
		}
		return eap_status_ok;
	}

	// 
	//--------------------------------------------------
}; // class isakmp_header_c


#endif //#if !defined(_ISAKMP_HEADER_H_)

//--------------------------------------------------



// End.
