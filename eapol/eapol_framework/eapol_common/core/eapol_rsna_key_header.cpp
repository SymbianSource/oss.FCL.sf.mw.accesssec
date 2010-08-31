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
	#define EAP_FILE_NUMBER_ENUM 56 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eapol_rsna_key_header.h"
#include "eap_automatic_variable.h"
#include "eapol_key_state_string.h"

//------------------------------------------------------

//
EAP_FUNC_EXPORT eapol_RSNA_key_header_c::~eapol_RSNA_key_header_c()
{
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eapol_RSNA_key_header_c::eapol_RSNA_key_header_c(
	abs_eap_am_tools_c * const tools,
	const bool is_RSNA_when_true,
	const bool is_WPXM_when_true,
	void * const header_begin,
	const u32_t header_buffer_length)
	: eap_general_header_base_c(tools, header_begin, header_buffer_length)
	, m_am_tools(tools)
	, m_is_RSNA_when_true(is_RSNA_when_true)
	, m_is_WPXM_when_true(is_WPXM_when_true)
{
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::set_key_information(const u16_t info)
{
	u8_t * const data = get_header_offset(m_offset_key_information, sizeof(u16_t));
	if (data != 0)
	{
		return eap_write_u16_t_network_order(data, sizeof(u16_t), info);
	}
	else
	{
		// ERROR.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}	

//------------------------------------------------------

//
EAP_FUNC_EXPORT eapol_protocol_version_e eapol_RSNA_key_header_c::get_eapol_protocol_version() const
{
	const u8_t * const data = get_header_offset(m_offset_eapol_version, sizeof(u8_t));
	if (data != 0)
	{
		return static_cast<eapol_protocol_version_e>(*data);
	}
	else
	{
		return eapol_protocol_version_none;
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eapol_packet_type_e eapol_RSNA_key_header_c::get_eapol_packet_type() const
{
	const u8_t * const data = get_header_offset(m_offset_eapol_type, sizeof(u8_t));
	if (data != 0)
	{
		return static_cast<eapol_packet_type_e>(*data);
	}
	else
	{
		return eapol_packet_type_no_type;
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT u16_t eapol_RSNA_key_header_c::get_eapol_packet_body_length() const
{
	const u8_t * const data = get_header_offset(m_offset_eapol_packet_body_length, sizeof(u16_t));
	if (data != 0)
	{
		return eap_read_u16_t_network_order(data, sizeof(u16_t));
	}
	else
	{
		return 0ul;
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT u16_t eapol_RSNA_key_header_c::get_eapol_packet_length() const
{
	// m_offset_key_descriptor_type is the length of the EAPOL header.
	// Including fields Version, Type and Packet Body Length.
	return static_cast<u16_t>(get_eapol_packet_body_length() + m_offset_key_descriptor_type);
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eapol_key_descriptor_type_e eapol_RSNA_key_header_c::get_key_descriptor_type() const
{
	const u8_t * const data = get_header_offset(m_offset_key_descriptor_type, sizeof(u8_t));
	if (data != 0)
	{
		return static_cast<eapol_key_descriptor_type_e>(*data);
	}
	else
	{
		return eapol_key_descriptor_type_none;
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT u16_t eapol_RSNA_key_header_c::get_key_information() const
{
	const u8_t * const data = get_header_offset(m_offset_key_information, sizeof(u16_t));
	if (data != 0)
	{
		return eap_read_u16_t_network_order(data, sizeof(u16_t));
	}
	else
	{
		// ERROR.
		return 0ul;
	}
}	

//------------------------------------------------------

//
EAP_FUNC_EXPORT eapol_RSNA_key_header_c::key_descriptor_version_e eapol_RSNA_key_header_c::get_key_information_key_descriptor_version() const
{
	const u16_t key_information = get_key_information();
	return static_cast<key_descriptor_version_e>((key_information & m_key_information_mask_key_descriptor_version)
		>> m_key_information_mask_key_descriptor_version_shift);
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT bool eapol_RSNA_key_header_c::get_key_information_key_type() const
{
	const u16_t key_information = get_key_information();
	const u16_t key_type = static_cast<u16_t>(key_information & m_key_information_mask_key_type);
	if (key_type != 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT u8_t eapol_RSNA_key_header_c::get_key_information_reserved_a() const
{
	EAP_ASSERT(m_is_RSNA_when_true == true || m_is_WPXM_when_true == true);

	const u16_t key_information = get_key_information();
	return static_cast<u8_t>((key_information & m_key_information_mask_reserved_a_RSNA)
		>> m_key_information_mask_reserved_a_shift_RSNA);
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT u8_t eapol_RSNA_key_header_c::get_key_information_key_index() const
{
	EAP_ASSERT(m_is_RSNA_when_true == false || m_is_WPXM_when_true == true);

	const u16_t key_information = get_key_information();
	return static_cast<u8_t>((key_information & m_key_information_mask_key_index_WPA)
		>> m_key_information_mask_key_index_shift_WPA);
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT bool eapol_RSNA_key_header_c::get_key_information_install() const
{
	const u16_t key_information = get_key_information();
	const u16_t key_type = static_cast<u16_t>(key_information & m_key_information_mask_install);
	if (key_type != 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT bool eapol_RSNA_key_header_c::get_key_information_key_ack() const
{
	const u16_t key_information = get_key_information();
	const u16_t key_type = static_cast<u16_t>(key_information & m_key_information_mask_key_ack);
	if (key_type != 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT bool eapol_RSNA_key_header_c::get_key_information_key_MIC() const
{
	const u16_t key_information = get_key_information();
	const u16_t key_type = static_cast<u16_t>(key_information & m_key_information_mask_key_MIC);
	if (key_type != 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT bool eapol_RSNA_key_header_c::get_key_information_secure() const
{
	const u16_t key_information = get_key_information();
	const u16_t key_type = static_cast<u16_t>(key_information & m_key_information_mask_secure);
	if (key_type != 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT bool eapol_RSNA_key_header_c::get_key_information_error() const
{
	const u16_t key_information = get_key_information();
	const u16_t key_type = static_cast<u16_t>(key_information & m_key_information_mask_error);
	if (key_type != 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT bool eapol_RSNA_key_header_c::get_key_information_request() const
{
	const u16_t key_information = get_key_information();
	const u16_t key_type = static_cast<u16_t>(key_information & m_key_information_mask_request);
	if (key_type != 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}


//------------------------------------------------------

//
EAP_FUNC_EXPORT bool eapol_RSNA_key_header_c::get_key_information_encrypted_key_data() const
{
	const u16_t key_information = get_key_information();
	const u16_t key_type = static_cast<u16_t>(key_information & m_key_information_mask_encrypted_key_data_RSNA);
	if (key_type != 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}


//------------------------------------------------------

//
EAP_FUNC_EXPORT u8_t eapol_RSNA_key_header_c::get_key_information_reserved_b() const
{
	const u16_t key_information = get_key_information();

	if (m_is_RSNA_when_true == true || m_is_WPXM_when_true == true)
	{
		return static_cast<u8_t>((key_information & m_key_information_mask_reserved_b_RSNA)
			>> m_key_information_mask_reserved_b_shift_RSNA);
	}
	else
	{
		return static_cast<u8_t>((key_information & m_key_information_mask_reserved_b_WPA)
			>> m_key_information_mask_reserved_b_shift_WPA);
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT u16_t eapol_RSNA_key_header_c::get_key_length() const
{
	const u8_t * const data = get_header_offset(m_offset_key_length, sizeof(u16_t));
	if (data != 0)
	{
		return eap_read_u16_t_network_order(data, sizeof(u16_t));
	}
	else
	{
		return 0ul;
	}
}	

//------------------------------------------------------

//
EAP_FUNC_EXPORT u64_t eapol_RSNA_key_header_c::get_key_replay_counter() const
{
	const u8_t * const data = get_header_offset(m_offset_key_replay_counter, EAPOL_RSNA_KEY_REPLY_COUNTER_SIZE);
	if (data != 0)
	{
		return eap_read_u64_t_network_order(data, EAPOL_RSNA_KEY_REPLY_COUNTER_SIZE);
	}
	else
	{
		return 0ul;
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT u8_t * eapol_RSNA_key_header_c::get_key_NONCE() const
{
	u8_t * const data = get_header_offset(m_offset_key_NONCE, EAPOL_RSNA_KEY_NONCE_SIZE);
	return data;
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT u8_t * eapol_RSNA_key_header_c::get_EAPOL_key_IV() const
{
	u8_t * const data = get_header_offset(m_offset_EAPOL_key_IV, EAPOL_RSNA_EAPOL_KEY_IV_SIZE);
	return data;
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT u8_t * eapol_RSNA_key_header_c::get_key_RSC() const
{
	u8_t * const data = get_header_offset(m_offset_key_RSC, EAPOL_RSNA_KEY_RSC_SIZE);
	return data;
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT u8_t * eapol_RSNA_key_header_c::get_key_STA_MAC_address() const
{
	u8_t * const data = get_header_offset(m_offset_key_STA_MAC_address, EAPOL_RSNA_KEY_STA_MAC_ADDRESS_SIZE);
	return data;
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT u8_t * eapol_RSNA_key_header_c::get_key_reserved() const
{
	u8_t * const data = get_header_offset(m_offset_key_reserved, EAPOL_RSNA_KEY_RESERVED_SIZE);
	return data;
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT u8_t * eapol_RSNA_key_header_c::get_key_MIC() const
{
	u8_t * const data = get_header_offset(m_offset_key_MIC, EAPOL_RSNA_KEY_MIC_SIZE);
	return data;
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT u16_t eapol_RSNA_key_header_c::get_key_data_length() const
{
	const u8_t * const data = get_header_offset(m_offset_key_data_length, EAPOL_RSNA_KEY_DATA_LENGTH_SIZE);
	if (data != 0)
	{
		return eap_read_u16_t_network_order(data, EAPOL_RSNA_KEY_DATA_LENGTH_SIZE);
	}
	else
	{
		return 0ul;
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT u8_t * eapol_RSNA_key_header_c::get_key_data(const u32_t key_length) const
{
	u8_t * const data = get_header_offset(
		m_offset_key_data,
		key_length);

	return data; // Data begins after the header.
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT u8_t * eapol_RSNA_key_header_c::get_key_data_offset(const u32_t offset, const u32_t key_length) const
{
	u8_t * const data = get_header_offset(
		m_offset_key_data + offset,
		key_length);

	return data; // Data begins after the header.
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT u16_t eapol_RSNA_key_header_c::get_header_length()
{
	return m_offset_key_data;
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::set_eapol_protocol_version(const eapol_protocol_version_e version)
{
	u8_t * const data = get_header_offset(m_offset_eapol_version, sizeof(u8_t));
	if (data != 0)
	{
		*data = static_cast<u8_t>(version);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::set_eapol_packet_type(const eapol_packet_type_e type)
{
	u8_t * const data = get_header_offset(m_offset_eapol_type, sizeof(u8_t));
	if (data != 0)
	{
		*data = static_cast<u8_t>(type);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::set_eapol_packet_body_length(const u32_t eapol_length)
{
	if (eapol_length - eapol_header_base_c::get_header_length() > eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_MAXIMUM_SIZE)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_long_message);
	}

	u8_t * const data = get_header_offset(m_offset_eapol_packet_body_length, sizeof(u16_t));
	if (data != 0)
	{
		const u16_t eapol_length_u16_t = static_cast<u16_t>(eapol_length);
		return eap_write_u16_t_network_order(data, sizeof(u16_t), eapol_length_u16_t);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::set_key_descriptor_type(const eapol_key_descriptor_type_e eapol_key_descriptor_type)
{
	u8_t * const data = get_header_offset(m_offset_key_descriptor_type, sizeof(u8_t));
	if (data != 0)
	{
		*data = static_cast<u8_t>(eapol_key_descriptor_type);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT u16_t eapol_RSNA_key_header_c::set_bits_on(
	u16_t key_information,
	const u16_t set_bits,
	const u32_t mask,
	const u32_t shift)
{
	key_information =
		static_cast<u16_t>((key_information & ~mask)
		| ((set_bits << shift) & mask));

	return key_information;
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::set_key_information_key_descriptor_version(const u8_t version)
{
	u16_t key_information = get_key_information();

	key_information = set_bits_on(
		key_information,
		static_cast<u16_t>(version),
		m_key_information_mask_key_descriptor_version,
		m_key_information_mask_key_descriptor_version_shift);

	return set_key_information(key_information);
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::set_key_information_key_type(const bool key_type_bit_on_when_true)
{
	u16_t key_information = get_key_information();

	u16_t key_type_bit = 0;
	if (key_type_bit_on_when_true == true)
	{
		key_type_bit = 1;
	}

	key_information = set_bits_on(
		key_information,
		key_type_bit,
		m_key_information_mask_key_type,
		m_key_information_mask_key_type_shift);

	return set_key_information(key_information);
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::set_key_information_key_index(const u8_t key_index)
{
	EAP_ASSERT(m_is_RSNA_when_true == false || m_is_WPXM_when_true == true);

	u16_t key_information = get_key_information();

	key_information = set_bits_on(
		key_information,
		static_cast<u16_t>(key_index),
		m_key_information_mask_key_index_WPA,
		m_key_information_mask_key_index_shift_WPA);

	return set_key_information(key_information);
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::set_key_information_install(const bool install_bit_on_when_true)
{
	u16_t key_information = get_key_information();

	u16_t install_bit = 0;
	if (install_bit_on_when_true == true)
	{
		install_bit = 1;
	}

	key_information = set_bits_on(
		key_information,
		install_bit,
		m_key_information_mask_install,
		m_key_information_mask_install_shift);

	return set_key_information(key_information);
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::set_key_information_key_ack(const bool key_ack_bit_on_when_true)
{
	u16_t key_information = get_key_information();

	u16_t key_ack_bit = 0;
	if (key_ack_bit_on_when_true == true)
	{
		key_ack_bit = 1;
	}

	key_information = set_bits_on(
		key_information,
		key_ack_bit,
		m_key_information_mask_key_ack,
		m_key_information_mask_key_ack_shift);

	return set_key_information(key_information);
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::set_key_information_key_MIC(const bool key_MIC_bit_on_when_true)
{
	u16_t key_information = get_key_information();

	u16_t key_MIC_bit = 0;
	if (key_MIC_bit_on_when_true == true)
	{
		key_MIC_bit = 1;
	}

	key_information = set_bits_on(
		key_information,
		key_MIC_bit,
		m_key_information_mask_key_MIC,
		m_key_information_mask_key_MIC_shift);

	return set_key_information(key_information);
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::set_key_information_secure(const bool secure_bit_on_when_true)
{
	u16_t key_information = get_key_information();

	u16_t secure_bit = 0;
	if (secure_bit_on_when_true == true)
	{
		secure_bit = 1;
	}

	key_information = set_bits_on(
		key_information,
		secure_bit,
		m_key_information_mask_secure,
		m_key_information_mask_secure_shift);

	return set_key_information(key_information);
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::set_key_information_error(const bool error_bit_on_when_true)
{
	u16_t key_information = get_key_information();

	u16_t error_bit = 0;
	if (error_bit_on_when_true == true)
	{
		error_bit = 1;
	}

	key_information = set_bits_on(
		key_information,
		error_bit,
		m_key_information_mask_error,
		m_key_information_mask_error_shift);

	return set_key_information(key_information);
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::set_key_information_request(const bool request_bit_is_on_when_true)
{
	u16_t key_information = get_key_information();

	u16_t request_bit = 0;
	if (request_bit_is_on_when_true == true)
	{
		request_bit = 1;
	}

	key_information = set_bits_on(
		key_information,
		request_bit,
		m_key_information_mask_request,
		m_key_information_mask_request_shift);

	return set_key_information(key_information);
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::set_key_information_encrypted_key_data(const bool encrypted_key_data_bit_is_on_when_true)
{
	EAP_ASSERT(m_is_RSNA_when_true == true || m_is_WPXM_when_true == true);

	u16_t key_information = get_key_information();

	u16_t encrypted_key_data_bit = 0;
	if (encrypted_key_data_bit_is_on_when_true == true)
	{
		encrypted_key_data_bit = 1;
	}

	key_information = set_bits_on(
		key_information,
		encrypted_key_data_bit,
		m_key_information_mask_encrypted_key_data_RSNA,
		m_key_information_mask_encrypted_key_data_shift_RSNA);

	return set_key_information(key_information);
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::set_key_length(const u16_t length)
{
	u8_t * const data = get_header_offset(m_offset_key_length, sizeof(u16_t));
	if (data != 0)
	{
		return eap_write_u16_t_network_order(data, sizeof(u16_t), length);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}	

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::set_key_replay_counter(const u64_t reply_counter)
{
	u8_t * const data = get_header_offset(m_offset_key_replay_counter, EAPOL_RSNA_KEY_REPLY_COUNTER_SIZE);
	if (data != 0)
	{
		return eap_write_u64_t_network_order(data, EAPOL_RSNA_KEY_REPLY_COUNTER_SIZE, reply_counter);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::set_key_data_length(const u16_t key_data_length)
{
	u8_t * const data = get_header_offset(m_offset_key_data_length, EAPOL_RSNA_KEY_DATA_LENGTH_SIZE);
	if (data != 0)
	{
		return eap_write_u16_t_network_order(data, EAPOL_RSNA_KEY_DATA_LENGTH_SIZE, key_data_length);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::zero_EAPOL_header_and_Key_descriptor(
	abs_eap_am_tools_c * const tools
	)
{
	u8_t * const data = get_header_offset(0ul, get_header_length());
	if (data != 0)
	{
		tools->memset(data, 0, get_header_length());
		return EAP_STATUS_RETURN(tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::zero_key_MIC(
	abs_eap_am_tools_c * const tools
	)
{
	u8_t * const data = get_key_MIC();
	if (data != 0)
	{
		tools->memset(data, 0, EAPOL_RSNA_KEY_MIC_SIZE);
		return EAP_STATUS_RETURN(tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::zero_key_NONCE(
	abs_eap_am_tools_c * const tools
	)
{
	u8_t * const data = get_key_NONCE();
	if (data != 0)
	{
		tools->memset(data, 0, EAPOL_RSNA_KEY_NONCE_SIZE);
		return EAP_STATUS_RETURN(tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::zero_EAPOL_key_IV(
	abs_eap_am_tools_c * const tools
	)
{
	u8_t * const data = get_EAPOL_key_IV();
	if (data != 0)
	{
		tools->memset(data, 0, EAPOL_RSNA_EAPOL_KEY_IV_SIZE);
		return EAP_STATUS_RETURN(tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::zero_key_RSC(
	abs_eap_am_tools_c * const tools
	)
{
	u8_t * const data = get_key_RSC();
	if (data != 0)
	{
		tools->memset(data, 0, EAPOL_RSNA_KEY_RSC_SIZE);
		return EAP_STATUS_RETURN(tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::zero_key_STA_MAC_address(
	abs_eap_am_tools_c * const tools
	)
{
	u8_t * const data = get_key_STA_MAC_address();
	if (data != 0)
	{
		tools->memset(data, 0, EAPOL_RSNA_KEY_STA_MAC_ADDRESS_SIZE);
		return EAP_STATUS_RETURN(tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::zero_key_reserved(
	abs_eap_am_tools_c * const tools
	)
{
	u8_t * const data = get_key_reserved();
	if (data != 0)
	{
		tools->memset(data, 0, EAPOL_RSNA_KEY_RESERVED_SIZE);
		return EAP_STATUS_RETURN(tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(tools, eap_status_allocation_error);
	}
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::check_header() const
{
	if (get_eapol_protocol_version() == eapol_protocol_version_none)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eapol_version);
	}
	else if (get_eapol_packet_type() > eapol_packet_type_enc_asf_alert)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eapol_type);
	}
	else if (get_key_information_key_descriptor_version() != m_key_descriptor_version_1
		&& get_key_information_key_descriptor_version() != m_key_descriptor_version_2)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_no_matching_protocol_version);
	}
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//------------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_RSNA_key_header_c::reset_header(
	const u8_t key_index,
	const eapol_key_authentication_type_e authentication_type,
	const eapol_RSNA_cipher_e eapol_pairwise_cipher,
	const u64_t key_reply_counter,
	const bool key_type_bit_on_when_true,
	const bool install_bit_on_when_true,
	const bool key_ack_bit_on_when_true,
	const bool key_MIC_bit_on_when_true,
	const bool secure_bit_on_when_true,
	const bool error_bit_on_when_true,
	const bool requst_bit_on_when_true,
	const bool STAKey_bit_on_when_true,
	const bool encrypted_key_data_bit_on_when_true,
	const eapol_protocol_version_e used_rsna_eapol_protocol_version,
	const eapol_key_descriptor_type_e received_key_descriptor_type)
{
	EAP_UNREFERENCED_PARAMETER(encrypted_key_data_bit_on_when_true);
	EAP_UNREFERENCED_PARAMETER(STAKey_bit_on_when_true);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: eapol_RSNA_key_header_c::reset_header()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_RSNA_key_header_c::reset_header()");


	eap_status_e status = zero_EAPOL_header_and_Key_descriptor(m_am_tools);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eapol_protocol_version_e eapol_version(eapol_protocol_version_1);
	eapol_key_descriptor_type_e eapol_key_descriptor_type(eapol_key_descriptor_type_WPA);

	if (authentication_type == eapol_key_authentication_type_RSNA_EAP
		|| authentication_type == eapol_key_authentication_type_RSNA_PSK)
	{
		eapol_version = used_rsna_eapol_protocol_version;
		eapol_key_descriptor_type = eapol_key_descriptor_type_RSNA;
	}
	else if (authentication_type == eapol_key_authentication_type_WPXM)
	{
		eapol_version = used_rsna_eapol_protocol_version;

		if (received_key_descriptor_type != eapol_key_descriptor_type_none)
		{
			eapol_key_descriptor_type = received_key_descriptor_type;
		}
	}

	eapol_key_state_string_c debug_string;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: eapol_RSNA_key_header_c::reset_header(): eapol_key_descriptor_type = %s = 0x%02x\n"),
		debug_string.get_eapol_key_descriptor_type_string(eapol_key_descriptor_type),
		eapol_key_descriptor_type));

	status = set_eapol_protocol_version(eapol_version);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	status = set_eapol_packet_type(eapol_packet_type_key);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_key_descriptor_type(eapol_key_descriptor_type);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (eapol_pairwise_cipher == eapol_RSNA_cipher_TKIP
		|| eapol_pairwise_cipher == eapol_RSNA_cipher_WEP_40
		|| eapol_pairwise_cipher == eapol_RSNA_cipher_WEP_104)
	{
		status = set_key_information_key_descriptor_version(m_key_descriptor_version_1);
	}
	else if (eapol_pairwise_cipher == eapol_RSNA_cipher_CCMP)
	{
		status = set_key_information_key_descriptor_version(m_key_descriptor_version_2);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_no_matching_protocol_version);
	}

	status = set_key_information_key_type(key_type_bit_on_when_true);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_key_information_install(install_bit_on_when_true);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_key_information_key_ack(key_ack_bit_on_when_true);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_key_information_key_MIC(key_MIC_bit_on_when_true);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_key_information_secure(secure_bit_on_when_true);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_key_information_error(error_bit_on_when_true);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_key_information_request(requst_bit_on_when_true);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (m_is_RSNA_when_true == true || m_is_WPXM_when_true == true)
	{
		// RSNA
		status = set_key_information_encrypted_key_data(
			encrypted_key_data_bit_on_when_true);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		// WPA
		status = set_key_information_key_index(key_index);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	
	status = set_key_replay_counter(key_reply_counter);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

// 
//------------------------------------------------------



// End.
