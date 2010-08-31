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
	#define EAP_FILE_NUMBER_ENUM 97 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_am_memory.h"
#include "eap_type_mschapv2_header.h"
#include "eap_type_mschapv2_types.h"


//--------------------------------------------------------------
//--------------------------------------------------------------
//--------------------------------------------------------------


EAP_FUNC_EXPORT mschapv2_header_c::~mschapv2_header_c()
{
}

EAP_FUNC_EXPORT mschapv2_header_c::mschapv2_header_c(
	abs_eap_am_tools_c * const tools,
	void * const header_buffer,
	const u32_t header_buffer_length)
	: eap_general_header_base_c(tools, header_buffer, header_buffer_length)
	, m_am_tools(tools)
	, m_length(header_buffer_length)
{
}

EAP_FUNC_EXPORT mschapv2_opcode_e mschapv2_header_c::get_opcode() const
{
	const u8_t * const opcode_data = get_header_offset(m_opcode_offset, sizeof(u8_t));
	if (opcode_data)
	{
		return static_cast<mschapv2_opcode_e>(*opcode_data);
	}
	return mschapv2_opcode_unknown; // Packet will be dropped silently
}

EAP_FUNC_EXPORT void mschapv2_header_c::set_opcode(
	const mschapv2_opcode_e p_opcode)
{
	u8_t * const opcode_data = get_header_offset(m_opcode_offset, sizeof(u8_t));
	EAP_ASSERT(opcode_data != 0);
	*opcode_data = static_cast<u8_t>(p_opcode);
}

EAP_FUNC_EXPORT u8_t mschapv2_header_c::get_mschapv2_id() const
{
	const u8_t * const mschapv2_id_data = get_header_offset(m_mschapv2_id_offset, sizeof(u8_t));
	return *mschapv2_id_data;
}

EAP_FUNC_EXPORT void mschapv2_header_c::set_mschapv2_id(u8_t p_id)
{
	u8_t * const mschapv2_id_data = get_header_offset(m_mschapv2_id_offset, sizeof(u8_t));
	EAP_ASSERT(mschapv2_id_data != 0);
	*mschapv2_id_data = p_id;
}

EAP_FUNC_EXPORT u16_t mschapv2_header_c::get_ms_length() const
{
	const u8_t * const length_data = get_header_offset(m_ms_length_offset, sizeof(u16_t));
	if (length_data != 0)
	{
		return static_cast<u16_t>((static_cast<u16_t>(length_data[0]) << 8 | static_cast<u16_t>(length_data[1])));
	}
	else
	{
		return 0ul;
	}
}

EAP_FUNC_EXPORT void mschapv2_header_c::set_ms_length(u16_t p_length)
{
	u8_t * const length_data = get_header_offset(m_ms_length_offset, sizeof(u16_t));
	EAP_ASSERT(length_data != 0);
	length_data[0] = static_cast<u8_t>(((p_length & 0xff00) >> 8));
	length_data[1] = static_cast<u8_t>((p_length & 0x00ff));
}

EAP_FUNC_EXPORT u8_t * mschapv2_header_c::get_data() const
{
	u8_t * const data_begin = get_header_offset(m_data_offset, 0);
	return data_begin;
}

EAP_FUNC_EXPORT u32_t mschapv2_header_c::get_data_length() const
{
	return m_length - m_data_offset;
}

EAP_FUNC_EXPORT eap_status_e mschapv2_header_c::check_header() const
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}


//--------------------------------------------------------------
//--------------------------------------------------------------
//--------------------------------------------------------------


EAP_FUNC_EXPORT mschapv2_challenge_c::~mschapv2_challenge_c()
{
}

// Challenge
EAP_FUNC_EXPORT mschapv2_challenge_c::mschapv2_challenge_c(
	abs_eap_am_tools_c * const tools,
	void * const buffer,
	const u32_t buffer_length)
	: eap_general_header_base_c(tools, buffer, buffer_length)
	, m_am_tools(tools)
	, m_length(buffer_length)
{
}

EAP_FUNC_EXPORT u32_t mschapv2_challenge_c::get_header_minimum_size()
{
	return m_name_offset;
}

EAP_FUNC_EXPORT eap_status_e mschapv2_challenge_c::check_header() const
{
	const u8_t * const value_size = get_header_offset(m_value_size_offset, sizeof(u8_t));
	if (*value_size == 0x10 && m_length >= 0x11)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
}

EAP_FUNC_EXPORT void mschapv2_challenge_c::set_value_size()
{
	u8_t * const value_size = get_header_offset(m_value_size_offset, sizeof(u8_t));
	EAP_ASSERT(value_size != 0);
	*value_size = static_cast<u8_t>(0x10);
}

EAP_FUNC_EXPORT const u8_t * mschapv2_challenge_c::get_challenge() const
{
	const u8_t * const challenge = get_header_offset(m_challenge_offset, sizeof(u8_t));
	return challenge;
}

EAP_FUNC_EXPORT void mschapv2_challenge_c::set_challenge(const u8_t * const p_challenge)
{
	u8_t * const challenge = get_header_offset(m_challenge_offset, 16);
	if (challenge != 0)
	{
		m_am_tools->memmove(challenge, p_challenge, 16);
	}
}

EAP_FUNC_EXPORT const u8_t * mschapv2_challenge_c::get_name() const
{
	const u8_t * const name = get_header_offset(m_name_offset, sizeof(u8_t));
	return name;
}

EAP_FUNC_EXPORT u32_t mschapv2_challenge_c::get_name_length() const
{
	return m_length - m_name_offset;
}

EAP_FUNC_EXPORT void mschapv2_challenge_c::set_name(const u8_t * const p_name)
{
	u8_t * const name = get_header_offset(m_name_offset, sizeof(u8_t));
	if (name != 0)
	{
		m_am_tools->memmove(name, p_name, m_length - m_name_offset);
	}
}


//--------------------------------------------------------------
//--------------------------------------------------------------
//--------------------------------------------------------------


// Change password

EAP_FUNC_EXPORT mschapv2_change_password_c::~mschapv2_change_password_c()
{
}

EAP_FUNC_EXPORT mschapv2_change_password_c::mschapv2_change_password_c(
	abs_eap_am_tools_c * const tools,
	void * const buffer,
	const u32_t buffer_length)
	: eap_general_header_base_c(tools, buffer, buffer_length)
	, m_am_tools(tools)
	, m_length(buffer_length)
{
}

EAP_FUNC_EXPORT u32_t mschapv2_change_password_c::get_header_minimum_size()
{
	return m_flags_offset + EAP_MSCHAPV2_CHANGE_PASSWORD_FLAGS_SIZE;
}

EAP_FUNC_EXPORT eap_status_e mschapv2_change_password_c::check_header() const
{
	const u8_t * const reserved = get_header_offset(m_reserved_offset, 8);
	const u8_t * const flags = get_header_offset(m_flags_offset, 2);
	if (!reserved || !flags)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	u8_t zero[8];
	m_am_tools->memset(zero, 0, 8);

	if (m_length >= m_flags_offset + 2
		&& m_am_tools->memcmp(reserved, &zero, 8) == 0
		&& m_am_tools->memcmp(flags, &zero, 2) == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
}

EAP_FUNC_EXPORT const u8_t * mschapv2_change_password_c::get_encrypted_pw_block() const
{
	const u8_t * const encrypted_pw_block = get_header_offset(m_encrypted_pw_block_offset, 516);
	return encrypted_pw_block;
}

EAP_FUNC_EXPORT void mschapv2_change_password_c::set_encrypted_pw_block(const u8_t * const p_encrypted_pw_block)
{
	u8_t * const encrypted_pw_block = get_header_offset(m_encrypted_pw_block_offset, 516);
	if (encrypted_pw_block != 0)
	{
		m_am_tools->memmove(encrypted_pw_block, p_encrypted_pw_block, 516);
	}
}

EAP_FUNC_EXPORT const u8_t * mschapv2_change_password_c::get_encrypted_hash() const
{
	const u8_t * const encrypted_hash = get_header_offset(m_encrypted_hash_offset, 16);
	return encrypted_hash;
}

EAP_FUNC_EXPORT void mschapv2_change_password_c::set_encrypted_hash(const u8_t * const p_encrypted_hash)
{
	u8_t * const encrypted_hash = get_header_offset(m_encrypted_hash_offset, 16);
	if (encrypted_hash != 0)
	{
		m_am_tools->memmove(encrypted_hash, p_encrypted_hash, 16);
	}
}

EAP_FUNC_EXPORT const u8_t * mschapv2_change_password_c::get_peer_challenge() const
{
	const u8_t * const peer_challenge = get_header_offset(m_peer_challenge_offset, 16);
	return peer_challenge;
}

EAP_FUNC_EXPORT void mschapv2_change_password_c::set_peer_challenge(const u8_t * const p_peer_challenge)
{
	u8_t * const peer_challenge = get_header_offset(m_peer_challenge_offset, 16);
	if (peer_challenge != 0)
	{
		m_am_tools->memmove(peer_challenge, p_peer_challenge, 16);
	}
}

EAP_FUNC_EXPORT const u8_t * mschapv2_change_password_c::get_nt_response() const
{
	const u8_t * const nt_response = get_header_offset(m_nt_response_offset, 24);
	return nt_response;
}

EAP_FUNC_EXPORT void mschapv2_change_password_c::set_nt_response(const u8_t * const p_nt_response)
{
	u8_t * const nt_response = get_header_offset(m_nt_response_offset, 24);
	if (nt_response != 0)
	{
		m_am_tools->memmove(nt_response, p_nt_response, 24);
	}
}

EAP_FUNC_EXPORT eap_status_e mschapv2_change_password_c::set_constants()
{
	u8_t * const reserved = get_header_offset(m_reserved_offset, 8);
	if (reserved == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u8_t * const flags = get_header_offset(m_flags_offset, sizeof(u8_t));
	if (flags == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	m_am_tools->memset(reserved, 0, 8);
	m_am_tools->memset(flags, 0, 2);

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}


//--------------------------------------------------------------
//--------------------------------------------------------------
//--------------------------------------------------------------


// Challenge response packet
EAP_FUNC_EXPORT mschapv2_response_c::~mschapv2_response_c()
{
}

EAP_FUNC_EXPORT mschapv2_response_c::mschapv2_response_c(
	abs_eap_am_tools_c * const tools,
	void * const buffer,
	const u32_t buffer_length)
	: eap_general_header_base_c(tools, buffer, buffer_length)
	, m_am_tools(tools)
	, m_length(buffer_length)
{
}

EAP_FUNC_EXPORT u32_t mschapv2_response_c::get_header_minimum_size()
{
	return m_name_offset;
}

EAP_FUNC_EXPORT eap_status_e mschapv2_response_c::check_header() const
{
	const u8_t * const reserved = get_header_offset(m_reserved_offset, 8);
	const u8_t * const flags = get_header_offset(m_flags_offset, sizeof(u8_t));
	if (!reserved || !flags)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	u8_t zero[8];
	m_am_tools->memset(zero, 0, 8);

	if (m_length >= m_flags_offset + 1
		&& m_am_tools->memcmp(reserved, &zero, 8) == 0
		&& *flags == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
}

EAP_FUNC_EXPORT const u8_t * mschapv2_response_c::get_peer_challenge() const
{
	const u8_t * const peer_challenge = get_header_offset(m_peer_challenge_offset, sizeof(u8_t));
	return peer_challenge;
}

EAP_FUNC_EXPORT void mschapv2_response_c::set_peer_challenge(const u8_t * const p_peer_challenge)
{
	u8_t * const peer_challenge = get_header_offset(m_peer_challenge_offset, 16);
	if (peer_challenge != 0)
	{
		m_am_tools->memmove(peer_challenge, p_peer_challenge, 16);
	}
}

EAP_FUNC_EXPORT const u8_t * mschapv2_response_c::get_nt_response() const
{
	const u8_t * const nt_response = get_header_offset(m_nt_response_offset, 24);
	return nt_response;
}

EAP_FUNC_EXPORT void mschapv2_response_c::set_nt_response(const u8_t * const p_nt_response)
{
	u8_t * const nt_response = get_header_offset(m_nt_response_offset, 24);
	if (nt_response != 0)
	{
		m_am_tools->memmove(nt_response, p_nt_response, 24);
	}
}

EAP_FUNC_EXPORT const u8_t * mschapv2_response_c::get_name() const
{
	const u8_t * const name = get_header_offset(m_name_offset, sizeof(u8_t));
	return name;
}

EAP_FUNC_EXPORT u32_t mschapv2_response_c::get_name_length() const
{
	return m_length - m_name_offset;
}

EAP_FUNC_EXPORT void mschapv2_response_c::set_name(const u8_t * const p_name)
{
	u8_t * const name = get_header_offset(m_name_offset, sizeof(u8_t));
	if (name != 0)
	{
		m_am_tools->memmove(name, p_name, m_length - m_name_offset);
	}
}

EAP_FUNC_EXPORT eap_status_e mschapv2_response_c::set_constants()
{
	{
		u8_t * const value_size = get_header_offset(m_value_size_offset, 8);
		if (value_size == 0)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		m_am_tools->memset(value_size, 0x31, 1);
	}

	{
		u8_t * const reserved = get_header_offset(m_reserved_offset, 8);
		if (reserved == 0)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		m_am_tools->memset(reserved, 0, 8);
	}

	if (m_length > m_flags_offset)
	{
		u8_t * const flags = get_header_offset(m_flags_offset, sizeof(u8_t));
		if (flags == 0)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		m_am_tools->memset(flags, 0, 1);
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}


//--------------------------------------------------------------
//--------------------------------------------------------------
//--------------------------------------------------------------
// End of File
