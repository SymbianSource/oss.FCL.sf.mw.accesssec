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

#ifndef _MSCHAPV2_HEADER_H_
#define _MSCHAPV2_HEADER_H_

#include "eap_am_tools.h"

#include "eap_tools.h"
#include "eap_general_header_base.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TYPE_MSCHAPV2_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H 
	#define EAP_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_HEADER_H 
#elif defined(EAP_EXPORT_EAP_TYPE_MSCHAPV2_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_HEADER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_HEADER_H 
#endif
// End: added by script change_export_macros.sh.


enum eap_mschapv2_version
{
	MSCHAPV2_ILLEGAL_VERSION = 0x0000,
	MSCHAPV2_VERSION_1       = 0x0001,
	MSCHAPV2_LAST_VERSION    = 0x0001  ///< Keep this same as the last acceptable version.
};

enum mschapv2_opcode_e
{
	mschapv2_opcode_challenge         =  1,
	mschapv2_opcode_response          =  2,
	mschapv2_opcode_success           =  3,
	mschapv2_opcode_failure           =  4,
	mschapv2_opcode_change_password   =  7,
	mschapv2_opcode_unknown           =  255 // Internal error
};

/// This class defines header of MS-CHAP-v2 EAP-type.
/**
 * Here is a figure of header of MS-CHAP-v2 EAP-type.
 * Data is m_eap_length - sizeof(mschapv2_header_c) data octets that follows mschapv2_header_c.
 * @code
 *
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Code      |   Identifier  |            Length             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Type=29   |   OpCode      |  MS-CHAPv2-ID |  MS-Length...
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   MS-Length   |     Data...
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * @endcode
 */
class EAP_CLASS_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H mschapv2_header_c
: public eap_general_header_base_c
{
private:

	abs_eap_am_tools_c * const m_am_tools;

	u32_t m_length;

protected:

	enum offsets
	{
		m_opcode_offset = 0ul,
		m_mschapv2_id_offset = m_opcode_offset + sizeof(u8_t),
		m_ms_length_offset = m_mschapv2_id_offset + sizeof(u8_t),
		m_data_offset = m_ms_length_offset + sizeof(u16_t)
	};

public:

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H virtual ~mschapv2_header_c();

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H mschapv2_header_c(
		abs_eap_am_tools_c * const tools,
		void * const header_buffer,
		const u32_t header_buffer_length);

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H mschapv2_opcode_e get_opcode() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H void set_opcode(const mschapv2_opcode_e p_opcode);

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H u8_t get_mschapv2_id() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H void set_mschapv2_id(u8_t p_id);

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H u16_t get_ms_length() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H void set_ms_length(u16_t p_length);

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H u8_t * get_data() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H u32_t get_data_length() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H eap_status_e check_header() const;

}; // class mschapv2_header_c

//--------------------------------------------------

/// This class defines Challenge payload of MS-CHAP-v2.
/**
 * Here is a figure of Challenge payload of MS-CHAP-v2.
 * @code
 *
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Value Size   |   Challenge 16 octets                         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-         -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |               |     Name ...
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * @endcode
 */
class EAP_CLASS_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H mschapv2_challenge_c
: public eap_general_header_base_c
{
private:

	abs_eap_am_tools_c * const m_am_tools;

	u32_t m_length;

protected:

	enum offsets
	{
		m_value_size_offset = 0ul,
		m_challenge_offset = m_value_size_offset + sizeof(u8_t),
		m_name_offset = m_challenge_offset + 16 * sizeof(u8_t),
	};

public:

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H virtual ~mschapv2_challenge_c();

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H mschapv2_challenge_c(
		abs_eap_am_tools_c * const tools,
		void * const header_buffer,
		const u32_t header_buffer_length);

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H static u32_t get_header_minimum_size();

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H eap_status_e check_header() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H void set_value_size();

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H const u8_t * get_challenge() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H void set_challenge(const u8_t * const p_challenge);

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H const u8_t * get_name() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H u32_t get_name_length() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H void set_name(const u8_t * const p_name);
}; // class mschapv2_challenge_c

//--------------------------------------------------

/// This class defines Change Password payload of MS-CHAP-v2.
/**
 * Here is a figure of Change Password payload of MS-CHAP-v2.
 * @code
 *
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Encrypted Block 516 octets                                   |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-                                                 -+-+-+-+
 *  .                                                               .
 *  .                                                               .
 *  .                                                               .
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Encrypted Hash 16 octets                                    |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Peer Challenge 16 octets                                    |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    Reserved 8 octets                                          |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    NT Response 24 octets                                      |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    Flags      |
 *  +-+-+-+-+-+-+-+-+
 * @endcode
 */
class EAP_CLASS_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H mschapv2_change_password_c
: public eap_general_header_base_c
{
private:

	abs_eap_am_tools_c * const m_am_tools;

	u32_t m_length;

protected:

	enum offsets
	{
		m_encrypted_pw_block_offset = 0ul,
		m_encrypted_hash_offset = m_encrypted_pw_block_offset + 516 * sizeof(u8_t),
		m_peer_challenge_offset = m_encrypted_hash_offset + 16 * sizeof(u8_t),
		m_reserved_offset = m_peer_challenge_offset + 16 * sizeof(u8_t),
		m_nt_response_offset = m_reserved_offset + 8 * sizeof(u8_t),
		m_flags_offset = m_nt_response_offset + 24 * sizeof(u8_t),
	};

public:

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H virtual ~mschapv2_change_password_c();

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H mschapv2_change_password_c(
		abs_eap_am_tools_c * const tools,
		void * const header_buffer,
		const u32_t header_buffer_length);

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H static u32_t get_header_minimum_size();

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H eap_status_e check_header() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H const u8_t * get_encrypted_pw_block() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H void set_encrypted_pw_block(const u8_t * const p_encrypted_pw_block);

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H const u8_t * get_encrypted_hash() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H void set_encrypted_hash(const u8_t * const p_encrypted_hash);

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H const u8_t * get_peer_challenge() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H void set_peer_challenge(const u8_t * const p_peer_challenge);

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H const u8_t * get_nt_response() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H void set_nt_response(const u8_t * const p_nt_response);

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H eap_status_e set_constants();
}; // class mschapv2_change_password_c

//--------------------------------------------------

/// This class defines Response payload of MS-CHAP-v2.
/**
 * Here is a figure of Response payload of MS-CHAP-v2.
 * @code
 *
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Value Size   |   Peer Challenge 16 octets                    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-         -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |               |     Reserved 8 octets                         |
 *  +-+-+-+-+-+-+-+-+-+-+-                                   -+-+-+-+
 *  |                                                               |
 *  +-+-         -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |               |     NT Response 24 octets                     |
 *  +-+-+-+-+-+-+-+-+-+-+-                                   -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-+-+-                                                 -+-+-+-+
 *  |                                                               |
 *  +-+-         -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |               |    Flags      |   Name ...                   
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 * @endcode
 */
class EAP_CLASS_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H mschapv2_response_c
: public eap_general_header_base_c
{
private:

	abs_eap_am_tools_c * const m_am_tools;

	u32_t m_length;

protected:

	enum offsets
	{
		m_value_size_offset = 0ul,
		m_peer_challenge_offset = m_value_size_offset + sizeof(u8_t),
		m_reserved_offset = m_peer_challenge_offset + 16 * sizeof(u8_t),
		m_nt_response_offset = m_reserved_offset + 8 * sizeof(u8_t),
		m_flags_offset = m_nt_response_offset + 24 * sizeof(u8_t),
		m_name_offset = m_flags_offset + sizeof(u8_t)
	};

public:

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H virtual ~mschapv2_response_c();

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H mschapv2_response_c(
		abs_eap_am_tools_c * const tools,
		void * const header_buffer,
		const u32_t header_buffer_length);

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H static u32_t get_header_minimum_size();

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H eap_status_e check_header() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H const u8_t * get_peer_challenge() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H void set_peer_challenge(const u8_t * const p_challenge);

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H const u8_t * get_nt_response() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H void set_nt_response(const u8_t * const p_challenge);

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H const u8_t * get_name() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H u32_t get_name_length() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H void set_name(const u8_t * const p_name);

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_HEADER_H eap_status_e set_constants();
}; // class mschapv2_response_c

//--------------------------------------------------

#endif //_MSCHAPV2_HEADER_H_

// End of File
