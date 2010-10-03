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

#if !defined(_AKA_HEADER_H_)
#define _AKA_HEADER_H_

#include "eap_tools.h"
#include "eap_header.h"
#include "eap_header_string.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TYPE_AKA_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_AKA_HEADER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H 
	#define EAP_FUNC_EXPORT_EAP_TYPE_AKA_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_AKA_HEADER_H 
#elif defined(EAP_EXPORT_EAP_TYPE_AKA_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_AKA_HEADER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_AKA_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_AKA_HEADER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_AKA_HEADER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_AKA_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_AKA_HEADER_H 
#endif
// End: added by script change_export_macros.sh.


/** @file */

const u32_t AKA_FIRST_SEQUENCE = 1u;
const u32_t AKA_PAYLOAD_LENGTH_ALIGN = 4u;
const u32_t EAP_AKA_PAYLOAD_ZERO_DATA_LENGTH = 0u;
const u8_t AKA_NAI_AT_BYTE = '@';


enum aka_subtype_e
{
	aka_subtype_NONE                    =  0,
	aka_subtype_Challenge               =  1,
	aka_subtype_Authentication_Reject   =  2,
	aka_subtype_Synchronization_Failure =  4,
	aka_subtype_Identity                =  5,
	aka_subtype_Notification            = 12,
	aka_subtype_Re_authentication       = 13,
	aka_subtype_Client_Error            = 14,
};

enum aka_payload_AT_type_e
{
	aka_payload_NONE                      =   0,

	aka_payload_AT_RAND                   =   1,
	aka_payload_AT_AUTN                   =   2,
	aka_payload_AT_RES                    =   3,
	aka_payload_AT_AUTS                   =   4,
	aka_payload_AT_PADDING                =   6,
	aka_payload_AT_PERMANENT_ID_REQ       =  10,
	aka_payload_AT_MAC                    =  11,
	aka_payload_AT_NOTIFICATION           =  12,
	aka_payload_AT_ANY_ID_REQ             =  13,
	aka_payload_AT_IDENTITY               =  14,
	aka_payload_AT_FULLAUTH_ID_REQ        =  17,
	aka_payload_AT_COUNTER                =  19,
	aka_payload_AT_COUNTER_TOO_SMALL      =  20,
	aka_payload_AT_NONCE_S                =  21,
	aka_payload_AT_CLIENT_ERROR_CODE      =  22,

	aka_payload_AT_IV                     = 129,
	aka_payload_AT_ENCR_DATA              = 130,
	aka_payload_AT_NEXT_PSEUDONYM         = 132,
	aka_payload_AT_NEXT_REAUTH_ID         = 133,
	aka_payload_AT_CHECKCODE              = 134,
	aka_payload_AT_RESULT_IND             = 135,
};

enum eap_aka_client_error_code_e
{
	eap_aka_client_error_code_unable_to_process_packet          = 0,
	eap_aka_client_error_code_unsupported_version               = 1,
	eap_aka_client_error_code_insufficient_number_of_challenges = 2,
	eap_aka_client_error_code_rands_are_not_fresh               = 3,
	eap_aka_client_error_code_maximum_value                     = eap_aka_client_error_code_rands_are_not_fresh,
	eap_aka_client_error_code_none                              = 0xff,
};

//----------------------------------------------------------------------------


/// This class defines the attribute payload header of AKA EAP-type.
/**
 * Here is a figure of attribute payload header of AKA EAP-type.
 * Attribute payload data is (m_length*4)-sizeof(aka_payload_AT_header_c) data octets that follows aka_payload_AT_header_c.
 * @code
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Type         |    Length     |    Value ...                  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Attribute payload data ...
 *  +-+-+-+-+-+-+-+-+-+-+-
 * @endcode
 *
 */
class EAP_CLASS_VISIBILITY_EAP_TYPE_AKA_HEADER_H aka_payload_AT_header_c
: public eap_general_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	enum offsets
	{
		m_type_offset = 0ul,
		m_length_offset = m_type_offset+sizeof(u8_t),
		m_reserved_offset = m_length_offset+sizeof(u8_t),
		m_data_offset = m_reserved_offset+sizeof(u16_t),
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H virtual ~aka_payload_AT_header_c();

	// 
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H aka_payload_AT_header_c(
		abs_eap_am_tools_c * const tools,
		void * const header_buffer,
		const u32_t header_buffer_length);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H aka_payload_AT_type_e get_current_payload() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H u16_t get_payload_length() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H u16_t get_reserved() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H u8_t * get_reserved_pointer(const u32_t contignuous_bytes) const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H u32_t get_data_length() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H static u16_t get_header_length();

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H static u16_t get_max_payload_data_length();

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H u8_t * get_data(const u32_t contignuous_bytes) const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H u8_t * get_data_offset(const u32_t offset, const u32_t contignuous_bytes) const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H u8_t * get_next_header() const;

	// Mostly this is zero.
	// With some attributes this is used for special purposes.
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H void set_reserved(const u16_t reserved);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H void set_current_payload(const aka_payload_AT_type_e p_current_payload);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H void set_data_length(const u16_t p_data_length);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H void reset_header(const u16_t data_length);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H static eap_const_string get_payload_AT_string(const aka_payload_AT_type_e payload_type);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H eap_const_string get_payload_AT_string() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H eap_status_e check_header() const;

	// 
	//--------------------------------------------------
}; // class aka_payload_AT_header_c



//----------------------------------------------------------------------------


/// This class defines header of AKA EAP-type.
/**
 * Here is a figure of header of AKA EAP-type.
 * Subtype-Data is m_length-sizeof(aka_header_c) data octets that follows aka_header_c.
 * @code
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Code      |  Identifier   |            Length             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Type=18      |    Subtype    |         Reserved = 0          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Subtype-Data...
 *  +-+-+-+-+-+-+-+-+-+-+-
 * @endcode
 *
 */
class EAP_CLASS_VISIBILITY_EAP_TYPE_AKA_HEADER_H aka_header_c
: public eap_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	enum delta_offsets
	{
		m_subtype_delta_offset = 0ul, // This is offset from the end of the type field. NOTE type field could be extented 8 bytes in length.
		m_reserved_delta_offset = m_subtype_delta_offset+sizeof(u8_t),
		m_data_delta_offset = m_reserved_delta_offset+sizeof(u16_t),
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H virtual ~aka_header_c();

	// 
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H aka_header_c(
		abs_eap_am_tools_c * const tools,
		u8_t * const header_buffer,
		const u32_t header_buffer_length);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H aka_subtype_e get_subtype() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H u16_t get_data_length() const;

	/// This returns the length of EAP-header, EAP-type, subtype and reserved fields.
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H u32_t get_header_length() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H u32_t get_sub_type_offset() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H u8_t * get_data_offset(const u32_t offset, const u32_t contignuous_bytes) const;


	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H u8_t * get_data(const u32_t contignuous_bytes) const;


	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H u16_t get_reserved() const;


	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H eap_status_e check_header() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H eap_const_string get_subtype_string() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H eap_const_string get_code_string() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H eap_const_string get_eap_type_string() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H void set_reserved(const u16_t reserved);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H void set_subtype(const aka_subtype_e p_subtype);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H void set_data_length(
		const u32_t p_data_length,
		const bool expanded_type_when_true);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_HEADER_H void reset_header(
		const u32_t buffer_length,
		const bool expanded_type_when_true);

	// 
	//--------------------------------------------------
}; // class aka_header_c

//--------------------------------------------------

#endif //#if !defined(_AKA_HEADER_H_)



// End.
