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
* %version: 10.1.2 %
*/

#if !defined(_EAP_EXPANDED_TYPE_H_)
#define _EAP_EXPANDED_TYPE_H_


#include "eap_general_header_base.h"


/** @file */

//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------

/// Enumeration of the EAP-Code values.
enum eap_code_value_e
{
	eap_code_none     = 0, ///< This is internal value for no type case.
	eap_code_request  = 1, ///< This is EAP-Request.
	eap_code_response = 2, ///< This is EAP-Response.
	eap_code_success  = 3, ///< This is EAP-Success.
	eap_code_failure  = 4, ///< This is EAP-Failure.
};


#if defined(USE_EAP_EXPANDED_TYPES)
/// Enumeration of the IETF defined EAP-Type values.
enum eap_type_ietf_values_e
#else
/// This is the original enumeration of the EAP-Type values.
enum eap_type_value_e
#endif //#if defined(USE_EAP_EXPANDED_TYPES)
{
	eap_type_none               = 0,  ///< This is internal value for no type case.
	eap_type_identity           = 1,  ///< This is Identity.
	eap_type_notification       = 2,  ///< This is Notification.
	eap_type_nak                = 3,  ///< This is Nak.
	eap_type_md5_challenge      = 4,  ///< This is EAP-MD5 type.
	eap_type_one_time_password  = 5,  ///< This is One Time Password (OTP) type.
	eap_type_generic_token_card = 6,  ///< This is Generic Token Card (GTC) type.
	eap_type_tls                = 13, ///< This is Transport Layer Security (TLS) type.
	eap_type_leap               = 17, ///< This is LEAP type.
	eap_type_gsmsim             = 18, ///< This is SIM type.
	eap_type_ttls               = 21, ///< This is tunneled TLS.
	eap_type_aka                = 23, ///< This is AKA type.
	eap_type_peap               = 25, ///< This is PEAP type.
	eap_type_mschapv2			= 26, ///< This is MsChapv2 type.
	eap_type_securid            = 32, ///< This is SecurID type.
	eap_type_tlv_extensions     = 33, ///< This is type/length/value extension type for PEAP payloads.
#if defined(USE_FAST_EAP_TYPE)
	eap_type_fast               = 43, ///< This is EAP-FAST type.
#endif //#if defined(USE_FAST_EAP_TYPE)

	eap_type_ttls_plain_pap     = 98, // This is for TTLS/PAP.

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	eap_type_plain_mschapv2     = 99, ///< This is used to indicate plain MSChapv2 inside TTLS tunnel.
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

	eap_type_saesim             = 252, ///< This is just a test EAP-type.
	eap_type_dummy_sim          = 253, ///< This is just a test EAP-type.

	eap_type_expanded_type      = 254, ///< This is Expanded Type.
	eap_type_experimental_type  = 255, ///< This is Experimental Type.
};


#if !defined(USE_EAP_EXPANDED_TYPES)
	typedef eap_type_value_e eap_type_ietf_values_e;
#endif //#if !defined(USE_EAP_EXPANDED_TYPES)



enum eap_type_vendor_id_e
{
	eap_type_vendor_id_ietf = 0,
	eap_type_vendor_id_broadcom = 0x0000113d,
	eap_type_vendor_id_WFA = 0x00372A,
	eap_type_vendor_id_hack = 0xFFFFFF, // This is for plain MCHAPv2 and TTLS
};

enum eap_type_vendor_type_e
{
	eap_type_vendor_type_secure_easy_setup = 10,
	eap_type_vendor_type_WFA_simple_config = 1,
	eap_type_vendor_type_ttls_plain_pap_hack = eap_type_ttls_plain_pap, // This is for TTLS/PAP.
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	eap_type_vendor_type_plain_MSCHAPv2_hack = eap_type_plain_mschapv2, // This is for plain MCHAPv2 and TTLS
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
};

//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------

class EAP_EXPORT eap_expanded_type_c
{

public:

	enum sizes
	{
		m_ietf_type_size = sizeof(u8_t),
		m_vendor_id_size = 3ul*sizeof(u8_t),
		m_vendor_type_size = sizeof(u32_t),
		m_eap_expanded_type_size = m_ietf_type_size+m_vendor_id_size+m_vendor_type_size,
	};

	EAP_FUNC_IMPORT ~eap_expanded_type_c();

	EAP_FUNC_IMPORT eap_expanded_type_c();

	EAP_FUNC_IMPORT eap_expanded_type_c(
		const eap_type_vendor_id_e vendor_id,
		const u32_t vendor_type);

	EAP_FUNC_IMPORT eap_expanded_type_c(
		const eap_type_ietf_values_e type);

	EAP_FUNC_IMPORT static bool is_expanded_type(const eap_type_ietf_values_e eap_type);

#if defined(USE_EAP_EXPANDED_TYPES)
	EAP_FUNC_IMPORT static bool is_ietf_type(const eap_expanded_type_c eap_type);
#else
	EAP_FUNC_IMPORT static bool is_ietf_type(const eap_type_ietf_values_e eap_type);
#endif //#if defined(USE_EAP_EXPANDED_TYPES)

	EAP_FUNC_IMPORT eap_status_e get_type_data(
		abs_eap_am_tools_c * const am_tools,
		eap_type_ietf_values_e * const type);

	EAP_FUNC_IMPORT eap_status_e get_type_data(
		abs_eap_am_tools_c * const am_tools,
		eap_expanded_type_c * const type);

	EAP_FUNC_IMPORT eap_status_e get_expanded_type_data(
		abs_eap_am_tools_c * const am_tools,
		eap_variable_data_c * const data);

	EAP_FUNC_IMPORT eap_status_e set_expanded_type_data(
		abs_eap_am_tools_c * const am_tools,
		const eap_variable_data_c * const data);

	EAP_FUNC_IMPORT void set_eap_type_values(
		const eap_type_vendor_id_e vendor_id,
		const u32_t vendor_type);

	EAP_FUNC_IMPORT eap_type_vendor_id_e get_vendor_id() const;

	EAP_FUNC_IMPORT u32_t get_vendor_type() const;

	EAP_FUNC_IMPORT static u32_t get_eap_expanded_type_size();

	EAP_FUNC_IMPORT bool operator == (const eap_type_ietf_values_e right_type_value) const;

	EAP_FUNC_IMPORT bool operator != (const eap_type_ietf_values_e right_type_value) const;

	EAP_FUNC_IMPORT bool operator == (const eap_expanded_type_c &right_type_value) const;

	EAP_FUNC_IMPORT bool operator != (const eap_expanded_type_c &right_type_value) const;

	EAP_FUNC_IMPORT eap_expanded_type_c &operator = (const eap_type_ietf_values_e right_type_value);

	EAP_FUNC_IMPORT eap_expanded_type_c &operator = (const eap_expanded_type_c &right_type_value);

	EAP_FUNC_IMPORT eap_expanded_type_c *operator & ();

	EAP_FUNC_IMPORT const eap_expanded_type_c *operator & () const;

	/// This function reads EAP-type from offset.
	EAP_FUNC_IMPORT static eap_status_e read_type(
		abs_eap_am_tools_c * const am_tools,
		const u32_t index,
		const void * const buffer,
		const u32_t buffer_length,
#if defined(USE_EAP_EXPANDED_TYPES)
		eap_expanded_type_c * const type
#else
		eap_type_ietf_values_e * const type
#endif //#if defined(USE_EAP_EXPANDED_TYPES)
		);

	/// This function writes EAP-type to offset.
	EAP_FUNC_IMPORT static eap_status_e write_type(
		abs_eap_am_tools_c * const am_tools,
		const u32_t index, ///< Index is from 0 to n. Index 0 is the first EAP type field after base EAP header.
		void * const buffer,
		const u32_t buffer_length,
		const bool write_extented_type_when_true, ///< True value writes always Extented Type.
#if defined(USE_EAP_EXPANDED_TYPES)
		const eap_expanded_type_c p_type ///< The EAP type to be written.
#else
		const eap_type_ietf_values_e p_type ///< The EAP type to be written.
#endif //#if defined(USE_EAP_EXPANDED_TYPES)
		);

#if defined(USE_EAP_EXPANDED_TYPES)
	EAP_FUNC_IMPORT i32_t compare(const eap_expanded_type_c * const data) const;
#endif //#if defined(USE_EAP_EXPANDED_TYPES)

private:

	eap_type_vendor_id_e   m_vendor_id; ///< Here we use only 24 least significant bits.
	u32_t                  m_vendor_type;
};

//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------

class EAP_EXPORT eap_static_expanded_type_c
{
public:

	EAP_FUNC_IMPORT const eap_expanded_type_c & get_type() const;

public:

	eap_type_vendor_id_e   m_vendor_id; ///< Here we use only 24 least significant bits.
	u32_t                  m_vendor_type;
};

#define EAP_EXPANDED_TYPE(name, vendor_id, vendor_type) \
	static const eap_static_expanded_type_c name={vendor_id, vendor_type}


// EAP Expanded Types.
EAP_EXPANDED_TYPE(
	eap_expanded_type_broadcom_secure_easy_setup,
	eap_type_vendor_id_broadcom,
	eap_type_vendor_type_secure_easy_setup);

EAP_EXPANDED_TYPE(
	eap_expanded_type_nak,
	eap_type_vendor_id_ietf,
	eap_type_nak);

EAP_EXPANDED_TYPE(
	eap_expanded_type_simple_config,
	eap_type_vendor_id_WFA,
	eap_type_vendor_type_WFA_simple_config);

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	EAP_EXPANDED_TYPE(
		eap_expanded_type_ttls_plain_mschapv2,
		eap_type_vendor_id_hack,
		eap_type_vendor_type_plain_MSCHAPv2_hack);
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

	EAP_EXPANDED_TYPE(
		eap_expanded_type_ttls_plain_pap,
		eap_type_vendor_id_hack,
		eap_type_vendor_type_ttls_plain_pap_hack);

//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------


#if defined(USE_EAP_EXPANDED_TYPES)

	typedef eap_expanded_type_c eap_type_value_e;

	EAP_C_FUNC_IMPORT u32_t convert_eap_type_to_u32_t(eap_type_value_e type);

	EAP_C_FUNC_IMPORT u64_t convert_eap_type_to_u64_t(eap_type_value_e type);

#else

	EAP_C_FUNC_IMPORT u32_t convert_eap_type_to_u32_t(eap_type_value_e type);

	EAP_C_FUNC_IMPORT u64_t convert_eap_type_to_u64_t(eap_type_value_e type);

#endif //#if defined(USE_EAP_EXPANDED_TYPES)


//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------

#endif //#if !defined(_EAP_EXPANDED_TYPE_H_)

//--------------------------------------------------



// End.
