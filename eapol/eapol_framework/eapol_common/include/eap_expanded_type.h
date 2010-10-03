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
* %version: 18 %
*/

#if !defined(_EAP_EXPANDED_TYPE_H_)
#define _EAP_EXPANDED_TYPE_H_


#include "eap_general_header_base.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_EXPANDED_TYPE_H)
	#define EAP_CLASS_VISIBILITY_EAP_EXPANDED_TYPE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H 
	#define EAP_FUNC_EXPORT_EAP_EXPANDED_TYPE_H 
	#define EAP_C_FUNC_EXPORT_EAP_EXPANDED_TYPE_H 
#elif defined(EAP_EXPORT_EAP_EXPANDED_TYPE_H)
	#define EAP_CLASS_VISIBILITY_EAP_EXPANDED_TYPE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_EXPANDED_TYPE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_EXPANDED_TYPE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_EXPANDED_TYPE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_EXPANDED_TYPE_H 
	#define EAP_C_FUNC_EXPORT_EAP_EXPANDED_TYPE_H 
#endif
// End: added by script change_export_macros.sh.



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


/// Enumeration of the IETF defined EAP-Type values.
enum eap_type_ietf_values_e
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

	eap_type_saesim             = 252, ///< This is just a test EAP-type.
	eap_type_dummy_sim          = 253, ///< This is just a test EAP-type.

	eap_type_expanded_type      = 254, ///< This is Expanded Type.
	eap_type_experimental_type  = 255, ///< This is Experimental Type.
};

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
	eap_type_vendor_type_ttls_plain_pap_hack = 98, // This is for TTLS/PAP.
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	eap_type_vendor_type_plain_MSCHAPv2_hack = 99, // This is for plain MCHAPv2 and TTLS
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
};

//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------

class EAP_CLASS_VISIBILITY_EAP_EXPANDED_TYPE_H eap_expanded_type_c
{

public:

	enum sizes
	{
		m_ietf_type_size = sizeof(u8_t),
		m_vendor_id_size = 3ul*sizeof(u8_t),
		m_vendor_type_size = sizeof(u32_t),
		m_eap_expanded_type_size = m_ietf_type_size+m_vendor_id_size+m_vendor_type_size,
	};

	// This must not be virtual destructor.
	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H ~eap_expanded_type_c();

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H eap_expanded_type_c();

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H eap_expanded_type_c(
		const eap_type_vendor_id_e vendor_id,
		const u32_t vendor_type);

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H eap_expanded_type_c(
		const eap_type_ietf_values_e type);

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H bool get_is_valid() const;

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H bool get_is_valid_data() const;

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H eap_expanded_type_c * copy() const;

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H static bool is_expanded_type(const eap_type_ietf_values_e eap_type);

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H static bool is_ietf_type(const eap_expanded_type_c eap_type);

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H eap_status_e get_type_data(
		abs_eap_am_tools_c * const am_tools,
		eap_type_ietf_values_e * const type) const;

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H eap_status_e get_type_data(
		abs_eap_am_tools_c * const am_tools,
		eap_expanded_type_c * const type) const;

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H eap_status_e get_expanded_type_data(
		abs_eap_am_tools_c * const am_tools,
		eap_variable_data_c * const data) const;

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H eap_status_e set_expanded_type_data(
		abs_eap_am_tools_c * const am_tools,
		const eap_variable_data_c * const data);

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H eap_status_e set_expanded_type_data(
		abs_eap_am_tools_c * const am_tools,
		const void * const data,
		const u32_t data_length);

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H void set_eap_type_values(
		const eap_type_vendor_id_e vendor_id,
		const u32_t vendor_type);

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H eap_type_vendor_id_e get_vendor_id() const;

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H u32_t get_vendor_type() const;

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H static u32_t get_eap_expanded_type_size();

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H bool operator == (const eap_type_ietf_values_e right_type_value) const;

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H bool operator != (const eap_type_ietf_values_e right_type_value) const;

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H bool operator == (const eap_expanded_type_c &right_type_value) const;

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H bool operator != (const eap_expanded_type_c &right_type_value) const;

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H eap_expanded_type_c &operator = (const eap_type_ietf_values_e right_type_value);

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H eap_expanded_type_c &operator = (const eap_expanded_type_c &right_type_value);

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H eap_expanded_type_c *operator & ();

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H const eap_expanded_type_c *operator & () const;

	/// This function reads EAP-type from offset.
	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H static eap_status_e read_type(
		abs_eap_am_tools_c * const am_tools,
		const u32_t index,
		const void * const buffer,
		const u32_t buffer_length,
		eap_expanded_type_c * const type
		);

	/// This function writes EAP-type to offset.
	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H static eap_status_e write_type(
		abs_eap_am_tools_c * const am_tools,
		const u32_t index, ///< Index is from 0 to n. Index 0 is the first EAP type field after base EAP header.
		void * const buffer,
		const u32_t buffer_length,
		const bool write_extented_type_when_true, ///< True value writes always Extented Type.
		const eap_expanded_type_c p_type ///< The EAP type to be written.
		);

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H i32_t compare(const eap_expanded_type_c * const data) const;

private:

	eap_type_vendor_id_e   m_vendor_id; ///< Here we use only 24 least significant bits.
	u32_t                  m_vendor_type;
};

//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------

class EAP_CLASS_VISIBILITY_EAP_EXPANDED_TYPE_H eap_static_expanded_type_c
{
public:

	EAP_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H const eap_expanded_type_c & get_type() const;

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


typedef eap_expanded_type_c eap_type_value_e;


EAP_C_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H u32_t convert_eap_type_to_u32_t(eap_type_value_e type);

EAP_C_FUNC_VISIBILITY_EAP_EXPANDED_TYPE_H u64_t convert_eap_type_to_u64_t(eap_type_value_e type);


//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------

#endif //#if !defined(_EAP_EXPANDED_TYPE_H_)

//--------------------------------------------------



// End.
