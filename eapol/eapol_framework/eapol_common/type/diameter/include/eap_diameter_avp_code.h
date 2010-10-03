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

#if !defined(_EAP_DIAMETER_AVP_CODE_H_)
#define _EAP_DIAMETER_AVP_CODE_H_


#include "eap_am_assert.h"
#include "eap_am_tools.h"
#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_DIAMETER_AVP_CODE_H)
	#define EAP_CLASS_VISIBILITY_EAP_DIAMETER_AVP_CODE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H 
	#define EAP_FUNC_EXPORT_EAP_DIAMETER_AVP_CODE_H 
	#define EAP_C_FUNC_EXPORT_EAP_DIAMETER_AVP_CODE_H 
#elif defined(EAP_EXPORT_EAP_DIAMETER_AVP_CODE_H)
	#define EAP_CLASS_VISIBILITY_EAP_DIAMETER_AVP_CODE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_DIAMETER_AVP_CODE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_DIAMETER_AVP_CODE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_DIAMETER_AVP_CODE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_DIAMETER_AVP_CODE_H 
	#define EAP_C_FUNC_EXPORT_EAP_DIAMETER_AVP_CODE_H 
#endif
// End: added by script change_export_macros.sh.



/** @file */

/**
 * Enumeration of the DIAMETER APV codes of IETF.
 * These are defined in IANA, "RADIUS Types",
 * http://www.iana.org/assignments/radius-types.
 */
enum eap_diameter_avp_code_of_ietf_e
{
	eap_diameter_avp_code_none = 0,
	eap_diameter_avp_code_user_name = 1,
	eap_diameter_avp_code_user_password = 2,
	eap_diameter_avp_code_chap_password = 3,
	eap_diameter_avp_code_nas_ip_address = 4,
	eap_diameter_avp_code_nas_port = 5,
	eap_diameter_avp_code_service_type = 6,
	eap_diameter_avp_code_framed_protocol = 7,
	eap_diameter_avp_code_framed_ip_address = 8,
	eap_diameter_avp_code_framed_ip_netmask = 9,
	eap_diameter_avp_code_framed_routing = 10,
	eap_diameter_avp_code_filter_id = 11,
	eap_diameter_avp_code_framed_mtu = 12,
	eap_diameter_avp_code_framed_compression = 13,
	eap_diameter_avp_code_login_ip_host = 14,
	eap_diameter_avp_code_login_service = 15,
	eap_diameter_avp_code_login_tcp_port = 16,
	eap_diameter_avp_code_reply_message = 18,
	eap_diameter_avp_code_callback_number = 19,
	eap_diameter_avp_code_callback_id = 20,
	eap_diameter_avp_code_framed_route = 22,
	eap_diameter_avp_code_framed_ipx_network = 23,
	eap_diameter_avp_code_state = 24,
	eap_diameter_avp_code_class = 25,
	eap_diameter_avp_code_vendor_specific = 26,
	eap_diameter_avp_code_session_timeout = 27,
	eap_diameter_avp_code_idle_timeout = 28,
	eap_diameter_avp_code_termination_action = 29,
	eap_diameter_avp_code_called_station_id = 30,
	eap_diameter_avp_code_calling_station_id = 31,
	eap_diameter_avp_code_nas_identifier = 32,
	eap_diameter_avp_code_proxy_state = 33,
	eap_diameter_avp_code_login_lat_service = 34,
	eap_diameter_avp_code_login_lat_node = 35,
	eap_diameter_avp_code_login_lat_group = 36,
	eap_diameter_avp_code_framed_appletalk_link = 37,
	eap_diameter_avp_code_framed_appletalk_network = 38,
	eap_diameter_avp_code_framed_appletalk_zone = 39,
	eap_diameter_avp_code_chap_challenge = 60,
	eap_diameter_avp_code_nas_port_type = 61,
	eap_diameter_avp_code_port_limit = 62,
	eap_diameter_avp_code_login_lat_port = 63,
	eap_diameter_avp_code_eap_message = 79,
	eap_diameter_avp_code_message_authenticator = 80,
};


/**
 * These values are defined in "ASSIGNED NUMBERS", RFC 1700.
 */
enum eap_diameter_vendor_id_e
{
	eap_diameter_vendor_id_of_ietf      =   0,
	eap_diameter_vendor_id_of_microsoft = 311,
};


/**
 * These are defined in "Microsoft Vendor-specific RADIUS Attributes", RFC 2548.
 */
enum eap_diameter_vendor_codes_of_microsoft_e
{
	eap_diameter_vendor_code_of_microsoft_ms_chap_error_value = 2,
	eap_diameter_vendor_code_of_microsoft_ms_chap_nt_enc_pw_value = 6,
	eap_diameter_vendor_code_of_microsoft_ms_chap_challenge_value = 11,
	eap_diameter_vendor_code_of_microsoft_ms_mppe_send_key_value = 16,
	eap_diameter_vendor_code_of_microsoft_ms_mppe_recv_key_value = 17,
	eap_diameter_vendor_code_of_microsoft_ms_chap2_response_value = 25,
	eap_diameter_vendor_code_of_microsoft_ms_chap2_success_value = 26,
	eap_diameter_vendor_code_of_microsoft_ms_chap2_cpw_value = 27,
};

//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------

class EAP_CLASS_VISIBILITY_EAP_DIAMETER_AVP_CODE_H eap_diameter_avp_code_c
{

public:

	EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H ~eap_diameter_avp_code_c();

	EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H eap_diameter_avp_code_c();

	EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H eap_diameter_avp_code_c(
		const eap_diameter_vendor_id_e vendor_id,
		const u32_t vendor_code);

	EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H eap_diameter_avp_code_c(
		const eap_diameter_avp_code_of_ietf_e ietf_code);


	EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H static bool is_ietf_code(const eap_diameter_avp_code_c code);


	EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H eap_status_e get_code_data(
		abs_eap_am_tools_c * const am_tools,
		eap_diameter_avp_code_of_ietf_e * const code);

	EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H eap_status_e get_code_data(
		abs_eap_am_tools_c * const am_tools,
		eap_diameter_avp_code_c * const code);


	EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H void set_code_values(
		const eap_diameter_vendor_id_e vendor_id,
		const u32_t vendor_code);

	EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H eap_diameter_vendor_id_e get_vendor_id() const;

	EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H u32_t get_vendor_code() const;


	EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H bool operator == (const eap_diameter_avp_code_of_ietf_e right_type_value) const;

	EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H bool operator != (const eap_diameter_avp_code_of_ietf_e right_type_value) const;

	EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H bool operator == (const eap_diameter_avp_code_c &right_type_value) const;

	EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H bool operator != (const eap_diameter_avp_code_c &right_type_value) const;


	EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H eap_diameter_avp_code_c &operator = (const eap_diameter_avp_code_of_ietf_e right_type_value);

	EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H eap_diameter_avp_code_c &operator = (const eap_diameter_avp_code_c &right_type_value);

	EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H eap_diameter_avp_code_c *operator & ();


	EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H const eap_diameter_avp_code_c *operator & () const;


private:

	eap_diameter_vendor_id_e   m_vendor_id;
	u32_t                      m_vendor_code;
};

//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------

class EAP_CLASS_VISIBILITY_EAP_DIAMETER_AVP_CODE_H eap_static_diameter_vendor_code_c
{
public:

	EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H const eap_diameter_avp_code_c & get_code() const;

public:

	eap_diameter_vendor_id_e   m_vendor_id;
	u32_t                      m_vendor_code;
};

#define EAP_DIAMETER_VENDOR_CODE(name, vendor_id, vendor_code) \
	static const eap_static_diameter_vendor_code_c name={vendor_id, vendor_code}

//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------

EAP_C_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H u32_t convert_eap_diameter_avp_code_to_u32_t(eap_diameter_avp_code_c code);

EAP_C_FUNC_VISIBILITY_EAP_DIAMETER_AVP_CODE_H u64_t convert_eap_diameter_avp_code_to_u64_t(eap_diameter_avp_code_c code);

//-----------------------------------------------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

// EAP Diameter Vendor Codes.

/**
 * This is defined in "Microsoft Vendor-specific RADIUS Attributes", RFC 2548.
 * Reference name is MS-CHAP-Error.
 */
EAP_DIAMETER_VENDOR_CODE(
	eap_diameter_vendor_code_of_microsoft_ms_chap_error,
	eap_diameter_vendor_id_of_microsoft,
	eap_diameter_vendor_code_of_microsoft_ms_chap_error_value);

/**
 * This is defined in "Microsoft Vendor-specific RADIUS Attributes", RFC 2548.
 * Reference name is MS-CHAP-NT-Enc-PW.
 */
EAP_DIAMETER_VENDOR_CODE(
	eap_diameter_vendor_code_of_microsoft_ms_chap_nt_enc_pw,
	eap_diameter_vendor_id_of_microsoft,
	eap_diameter_vendor_code_of_microsoft_ms_chap_nt_enc_pw_value);

/**
 * This is defined in "Microsoft Vendor-specific RADIUS Attributes", RFC 2548.
 * Reference name is MS-CHAP-Challenge.
 */
EAP_DIAMETER_VENDOR_CODE(
	eap_diameter_vendor_code_of_microsoft_ms_chap_challenge,
	eap_diameter_vendor_id_of_microsoft,
	eap_diameter_vendor_code_of_microsoft_ms_chap_challenge_value);


EAP_DIAMETER_VENDOR_CODE(
	eap_diameter_vendor_code_of_microsoft_ms_mppe_send_key,
	eap_diameter_vendor_id_of_microsoft,
	eap_diameter_vendor_code_of_microsoft_ms_mppe_send_key_value);

EAP_DIAMETER_VENDOR_CODE(
	eap_diameter_vendor_code_of_microsoft_ms_mppe_recv_key,
	eap_diameter_vendor_id_of_microsoft,
	eap_diameter_vendor_code_of_microsoft_ms_mppe_recv_key_value);


/**
 * This is defined in "Microsoft Vendor-specific RADIUS Attributes", RFC 2548.
 * Reference name is MS-CHAP2-Response.
 */
EAP_DIAMETER_VENDOR_CODE(
	eap_diameter_vendor_code_of_microsoft_ms_chap2_response,
	eap_diameter_vendor_id_of_microsoft,
	eap_diameter_vendor_code_of_microsoft_ms_chap2_response_value);

/**
 * This is defined in "Microsoft Vendor-specific RADIUS Attributes", RFC 2548.
 * Reference name is MS-CHAP2-Success.
 */
EAP_DIAMETER_VENDOR_CODE(
	eap_diameter_vendor_code_of_microsoft_ms_chap2_success,
	eap_diameter_vendor_id_of_microsoft,
	eap_diameter_vendor_code_of_microsoft_ms_chap2_success_value);

/**
 * This is defined in "Microsoft Vendor-specific RADIUS Attributes", RFC 2548.
 * Reference name is MS-CHAP2-CPW.
 */
EAP_DIAMETER_VENDOR_CODE(
	eap_diameter_vendor_code_of_microsoft_ms_chap2_cpw,
	eap_diameter_vendor_id_of_microsoft,
	eap_diameter_vendor_code_of_microsoft_ms_chap2_cpw_value);

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------

#endif //#if !defined(_EAP_DIAMETER_AVP_CODE_H_)



// End.
