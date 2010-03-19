/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/wapi_types.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 39 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.2
*/



#if !defined(_WAPI_TYPES_H_)
#define _WAPI_TYPES_H_

#if defined(USE_WAPI_CORE)

#include "eap_am_export.h"
#include "eap_tools.h"

/** @file */

//----------------------------------------------------------------------------

enum wapi_completion_operation_e
{
	wapi_completion_operation_none,
	wapi_completion_operation_continue_certificate_authentication,
};

enum wai_protocol_version_e
{
	wai_protocol_version_none = 0,
	wai_protocol_version_1 = 1,
};

enum wai_protocol_type_e
{
	wai_protocol_type_none,
	wai_protocol_type_wai = 1,
};

enum wai_protocol_subtype_e
{
	wai_protocol_subtype_none,
	wai_protocol_subtype_pre_authentication_start = 1,
	wai_protocol_subtype_stakey_request,
	wai_protocol_subtype_authentication_activation,
	wai_protocol_subtype_access_authentication_request,
	wai_protocol_subtype_access_authentication_response,
	wai_protocol_subtype_certificate_authentication_request,
	wai_protocol_subtype_certificate_authentication_response,
	wai_protocol_subtype_unicast_key_negotiation_request,
	wai_protocol_subtype_unicast_key_negotiation_response,
	wai_protocol_subtype_unicast_key_negotiation_confirmation,
	wai_protocol_subtype_multicast_key_announcement,
	wai_protocol_subtype_multicast_key_announcement_response,
};

/// This enumerates wai_tlv_header_c types.
enum wai_tlv_type_e
{
	wai_tlv_type_none,
	wai_tlv_type_signature_attribute              = 1,
	wai_tlv_type_echd_parameter                   = 1,
	wai_tlv_type_result_of_certificate_validation = 2,
	wai_tlv_type_identity_list                    = 3,

	wai_tlv_type_first_known = wai_tlv_type_signature_attribute,
	wai_tlv_type_last_known = wai_tlv_type_identity_list,
};

enum wai_certificate_identifier_e
{
	wai_certificate_identifier_none,
	wai_certificate_identifier_x_509_v3 = 1,
	wai_certificate_identifier_gbw      = 2,
};

enum wai_payload_type_e
{
	wai_payload_type_none,
	wai_payload_type_flag, ///< This is type of 1 octet.
	wai_payload_type_access_result, ///< This is type of 1 octet.
	wai_payload_type_uskid, ///< This is type of 1 octet.
	wai_payload_type_mskid_stakeyid, ///< This is type of 1 octet.
	wai_payload_type_result, ///< This is type of 1 octet.

	wai_payload_type_addid, ///< This is type of 12 octets. Two MAC addresses each 6 octet in length.

	wai_payload_type_bkid, ///< This is type of 16 octets.
	wai_payload_type_key_announcement_identifier, ///< This is type of 16 octets.
	wai_payload_type_data_sequence_number, ///< This is type of 16 octets.

	wai_payload_type_message_authentication_code, ///< This is type of 20 octets. Output from HMAC-SHA256.

	wai_payload_type_authentication_identifier, ///< This is type of 32 octet.
	wai_payload_type_nonce, ///< This is type of 32 octets.

	wai_payload_type_key_data, ///< This is type of <1 octet length><length count of octets>

	wai_payload_type_wie, ///< This is type of WIE <1 octet Element ID><1 octet length><length count of octets>.

	wai_payload_type_echd_parameter, ///< This is type of wai_tlv_header_c.
	wai_payload_type_signature_attributes, ///< This is type of wai_tlv_header_c.
	wai_payload_type_result_of_certificate_verification, ///< This is type of wai_tlv_header_c.
	wai_payload_type_identity_list, ///< This is type of wai_tlv_header_c.
	wai_payload_type_optional, ///< This is type of wai_tlv_header_c.

	wai_payload_type_certificate, ///< This is type of ec_cs_tlv_header_c.
	wai_payload_type_identity, ///< This is type of ec_cs_tlv_header_c.

	wai_payload_type_first_known = wai_payload_type_flag,
	wai_payload_type_last_known = wai_payload_type_identity,

	wai_payload_type_terminator = 0xffffffff,
};

enum wai_payload_type_size_e
{
	wai_payload_type_size_none = 0,

	wai_payload_type_size_1_octet = 1, ///< This is type class of 1 octet.

	wai_payload_type_size_12_octets = 12, ///< This is type class of 12 octets.

	wai_payload_type_size_16_octets = 16, ///< This is type class of 16 octets.

	wai_payload_type_size_20_octets = 20, ///< This is type class of 20 octets.

	wai_payload_type_size_32_octets = 32, ///< This is type class of 32 octet.

	wai_payload_type_size_1_octet_length_field = 0x7001, ///< This is type class of <1 octet length><length count of octets>

	wai_payload_type_size_wie = 0x7002, ///< This is type of WIE <1 octet Element ID><1 octet length><length count of octets>.

	wai_payload_type_size_wai_tlv_header = 0x7003, ///< This is type of wai_tlv_header_c.

	wai_payload_type_size_ec_cs_tlv_header = 0x7004, ///< This is type of ec_cs_tlv_header_c.
};

//----------------------------------------------------------------------------

struct wai_payload_type_to_size_map_s
{
	wai_payload_type_size_e m_size;
	wai_payload_type_e       m_type;
};

const wai_payload_type_to_size_map_s wai_payload_type_to_class_map[] =
{
	{ wai_payload_type_size_none, wai_payload_type_none },

	{ wai_payload_type_size_1_octet, wai_payload_type_flag },
	{ wai_payload_type_size_1_octet, wai_payload_type_access_result },
	{ wai_payload_type_size_1_octet, wai_payload_type_uskid },
	{ wai_payload_type_size_1_octet, wai_payload_type_mskid_stakeyid },
	{ wai_payload_type_size_1_octet, wai_payload_type_result },

	{ wai_payload_type_size_12_octets, wai_payload_type_addid },

	{ wai_payload_type_size_16_octets, wai_payload_type_bkid },
	{ wai_payload_type_size_16_octets, wai_payload_type_key_announcement_identifier },
	{ wai_payload_type_size_16_octets, wai_payload_type_data_sequence_number },

	{ wai_payload_type_size_20_octets, wai_payload_type_message_authentication_code },

	{ wai_payload_type_size_32_octets, wai_payload_type_authentication_identifier },
	{ wai_payload_type_size_32_octets, wai_payload_type_nonce },

	{ wai_payload_type_size_1_octet_length_field, wai_payload_type_key_data },

	{ wai_payload_type_size_wie, wai_payload_type_wie },

	{ wai_payload_type_size_wai_tlv_header, wai_payload_type_echd_parameter },
	{ wai_payload_type_size_wai_tlv_header, wai_payload_type_signature_attributes },
	{ wai_payload_type_size_wai_tlv_header, wai_payload_type_result_of_certificate_verification },
	{ wai_payload_type_size_wai_tlv_header, wai_payload_type_identity_list },
	{ wai_payload_type_size_wai_tlv_header, wai_payload_type_optional },

	{ wai_payload_type_size_ec_cs_tlv_header, wai_payload_type_certificate },
	{ wai_payload_type_size_ec_cs_tlv_header, wai_payload_type_identity },
};

//----------------------------------------------------------------------------

const wai_payload_type_e required_payloads_authentication_activation[] =
{
	wai_payload_type_flag,
	wai_payload_type_authentication_identifier,
	wai_payload_type_identity,
	wai_payload_type_certificate,
	wai_payload_type_echd_parameter,
	wai_payload_type_terminator
};

const wai_payload_type_e required_payloads_access_authentication_request[] =
{
	wai_payload_type_flag,
	wai_payload_type_authentication_identifier,
	wai_payload_type_nonce,
	wai_payload_type_key_data,
	wai_payload_type_identity,
	wai_payload_type_certificate,
	wai_payload_type_echd_parameter,
	wai_payload_type_optional,
	//wai_payload_type_signature_attributes,
	wai_payload_type_terminator
};

const wai_payload_type_e required_payloads_access_authentication_response[] =
{
	wai_payload_type_flag,
	wai_payload_type_nonce,
	wai_payload_type_nonce,
	wai_payload_type_access_result,
	wai_payload_type_key_data,
	wai_payload_type_key_data,
	wai_payload_type_identity,
	wai_payload_type_identity,
	wai_payload_type_optional,
	//wai_payload_type_signature_attributes,
	wai_payload_type_terminator
};

const wai_payload_type_e required_payloads_certificate_authentication_request[] =
{
	wai_payload_type_addid,
	wai_payload_type_nonce,
	wai_payload_type_nonce,
	wai_payload_type_certificate,
	wai_payload_type_certificate,
	wai_payload_type_optional,
	wai_payload_type_terminator
};

const wai_payload_type_e required_payloads_certificate_authentication_response[] =
{
	wai_payload_type_addid,
	wai_payload_type_result_of_certificate_verification,
	wai_payload_type_signature_attributes,
	wai_payload_type_signature_attributes,
	wai_payload_type_terminator
};

const wai_payload_type_e required_payloads_unicast_key_negotiation_request[] =
{
	wai_payload_type_flag,
	wai_payload_type_bkid,
	wai_payload_type_uskid,
	wai_payload_type_addid,
	wai_payload_type_nonce,
	wai_payload_type_terminator
};

const wai_payload_type_e required_payloads_unicast_key_negotiation_response[] =
{
	wai_payload_type_flag,
	wai_payload_type_bkid,
	wai_payload_type_uskid,
	wai_payload_type_addid,
	wai_payload_type_nonce,
	wai_payload_type_nonce,
	wai_payload_type_wie,
	wai_payload_type_message_authentication_code,
	wai_payload_type_terminator
};

const wai_payload_type_e required_payloads_unicast_key_negotiation_confirmation[] =
{
	wai_payload_type_flag,
	wai_payload_type_bkid,
	wai_payload_type_uskid,
	wai_payload_type_addid,
	wai_payload_type_nonce,
	wai_payload_type_wie,
	wai_payload_type_message_authentication_code,
	wai_payload_type_terminator
};

const wai_payload_type_e required_payloads_multicast_key_announcement[] =
{
	wai_payload_type_flag,
	wai_payload_type_mskid_stakeyid,
	wai_payload_type_uskid,
	wai_payload_type_addid,
	wai_payload_type_data_sequence_number,
	wai_payload_type_key_announcement_identifier,
	wai_payload_type_key_data,
	wai_payload_type_message_authentication_code,
	wai_payload_type_terminator
};

const wai_payload_type_e required_payloads_multicast_key_announcement_response[] =
{
	wai_payload_type_flag,
	wai_payload_type_mskid_stakeyid,
	wai_payload_type_uskid,
	wai_payload_type_addid,
	wai_payload_type_key_announcement_identifier,
	wai_payload_type_message_authentication_code,
	wai_payload_type_terminator
};

//----------------------------------------------------------------------------

enum wai_data_flag_mask_e
{
	wai_data_flag_mask_none                           = 0x00,
	wai_data_flag_mask_BK_Rekeying                    = (1u << 0u),
	wai_data_flag_mask_Pre_Authentication             = (1u << 1u),
	wai_data_flag_mask_Certificate_Validation_Request = (1u << 2u),
	wai_data_flag_mask_Optional_Field                 = (1u << 3u),
	wai_data_flag_mask_USK_Rekeying                   = (1u << 4u),
	wai_data_flag_mask_STAKey_Negotiation             = (1u << 5u),
	wai_data_flag_mask_STAKey_Revoking                = (1u << 6u),
};

enum wai_data_uskid_mask_e
{
	wai_data_uskid_mask_none  = 0x00,
	wai_data_uskid_mask_uskid = (1u << 0u),
	wai_data_uskid_mask_mskid = (1u << 0u),
};

enum wai_unicast_cipher_suite_e
{
	wai_unicast_cipher_suite_none,
	wai_unicast_cipher_suite_SMS4,
};

enum wapi_core_state_e
{
	wapi_core_state_none,
	wapi_core_state_start_unicast_key_negotiation,
	wapi_core_state_start_certificate_negotiation,
	wapi_core_state_start_multicast_key_announcement,
	wapi_core_state_wait_authentication_activation_message,
	wapi_core_state_process_authentication_activation_message,
	wapi_core_state_wait_access_authentication_request_message,
	wapi_core_state_process_access_authentication_request_message,
	wapi_core_state_process_access_authentication_request_message_ASU_signature_trusted_by_AE,
	wapi_core_state_process_access_authentication_request_message_AE_signature_trusted_by_ASUE,
	wapi_core_state_wait_certificate_authentication_request_message,
	wapi_core_state_wait_certificate_authentication_response_message,
	wapi_core_state_wait_access_authentication_response_message,
	wapi_core_state_process_access_authentication_response_message,
	wapi_core_state_process_access_authentication_response_message_ASU_signature,
	wapi_core_state_wait_unicast_key_negotiation_request_message,
	wapi_core_state_wait_unicast_key_negotiation_response_message,
	wapi_core_state_wait_unicast_key_negotiation_confirmation_message,
	wapi_core_state_wait_multicast_announcement_message,
	wapi_core_state_wait_multicast_announcement_response_message,
	wapi_core_state_authentication_ok,
	wapi_core_state_authentication_failed,
};

enum wapi_negotiation_state_e
{
	wapi_negotiation_state_none,
	wapi_negotiation_state_initial_negotiation,
	wapi_negotiation_state_rekeying,
};

enum wapi_certificate_result_e
{
	wapi_certificate_result_none                                           = 0xff,
	wapi_certificate_result_valid                                          = 0u,
	wapi_certificate_result_issuer_is_unknown                              = 1u,
	wapi_certificate_result_certificate_is_based_on_an_untrusted_root      = 2u,
	wapi_certificate_result_certificate_is_not_time_valid                  = 3u,
	wapi_certificate_result_certificate_have_not_a_valid_signature         = 4u,
	wapi_certificate_result_certificate_is_revoked                         = 5u,
	wapi_certificate_result_certificate_is_not_valid_for_proposed_usage    = 6u,
	wapi_certificate_result_revocation_state_of_the_certificate_is_unknown = 7u,
};

enum wapi_access_result_e
{
	wapi_access_result_none                            = 0xff,
	wapi_access_result_successfull_access              = 0u,
	wapi_access_result_certificate_cannot_be_verified  = 1u,
	wapi_access_result_certificate_error               = 2u,
	wapi_access_result_prohibition_on_the_local_policy = 3u,
};

//----------------------------------------------------------------------------

const u8_t WAPI_PRESHARED_KEY_LABEL[] = "preshared key expansion for authentication and key negotiation";

const u32_t WAPI_PRESHARED_KEY_LABEL_LENGTH = sizeof(WAPI_PRESHARED_KEY_LABEL)-1ul;

const u8_t WAPI_CERTIFICATE_KEY_LABEL[] = "base key expansion for key and additional nonce";

const u32_t WAPI_CERTIFICATE_KEY_LABEL_LENGTH = sizeof(WAPI_CERTIFICATE_KEY_LABEL)-1ul;

const u32_t WAPI_BK_LENGTH = 16ul;


const u32_t WAPI_BKID_LENGTH = 16ul;

const u32_t WAPI_USKSA_COUNT = 2ul;

const u32_t WAPI_MSKSA_COUNT = 2ul;

const u32_t WAPI_CHALLENGE_LENGTH = 32ul;

const u32_t WAPI_AUTHENTICATION_IDENTIFIER_LENGTH = 32ul;


const u8_t WAPI_UNICAST_KEY_LABEL[] = "pairwise key expansion for unicast and additional keys and nonce";

const u32_t WAPI_UNICAST_KEY_LABEL_LENGTH = sizeof(WAPI_UNICAST_KEY_LABEL)-1ul;


const u8_t WAPI_MULTICAST_KEY_EXPANSION_LABEL[] = "multicast or station key expansion for station unicast and multicast and broadcast";

const u32_t WAPI_MULTICAST_KEY_EXPANSION_LABEL_LENGTH = sizeof(WAPI_MULTICAST_KEY_EXPANSION_LABEL)-1ul;


const u32_t WAPI_UNICAST_ENCRYPTION_KEY_UEK_LENGTH = 16ul;

const u32_t WAPI_UNICAST_INTEGRITY_CHECK_KEY_UCK_LENGTH = 16ul;

const u32_t WAPI_MESSAGE_AUTHENTICATION_KEY_MAK_LENGTH = 16ul;

const u32_t WAPI_KEY_ENCRYPTION_KEY_KEK_LENGTH = 16ul;

const u32_t WAPI_CHALLENGE_SEED_LENGTH = 32ul;

const u32_t WAPI_MESSAGE_AUTHENTICATION_CODE_LENGTH = 20ul;

const u32_t WAPI_NOTIFICATION_MASTER_KEY_LENGTH = 16ul;

const u32_t WAPI_MULTICAST_KEY_LENGTH = 32ul;


const u32_t WAPI_UNICAST_KEY_LENGTH
	= WAPI_UNICAST_ENCRYPTION_KEY_UEK_LENGTH
	+ WAPI_UNICAST_INTEGRITY_CHECK_KEY_UCK_LENGTH
	+ WAPI_MESSAGE_AUTHENTICATION_KEY_MAK_LENGTH
	+ WAPI_KEY_ENCRYPTION_KEY_KEK_LENGTH
	+ WAPI_CHALLENGE_SEED_LENGTH;

const u16_t WAI_FIRST_SEQUENCE_NUMBER = 1u;

const u16_t WAI_FIRST_FRAGMENT_NUMBER = 0u;

const u32_t WIE_HEADER_LENGTH = 2ul*sizeof(u8_t);

const u8_t WAPI_ECDH_OID_PARAMETER[] =
{
	0x06, 0x09, //# U, P, 0x06 = OBJECT IDENTIFIER, length 0x09 = 9 octets
	0x2a,     //# = 42 = 40 * 1 + 2 => 1.2
	0x81, 0x1c, //# 0x1 * 128^1 + 0x1c = 156 
	0xd7, 0x63, //# 0x57 * 128^1 + 0x63 = 11235 
	0x01,     //# 0x1 = 1 
	0x01,     //# 0x1 = 1 
	0x02,     //# 0x2 = 2 
	0x01,     //# 0x1 = 1 : full OID = 1.2.156.11235.1.1.2.1 = elliptic curve parameters 
};

const u8_t WAI_HASH_ALGORITHM_ID = 1u;
const u8_t WAI_SIGNATURE_ALGORITHM_ID = 1u;
const u8_t WAI_SIGNATURE_PARAMETER_ID = 1u;

const u8_t WAI_EC_POINT_TYPE_NO_COMPRESSION_ID = 4u;

const u8_t WAPI_ORGANIZATIONAL_UNIT_NAME_OID_PARAMETER[] =
{
	0x06, 0x03, //# U, P, 0x06 = OBJECT IDENTIFIER, length 0x03 = 3 octets
	0x55,       //# = 85 = 40 * 2 + 5 => 2.5
	0x04,       //# 0x4 = 4
	0x0b,     //# 0xb = 11 : full OID = 2.5.4.11 = organizational unit name 
};

const u8_t WAPI_COMMON_NAME_OID_PARAMETER[] =
{
	0x06, 0x03, //# U, P, 0x06 = OBJECT IDENTIFIER, length 0x03 = 3 octets
	0x55,       //# = 85 = 40 * 2 + 5 => 2.5
	0x04,       //# 0x4 = 4
	0x03,     //# 0x3 = 3 : full OID = 2.5.4.3 = common name 
};

//----------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

#endif //#if !defined(_WAPI_TYPES_H_)


// End.
