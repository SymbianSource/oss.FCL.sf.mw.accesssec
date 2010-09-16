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
* %version: 45.1.4 %
*/

#if !defined(_TLS_PEAP_TYPES_H_)
#define _TLS_PEAP_TYPES_H_

#include "eap_buffer.h"
#include "eap_tools.h"
#include "eap_am_tools.h"
#include "eap_type_all_types.h"
#include "eap_configuration_field.h"

#if defined(USE_FAST_EAP_TYPE)
	#include "eap_fast_types.h"
#endif //#if defined(USE_FAST_EAP_TYPE)

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_TLS_PEAP_TYPES_H)
	#define EAP_CLASS_VISIBILITY_TLS_PEAP_TYPES_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_TLS_PEAP_TYPES_H 
	#define EAP_C_FUNC_VISIBILITY_TLS_PEAP_TYPES_H 
	#define EAP_FUNC_EXPORT_TLS_PEAP_TYPES_H 
	#define EAP_C_FUNC_EXPORT_TLS_PEAP_TYPES_H 
#elif defined(EAP_EXPORT_TLS_PEAP_TYPES_H)
	#define EAP_CLASS_VISIBILITY_TLS_PEAP_TYPES_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_TLS_PEAP_TYPES_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_PEAP_TYPES_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_TLS_PEAP_TYPES_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_TLS_PEAP_TYPES_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_TLS_PEAP_TYPES_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_TLS_PEAP_TYPES_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_PEAP_TYPES_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_TLS_PEAP_TYPES_H 
	#define EAP_C_FUNC_EXPORT_TLS_PEAP_TYPES_H 
#endif
// End: added by script change_export_macros.sh.


/** @file tls_peap_types.h 
 *  @brief This file defines the constants of the TLS and PEAP.
 */

//--------------------------------------------------

/// Macro traces payload type and data.
#define EAP_TLS_PEAP_TRACE_PAYLOAD(prefix, payload, is_client) \
	{ \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n"))); \
		EAP_TRACE_DEBUG( \
			m_am_tools, \
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("- %s (0x%08x): %s, current payload 0x%04x=%s, data length 0x%04x.\n"), \
			prefix, (payload), (is_client == true ? "client": "server"), (payload)->get_flag_tlv_type(), \
			(payload)->get_tlv_type_string(), (payload)->get_data_length())); \
		EAP_TRACE_DATA_DEBUG( \
			m_am_tools, \
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("- payload"), \
			(payload)->get_header_buffer( \
				(payload)->get_header_length()+(payload)->get_data_length()), \
			(payload)->get_header_length()+(payload)->get_data_length())); \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n"))); \
	}

#define EAP_TLS_PEAP_TRACE_TTLS_PAYLOAD(prefix, payload, is_client) \
	{ \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n"))); \
		EAP_TRACE_DEBUG( \
			m_am_tools, \
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("- %s (0x%08x): %s, current payload 0x%08x:0x%08x=%s, data length 0x%04x.\n"), \
			prefix, (payload), (is_client == true ? "client": "server"), (payload)->get_avp_code().get_vendor_id(), \
			(payload)->get_avp_code().get_vendor_code(), \
			(payload)->get_avp_code_string(), (payload)->get_data_length())); \
		EAP_TRACE_DATA_DEBUG( \
			m_am_tools, \
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("- payload"), \
			(payload)->get_header_buffer( \
				(payload)->get_header_length()+(payload)->get_data_length()), \
			(payload)->get_header_length()+(payload)->get_data_length())); \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n"))); \
	}

//--------------------------------------------------

/**
 * This is the size of the local send buffer.
 */
const u32_t TLS_PEAP_LOCAL_PACKET_BUFFER_LENGTH = EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH;

/**
 * This is the default size of the TLS-record buffer.
 */
const u32_t TLS_PEAP_DEFAULT_RECORD_LENGTH = 4096ul;

/**
 * This is the maximum size of the TLS-record fragment.
 */
const u32_t TLS_PEAP_MAX_RECORD_FRAGMENT_LENGTH = (2ul << 13); // 2^14 bytes = 16384 bytes.

/**
 * This is the maximum size of the TLS-handshake message.
 */
const u32_t TLS_PEAP_MAX_HANDSHAKE_DATA_LENGTH = (2ul << 23) - 1ul; // (2^24 - 1) bytes = 16777215 bytes.

/**
 * This is the default trace mask for TLS and PEAP.
 */
const u32_t TRACE_FLAGS_TLS_PEAP_ERROR = eap_am_tools_c::eap_trace_mask_error;


/**
 * This is the size of the TLS-hello random.
 */
const u32_t TLS_HANDSHAKE_RANDOM_VALUE_SIZE = 32ul;

/**
 * This is the size of the TLS-session ID.
 */
const u32_t TLS_SESSION_ID_SIZE = 32ul;

/**
 * This is the size of the TLS-premaster secret.
 */
const u32_t TLS_PREMASTER_SECRET_SIZE = 48ul;

/**
 * This is the size of the TLS-master secret.
 */
const u32_t TLS_MASTER_SECRET_SIZE = 48ul;


enum tls_peap_protocol_field_size_e
{
	TLS_ALERT_DESCRIPTION_FIELD_SIZE = sizeof(u8_t),
	TLS_ALERT_LEVEL_FIELD_SIZE = sizeof(u8_t),
	TLS_CERTIFICATE_AUTHORITIES_LENGTH_FIELD_SIZE = sizeof(u16_t),
	TLS_CERTIFICATE_LENGTH_FIELD_SIZE = 3UL*sizeof(u8_t),
	TLS_CERTIFICATE_TYPE_FIELD_SIZE = sizeof(u8_t),
	TLS_CERTIFICATE_TYPE_LENGTH_FIELD_SIZE = sizeof(u8_t),
	TLS_CHANGE_CIPHER_SPEC_FIELD_SIZE = sizeof(u8_t),
	TLS_CIPHER_SUITE_FIELD_SIZE = sizeof(u16_t),
	TLS_CIPHER_SUITE_LENGTH_FIELD_SIZE = sizeof(u16_t),
	TLS_COMPRESSION_FIELD_SIZE = sizeof(u8_t),
	TLS_COMPRESSION_LENGTH_FIELD_SIZE = sizeof(u8_t),
	TLS_COMPRESSION_METHOD_FIELD_SIZE = sizeof(u8_t),
	TLS_EXTENSIONS_LENGTH_FIELD_SIZE = sizeof(u16_t),
	TLS_EXTENSION_TYPE_FIELD_SIZE = sizeof(u16_t),
	TLS_EXTENSION_DATA_LENGTH_FIELD_SIZE = sizeof(u16_t),
	TLS_DHE_GROUP_GENERATOR_LENGTH_FIELD_SIZE = sizeof(u16_t),
	TLS_DHE_PRIME_LENGTH_FIELD_SIZE = sizeof(u16_t),
	TLS_ENCRYPTED_PREMASTER_SECRET_LENGTH_FIELD_SIZE = sizeof(u16_t),
	TLS_PADDINF_LENGTH_FIELD_SIZE = sizeof(u8_t),
	TLS_PUBLIC_DHE_KEY_LENGTH_FIELD_SIZE = sizeof(u16_t),
	TLS_PUBLIC_DHE_KEY_LENGTH_LENGTH_FIELD_SIZE = sizeof(u16_t),
	TLS_DSS_SHA1_SIGNATURE_LENGTH_FIELD_SIZE = sizeof(u16_t),
	TLS_SESSION_ID_LENGTH_FIELD_SIZE = sizeof(u8_t),
	TLS_SIGNATURE_LENGTH_FIELD_SIZE = sizeof(u16_t),
	TLS_VERSION_FIELD_SIZE = sizeof(u16_t),
	TLS_SESSION_TICKET_LIFETIME_HINT_FIELD_SIZE = sizeof(u32_t),
};


/**
 * This is the label of the TLS-premaster secret.
 * See Chapter "8.1. Computing the master secret" in <a href="../../type/tls_peap/documentation/rfc2246.txt">RFC 2246</a>.
 */
const u8_t TLS_MASTER_SECRET_LABEL[] = "master secret";

/**
 * This is the length of the label of the TLS-premaster secret.
 */
const u32_t TLS_MASTER_SECRET_LABEL_LENGTH = sizeof(TLS_MASTER_SECRET_LABEL)-1ul;


/**
 * This is the label of the TLS-client finished message.
 * See Chapter "7.4.9. Finished" in <a href="../../type/tls_peap/documentation/rfc2246.txt">RFC 2246</a>.
 */
const u8_t TLS_CLIENT_FINISHED_LABEL[] = "client finished";

/**
 * This is the length of the label of the TLS-client finished message.
 */
const u32_t TLS_CLIENT_FINISHED_LABEL_LENGTH = sizeof(TLS_CLIENT_FINISHED_LABEL)-1ul;

/**
 * This is the label of the TLS-server finished message.
 * See Chapter "7.4.9. Finished" in <a href="../../type/tls_peap/documentation/rfc2246.txt">RFC 2246</a>.
 */
const u8_t TLS_SERVER_FINISHED_LABEL[] = "server finished";

/**
 * This is the length of the label of the TLS-server finished message.
 */
const u32_t TLS_SERVER_FINISHED_LABEL_LENGTH = sizeof(TLS_SERVER_FINISHED_LABEL)-1ul;

/**
 * This is the length of the data of the TLS-finished message.
 */
const u32_t TLS_FINISHED_DATA_SIZE = 12ul;


/**
 * This is the label of the TLS-key expansion function.
 * See Chapter "6.3. Key calculation" in <a href="../../type/tls_peap/documentation/rfc2246.txt">RFC 2246</a>.
 */
const u8_t TLS_PEAP_KEY_EXPANSION_LABEL[] = "key expansion";

/**
 * This is the length of the label of the TLS-key expansion function.
 */
const u32_t TLS_PEAP_KEY_EXPANSION_LABEL_LENGTH = sizeof(TLS_PEAP_KEY_EXPANSION_LABEL)-1ul;


/**
 * This is the label of the TTLS-key expansion function.
 * See Chapter "7. Generating Keying Material" in <a href="../../type/tls_peap/documentation/draft-funk-eap-ttls-v0-00.txt">EAP-TTLSv0</a>.
 */
const u8_t EAP_TTLS_KEY_EXPANSION_LABEL[] = "ttls keying material";

/**
 * This is the length of the label of the TTLS-key expansion function.
 */
const u32_t EAP_TTLS_KEY_EXPANSION_LABEL_LENGTH = sizeof(EAP_TTLS_KEY_EXPANSION_LABEL)-1ul;


/**
 * This is the label of the TTLS implicit challenge function.
 * See Chapter "10.1 Implicit challenge" in <a href="../../type/tls_peap/documentation/draft-funk-eap-ttls-v0-00.txt">EAP-TTLSv0</a>.
 */
const u8_t EAP_TTLS_IMPLICIT_CHALLENGE_LABEL[] = "ttls challenge";

/**
 * This is the length of the label of the TTLS implicit challenge function.
 */
const u32_t EAP_TTLS_IMPLICIT_CHALLENGE_LABEL_LENGTH = sizeof(EAP_TTLS_IMPLICIT_CHALLENGE_LABEL)-1ul;



const u8_t EAP_TLS_PEAP_CLIENT_ENCRYPTION_LABEL_V1_DRAFT_5[] = "client PEAP encryption";

const u32_t EAP_TLS_PEAP_CLIENT_ENCRYPTION_LABEL_V1_DRAFT_5_LENGTH = sizeof(EAP_TLS_PEAP_CLIENT_ENCRYPTION_LABEL_V1_DRAFT_5)-1ul;


const u8_t EAP_TLS_PEAP_CLIENT_ENCRYPTION_LABEL[] = "client EAP encryption";

const u32_t EAP_TLS_PEAP_CLIENT_ENCRYPTION_LABEL_LENGTH = sizeof(EAP_TLS_PEAP_CLIENT_ENCRYPTION_LABEL)-1ul;

const u32_t EAP_TLS_PEAP_MSK_SIZE = 64ul;
const u32_t EAP_TLS_PEAP_EMSK_SIZE = 64ul;
const u32_t EAP_TLS_PEAP_MASTER_SESSION_KEY_SIZE = EAP_TLS_PEAP_MSK_SIZE + EAP_TLS_PEAP_EMSK_SIZE;


/**
 * This is the label of the PEAPv2 Intermediate Combined Key.
 * See Chapter "2.5.  Key derivation" in <a href="../../type/tls_peap/documentation/draft-josefsson-pppext-eap-tls-eap-07.txt">PEAPv2 draft 07</a>.
 */
const u8_t TLS_INTERMEDIATE_COMBINED_KEY_LABEL[] = "Intermediate PEAP MAC key";

/**
 * This is the length of the label of the PEAPv2 Intermediate Combined Key.
 */
const u32_t TLS_INTERMEDIATE_COMBINED_KEY_LABEL_LENGTH = sizeof(TLS_INTERMEDIATE_COMBINED_KEY_LABEL)-1ul;


/**
 * This is the label of the PEAPv2 Compound Server MAC Key.
 * See Chapter "2.5.  Key derivation" in <a href="../../type/tls_peap/documentation/draft-josefsson-pppext-eap-tls-eap-07.txt">PEAPv2 draft 07</a>.
 */
const u8_t TLS_INTERMEDIATE_COMPOUND_SERVER_MAC_KEY_LABEL[] = "PEAP Server B1 MAC key";

/**
 * This is the length of the label of the PEAPv2 Compound Server MAC Key.
 */
const u32_t TLS_INTERMEDIATE_COMPOUND_SERVER_MAC_KEY_LABEL_LENGTH = sizeof(TLS_INTERMEDIATE_COMPOUND_SERVER_MAC_KEY_LABEL)-1ul;


/**
 * This is the label of the PEAPv2 Compound Client MAC Key.
 * See Chapter "2.5.  Key derivation" in <a href="../../type/tls_peap/documentation/draft-josefsson-pppext-eap-tls-eap-07.txt">PEAPv2 draft 07</a>.
 */
const u8_t TLS_INTERMEDIATE_COMPOUND_CLIENT_MAC_KEY_LABEL[] = "PEAP Client B2 MAC key";

/**
 * This is the length of the label of the PEAPv2 Compound Client MAC Key.
 */
const u32_t TLS_INTERMEDIATE_COMPOUND_CLIENT_MAC_KEY_LABEL_LENGTH = sizeof(TLS_INTERMEDIATE_COMPOUND_CLIENT_MAC_KEY_LABEL)-1ul;


/**
 * This is the label of the PEAPv2 Compound Session Key.
 * See Chapter "2.5.  Key derivation" in <a href="../../type/tls_peap/documentation/draft-josefsson-pppext-eap-tls-eap-07.txt">PEAPv2 draft 07</a>.
 */
const u8_t TLS_INTERMEDIATE_COMPOUND_SESSION_KEY_LABEL[] = "PEAP compound session key";

/**
 * This is the length of the label of the PEAPv2 Compound Session Key.
 */
const u32_t TLS_INTERMEDIATE_COMPOUND_SESSION_KEY_LABEL_LENGTH = sizeof(TLS_INTERMEDIATE_COMPOUND_SESSION_KEY_LABEL)-1ul;


/**
 * This is the length of the RC4 key used in TLS.
 */
const u32_t TLS_RC4_128_KEY_LENGTH = 16ul;

/**
 * This is the length of the RC4 initialization vector used in TLS.
 */
const u32_t TLS_RC4_128_IV_LENGTH = 0ul;


/**
 * The supported TLS-cipher suites are defined here.
 */
enum tls_cipher_suites_e
{
	tls_cipher_suites_TLS_NULL_WITH_NULL_NULL = (0x0000), ///< No key exchange, no encryption and no authentication.
	tls_cipher_suites_TLS_RSA_WITH_RC4_128_MD5 = (0x0004), ///< RSA key exchange, RC4_128 encryption and MD5 authentication. NOTE this is included only because PEAP requires this cipher suite as a mandatory. Think carefully whether this meets your security requirements.
	tls_cipher_suites_TLS_RSA_WITH_RC4_128_SHA = (0x0005), ///< RSA key exchange, RC4_128 encryption and SHA1 authentication. NOTE this is included only because PEAP requires this cipher suite as a mandatory. Think carefully whether this meets your security requirements.
	tls_cipher_suites_TLS_RSA_WITH_3DES_EDE_CBC_SHA = (0x000a), ///< RSA key exchange, 3DES-EDE-CBC encryption and SHA1 authentication.
	// not supported: tls_cipher_suites_TLS_RSA_WITH_DES_CBC_SHA = (0x0009),
	tls_cipher_suites_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = (0x0016), ///< Diffie-Helmann RSA key exchange, 3DES-EDE-CBC encryption and SHA1 authentication.
	// not supported: tls_cipher_suites_TLS_RSA_EXPORT1024_WITH_RC4_56_SHA = (0x0064),
	// not supported: tls_cipher_suites_TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA = (0x0062),
	// not supported: tls_cipher_suites_TLS_RSA_EXPORT_WITH_RC4_40_MD5 = (0x0003),
	// not supported: tls_cipher_suites_TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = (0x0006),
	tls_cipher_suites_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = (0x0013), ///< Diffie-Helmann DSS key exchange, 3DES-EDE-CBC encryption and SHA1 authentication.
	// not supported: tls_cipher_suites_TLS_DHE_DSS_WITH_DES_CBC_SHA = (0x0012),
	// not supported: tls_cipher_suites_TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA = (0x0063),
	tls_cipher_suites_TLS_RSA_WITH_AES_128_CBC_SHA      = 0x002F, ///< RSA key exchange, AES-128 encryption and SHA1 authentication.
	// not supported: tls_cipher_suites_TLS_DH_DSS_WITH_AES_128_CBC_SHA   = 0x0030,
	// not supported: tls_cipher_suites_TLS_DH_RSA_WITH_AES_128_CBC_SHA   = 0x0031,
	tls_cipher_suites_TLS_DHE_DSS_WITH_AES_128_CBC_SHA  = 0x0032, ///< Diffie-Helmann DSS key exchange, AES-128-CBC encryption and SHA1 authentication.
	tls_cipher_suites_TLS_DHE_RSA_WITH_AES_128_CBC_SHA  = 0x0033, ///< Diffie-Helmann RSA key exchange, AES-128-CBC encryption and SHA1 authentication.
#if defined(USE_FAST_EAP_TYPE)
	tls_cipher_suites_TLS_DH_anon_WITH_AES_128_CBC_SHA  = 0x0034, ///< Diffie-Helmann anonymous key exchange, AES-128-CBC encryption and SHA1 authentication.
#endif //#if defined(USE_FAST_EAP_TYPE)
	// not supported: tls_cipher_suites_TLS_DH_anon_WITH_AES_128_CBC_SHA  = 0x0034,

	tls_cipher_suites_none = (0xffff), ///< Internally used initialization value. This means no cipher suite is selected.
};


/**
 * The supported certificate types are defined here.
 */
enum tls_certificate_type_e
{
	tls_certificate_type_rsa_sign = (1), ///< RSA 
	tls_certificate_type_dss_sign = (2), ///< DSS
	// not supported: tls_certificate_type_rsa_fixed_dh = (3),
	// not supported: tls_certificate_type_dss_fixed_dh = (4),
	tls_certificate_type_none = (255), ///< Internally used value.
};


/**
 * The supported compression methods are defined here.
 */
enum tls_compression_method_e
{
	tls_compression_method_null = (0), ///< No compression.
	tls_compression_method_none = (255), ///< Internally used value.
};


/**
 * These are the internal TLS-states.
 */
enum tls_peap_state_e
{
	tls_peap_state_none, ///< Initialization value.
	tls_peap_state_wait_tls_start, ///< Waits start of TLS.
	tls_peap_state_wait_handshake_type_client_hello, ///< Waits TLS-handshake ClientHello.
	tls_peap_state_wait_handshake_type_server_hello, ///< Waits TLS-handshake ServerHello.
	tls_peap_state_wait_handshake_type_certificate, ///< Waits TLS-handshake Certificate.
	tls_peap_state_wait_handshake_type_server_key_exchange, ///< Waits TLS-handshake ServerKeyExchange.
	tls_peap_state_wait_handshake_type_certificate_request_or_server_hello_done, ///< Waits TLS-handshake CertificateRequest.
	tls_peap_state_wait_handshake_type_server_hello_done, ///< Waits TLS-handshake ServerHelloDone.
	tls_peap_state_wait_handshake_type_client_key_exchange, ///< Waits TLS-handshake ClientKeyExchange.
	tls_peap_state_wait_handshake_type_certificate_verify, ///< Waits TLS-handshake CertificateVerify.
	tls_peap_state_wait_handshake_type_finished, ///< Waits TLS-handshake Finished.
#if defined(USE_EAP_TLS_SESSION_TICKET)
	tls_peap_state_wait_handshake_type_new_session_ticket, ///< Waits TLS-handshake NewSessionTicket.
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
	tls_peap_state_wait_change_cipher_spec, ///< Waits TLS-ChangeCipherSpec
	tls_peap_state_peap_tunnel_ready, ///< PEAP tunnel ready.
	tls_peap_state_full_authentication, ///< Full TLS/PEAP authentication is running. 
	tls_peap_state_original_session_resumption, ///< Saved TLS/PEAP original session is being resumed.
#if defined(USE_EAP_TLS_SESSION_TICKET)
	tls_peap_state_stateless_session_resumption, ///< Saved stateless TLS/PEAP session is being resumed, see RFC 4507.
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
	tls_peap_state_tppd_peapv1_waits_eap_success_or_tunneled_packet, ///< PEAPv1 waits EAP-Success or tunneled packet.
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	tls_peap_state_client_send_ttls_plain_ms_chap_v2_empty_ack,
	tls_peap_state_server_waits_ttls_plain_ms_chap_v2_empty_ack,
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	tls_peap_state_wait_tunneled_authentication_start, ///< Server waits the lower layer start tunneled authentication.
	tls_peap_state_wait_application_data, ///< Waits TLS-ApplicationData, this will include the tunneled EAP-type.
	tls_peap_state_process_pending_tls_completions, ///< This is state process the pending completions.
	tls_peap_state_pending_tls_messages_processed, ///< This is indication to lower layer that pending TLS-messages are processed, new messages could be accepted.
	tls_peap_state_tls_success, ///< TLS authentication success.
	tls_peap_state_failure, ///< Authentication failure.
	tls_peap_state_peap_tunnel_ready_wait_request, ///< Tunnel ready waits new request.
};

enum tls_identity_privacy_handshake_state_e
{
	tls_identity_privacy_handshake_state_none,
	tls_identity_privacy_handshake_state_negotiates,
	tls_identity_privacy_handshake_state_runs,
};

/**
 * This enumeration tells which authentication mode is used.
 */
enum tls_session_type_e
{
	tls_session_type_none, ///< Initial value.
	tls_session_type_full_authentication, ///< Full authentication is performed.
	tls_session_type_original_session_resumption, ///< Session is being resumed.
	tls_session_type_stateless_session_resumption, ///< Stateless session is being resumed, see RFC 4507.
#if defined(USE_FAST_EAP_TYPE)
	tls_session_type_eap_fast_pac_session_resumption, ///< EAP-FAST stateless session using PAC is being resumed, see RFC 4851.
	tls_session_type_eap_fast_server_unauthenticated_provisioning_mode_ADHP, ///< EAP-FAST server unauthenticated provisioning mode (ADHP), see draft-cam-winget-eap-fast-provisioning-**.
#endif //#if defined(USE_FAST_EAP_TYPE)
};

/**
 * This enumeration separates the different PEAP versions.
 */
enum peap_version_e
{
	peap_version_0_xp = 0x00, ///< This version is specified in <a href="../../type/tls_peap/documentation/draft-kamath-pppext-peapv0-00.txt">draft-kamath-pppext-peapv0-00.txt</a>.
	peap_version_1    = 0x01, ///< This version is specified in <a href="../../type/tls_peap/documentation/draft-josefsson-pppext-eap-tls-eap-05.txt">draft-josefsson-pppext-eap-tls-eap-05.txt</a>.
	peap_version_2    = 0x02, ///< This version is specified in <a href="../../type/tls_peap/documentation/draft-josefsson-pppext-eap-tls-eap-07.txt">draft-josefsson-pppext-eap-tls-eap-07.txt</a>. This is not implemented yet.
	peap_version_none = 0xff,
};

enum eap_ttls_tunneled_message_type_e
{
	eap_ttls_tunneled_message_type_none,
	eap_ttls_tunneled_message_type_eap, ///< Client and server handles these messages.
	eap_ttls_tunneled_message_type_ms_chapv2_response, ///< Client sends and server handles these messages.
	eap_ttls_tunneled_message_type_ms_chapv2_change_password, ///< Client sends and server handles these messages.
	eap_ttls_tunneled_message_type_ms_chapv2_success, ///< Server sends and client handles these messages.
	eap_ttls_tunneled_message_type_ms_chapv2_error, ///< Server sends and client handles these messages.
	eap_ttls_tunneled_message_type_pap_response, ///< Client sends and server handles these messages.
	eap_ttls_tunneled_message_type_pap_reply_message, ///< Server sends and client handles these messages.
};

enum eap_ttls_tunneled_message_state_e
{
	eap_ttls_tunneled_message_state_none,
	eap_ttls_tunneled_message_state_process_identity_response,
	eap_ttls_tunneled_message_state_process_response,
	eap_ttls_tunneled_message_state_process_change_password_response,
	eap_ttls_tunneled_message_state_process_identity_request,
	eap_ttls_tunneled_message_state_process_identity_request_pending,
	eap_ttls_tunneled_message_state_process_challenge_request,
	eap_ttls_tunneled_message_state_process_success_request,
	eap_ttls_tunneled_message_state_complete_success_request,
	eap_ttls_tunneled_message_state_process_error_request,
	eap_ttls_tunneled_message_state_complete_error_request,
};


const u32_t EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_OFFSET = 0ul;
const u32_t EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_LENGTH = 16ul;

const u32_t EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_IDENT_OFFSET = EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_LENGTH;
const u32_t EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_IDENT_LENGTH = 1ul;

const u32_t EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_FULL_LENGTH
	= EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_LENGTH
	+ EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_IDENT_LENGTH;


//--------------------------------------------------------------------

enum tls_alert_level_e
{
	tls_alert_level_warning = (1),	///< if an alert with a level of warning is received,
									///< the receiving party may decide at its discretion whether to treat this as
									///< a fatal error or not.
	tls_alert_level_fatal = (2),	///< Alert messages with a level of fatal result
									///< in the immediate termination of the connection. In this case, other
									///< connections corresponding to the session may continue, but the
									///< session identifier must be invalidated, preventing the failed session
									///< from being used to establish new connections.
									///< All messages which are transmitted
									///< with a level of fatal must be treated as fatal messages.
	tls_alert_level_none = (255)
};

enum tls_alert_description_e
{
	tls_alert_description_close_notify = (0),	///< This message notifies the recipient that the sender will not send
												///< any more messages on this connection. The session becomes
												///< unresumable if any connection is terminated without proper
												///< close_notify messages with level equal to warning.

	tls_alert_description_unexpected_message = (10),	///< This message is always fatal. An inappropriate message was received.
														///< and should never be observed in communication between proper
														///< implementations.

	tls_alert_description_bad_record_mac = (20),	///< This message is always fatal.
													///<This alert is returned if a record is received with an incorrect MAC.

	tls_alert_description_decryption_failed = (21), ///< This message is always fatal.
													///< A TLSCiphertext decrypted in an invalid way: either it wasn`t an
													///< even multiple of the block length or its padding values, when
													///< checked, weren`t correct.

	tls_alert_description_record_overflow = (22),	///< This message is always fatal.
													///< A TLSCiphertext record was received which had a length more than
													///< 2^14+2048 bytes, or a record decrypted to a TLSCompressed record
													///< with more than 2^14+1024 bytes.

	tls_alert_description_decompression_failure = (30),	///< This message is always fatal.
														///< The decompression function received improper input (e.g. data
														///< that would expand to excessive length).

	tls_alert_description_handshake_failure = (40),	///< This message is always fatal.
													///< Reception of a handshake_failure alert message indicates that the
													///< sender was unable to negotiate an acceptable set of security
													///< parameters given the options available.

	tls_alert_description_bad_certificate = (42),	///< A certificate was corrupt, contained signatures that did not
													///< verify correctly, etc.

	tls_alert_description_unsupported_certificate = (43), ///< A certificate was of an unsupported type.

	tls_alert_description_certificate_revoked = (44), ///< A certificate was revoked by its signer.

	tls_alert_description_certificate_expired = (45), ///< A certificate has expired or is not currently valid.

	tls_alert_description_certificate_unknown = (46),	///< Some other (unspecified) issue arose in processing the
														///< certificate, rendering it unacceptable.

	tls_alert_description_illegal_parameter = (47), ///< This message is always fatal.
													///< A field in the handshake was out of range or inconsistent with
													///< other fields. This is always fatal.

	tls_alert_description_unknown_ca = (48),	///< This message is always fatal.
												///< A valid certificate chain or partial chain was received, but the
												///< certificate was not accepted because the CA certificate could not
												///< be located or couldn`t be matched with a known, trusted CA.

	tls_alert_description_access_denied = (49), ///< This message is always fatal.
												///< A valid certificate was received, but when access control was
												///< applied, the sender decided not to proceed with negotiation.

	tls_alert_description_decode_error = (50), ///< This message is always fatal.
												///< A message could not be decoded because some field was out of the
												///< specified range or the length of the message was incorrect. This
												///< message is always fatal.

	tls_alert_description_decrypt_error = (51), ///< A handshake cryptographic operation failed, including being
												///< unable to correctly verify a signature, decrypt a key exchange,
												///< or validate a finished message.

	tls_alert_description_export_restriction = (60), ///< This message is always fatal.
													///< A negotiation not in compliance with export restrictions was
													///< detected, for example, attempting to transfer a 1024 bit
													///< ephemeral RSA key for the RSA_EXPORT handshake method.

	tls_alert_description_protocol_version = (70), ///< This message is always fatal.
													///< The protocol version the client has attempted to negotiate is
													///< recognized, but not supported. (For example, old protocol
													///< versions might be avoided for security reasons).

	tls_alert_description_insufficient_security = (71), ///< This message is always fatal.
														///< Returned instead of handshake_failure when a negotiation has
														///< failed specifically because the server requires ciphers more
														///< secure than those supported by the client.

	tls_alert_description_internal_error = (80), ///< This message is always fatal.
												///< An internal error unrelated to the peer or the correctness of the
												///< protocol makes it impossible to continue (such as a memory
												///< allocation failure).

	tls_alert_description_user_canceled = (90), ///< This handshake is being canceled for some reason unrelated to a
												///< protocol failure. If the user cancels an operation after the
												///< handshake is complete, just closing the connection by sending a
												///< close_notify is more appropriate. This alert should be followed
												///< by a close_notify. This message is generally a warning.

	tls_alert_description_no_renegotiation = (100), ///< Sent by the client in response to a hello request or by the
													///< server in response to a client hello after initial handshaking.
													///< Either of these would normally lead to renegotiation, when that
													///< is not appropriate, the recipient should respond with this alert,
													///< at that point, the original requester can decide whether to
													///< proceed with the connection. One case where this would be
													///< appropriate would be where a server has spawned a process to
													///< satisfy a request, the process might receive security parameters
													///< (key length, authentication, etc.) at startup and it might be
													///< difficult to communicate changes to these parameters after that
													///< point. This message is always a warning.

	tls_alert_description_none = (255) ///< This value is used on initialization and where special alert description is not used.
};

//----------------------------------------------------------------------------

/**
 *  @defgroup TLS_PEAP_config_options Configuration options of TLS_PEAP.
 *  The following configuration options are read through abs_eap_base_type_c::read_configure() function.
 *  @{
 */

/**
 *  This is boolean configuration option.
 *  True value means on TLS-messages are set to separate TLS-records.
 *  False value means on TLS-messages are combined to same TLS-records if possible.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_TLS_use_separate_tls_record,
	"TLS_use_separate_tls_record",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  True value means on TLS-server offers new session ID to client.
 *  False value means on TLS-server does not offer new session id to client.
 *  Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_TLS_server_offers_new_session_id,
	"TLS_server_offers_new_session_id",
	eap_configure_type_boolean,
	false);

/**
 *  NOTE this is against the RFC 2246 The TLS Protocol Version 1.0.
 *  Look at chapter 7.4.4. Certificate request.
 *  This is implemented for IOP reason.
 *  This is boolean configuration option.
 *  True value means client accepts an empty certificate authority list.
 *  False value means client does NOT accept an empty certificate authority list.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_TLS_client_allows_empty_certificate_authorities_list,
	"TLS_client_allows_empty_certificate_authorities_list",
	eap_configure_type_boolean,
	false);

/**
 *  NOTE this is against the RFC 2246 The TLS Protocol Version 1.0.
 *  Look at chapter 7.4.4. Certificate request.
 *  This is implemented for IOP reason.
 *  This is boolean configuration option.
 *  True value means server sends an empty certificate authority list.
 *  False value means server does NOT send an empty certificate authority list.
 *  Default value is false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_TLS_server_sends_empty_certificate_authorities_list,
	"TLS_server_sends_empty_certificate_authorities_list",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * True value means server initiates mutual authentication.
 * False value means server initiates server only authentication.
 * Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_TLS_server_authenticates_client,
	"TLS_server_authenticates_client",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * True value means the client requires mutual authentication.
 * False value means the client does NOT require mutual authentication,
 * instead client allows server only authentication.
 * Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_TLS_server_authenticates_client_policy_in_client,
	"TLS_server_authenticates_client_policy_in_client",
	eap_configure_type_boolean,
	false);

/**
 * This is boolean configuration option.
 * True value means the server requires mutual authentication.
 * False value means the server does NOT require mutual authentication,
 * instead server allows server only authentication.
 * Default value is true.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_TLS_server_authenticates_client_policy_in_server,
	"TLS_server_authenticates_client_policy_in_server",
	eap_configure_type_boolean,
	false);

/**
 *  This is u32_t or hex data configuration option.
 *  THis is the tunneled EAP-type run inside PEAP.
 *  Default value is eap_type_none.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_PEAP_tunneled_eap_type_hex_data,
	"PEAP_tunneled_eap_type",
	eap_configure_type_hex_data,
	false);
EAP_CONFIGURATION_FIELD(
	cf_str_PEAP_tunneled_eap_type_u32_t,
	"PEAP_tunneled_eap_type",
	eap_configure_type_u32_t,
	false);

/**
 *  This option defines default EAP-type of EAP-server inside the PEAP.
 *  Reason for this is we could test EAP-Core in a case where
 *  EAP-client and EAP-server have different default EAP-types inside the PEAP.
 *  If this is not defined EAP-server uses PEAP_tunneled_eap_type option.
 *  This is u32_t or hex data configuration option.
 *  THis is the tunneled EAP-type run inside PEAP.
 *  Default value is eap_type_none.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_PEAP_server_tunneled_eap_type_hex_data,
	"PEAP_server_tunneled_eap_type",
	eap_configure_type_hex_data,
	false);
EAP_CONFIGURATION_FIELD(
	cf_str_PEAP_server_tunneled_eap_type_u32_t,
	"PEAP_server_tunneled_eap_type",
	eap_configure_type_u32_t,
	false);

/** @} */ // End of group TLS_PEAP_config_options.
//--------------------------------------------------------------------


/// This class includes the debug strings of the tls_cipher_suites_e, tls_certificate_type_e and tls_compression_method_e.
class EAP_CLASS_VISIBILITY_TLS_PEAP_TYPES_H eap_tls_trace_string_c
{
public:

	EAP_FUNC_VISIBILITY_TLS_PEAP_TYPES_H virtual ~eap_tls_trace_string_c();

	EAP_FUNC_VISIBILITY_TLS_PEAP_TYPES_H eap_tls_trace_string_c();

#if defined(USE_FAST_EAP_TYPE)
	/**
	 * Function returns string of eap_fast_state_e.
	 * @param state is the queried string.
	 */
	EAP_FUNC_VISIBILITY_TLS_PEAP_TYPES_H static eap_const_string get_eap_fast_state_string(const eap_fast_state_e state);
#endif //#if defined(USE_FAST_EAP_TYPE)

	/**
	 * Function returns string of tls_cipher_suites_e.
	 * @param suite is the queried string.
	 */
	EAP_FUNC_VISIBILITY_TLS_PEAP_TYPES_H static eap_const_string get_cipher_suite_string(const tls_cipher_suites_e suite);

	/**
	 * Function returns string of tls_certificate_type_e.
	 * @param suite is the queried string.
	 */
	EAP_FUNC_VISIBILITY_TLS_PEAP_TYPES_H static eap_const_string get_certificate_type_string(const tls_certificate_type_e certificate_type);

	/**
	 * Function returns string of tls_compression_method_e.
	 * @param suite is the queried string.
	 */
	EAP_FUNC_VISIBILITY_TLS_PEAP_TYPES_H static eap_const_string get_compression_method_string(const tls_compression_method_e compression_method);

	/**
	 * Function returns string of tls_peap_state_e.
	 * @param state is the queried string.
	 */
	EAP_FUNC_VISIBILITY_TLS_PEAP_TYPES_H static eap_const_string get_state_string(const tls_peap_state_e state);

	/**
	 * Function returns string of peap_version_e.
	 * @param peap_version is the queried string.
	 */
	EAP_FUNC_VISIBILITY_TLS_PEAP_TYPES_H static eap_const_string get_peap_version_string(const peap_version_e peap_version);

	/**
	 * Function returns string of tls_alert_level_e.
	 * @param alert_level is the queried string.
	 */
	EAP_FUNC_VISIBILITY_TLS_PEAP_TYPES_H static eap_const_string get_alert_level_string(const tls_alert_level_e alert_level);

	/**
	 * Function returns string of tls_alert_description_e.
	 * @param alert_level is the queried string.
	 */
	EAP_FUNC_VISIBILITY_TLS_PEAP_TYPES_H static eap_const_string get_alert_description_string(const tls_alert_description_e alert_description);

	/**
	 * Function returns string of tls_session_type_e.
	 * @param tls_session_type is the queried string.
	 */
	EAP_FUNC_VISIBILITY_TLS_PEAP_TYPES_H static eap_const_string get_tls_session_type_string(const tls_session_type_e tls_session_type);

	/**
	 * Function returns string of eap_ttls_tunneled_message_state_e.
	 * @param ttls_state is the queried string.
	 */
	EAP_FUNC_VISIBILITY_TLS_PEAP_TYPES_H static eap_const_string get_ttls_state_string(const eap_ttls_tunneled_message_state_e ttls_state);

	/**
	 * Function returns string of tls_identity_privacy_handshake_state_e.
	 * @param ttls_state is the queried string.
	 */
	EAP_FUNC_VISIBILITY_TLS_PEAP_TYPES_H static eap_const_string get_tls_identity_privacy_handshake_state_string(const tls_identity_privacy_handshake_state_e privacy_state);
};


//--------------------------------------------------

#endif //#if !defined(_TLS_PEAP_TYPES_H_)

//--------------------------------------------------



// End.
