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

#ifndef _MSCHAPV2_CORE_H_
#define _MSCHAPV2_CORE_H_

#include "eap_base_type.h"
#include "eap_crypto_api.h"
#include "eap_type_mschapv2_state.h"

#include "eap_am_network_id.h"
#include "abs_eap_am_type_mschapv2.h"
#include "eap_am_type_mschapv2.h"
#include "eap_type_mschapv2_header.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TYPE_MSCHAPV2_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_MSCHAPV2_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H 
	#define EAP_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_H 
#elif defined(EAP_EXPORT_EAP_TYPE_MSCHAPV2_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_MSCHAPV2_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_MSCHAPV2_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_H 
#endif
// End: added by script change_export_macros.sh.



/// This class is implementation of MS-CHAP-v2 EAP-type.
class EAP_CLASS_VISIBILITY_EAP_TYPE_MSCHAPV2_H eap_type_mschapv2_c
	: public abs_eap_am_type_mschapv2_c 
	, public eap_base_type_c
{

private:

	/// This is pointer to adaptation module of MS-Chap-v2 EAP type.
	eap_am_type_mschapv2_c * const m_am_type_mschapv2;

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// When eap_session_core_c is used. Each EAP type object does handle only one session.
	eap_type_mschapv2_state_c m_session;

	eap_am_network_id_c m_send_network_id;

	crypto_random_c m_rand;
	
	/// This is username and identity (UTF8)
	eap_variable_data_c m_username_utf8;

	eap_variable_data_c m_password_utf8;

	eap_variable_data_c m_old_password_utf8;

	eap_variable_data_c m_password_hash;

	eap_variable_data_c m_password_hash_hash;


#if defined(USE_FAST_EAP_TYPE)
	eap_variable_data_c m_client_EAP_FAST_challenge;

	eap_variable_data_c m_server_EAP_FAST_challenge;
#endif //#if defined(USE_FAST_EAP_TYPE)


	u8_t m_authenticator_challenge[EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE];

	u8_t m_peer_challenge[EAP_MSCHAPV2_PEER_CHALLENGE_SIZE];

	u8_t m_nt_response[EAP_MSCHAPV2_NT_RESPONSE_SIZE];

	u32_t m_offset;

	u32_t m_mtu_length;

	u32_t m_trailer_length;

	u32_t m_error_code;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/// This indicates whether this object is client (true) or server (false).
	/// In terms of EAP-protocol whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	bool m_is_client;

	bool m_free_am_type_mschapv2;

	bool m_is_pending;

	bool m_identity_asked;

	bool m_wait_eap_success;

	bool m_wait_eap_success_packet;

	bool m_is_reauthentication;
	
	bool m_is_notification_sent;

	bool m_shutdown_was_called;

	bool m_password_prompt_enabled;

	u8_t m_identifier;

	u8_t m_mschapv2id;

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	bool m_use_implicit_challenge;
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

#if defined(EAP_MSCHAPV2_SERVER)
	bool m_do_password_expiration_tests;

	bool m_password_expired;
#endif //#if defined(EAP_MSCHAPV2_SERVER)

	bool m_do_wrong_password_tests;

	bool m_use_eap_expanded_type;

#if defined(USE_FAST_EAP_TYPE)

	bool m_use_EAP_FAST_full_key;

	bool m_use_EAP_FAST_challenge;

#endif //#if defined(USE_FAST_EAP_TYPE)

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	void send_error_notification(const eap_status_e error);

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H eap_status_e finish_successful_authentication();

	eap_status_e finish_unsuccessful_authentication(
		const bool authentication_cancelled);

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H eap_status_e complete_eap_identity_query();

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H eap_status_e complete_failure_retry_response();

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H eap_status_e complete_change_password_query();

	eap_status_e client_packet_process(
		eap_header_wr_c * const eap, ///< This is pointer to EAP header and data.
		const u32_t eap_packet_length ///< This is length of received EAP packet.
		);

	eap_status_e client_mschapv2_packet_process(
	eap_header_wr_c * const received_eap,
	const u32_t eap_packet_length);

	eap_status_e client_handle_challenge_request(mschapv2_header_c &challenge_request);

	eap_status_e client_handle_success_request(mschapv2_header_c &success_request);

	eap_status_e client_handle_failure_request(mschapv2_header_c &success_request);

	eap_status_e client_send_challenge_response();


	/**
	 * This function processes the MS-CHAP-V2 packets.
	 */
	eap_status_e mschapv2_packet_process(
		eap_header_wr_c * const eap, ///< This is pointer to EAP header and data.
		const u32_t eap_packet_length ///< This is length of received EAP packet.
		);

	/**
	 * This function tells if the object is a client or a server..
	 */
	bool get_is_client();

	eap_buf_chain_wr_c * create_send_packet(u32_t length);

	eap_status_e packet_send(
		eap_buf_chain_wr_c * const data,
		const u32_t data_length);

	eap_status_e send_success_failure_response(bool is_success_response);

	eap_status_e mschapv2_convert_unicode_to_ascii(eap_variable_data_c & dest_ascii, const eap_variable_data_c & src_unicode);

	eap_status_e mschapv2_convert_ascii_to_unicode(eap_variable_data_c & dest_unicode, const eap_variable_data_c & src_ascii);

	/* From Ms-CHAP-v2 RFC */

	eap_status_e generate_nt_response(
		const u8_t * const authenticator_challenge,
		const u8_t * const peer_challenge,
		const u8_t * const username_utf8,
		const u32_t username_size,
		const eap_variable_data_c * const password_hash,
		u8_t * const response);

	eap_status_e challenge_hash(
		const u8_t * const peer_challenge,
		const u8_t * const authenticator_challenge,
		const u8_t * const username_utf8,
		const u32_t username_size,
		u8_t * const challenge);

	eap_status_e challenge_response(
		const u8_t * const challenge,
		const u8_t * const password_hash,
		u8_t * const response);

	eap_status_e des_crypt(
		const u8_t * const data_in,
		const u8_t * const key,
		u8_t * const data_out,
		const bool is_encrypt);

	eap_status_e des_encrypt(
		const u8_t * const clear,
		const u8_t * const block,
		u8_t * const cypher)
	{
		return des_crypt(clear, block, cypher, true);
	}

	eap_status_e des_decrypt(
		u8_t * const clear,
		const u8_t * const block,
		const u8_t * const cypher)
	{
		return des_crypt(cypher, block, clear, false);
	}

	eap_status_e generate_authenticator_response(
		const u8_t * const password_hash_hash,
		const u8_t * const nt_response,
		const u8_t * const peer_challenge,
		const u8_t * const authenticator_challenge,
		const u8_t * const username,
		const u32_t username_size,
		u8_t * const authenticator_response);

	eap_status_e check_authenticator_response(
		const eap_variable_data_c * const password_hash_hash,
		const u8_t * const nt_response,
		const u8_t * const peer_challenge,
		const u8_t * const authenticator_challenge,
		const u8_t * const username,
		const u32_t username_size,
		const u8_t * const received_response,
		bool & response_ok);

	eap_status_e new_password_encrypted_with_old_nt_password_hash(
		const eap_variable_data_c * const new_password_utf8,
		const eap_variable_data_c * const old_password_hash,
		u8_t * encrypted_pw_block);

	eap_status_e encrypt_pw_block_with_password_hash(
		const eap_variable_data_c * const new_password_utf8,
		const u8_t * const password_hash,
		u8_t * pw_block);

	eap_status_e rc4_encrypt(
		const u8_t * const clear,
		const u32_t clear_length,
		const u8_t * const key,
		const u32_t key_length,
		u8_t * const cypher);

	eap_status_e old_nt_password_hash_encrypted_with_new_nt_password_hash(
		const eap_variable_data_c * const new_password_hash,
		const eap_variable_data_c * const old_password_hash,
		eap_variable_data_c * const encrypted_password_hash);

	eap_status_e nt_password_hash_encrypted_with_block(
		const eap_variable_data_c * const password_hash,
		const eap_variable_data_c * const block,
		eap_variable_data_c * const cypher);

	eap_status_e generate_session_key(
		eap_master_session_key_c * const key);

	/***************************/

#if defined(EAP_MSCHAPV2_SERVER)

	eap_status_e server_packet_process(
		eap_header_wr_c * const received_eap,
		const u32_t eap_packet_length);

	eap_status_e server_mschapv2_packet_process(
		eap_header_wr_c * const received_eap,
		const u32_t eap_packet_length);

	bool check_expired_password();

	eap_status_e server_handle_challenge_response(mschapv2_header_c &machapv2_packet);

	eap_status_e server_handle_success_response();

	eap_status_e server_handle_failure_response();

	eap_status_e server_handle_password_change(mschapv2_header_c &machapv2_packet);

	/**
	 * This function parses all payloads of the whole MSCHAPV2 EAP packet.
	 */
	eap_status_e parse_mschapv2_packet(
		eap_header_wr_c * const eap, ///< This is pointer to EAP header and data.
		const u32_t eap_packet_length ///< This is length of received EAP packet.
		);


	eap_status_e parse_mschapv2_payload(
		eap_header_wr_c * const eap, ///< This is pointer to EAP header and data.
		const u32_t eap_packet_length ///< This is length of received EAP packet.
		);

	eap_status_e send_failure_request(
		const bool retry_allowed,
		const u8_t * const message,
		const u32_t message_length);

	eap_status_e send_success_request(
		const u8_t * const message,
		const u32_t message_length);

	 /**
	 * This function handles the received EAP-Response/Identity message and chenge challenge request to client.
	 */
	eap_status_e handle_identity_response_message();

	eap_status_e rc4_decrypt(
		const u8_t * const cypher,
		const u32_t cypher_length,
		const u8_t * const key,
		const u32_t key_length,
		u8_t * const clear);

#endif //#if defined(EAP_MSCHAPV2_SERVER)

	/******************************/

protected:

public:

	/**
	 * Destructor cancels all timers and deletes member attributes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H virtual ~eap_type_mschapv2_c();

	/**
	 * Constructor initializes all member attributes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H eap_type_mschapv2_c(
		abs_eap_am_tools_c * const tools,
		abs_eap_base_type_c * const partner,
		eap_am_type_mschapv2_c * const am_type_mschapv2,
		const bool free_am_type_mschapv2,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * The partner class calls this function when EAP/MS-CHAP-v2 packet is received.
	 * see also eap_base_type_c::packet_process().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		eap_header_wr_c * const eap, ///< This is pointer to EAP header and data.
		const u32_t eap_packet_length ///< This is length of received EAP packet.
		);

	// This is commented in eap_base_type_c::get_is_valid().
	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H bool get_is_valid();
	
	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H void set_is_valid();

	/**
	 * This function resets the reused eap_type_mschapv2_c object.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H eap_status_e reset();

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H eap_status_e shutdown();

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H eap_status_e set_initial_eap_identifier(
		const eap_am_network_id_c * const receive_network_id,
		const u8_t initial_identifier);

	// This is commented in eap_base_type_c::eap_acknowledge().
	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H eap_status_e eap_acknowledge(
		const eap_am_network_id_c * const receive_network_id);

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H eap_status_e configure();

	// This is commented in eap_base_type_c::query_eap_identity().
	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_H eap_status_e query_eap_identity(
		const bool must_be_synchronous,
		eap_variable_data_c * const identity,
		const eap_am_network_id_c * const receive_network_id,
		const u8_t eap_identifier);

}; // class eap_type_mschap_c

#endif // _MSCHAPV2_CORE_H_
