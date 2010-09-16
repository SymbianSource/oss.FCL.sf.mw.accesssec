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
* %version: 73 %
*/

#if !defined(_TLS_RECORD_H_)
#define _TLS_RECORD_H_


#include "abs_tls_am_services.h"
#include "tls_base_record.h"
#include "eap_array_algorithms.h"
#include "tls_message.h"
#include "tls_peap_types.h"
#include "abs_tls_message_hash.h"
#include "tls_completion.h"
#include "abs_tls_change_cipher_spec.h"
#include "abs_tls_base_application.h"
#include "tls_base_application.h"
#include "eap_protocol_layer.h"
#include "eap_am_network_id.h"
#include "eap_automatic_variable.h"
#include "eap_master_session_key.h"
#if defined(USE_FAST_EAP_TYPE)
	#include "abs_pac_store_initializer.h"
#endif //#if defined(USE_FAST_EAP_TYPE)
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_TLS_RECORD_H)
	#define EAP_CLASS_VISIBILITY_TLS_RECORD_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_TLS_RECORD_H 
	#define EAP_C_FUNC_VISIBILITY_TLS_RECORD_H 
	#define EAP_FUNC_EXPORT_TLS_RECORD_H 
	#define EAP_C_FUNC_EXPORT_TLS_RECORD_H 
#elif defined(EAP_EXPORT_TLS_RECORD_H)
	#define EAP_CLASS_VISIBILITY_TLS_RECORD_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_TLS_RECORD_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_RECORD_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_TLS_RECORD_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_TLS_RECORD_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_TLS_RECORD_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_TLS_RECORD_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_RECORD_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_TLS_RECORD_H 
	#define EAP_C_FUNC_EXPORT_TLS_RECORD_H 
#endif
// End: added by script change_export_macros.sh.



class abs_tls_base_record_c;
class abs_eap_am_tools_c;
class eap_am_network_id_c;
class tls_record_header_c;
class tls_am_services_c;
class tls_handshake_header_c;
class tls_record_message_c;
class tls_handshake_message_c;
class abs_crypto_cbc_block_algorithm_c;
class abs_crypto_block_algorithm_c;
class abs_crypto_stream_algorithm_c;

#if defined(USE_FAST_EAP_TYPE)
	#if !defined(USE_EAP_TLS_SESSION_TICKET)
		#error ERROR: With USE_FAST_EAP_TYPE you must use USE_EAP_TLS_SESSION_TICKET flag too.
	#endif //#if !defined(USE_EAP_TLS_SESSION_TICKET)
#endif //#if defined(USE_FAST_EAP_TYPE)

//--------------------------------------------------------------------

/**
 * The tls_record_c class implements tls_base_record_c.
 * See more detailed design and architecture document <a href="../../type/tls_peap/documentation/EAP_TLS_PEAP.doc">EAP_TLS_PEAP.doc</a>
 * and <a href="../../type/tls_peap/documentation/rfc2246.txt">RFC 2246</a>.
 */
class EAP_CLASS_VISIBILITY_TLS_RECORD_H tls_record_c
: public tls_base_record_c
, public abs_tls_am_services_c
, public abs_tls_message_hash_c
, public abs_tls_change_cipher_spec_c
, public abs_tls_apply_cipher_spec_c
, public abs_tls_base_application_c
#if defined(USE_FAST_EAP_TYPE)
, public abs_pac_store_initializer_c
#endif //#if defined(USE_FAST_EAP_TYPE)
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class. @see abs_eap_am_tools_c.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is pointer to adaptation module of TLS.
	tls_am_services_c * m_am_tls_services;

	/// This flag tells whether the m_am_tls_services must be freed in destructor.
	const bool m_free_am_tls_services;

	/// This is pointer to application object. Mostly this is used in PEAP and the application is tls_application_eap_core_c object.
	tls_base_application_c * m_application;

	/// This flag tells whether the m_application must be freed in destructor.
	const bool m_free_application;



	/// This object includes pending asyncronous actions or it may be empty.
	/// The check_sent_tls_message() function call will check and complete pending actions.
	eap_array_c<tls_completion_c> m_completion_queue;



	/// This object includes received message in parsed tree.
	tls_message_c m_received_tls_message;

	/// This object includes the new created message in parsed tree.
	/// The send message will be generated from this.
	tls_message_c m_new_tls_message;



	/// This object includes MD5 HASH of received handshake messages.
	crypto_md5_c m_message_hash_md5;

	/// This object includes SHA1 HASH of received handshake messages.
	crypto_sha1_c m_message_hash_sha1;

	/// This object includes MD5 HASH for certificate verify message.
	eap_variable_data_c m_message_hash_md5_certificate_verify;

	/// This object includes SHA1 HASH for certificate verify message.
	eap_variable_data_c m_message_hash_sha1_certificate_verify;

	/// This object includes MD5 HASH of Finished message of client.
	eap_variable_data_c m_client_message_hash_md5_finished;

	/// This object includes SHA1 HASH of Finished message of client.
	eap_variable_data_c m_client_message_hash_sha1_finished;

	/// This object includes MD5 HASH of Finished message of server.
	eap_variable_data_c m_server_message_hash_md5_finished;

	/// This object includes SHA1 HASH of Finished message of server.
	eap_variable_data_c m_server_message_hash_sha1_finished;



	/// This object includes client random value for client handshake message.
	eap_variable_data_c m_client_handshake_random_value;

	/// This object includes server random value for server handshake message.
	eap_variable_data_c m_server_handshake_random_value;

	/// This object includes session ID.
	eap_variable_data_c m_session_id;

	/// This object includes master secret.
	eap_variable_data_c m_master_secret;

	/// This object includes EAP-TLS master session key.
	eap_master_session_key_c m_eap_master_session_key;



	/// This object includes shared secret key for MAC of send packets.
	eap_variable_data_c m_new_send_mac_key;

	/// This object includes shared secret key for MAC of received packets.
	eap_variable_data_c m_new_receive_mac_key;

	/// This object includes shared secret key for encryption of send packets.
	eap_variable_data_c m_new_send_encryption_key;

	/// This object includes shared secret key for decryption of received packets.
	eap_variable_data_c m_new_receive_encryption_key;

	/// This object includes initialization vector for block encryption of send packets.
	eap_variable_data_c m_new_send_iv;

	/// This object includes initialization vector for decryption of received packets.
	eap_variable_data_c m_new_receive_iv;



	/// This object includes shared secret key for MAC of send packets.
	eap_variable_data_c m_send_mac_key;

	/// This object includes shared secret key for MAC of received packets.
	eap_variable_data_c m_receive_mac_key;

	/// This object includes shared secret key for encryption of send packets.
	eap_variable_data_c m_send_encryption_key;

	/// This object includes shared secret key for decryption of received packets.
	eap_variable_data_c m_receive_encryption_key;

	/// This object includes initialization vector for block encryption of send packets.
	eap_variable_data_c m_send_iv;

	/// This object includes initialization vector for decryption of received packets.
	eap_variable_data_c m_receive_iv;



	/// This object includes session key seed for EAP-FAST.
	eap_variable_data_c m_session_key_seed;

	/// This object includes MsChapv2 challenges for EAP-FAST.
	eap_variable_data_c m_mschapv2_challenges;


	/// This object includes Diffie-Hellman private key of this TLS end point.
	eap_variable_data_c m_own_private_dhe_key;

	/// This object includes Diffie-Hellman public key of this TLS end point.
	eap_variable_data_c m_own_public_dhe_key;

	/// This object includes Diffie-Hellman public key of other TLS end point.
	eap_variable_data_c m_peer_public_dhe_key;

	/// This object includes Diffie-Hellman shared key of the TLS session.
	eap_variable_data_c m_shared_dh_key;

	/// This object includes Diffie-Hellman prime of the TLS session.
	eap_variable_data_c m_dhe_prime;

	/// This object includes Diffie-Hellman group generator of the TLS session.
	eap_variable_data_c m_dhe_group_generator;


	/// This object includes signed HASH. This is needed to store asyncronously completed signature creation.
	eap_variable_data_c m_signed_message_hash;

	/// This object includes the premaster secret.
	/// In RSA cipher suite client generates this and and encrypts with server public key.
	/// Server decrypts this within the client key exchange message and decrypts this with private key.
	/// In DHE cipher suite this is the shared Diffie-Hellman secret.
	eap_variable_data_c m_premaster_secret;

	/// This object includes encrypted premaster secret of this TLS end point.
	/// This is needed to store asyncronously completed result of encryption.
	eap_variable_data_c m_own_encrypted_premaster_secret;

#if defined(USE_FAST_EAP_TYPE)
	/// This object includes PAC-Key of EAP-FAST.
	/// PAC-Key is stored here before master secret can be generated.
	eap_variable_data_c m_eap_fast_pac_key;
#endif //#if defined(USE_FAST_EAP_TYPE)

	/// This object includes the proposed cipher suites.
	/// Objects are in host network order.
	/// Client creates this list and server receives the list in client hello handshake message.
	eap_array_c<u16_t> m_proposed_cipher_suites;

	/// This object includes the proposed compression methods.
	/// Client creates this list and server receives the list in client hello handshake message.
	eap_array_c<u8_t> m_proposed_compression_methods;

#if defined(USE_EAP_TLS_SESSION_TICKET)
	/// All supported TLS extensions.
	eap_array_c<tls_extension_c> m_supported_tls_extensions;

	/// All received TLS extensions.
	eap_array_c<tls_extension_c> m_received_tls_extensions;
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)


	/// This is the realm part of the NAI of the client.
	eap_variable_data_c m_NAI_realm;

	/// This is network identity of the sent packet from this authentication session.
	eap_am_network_id_c m_send_network_id;

	/// This object includes certificate chain of this TLS end point.
	/// This is needed to store asyncronously completed result of certificate chain qyery.
	eap_array_c<eap_variable_data_c> m_own_certificate_chain;

	/// This object includes certificate types required by this TLS end point.
	/// This is needed to store asyncronously completed result of certificate type qyery.
	eap_array_c<u8_t> m_own_certificate_types;

	/// This object includes certificate authorities required by this TLS end point.
	/// This is needed to store asyncronously completed result of certificate authorities qyery.
	eap_array_c<eap_variable_data_c> m_own_certificate_authorities;

	/// This object includes certificate chain of the other TLS end point.
	eap_array_c<eap_variable_data_c> m_peer_certificate_chain;

	/// This variable includes validity result of certificate chain of the other TLS end point.
	eap_status_e m_peer_certificate_chain_result;

	/// This variable includes validity result of signature verification of the received message that includes signature.
	eap_status_e m_verify_signature;

	/// This object includes certificate types of the other TLS end point.
	eap_array_c<u8_t> m_peer_certificate_types;

	/// This object includes certificate authorities of the other TLS end point.
	eap_array_c<eap_variable_data_c> m_peer_certificate_authorities;



	/// This is the resumed cipher suite from previous TLS session.
	tls_cipher_suites_e m_resumed_cipher_suite;

	/// This is the selected cipher suite for this TLS session.
	tls_cipher_suites_e m_selected_cipher_suite;

	/// This is the selected compression method for this TLS session.
	/// NOTE this is always null compression.
	tls_compression_method_e m_selected_compression_method;

	/// This is the active cipher suite of received packets for this TLS session.
	tls_cipher_suites_e m_receive_cipher_suite;

	/// This is the active compression method of received packets for this TLS session.
	/// NOTE this is always null compression.
	tls_compression_method_e m_receive_compression_method;

	/// This is the active cipher suite of send packets for this TLS session.
	tls_cipher_suites_e m_send_cipher_suite;

	/// This is the active compression method of send packets for this TLS session.
	/// NOTE this is always null compression.
	tls_compression_method_e m_send_compression_method;



	/// This is pointer to CBC block cipher algorithm of send packets when cipher suite uses block cipher.
	abs_crypto_cbc_block_algorithm_c *m_send_block_cipher;

	/// This is pointer to CBC block cipher algorithm of received packets when cipher suite uses block cipher.
	abs_crypto_cbc_block_algorithm_c *m_receive_block_cipher;

	/// This is pointer to stream cipher algorithm of send packets when cipher suite uses block cipher.
	abs_crypto_stream_algorithm_c *m_send_stream_cipher;

	/// This is pointer to stream cipher algorithm of received packets when cipher suite uses block cipher.
	abs_crypto_stream_algorithm_c *m_receive_stream_cipher;



	/// This is pointer to HMAC algorithm of send packets.
	abs_crypto_hmac_algorithm_c *m_send_hmac_algorithm;

	/// This is pointer to HMAC algorithm of received packets.
	abs_crypto_hmac_algorithm_c *m_receive_hmac_algorithm;

	
	
	/// This is the counter of send TLS-records. See chapters "6.2.3. Record payload protection"
	/// and "6.1. Connection states" from <a href="../../type/tls_peap/documentation/rfc2246.txt">RFC 2246</a>.
	/// Sequence number is initialized to zero and incrmented after each record is processed.
	u64_t m_send_record_sequence_number;

	/// This is the counter of received TLS-records. See chapters "6.2.3. Record payload protection"
	/// and "6.1. Connection states" from <a href="../../type/tls_peap/documentation/rfc2246.txt">RFC 2246</a>.
	/// Sequence number is initialized to zero and incrmented after each record is processed.
	u64_t m_receive_record_sequence_number;



	/// This variable stored the internal state of TLS-session. See tls_peap_state_e.
	tls_peap_state_e m_tls_peap_state;

	/// This flag tells which TLS session type is selected,
	/// full authentication, original session resumption or stateless session resumption (RFC 4507).
	tls_session_type_e m_tls_session_type;


	/// This is the EAP-type (TLS, PEAP or TTLS).
	eap_type_value_e m_eap_type;

	/// This separates different PEAP versions (PEAPv2, PEAPv1 or XP PEAPv0).
	peap_version_e m_peap_version;

	/// This variable stores the state of tunneled EAP-authentication.
	eap_state_variable_e m_tunneled_eap_type_authentication_state;

	/// This variable saves the EAP-identifier of the last received EAP-message.
	u8_t m_received_eap_identifier;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/// This indicates whether this object is client (true) or server (false).
	const bool m_is_client;

	/// This flag tells whether messages could be send in the check_sent_tls_message() function.
	bool m_allow_message_send;

	/// This flag prevents recursive calls of the completion_action_check() function.
	bool m_already_in_completion_action_check;

	/// This flag prevents recursive calls of the process_tls_records() function.
	bool m_already_in_process_tls_records;



	/// This flag tells whether this function call is pending (true value).
	/// After this function call is completed with appropriate completion function flag is set to false value.
	bool m_pending_query_certificate_authorities_and_types;

	/// This flag tells whether this function call is pending (true value).
	/// After this function call is completed with appropriate completion function flag is set to false value.
	bool m_pending_query_certificate_chain;

	/// This flag tells whether this function call is pending (true value).
	/// After this function call is completed with appropriate completion function flag is set to false value.
	bool m_pending_query_cipher_suites_and_previous_session;

	/// This flag tells whether this function call is pending (true value).
	/// After this function call is completed with appropriate completion function flag is set to false value.
	bool m_pending_query_dh_parameters;

	/// This flag tells whether this function call is pending (true value).
	/// After this function call is completed with appropriate completion function flag is set to false value.
	bool m_pending_query_realm;

	/// This flag tells whether this function call is pending (true value).
	/// After this function call is completed with appropriate completion function flag is set to false value.
	bool m_pending_select_cipher_suite_and_check_session_id;

	/// This flag tells whether this function call is pending (true value).
	/// After this function call is completed with appropriate completion function flag is set to false value.
	bool m_pending_verify_certificate_chain;

	/// This flag tells whether this function call is pending (true value).
	/// After this function call is completed with appropriate completion function flag is set to false value.
	bool m_pending_rsa_decrypt_with_private_key;

	/// This flag tells whether this function call is pending (true value).
	/// After this function call is completed with appropriate completion function flag is set to false value.
	bool m_pending_rsa_encrypt_with_public_key;

	/// This flag tells whether this function call is pending (true value).
	/// After this function call is completed with appropriate completion function flag is set to false value.
	bool m_pending_sign_with_private_key;

	/// This flag tells whether this function call is pending (true value).
	/// After this function call is completed with appropriate completion function flag is set to false value.
	bool m_pending_verify_with_public_key;

	/// This flag tells whether this function call is pending (true value).
	/// After this function call is completed with appropriate completion function flag is set to false value.
	bool m_pending_query_tunnel_PAC;


	/// This flag tells whether this instance is test version (true) or real version (false).
	/// Test version allows many subsequent TLS-sessions.
	bool m_tls_peap_test_version;

	/// The flag prevents multiple call of generate_key_material() function.
	bool m_key_material_generated;

	/// This flag tells whether the server authenticates client (true) or not (false).
	/// NOTE: Server and client read this value from it's configuration.
	/// Server acts as this flag says.
	/// Client does allow only client and server mutual authentication when this flag is true.
	/// Client does allow server authentication too when this flag is false.
	bool m_tls_peap_server_authenticates_client_policy_flag;

	/// Server reads this from configure.
	/// Server initiates mutual authentication when value is true.
	/// Server initiates server authentication when value is false.
	bool m_tls_peap_server_authenticates_client_config_server;

	/// Client and server set this flag to indicate the current function.
	/// Action is mutual authentication when value is true.
	/// Action is server authentication when value is false.
	bool m_tls_peap_server_authenticates_client_action;

	/// Client uses this flag to remember the the certificate request message.
	bool m_tls_peap_server_requested_client_certificate;

	/// This flag tells whether we could send fatal TLS-alert message (true) or not (false).
	/// This is set false after we receive one TLS-alert message.
	bool m_could_send_fatal_alert_message;

	/// This flag tells whether we could send warning TLS-alert message (true) or not (false).
	/// This is set false after we receive one TLS-alert message.
	bool m_could_send_warning_alert_message;

	/// This flag tells whether the check_sent_tls_message() must send TLS-alert message (true) or not (false).
	/// This flag is set after the TLS-alert message is generated. This flag forses send of the TLS-alert message.
	bool m_force_tls_message_send;

	/// This flag tells whether the shutdown() function was called (true) or not (false).
	bool m_shutdown_was_called;

	/// This flag tells whether TLS-messages should be set to separate TLS-records (true) or TLS-message should
	/// be packed to same TLS-record if it is possible (false).
	bool m_use_separate_tls_record;

	/// This flag tells whether extra padding of block cipher should be used.
	bool m_use_extra_padding_length;

	/// NOTE this is against the RFC 2246 The TLS Protocol Version 1.0.
	/// Look at chapter 7.4.4. Certificate request.
	bool m_client_allows_empty_certificate_authorities_list;

	/// NOTE this is against the RFC 2246 The TLS Protocol Version 1.0.
	/// Look at chapter 7.4.4. Certificate request.
	bool m_server_sends_empty_certificate_authorities_list;

	/// This configurable option selects whether the special TLS/PEAP style
	/// is used, the length field is added to all message fragments
	/// even the message fits to one fragment except EAP-TLS-start, EAP-TLS-Acknowledge and
	/// PEAP-application data. The client acknowledges tunneled EAP-Success message
	/// with empty PEAP message.
	bool m_use_tppd_tls_peap;

	/// On fast session resume server does not send tunneled EAP-Success.
	/// Instead it sends plain EAP-Success.
	/// True value of this flag allows this plain EAP-Success.
	bool m_use_tppd_peapv1_acknowledge_hack;

	/// This configuration flag tells the server will offer new session ID to client.
	bool m_server_offers_new_session_id;

	/// Client will receive a new session ticket in NewSessionTicket message.
	bool m_will_receive_new_session_ticket;

	/// True value means EAP-FAST server sends piggypacked EAP-Identity/Request.
	/// False value means EAP-FAST server does not send piggypacked EAP-Identity/Request, instead it waits empty Ack-message from client.
	bool m_send_piggypacked_eap_identity_request;

#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	/// Flag causes TLS client to use privacy.
	bool m_tls_use_identity_privacy;

	/// Variable tells state of TLS identity privacy handshake.
	tls_identity_privacy_handshake_state_e m_tls_identity_privacy_handshake_state;
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)

#if defined(USE_FAST_EAP_TYPE)
	/// This flag allows use of dynamic provisioning of PAC in Server-Unauthenticated Mode.
	/// This is called also Authenticated Diffie-Hellman Protocol (ADHP).
	bool m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP;

	/// This flag allows use of dynamic provisioning of PAC in Server-Authenticated Mode.
	bool m_fast_allow_server_authenticated_provisioning_mode;

	bool m_remove_tunnel_pac;
#endif //#if defined(USE_FAST_EAP_TYPE)

	//--------------------------------------------------

	/**
	 * The set_is_valid() function sets the state of the object valid.
	 * The creator of this object calls this function after it is initialized. 
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H void set_is_valid();

	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e allocate_handshake_message(
		tls_handshake_message_c ** const tls_handshake_message,
		eap_automatic_variable_c<tls_handshake_message_c> * const automatic_tls_handshake_message,
		const tls_handshake_type_e handshake_type);

	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e allocate_handshake_message_copy(
		tls_handshake_message_c ** const tls_handshake_message,
		eap_automatic_variable_c<tls_handshake_message_c> * const automatic_tls_handshake_message,
		tls_handshake_header_c * const tls_handshake_header);

	/**
	 * This function creates TLS Handshake/HelloRequest message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e create_handshake_type_hello_request();

	/**
	 * This function creates TLS Handshake/ClientHello message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e create_handshake_type_client_hello();

	/**
	 * This function creates TLS Handshake/ServerHello message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e create_handshake_type_server_hello(
		const u16_t selected_cipher_suite,
		const u8_t selected_compression_method);

	/**
	 * This function creates TLS Handshake/Certificate message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e create_handshake_type_certificate(
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_chain);

	/**
	 * This function creates TLS Handshake/CertificateRequest message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e create_handshake_type_certificate_request(
		EAP_TEMPLATE_CONST eap_array_c<u8_t> * const certificate_types,
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_authorities);

	/**
	 * This function creates TLS Handshake/ServerHelloDone message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e create_handshake_type_server_hello_done();

	/**
	 * This function completes creation of TLS Handshake/ServerKeyExchange message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e complete_create_handshake_type_server_key_exchange();

	/**
	 * This function creates TLS Handshake/ServerKeyExchange message.
	 * NOTE: this function is asyncronous. complete_create_handshake_type_server_key_exchange()
	 * completes this operation.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e create_handshake_type_server_key_exchange();

	/**
	 * This function completes creation of TLS Handshake/ClientKeyExchange message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e complete_create_handshake_type_client_key_exchange();

	/**
	 * This function creates TLS Handshake/ClientKeyExchange message.
	 * NOTE: this function is asyncronous. complete_create_handshake_type_client_key_exchange()
	 * completes this operation.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e create_handshake_type_client_key_exchange();

	/**
	 * This function completes creation of TLS Handshake/CertificateVerify message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e complete_create_handshake_type_certificate_verify();

	/**
	 * This function creates TLS Handshake/CertificateVerify message.
	 * NOTE: this function is asyncronous.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e create_handshake_type_certificate_verify();

	/**
	 * This function creates TLS Handshake/Finished message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e create_handshake_type_finished();

	/**
	 * This function creates TLS Handshake/NewSessionTicket message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e create_handshake_type_new_session_ticket();

	/**
	 * This function creates TLS ChangeCipherSpec/ChangeCipherSpec message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e create_change_cipher_spec_type_change_cipher_spec();

	/**
	 * This function finish TLS handshake.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e finish_handshake();

	/**
	 * This function creates TLS Alert/Alert message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e create_tls_protocol_alert(
		const tls_alert_description_e alert_description,
		const tls_alert_level_e alert_level,
		const eap_status_e result);

	/**
	 * This function creates TLS ApplicationData message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e create_tls_application_data(
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset);

	/**
	 * This function starts tunneled authentication.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e start_peap_tunneled_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const u8_t received_eap_identifier,
		const tls_session_type_e tls_session_type);

	/**
	 * This function parses TLS extension list, see RFC 4366.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e parse_tls_extension_list(
		const u32_t handshake_data_length,
		u32_t * const data_offset,
		const tls_handshake_header_c * const tls_handshake_header,
		tls_handshake_message_c * const tls_handshake_message);

	/**
	 * This function parses TLS Handshake/HelloRequest message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e parse_handshake_type_hello_request(
		tls_record_message_c * const received_tls_record_message,
		tls_handshake_header_c * const tls_handshake_header,
		const u32_t handshake_data_length);


	/**
	 * This function parses TLS Handshake/ClientHello message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e parse_handshake_type_client_hello(
		tls_record_message_c * const received_tls_record_message,
		tls_handshake_header_c * const tls_handshake_header,
		const u32_t handshake_data_length);

	/**
	 * This function parses TLS Handshake/ServerHello message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e parse_handshake_type_server_hello(
		tls_record_message_c * const received_tls_record_message,
		tls_handshake_header_c * const tls_handshake_header,
		const u32_t handshake_data_length);

	/**
	 * This function parses TLS Handshake/Certificate message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e parse_handshake_type_certificate(
		tls_record_message_c * const received_tls_record_message,
		tls_handshake_header_c * const tls_handshake_header,
		const u32_t handshake_data_length);

	/**
	 * This function parses TLS Handshake/CertificateRequest message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e parse_handshake_type_certificate_request(
		tls_record_message_c * const received_tls_record_message,
		tls_handshake_header_c * const tls_handshake_header,
		const u32_t handshake_data_length);

	/**
	 * This function parses TLS Handshake/ServerHelloDone message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e parse_handshake_type_server_hello_done(
		tls_record_message_c * const received_tls_record_message,
		tls_handshake_header_c * const tls_handshake_header,
		const u32_t handshake_data_length);

	/**
	 * This function parses TLS Handshake/ServerKeyExchange message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e parse_handshake_type_server_key_exchange(
		tls_record_message_c * const received_tls_record_message,
		tls_handshake_header_c * const tls_handshake_header,
		const u32_t handshake_data_length);

	/**
	 * This function parses TLS Handshake/ClientKeyExchange message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e parse_handshake_type_client_key_exchange(
		tls_record_message_c * const received_tls_record_message,
		tls_handshake_header_c * const tls_handshake_header,
		const u32_t handshake_data_length);

	/**
	 * This function parses TLS Handshake/CertificateVerify message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e parse_handshake_type_certificate_verify(
		tls_record_message_c * const received_tls_record_message,
		tls_handshake_header_c * const tls_handshake_header,
		const u32_t handshake_data_length);

	/**
	 * This function parses TLS Handshake/Finished message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e parse_handshake_type_finished(
		tls_record_message_c * const received_tls_record_message,
		tls_handshake_header_c * const tls_handshake_header,
		const u32_t handshake_data_length);


#if defined(USE_EAP_TLS_SESSION_TICKET)

	/**
	 * This function parses TLS Handshake/NewSessionTicket message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e parse_handshake_type_new_session_ticket(
		tls_record_message_c * const received_tls_record_message,
		tls_handshake_header_c * const tls_handshake_header,
		const u32_t handshake_data_length);

#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)


	/**
	 * This function parses TLS ChangeCipherSpec protocol.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e parse_tls_protocol_change_cipher_spec(
		tls_record_message_c * const tls_record_message,
		eap_variable_data_c * const tls_protocols_messages_buffer);

	/**
	 * This function parses TLS Alert protocol.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e parse_tls_protocol_alert(
		tls_record_message_c * const tls_record_message,
		eap_variable_data_c * const tls_protocols_messages_buffer);

	/**
	 * This function parses TLS Handshake protocol.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e parse_tls_protocol_handshake(
		tls_record_message_c * const tls_record_message,
		eap_variable_data_c * const tls_protocols_messages_buffer);

	/**
	 * This function parses TLS ApplicationData protocol.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e parse_tls_protocol_application_data(
		tls_record_message_c * const tls_record_message,
		eap_variable_data_c * const tls_protocols_messages_buffer);

	/**
	 * This function reassembles data of received consecutive TLS-records with same protocol to tls_record_message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e reassemble_tls_records(
		tls_record_message_c * const tls_record_message,
		tls_record_header_c * const next_tls_record_header);

	/**
	 * This function processes received TLS records.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e process_tls_records();

	/**
	 * This function processes received TLS message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e process_tls_message();

	EAP_FUNC_VISIBILITY_TLS_RECORD_H tls_record_protocol_e get_next_tls_record_message_protocol();

	EAP_FUNC_VISIBILITY_TLS_RECORD_H tls_handshake_type_e get_next_tls_handshake_message_type();

	/**
	 * This function analyses TLS Handshake/HelloRequest message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e analyse_handshake_type_hello_request(
		EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message);

	/**
	 * This function analyses TLS Handshake/ClientHello message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e analyse_handshake_type_client_hello(
		EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message);

	/**
	 * This function analyses TLS Handshake/ServerHello message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e analyse_handshake_type_server_hello(
		EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message);

	/**
	 * This function analyses TLS Handshake/Certificate message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e analyse_handshake_type_certificate(
		EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message);

	/**
	 * This function analyses TLS Handshake/CertificateRequest message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e analyse_handshake_type_certificate_request(
		EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message);

	/**
	 * This function analyses TLS Handshake/ServerHelloDone message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e analyse_handshake_type_server_hello_done(
		EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message);

	/**
	 * This function analyses TLS Handshake/ServerKeyExchange message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e analyse_handshake_type_server_key_exchange(
		EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message);

	/**
	 * This function analyses TLS Handshake/ClientKeyExchange message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e analyse_handshake_type_client_key_exchange(
		EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message);

	/**
	 * This function analyses TLS Handshake/CertificateVerify message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e analyse_handshake_type_certificate_verify(
		EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message);

	/**
	 * This function analyses TLS Handshake/Finished message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e analyse_handshake_type_finished(
		EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message,
		const u8_t received_eap_identifier);

#if defined(USE_EAP_TLS_SESSION_TICKET)

	/**
	 * This function analyses TLS Handshake/NewSessionTicket message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e analyse_handshake_type_new_session_ticket(
		EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message,
		const u8_t received_eap_identifier);

#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)

	/**
	 * This function analyses TLS ChangeCipherSpec protocol.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e analyse_tls_protocol_change_cipher_spec(
		const tls_record_message_c * const record);

	/**
	 * This function analyses TLS Alert protocol.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e analyse_tls_protocol_alert(
		const tls_record_message_c * const record);

	/**
	 * This function analyses TLS Handshake protocol.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e analyse_tls_protocol_handshake(
		tls_record_message_c * const record,
		const u8_t received_eap_identifier);

	/**
	 * This function analyses TLS ApplicationData protocol.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e analyse_tls_protocol_application_data(
		const tls_record_message_c * const record,
		const u8_t received_eap_identifier);

	/**
	 * This function checks whether all pending queries are completed.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e are_pending_queries_completed();

	/**
	 * This function indicates state to lower layer.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e indicate_state_to_lower_layer(
		const tls_peap_state_e indicated_state);

	/**
	 * This function indicates all message processed to lower layer.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e indicate_messages_processed();

	/**
	 * This function combines TLS-protocols data to a buffer and sends TLS-message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e send_tls_message();

	/**
	 * This function checks all queries are completed.
	 * If all queries are completed this function send the pending LS-messages.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e check_sent_tls_message();

	/**
	 * This function check the selected cipher suite is one of the proposed cipher suites.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e check_selected_cipher_suite(
		const tls_cipher_suites_e selected_cipher_suite);

	/**
	 * This function check the selected compression method is one of the proposed compression method.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e check_selected_compression_method(
		const tls_compression_method_e selected_compression_method);

	/**
	 * This function changes one 16-bit value pointed by parameter value from network order to host order.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H static eap_status_e u16_t_to_host_order(
		u16_t * const value,
		abs_eap_am_tools_c * const m_am_tools);

	/**
	 * This function changes one 16-bit value pointed by parameter value from host order to network order.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H static eap_status_e u16_t_to_network_order(
		u16_t * const value,
		abs_eap_am_tools_c * const m_am_tools);

	/**
	 * This function initializes MD5 and SHA hashes.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e message_hash_init();

	/**
	 * This function adds the send and received TLS-handshake message to MD5 and SHA hashes.
	 * @param eap includes the buffer of the whole reassembled TLS-packet.
	 * @param packet_length is length in bytes of the TLS-packet.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e message_hash_update(
		const bool true_when_parse_message,
		const tls_handshake_type_e type,
		u8_t * const tls_packet,
		const u32_t tls_packet_length);

	/**
	 * This function obtains and concatenates the message digest of MD5 and SHA hashes.
	 * @param type tells the handshake type where the message digest is used.
	 * @param message_hash includes the buffer of the message digest. The message_hash_create() function initializes the buffer.
	 * @param client_originated is boolean flag. When client calls this function value is true, when server calls this function value is false.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e message_hash_create(
		const bool true_when_parse_message,
		const tls_handshake_type_e type,
		eap_variable_data_c * const message_hash,
		const bool client_originated);

	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e message_hash_final(
		eap_variable_data_c * const md5_digest,
		eap_variable_data_c * const sha1_digest);

	/**
	 * This function saves MD5 and SHA hashes for certificate verify message to
	 * member attributes m_message_hash_md5_certificate_verify and m_message_hash_sha1_certificate_verify.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e message_hash_save_certificate_verify();

	/**
	 * This function saves MD5 and SHA hashes for finished message to
	 * member attributes message_hash_md5_finished and message_hash_sha1_finished.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e message_hash_save_finished(
		const bool client_originated);

	/**
	 * This function creates certificate verfy message hash.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e message_hash_create_certificate_verify(
		const bool client_originated);

	/**
	 * This function creates finished message hash.
	 * @param signed_message_hash is pointer to buffer of the message hash.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e message_hash_create_finished(
		const bool client_originated_message,
		eap_variable_data_c * const signed_message_hash);


	/**
	 * This function creates SHA1 HASH of server key exchange message when DHE cipher suite is used.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e create_server_key_exchange_sha1_hash(
		const eap_variable_data_c * const dhe_prime,
		const eap_variable_data_c * const dhe_group_generator,
		const eap_variable_data_c * const public_dhe_key,
		eap_variable_data_c * const hash);

	/**
	 * This function creates MD5 HASH of server key exchange message when DHE cipher suite is used.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e create_server_key_exchange_md5_hash(
		const eap_variable_data_c * const dhe_prime,
		const eap_variable_data_c * const dhe_group_generator,
		const eap_variable_data_c * const public_dhe_key,
		eap_variable_data_c * const hash);

	/**
	 * This function verifies the HASH of server key exchange message is valid.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e verify_signature_of_server_key_exchange(
		const eap_variable_data_c * const signed_server_key_exchange_hash);



	/**
	 * This function verifies the cipher suite is one of using 3DES_EDE_CBC_SHA.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H bool cipher_suite_is_3DES_EDE_CBC_SHA(tls_cipher_suites_e cipher_suite) const;

	/**
	 * This function verifies the cipher suite is one of using AES_128_CBC_SHA.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H bool cipher_suite_is_AES_128_CBC_SHA(tls_cipher_suites_e cipher_suite) const;

	/**
	 * This function verifies the cipher suite is one of using RC4_128_MD5.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H bool cipher_suite_is_RC4_128_MD5(tls_cipher_suites_e cipher_suite) const;

	/**
	 * This function verifies the cipher suite is one of using RC4_128_SHA.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H bool cipher_suite_is_RC4_128_SHA(tls_cipher_suites_e cipher_suite) const;



	/**
	 * This function verifies the current cipher suite is one of using TLS_RSA.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H bool cipher_suite_is_TLS_RSA() const;

	/**
	 * This function verifies the current cipher suite is one of using TLS_DHE_RSA.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H bool cipher_suite_is_TLS_DHE_RSA() const;

	/**
	 * This function verifies the current cipher suite is one of using TLS_DHE_DSS.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H bool cipher_suite_is_TLS_DHE_DSS() const;

#if defined(USE_FAST_EAP_TYPE)
	/**
	 * This function verifies the current cipher suite is one of using TLS_DH_anon.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H bool cipher_suite_is_TLS_DH_anon() const;
#endif //#if defined(USE_FAST_EAP_TYPE)


#if EAP_TLS_NOT_SUPPORTED_CIPHER_SUITE
	This is not implemented yet
	EAP_FUNC_VISIBILITY_TLS_RECORD_H bool cipher_suite_is_TLS_DH_DSS() const;
#endif



	/**
	 * This function generates ephemeral Diffie-Hellman keys.
	 * Keys are stored to m_own_private_dhe_key and m_own_public_dhe_key.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e generate_dhe_keys();

	/**
	 * This function generates master secret.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e generate_master_secret();

	/**
	 * This function generates premaster secret.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e generate_premaster_secret();

#if defined(USE_FAST_EAP_TYPE)
	/**
	 * This function generates master secret from EAP-FAST PAC-Key.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e generate_eap_fast_master_secret_from_pac_key(
		const eap_variable_data_c * const pac_key);
#endif //#if defined(USE_FAST_EAP_TYPE)


	EAP_FUNC_VISIBILITY_TLS_RECORD_H void send_error_notification(const eap_status_e error);

	/**
	 * This function adds new completion action to the end of the m_completion_queue.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e completion_action_add(
		tls_completion_action_e action);

	/**
	 * This function verifies all completion actions are completed.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e completion_action_clenup();

	/**
	 * This function checks and completes completion actions.
	 * This function could return eap_status_pending_request if the
	 * first completion action cannot be completed yet.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e completion_action_check();




	/**
	 * This function generates random padding length. See chapter "6.2.3.2. CBC block cipher" in <a href="../../type/tls_peap/documentation/rfc2246.txt">RFC 2246</a>.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H u8_t get_extra_padding_length(const u8_t padding_length, const u32_t block_size);

	/**
	 * This function applies the current block cipher suite to send TLS-record.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e apply_send_block_cipher_suite(
		eap_variable_data_c * const tls_record_message_buffer,
		abs_crypto_cbc_block_algorithm_c * const encrypt,
		abs_crypto_hmac_algorithm_c * const mac);

	/**
	 * This function applies the current block cipher suite to received TLS-record.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e apply_receive_block_cipher_suite(
		eap_variable_data_c * const tls_record_message_buffer,
		abs_crypto_cbc_block_algorithm_c * const decrypt,
		abs_crypto_hmac_algorithm_c * const mac);

	/**
	 * This function applies the current stream cipher suite to send TLS-record.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e apply_send_stream_cipher_suite(
		eap_variable_data_c * const tls_record_message_buffer,
		abs_crypto_stream_algorithm_c * const encrypt,
		abs_crypto_hmac_algorithm_c * const mac);

	/**
	 * This function applies the current stream cipher suite to received TLS-record.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e apply_receive_stream_cipher_suite(
		eap_variable_data_c * const tls_record_message_buffer,
		abs_crypto_stream_algorithm_c * const decrypt,
		abs_crypto_hmac_algorithm_c * const mac);

	/**
	 * This function applies the current cipher suite to send TLS-record.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e apply_send_cipher_suite(
		eap_variable_data_c * const tls_record_message_buffer);

	/**
	 * This function applies the current cipher suite to received TLS-record.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e apply_receive_cipher_suite(
		eap_variable_data_c * const tls_record_message_buffer);

	/** This function hides create_tls_protocol_alert() call.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e eap_status_return_and_create_tls_protocol_alert(
		const eap_status_e status);


	/**
	 * This function sets the state of TLS.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H tls_peap_state_e get_state() const;

	/**
	 * This function gets the state of TLS.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H void set_state(const tls_peap_state_e state);

	/**
	 * This function verified the current state of TLS and parameter state are equal.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H bool verify_state(const tls_peap_state_e state);



	/**
	 * This function initializes encryption and decryption objects for block cipher suite.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e cipher_suite_initialization_cbc(
		abs_crypto_cbc_block_algorithm_c ** const cbc_crypto_block_algorithm,
		abs_crypto_block_algorithm_c * const crypto_block_algorithm,
		const eap_variable_data_c * const iv,
		const eap_variable_data_c * const key,
		const bool true_when_encrypt);

	/**
	 * This function initializes HMAC algorithm objects.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e cipher_suite_initialization_hmac(
		abs_crypto_hmac_algorithm_c * const hmac_algorithm,
		const eap_variable_data_c * const key);

	/**
	 * This function initializes encryption and decryption objects for stream cipher suite.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e cipher_suite_initialization_stream(
		abs_crypto_stream_algorithm_c * const crypto_stream_algorithm,
		const eap_variable_data_c * const key,
		const bool true_when_encrypt);

	/**
	 * This function initializes HMAC-SHA1 objects for current cipher suite.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e cipher_suite_initialization_hmac_sha1(const bool send_when_true);

	/**
	 * This function initializes HMAC-MD5 objects for current cipher suite.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e cipher_suite_initialization_hmac_md5(const bool send_when_true);

	/**
	 * This function initializes encryption and decryption objects for current cipher suite.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e cipher_suite_initialization(
		const bool send_when_true);



	/**
	 * This function creates a new TLS-record message or returns tha last one if
	 * parameter protocol and ther last TLS-record message match.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e new_record_message(
		tls_record_message_c ** const tls_record_message,
		const tls_record_protocol_e protocol);

	/**
	 * This function creates a new TLS-record including handshake protocol message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e add_record_message(
		tls_handshake_message_c * const tls_handshake_message);

	/**
	 * This function creates a new TLS-record including change cipher spec protocol message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e add_record_message(
		tls_change_cipher_spec_message_c * const change_cipher_spec_message);

	/**
	 * This function creates a new TLS-record including alert protocol message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e add_record_message(
		tls_alert_message_c * const alert_message);

	/**
	 * This function creates a new TLS-record including application data protocol message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e add_record_message(
		tls_application_data_message_c * const application_data_message);

	EAP_FUNC_VISIBILITY_TLS_RECORD_H void reset_block_ciphers(const bool send_when_true);

	EAP_FUNC_VISIBILITY_TLS_RECORD_H void reset_stream_ciphers(const bool send_when_true);

	EAP_FUNC_VISIBILITY_TLS_RECORD_H void reset_hmac_algorithms(const bool send_when_true);

	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e get_tls_prf_data(
		const eap_variable_data_c * const master_secret,
		const eap_variable_data_c * const client_random,
		const eap_variable_data_c * const server_random,
		const eap_variable_data_c * const label,
		eap_variable_data_c * const prf_data,
		const u32_t required_prf_data_length);

	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e set_tls_session_type(const tls_session_type_e tls_session_type);

	EAP_FUNC_VISIBILITY_TLS_RECORD_H tls_session_type_e get_tls_session_type();

	EAP_FUNC_VISIBILITY_TLS_RECORD_H void set_tls_identity_privacy_handshake_state(const tls_identity_privacy_handshake_state_e state);

	EAP_FUNC_VISIBILITY_TLS_RECORD_H void set_selected_cipher_suite(const tls_cipher_suites_e cipher_suite);

	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e set_receive_cipher_suite(const tls_cipher_suites_e cipher_suite);

	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e set_send_cipher_suite(const tls_cipher_suites_e cipher_suite);

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the tls_record_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H virtual ~tls_record_c();

	/**
	 * The constructor of the tls_record_c class simply initializes the attributes.
	 * The tls_record_c object sends packets to the network using tls_base_record_c::get_type_partner() object.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H tls_record_c(
		abs_eap_am_tools_c * const tools, ///< tools is pointer to the tools class. @see abs_eap_am_tools_c.
		tls_am_services_c * const am_tls_services, ///< This is pointer to adaoptation module of TLS.
		const bool free_am_tls_services,
		tls_base_application_c * const application, ///< application is pointer to application object.
		const bool free_application,
		const bool is_client_when_true, ///< Indicates whether this is client (true) or server (false).
		const eap_type_value_e eap_type,
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * This function returns true when EAP-type is TTLS or PEAP.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H bool get_is_tunneled_tls();

	/**
	 * This function sets the tunnel type.
	 */
	void set_peap_version(
		const peap_version_e peap_version, ///< This is the PEAP version (PEAPv2, PEAPv1, XP PEAPv0), yes very nice to have many different versions.
		const bool use_tppd_tls_peap, ///< Of course some vendors have own TLS/PEAP quirks.
		const bool use_tppd_peapv1_acknowledge_hack);

	/**
	 * The configure() function is called after the constructor of the 
	 * object is successfully executed. During the function call the object 
	 * could query the configuration. Each derived class must define this function.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e configure();

	/**
	 * The shutdown() function is called before the destructor of the 
	 * object is executed. During the function call the object 
	 * could shutdown the operations, for example cancel timers.
	 * Each derived class must define this function.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e shutdown();

	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e get_ttls_implicit_challenge(
		eap_variable_data_c * const ttls_implicit_challenge,
		const u32_t required_ttls_implicit_challenge_length);

	/**
	 * This function sets the NAI realm.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e set_nai_realm(
		const eap_variable_data_c * const NAI_realm ///< This is the full NAI realm.
		);

	// This is commented in abs_tls_base_application_c.
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e packet_send(
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length);

	// This is commented in abs_tls_base_application_c.
	EAP_FUNC_VISIBILITY_TLS_RECORD_H u32_t get_header_offset(
		u32_t * const MTU_length,
		u32_t * const trailer_length);

	// This is commented in abs_tls_base_application_c.
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	// This is commented in abs_tls_base_application_c.
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	// This is commented in abs_tls_base_application_c.
	EAP_FUNC_VISIBILITY_TLS_RECORD_H void state_notification(
		const abs_eap_state_notification_c * const state);

	// This is commented in abs_tls_base_application_c.
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e set_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id, 
		void * const data,
		const u32_t p_time_ms);

	// This is commented in abs_tls_base_application_c.
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e cancel_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id);

	// This is commented in abs_tls_base_application_c.
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e /* tunneling_type */,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id);

	// This is commented in abs_tls_base_application_c.
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e unload_module(const eap_type_value_e type);

	// This is commented in abs_tls_base_application_c.
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e restart_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const bool is_client_when_true,
		const bool force_clean_restart,
		const bool from_timer);

	// This is commented in abs_tls_base_application_c.
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e packet_data_crypto_keys(
		const eap_am_network_id_c * const send_network_id,
		const eap_master_session_key_c * const master_session_key);

	// This is commented in abs_tls_base_application_c.
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e check_is_valid_eap_type(const eap_type_value_e eap_type);

	// This is commented in abs_tls_base_application_c::get_eap_type_list().
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e get_eap_type_list(
		eap_array_c<eap_type_value_e> * const eap_type_list);

	/**
	 * This function sends starts EAP-TLS/PEAP after a start message is received.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e start_tls_peap_authentication(
		const eap_variable_data_c * const received_authority_identity
		);

	/**
	 * This function processes the received packet.
	 * @param tls_packet includes the buffer of the whole reassembled TLS-packet.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e packet_process(
		eap_variable_data_c * const tls_packet,
		const u8_t received_eap_identifier);

	/**
	 * This function indicates the plain text EAP-Success or EAP-Failure packet is received.
	 * @param receive_network_id includes the addresses (network identity) and packet type.
	 * @param received_eap_identifier is the EAP-Identifier of the received EAP-Success packet.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e plain_eap_success_failure_packet_received(
		const eap_am_network_id_c * const receive_network_id,
		const eap_code_value_e received_eap_code,
		const u8_t received_eap_identifier);

	/**
	 * This function indicates the empty Ack packet is received.
	 * This is used in TTLS.
	 * @param receive_network_id includes the addresses (network identity) and packet type.
	 * @param received_eap_identifier is the EAP-Identifier of the received EAP-Success packet.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e empty_ack_packet_received(
		const eap_am_network_id_c * const receive_network_id,
		const u8_t received_eap_identifier);

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H bool get_is_valid();

	/**
	 * This function must reset the state of object to same as 
	 * state was after the configure() function call.
	 * If object reset succeeds this function must return eap_status_ok.
	 * If object reset fails this function must return corresponding error status.
	 * @return This function returns the status of reset operation.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e reset();

	/**
	 * This function calculates the required key lengths. This function consults current cipher suite.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H u32_t get_key_expansion_size(
		u32_t * const mac_key_length,
		u32_t * const encryption_key_length,
		u32_t * const iv_length,
		u32_t * const session_key_seed_length,
		u32_t * const mschapv2_challenges_length);

	/**
	 * This function generates the key material for the current cipher suite.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e generate_key_material();

	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e set_tls_master_secret(
		const eap_variable_data_c * const master_secret,
		const eap_variable_data_c * const client_random,
		const eap_variable_data_c * const server_random);

	/**
	 * This function changes the current cipher suite to negotiated cipher suite.
	 * Parameter send_when_true tells whether the send cipher suite (true) or receive cipher suite (false)
	 * is acquired to be changed.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e change_cipher_spec(const bool send_when_true);


	// This is commented in tls_base_record_c::read_authority_identity().
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e read_authority_identity(eap_variable_data_c * const authority_identity_payload);

	
	// This is commented in abs_tls_am_services_c::complete_query_cipher_suites_and_previous_session().
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e complete_query_cipher_suites_and_previous_session(
		const tls_session_type_e session_type,
		EAP_TEMPLATE_CONST eap_array_c<u16_t> * const cipher_suites,
		EAP_TEMPLATE_CONST eap_array_c<u8_t> * const compression_methods,
#if defined(USE_EAP_TLS_SESSION_TICKET)
		EAP_TEMPLATE_CONST eap_array_c<tls_extension_c> * const tls_extensions,
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
		const eap_variable_data_c * const resumed_session_id,
		const eap_variable_data_c * const resumed_master_secret,
		const tls_cipher_suites_e resumed_cipher_suite,
		const eap_status_e completion_status);

	// This is commented in abs_tls_am_services_c::complete_select_cipher_suite_and_check_session_id().
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e complete_select_cipher_suite_and_check_session_id(
		const tls_session_type_e session_type,
		const u16_t selected_cipher_suite,
		const eap_variable_data_c * const session_id,
		const eap_variable_data_c * const master_secret,
#if defined(USE_EAP_TLS_SESSION_TICKET)
		const tls_extension_c * const new_session_ticket_or_null,
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)
		const eap_status_e completion_status);

#if defined(USE_EAP_TLS_SESSION_TICKET)
	// This is commented in abs_tls_am_services_c::complete_query_new_session_ticket().
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e complete_query_new_session_ticket(
		const tls_extension_c * const new_session_ticket_or_null);
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)

	// This is commented in abs_tls_am_services_c::complete_verify_certificate_chain().
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e complete_verify_certificate_chain(
		const eap_status_e result);

	// This is commented in abs_tls_am_services_c::complete_query_certificate_chain().
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e complete_query_certificate_chain(
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_chain,
		const eap_status_e completion_status);

	// This is commented in abs_tls_am_services_c::complete_query_certificate_authorities_and_types().
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e complete_query_certificate_authorities_and_types(
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const authorities,
		EAP_TEMPLATE_CONST eap_array_c<u8_t> * const types,
		const eap_status_e completion_status);

	// This is commented in abs_tls_am_services_c::complete_query_dh_parameters().
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e complete_query_dh_parameters(
		const eap_variable_data_c * const dhe_prime,
		const eap_variable_data_c * const dhe_group_generator,
		const eap_status_e completion_status);

	// This is commented in abs_tls_am_services_c::complete_query_realm().
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e complete_query_realm(
		const eap_variable_data_c * const realm,
		const eap_status_e completion_status);

	// This is commented in abs_tls_am_services_c::complete_rsa_encrypt_with_public_key().
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e complete_rsa_encrypt_with_public_key(
		const eap_variable_data_c * const encrypted_premaster_secret,
		const eap_status_e completion_status);

	// This is commented in abs_tls_am_services_c::complete_rsa_decrypt_with_private_key().
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e complete_rsa_decrypt_with_private_key(
		const eap_variable_data_c * const premaster_secret,
		const eap_status_e completion_status);

	// This is commented in abs_tls_am_services_c::complete_sign_with_private_key().
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e complete_sign_with_private_key(
		const eap_variable_data_c * const message_hash,
		const eap_status_e completion_status);

	// This is commented in abs_tls_am_services_c::complete_verify_with_public_key().
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e complete_verify_with_public_key(
		const eap_status_e verify_status);

	// See abs_tls_base_application_c::get_eap_tls_master_session_key().
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e get_eap_tls_master_session_key(
		eap_variable_data_c * const eap_tls_master_session_key,
		eap_variable_data_c * const mschapv2_challenges
		);

	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e add_rogue_ap(eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list);

	// This is documented in abs_tls_base_application_c::set_session_timeout().
	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e set_session_timeout(
		const u32_t session_timeout_ms);

#if defined(USE_FAST_EAP_TYPE)

	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e complete_query_tunnel_PAC(
		const eap_status_e in_completion_status,
		const eap_fast_pac_type_e in_pac_type,
		const eap_fast_variable_data_c * const in_tunnel_PAC_key_tlv,
		const eap_fast_variable_data_c * const in_tunnel_PAC_opaque_tlv);

	eap_status_e complete_start_initialize_PAC_store(
		const eap_fast_completion_operation_e completion_operation,
		const eap_fast_initialize_pac_store_completion_e completion);

#endif //#if defined(USE_FAST_EAP_TYPE)

	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e query_ttls_pap_username_and_password(
		const eap_variable_data_c * const reply_message);

	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e complete_query_ttls_pap_username_and_password(
		const eap_variable_data_c * const ttls_pap_username,
		const eap_variable_data_c * const ttls_pap_password,
		const eap_status_e query_result);

	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e verify_ttls_pap_username_and_password(
		const eap_variable_data_c * const user_name,
		const eap_variable_data_c * const user_password);

	EAP_FUNC_VISIBILITY_TLS_RECORD_H eap_status_e complete_verify_ttls_pap_username_and_password(
		const eap_status_e authentication_result,
		const eap_variable_data_c * const ttls_pap_reply_message);

	//--------------------------------------------------
}; // class tls_record_c

#endif //#if !defined(_TLS_RECORD_H_)

//--------------------------------------------------



// End.
