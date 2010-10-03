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

#if !defined(_EAPOL_KEY_STATE_H_)
#define _EAPOL_KEY_STATE_H_


#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPOL_KEY_STATE_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_KEY_STATE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_KEY_STATE_H 
	#define EAP_FUNC_EXPORT_EAPOL_KEY_STATE_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_KEY_STATE_H 
#elif defined(EAP_EXPORT_EAPOL_KEY_STATE_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_KEY_STATE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_KEY_STATE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPOL_KEY_STATE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPOL_KEY_STATE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPOL_KEY_STATE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_KEY_STATE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPOL_KEY_STATE_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_KEY_STATE_H 
#endif
// End: added by script change_export_macros.sh.
#include "eapol_rsna_key_data_header.h"
#include "eapol_rsna_key_header.h"
#include "eap_am_network_id.h"
#include "eapol_key_types.h"

class abs_eapol_core_c;
class abs_eapol_key_state_c;
class eapol_rsna_key_data_payloads_c;
class eap_core_retransmission_c;


#if defined(EAPOL_KEY_TEST_PRIVATE_FUNCTION)
#define EAP_KEY_TEST_PUBLIC_FUNCTION public:
#define EAP_KEY_TEST_PRIVATE_FUNCTION private:
#else
#define EAP_KEY_TEST_PUBLIC_FUNCTION
#define EAP_KEY_TEST_PRIVATE_FUNCTION
#endif // #if defined(EAPOL_KEY_TEST_PRIVATE_FUNCTION)

/** @file */

/**
 * This is the timer ID used with abs_eap_am_tools_c::set_timer() and abs_eap_am_tools_c::cancel_timer().
 */
enum eapol_key_state_timer_id_e
{
	EAPOL_KEY_STATE_TIMER_HANDSHAKE_TIMEOUT_ID, ///< See EAPOL_KEY_STATE_TIMER_HANDSHAKE_TIMEOUT_TIMEOUT.
	EAPOL_KEY_STATE_TIMER_RETRANSMISSION_ID, ///< See EAPOL_KEY_STATE_TIMER_RETRANSMISSION_TIMEOUT.
	EAPOL_KEY_STATE_TIMER_PMKSA_CACHING_TIMEOUT_ID, ///< See EAPOL_KEY_STATE_TIMER_PMK_CACHING_TIMEOUT.
	EAPOL_KEY_STATE_TIMER_REASSOCIATE_TIMEOUT_ID, ///<  See EAPOL_KEY_STATE_TIMER_REASSOCIATE_TIMEOUT.
	EAPOL_KEY_STATE_TIMER_GROUP_KEY_UPDATE_TIMEOUT_ID,  ///<  See EAPOL_KEY_STATE_TIMER_GROUP_KEY_UPDATE_TIMEOUT.
	EAPOL_KEY_STATE_TIMER_INITIALIZE_4_WAY_HANDSHAKE_TIMEOUT_ID, ///<  See EAPOL_KEY_STATE_TIMER_INITIALIZE_4_WAY_HANDSHAKE_TIMEOUT.
};

/**
 * These are the default timeout values.
 */
enum eapol_key_state_timer_timeout_value_e
{
	EAPOL_KEY_STATE_TIMER_HANDSHAKE_TIMEOUT_TIMEOUT = 20000ul, // milli seconds
	EAPOL_KEY_STATE_TIMER_RETRANSMISSION_TIMEOUT    = 2000ul, // milli seconds
	EAPOL_KEY_STATE_RETRANSMISSION_COUNTER          = 3ul,
	EAPOL_KEY_STATE_TIMER_PMKSA_CACHING_TIMEOUT     = 43200000ul,  // milli seconds = 12 hours
	EAPOL_KEY_STATE_TIMER_REASSOCIATE_TIMEOUT       = 500ul,  // milli seconds
	EAPOL_KEY_STATE_TIMER_GROUP_KEY_UPDATE_TIMEOUT  = 0ul, // milli seconds, this is for testing, zero means in test case group key is updated immediately.
	EAPOL_KEY_STATE_TIMER_INITIALIZE_4_WAY_HANDSHAKE_TIMEOUT = 100ul, // milli seconds before client initializes 4-Way Handshake.
	EAPOL_KEY_STATE_TIMER_WPXM_CACHE_TIMEOUT       = 1000ul,  // milli seconds, This is short timeout to remove WPXM SA.
};


const u8_t EAPOL_RSNA_PAIRWISE_KEY_EXPANSION_LABEL[] = "Pairwise key expansion";
const u32_t EAPOL_RSNA_PAIRWISE_KEY_EXPANSION_LABEL_LENGTH = (sizeof(EAPOL_RSNA_PAIRWISE_KEY_EXPANSION_LABEL) - 1ul); // Terminating null is not included.

const u8_t EAPOL_RSNA_PMK_NAME_LABEL[] = "PMK Name";
const u32_t EAPOL_RSNA_PMK_NAME_LABEL_LENGTH = (sizeof(EAPOL_RSNA_PMK_NAME_LABEL) - 1ul); // Terminating null is not included.

enum eapol_key_wpxm_constant_e
{
	eapol_key_constant_wpxm_initial_wpxc_counter_value = 1,
};


//--------------------------------------------------------------------------------------------------


/// Class eapol_key_state_c
/**
 * This class stores the EAPOL-Key state.
 */
class EAP_CLASS_VISIBILITY_EAPOL_KEY_STATE_H eapol_key_state_c
: public abs_eap_base_timer_c
{

public:
	//--------------------------------------------------

	//--------------------------------------------------
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is back pointer to object which created this object.
	/// Packets are sent to the partner.
	abs_eapol_key_state_c * const m_key_state_partner;

	/// This is back pointer to object which created eapol_core_c object.
	/// eapol_key_state_c object sent packets to this object.
	abs_eapol_core_c * const m_eapol_partner;

	eap_am_network_id_c m_send_network_id;

	/// Authenticator RSN IE. Authenticator sends this in Beacon or Probe message.
	eap_variable_data_c m_authenticator_RSNA_IE;

	/// If a second RSN IE is provided in the message, the Supplicant shall use
	// the unicast cipher suite specified in the second RSN IE or deauthenticate.
	eap_variable_data_c m_unicast_cipher_suite_RSNA_IE;

	/// Supplicant RSN IE. Supplicant sends this in (re)association request message.
	eap_variable_data_c m_supplicant_RSNA_IE;

	/// Received Pairwise Master Key ID (PMKID). Authenticator sends this in 4-Way Handshake message 1.
	eap_variable_data_c m_received_PMKID;

	/// This is Supplicant's MAC address. This is given from MAC layer when EAPOL-Key state is initialized.
	eap_variable_data_c m_supplicant_MAC_address;

	/// This is Authenticator's MAC address. This is given from MAC layer when EAPOL-Key state is initialized.
	eap_variable_data_c m_authenticator_MAC_address;

	/// This is Athenticator Nonce.
	eap_variable_data_c m_ANonce;

	/// This is Supplicant Nonce.
	eap_variable_data_c m_SNonce;

	/// This is EAPOL-Key IV.
	eap_variable_data_c m_EAPOL_key_IV;

	/// This is the Pairwise Master Key (PMK 802.11i or WPXK3 WPXM) derived from a successful authentication.
	eap_variable_data_c m_pairwise_PMK_WPXK3;

	/// Pairwise Master Key ID (PMKID). Derived with function:
	/// PMKID = HMAC-SHA1-128(PMK, "PMK Name" || Authenticator-MAC-Addr || Supplicant-MAC-Addr).
	eap_variable_data_c m_PMKID;

	/// Pairwise Transient Key (PTK).
	/// PTK = PRF-X(PMK, "Pairwise key expansion", Min(AA,SA) || Max(AA, SA) || Min(ANonce,SNonce) || Max(ANonce,SNonce)).
	eap_variable_data_c m_transient_PTK;

	/// EAPOL-Key Confirmation Key (KCK).
	/// KCK = L(PTK, 0, 128).
	eap_variable_data_c m_confirmation_KCK;

	/// EAPOL-Key Encryption Key (KEK).
	/// KEK = L(PTK, 128, 128).
	eap_variable_data_c m_encryption_KEK;

	/// Temporal Key (TK).
	/// In TKIP: TK = L(PTK, 256, 256).
	/// In CCMP: TK = L(PTK, 256, 128).
	eap_variable_data_c m_temporal_TK;

	/// Group Temporal Key (GTK).
	/// In TKIP: 256 bits.
	/// In CCMP: 128 bits.
	/// In WEP 40: 40 bits.
	/// In WEP 104: 104 bits.
	eap_variable_data_c m_group_GTK;

#if defined(EAP_USE_WPXM)
	eap_variable_data_c m_WPXM_WPXK1;
	eap_variable_data_c m_WPXM_WPXK2;

	u32_t m_WPXM_WPXC;
#endif //#if defined(EAP_USE_WPXM)

	bool m_received_802_1x_keys[eapol_key_type_last_type];

	u8_t m_group_GTK_ID;

	bool m_group_GTK_Tx_bit;

	u32_t m_eapol_header_offset;

	u32_t m_MTU;

	u32_t m_trailer_length;

	/// Re-transmission is used to test protocols.
	/// This stores the information to resent a message. This is used for testing purposes.
	eap_core_retransmission_c *m_retransmission;

	/// Re-transmission is used to test protocols.
	/// This is the time after resent a message. This is used for testing purposes.
	u32_t m_retransmission_time;

	/// Re-transmission is used to test protocols.
	/// This is the maximum count of retransmission of one message. This is used for testing purposes.
	u32_t m_retransmission_counter;

	/// This is the maximum time EAPOL-Key Handshake could succeed.
	/// EAPOl-Key Handshake is terminated after this time elapses.
	u32_t m_handshake_timeout;


#if defined(EAP_USE_WPXM)

	/// This is the maximum time WPXM reassociation could succeed.
	/// WPXM reassociation is terminated after this time elapses.
	u32_t m_wpxm_reassociate_timeout;

	/// This is used in test server. WPXM can be configured to to use RSNA or WPA Key descriptor.
	eapol_key_descriptor_type_e m_EAPOL_WPXM_key_descriptor_type;

#endif //#if defined(EAP_USE_WPXM)

	/// This is the authentication type. One of RSNA, WPA or 802.1X.
	eapol_key_authentication_type_e m_authentication_type;

	/// This is the selected pairwise cipher.
	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e m_eapol_pairwise_cipher;

	/// This is the selected group cipher.
	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e m_eapol_group_cipher;

	/// This is the state of EAPOL-Key Handshake.
	eapol_key_state_e m_eapol_key_state;

	/// This is the the current running handshake type.
	eapol_key_handshake_type_e m_eapol_key_handshake_type;

	/// This used in EAPOL key MIC failure tests. Activation requires USE_EAPOL_KEY_TEST_FAILURES compiler flag.
	eapol_key_state_e m_create_key_failure;

	u32_t m_pmksa_caching_timeout;

	/// This is Key Reply Counter.
	u64_t m_key_reply_counter;

	/// This is Key Reply Counter for requests that client sends.
	u64_t m_client_send_key_reply_counter;

	/// This indicates whether this object is client (true) or server (false).
	/// In terms of EAP-protocol whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	bool m_is_client;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/// This flag indicates that this object is marked to removed asynchronously.
	/// The very same object could be taken use before the removing timer elapses.
	bool m_marked_removed;

	bool m_shutdown_was_called;

	/// This flag tells whether broken 4-Way Handshake message 1 without PMKID is allowed (true) or dropped (false).
	/// Default value id false.
	/// Use configuration option EAPOL_key_state_allow_missing_PMKID_in_message_1 to change this value.
	bool m_allow_missing_PMKID_in_message_1;

	/// This flag tells whether broken 4-Way Handshake message 1 without PMKID is created in server (true) or not (false).
	/// Default value id false.
	/// Use configuration option EAPOL_key_state_skip_PMKID_key_data_in_message_1 to change this value.
	bool m_skip_PMKID_key_data_in_message_1;

	/// This flag tells whether broken 4-Way Handshake message 1 with non zero MIC or non zero reserved is allowed (true) or dropped (false).
	/// Default value id false.
	/// Use configuration option EAPOL_key_state_allow_non_zero_mic_in_message_1 to change this value.
	bool m_allow_non_zero_mic_and_reserved_in_message_1;

	/// This flag tells the EAPOL must indicate PMKID to lower layers (true) or not (false).
	/// The configuration option is EAPOL_key_state_indicate_pmkid_to_lower_layer.
	bool m_indicate_pmkid_to_lower_layer;

	/// This flag tells the handshake timeout is already active (true) or not (false).
	bool m_handshake_timeout_set;

	/// This flag activates group key update test (true) or not (false).
	/// The configuration option is EAPOL_key_state_TEST_group_key_update.
	bool m_server_TEST_group_key_update;

	bool m_is_associated;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	enum eapol_key_state_constants_e
	{
		eapol_key_state_mppe_key_length_leap                       =  16ul, // LEAP gives only 16 bytes of key material
		eapol_key_state_mppe_key_length                            =  32ul,
		EAPOL_RSNA_PMK_LENGTH_BYTES								   =  32ul,
		EAPOL_RSNA_NONCE_LENGTH_BYTES                              =  32ul,
		EAPOL_RSNA_4_WAY_HANDSHAKE_MESSAGE_1_KEY_DATA_LENGTH_BYTES = eapol_rsna_key_data_header_c::EAPOL_RSNA_KEY_HEADER_LENGTH
																	 + eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_DATA_PMKID_SIZE, // sizeof(Key Data Encapsulation header) 6 + sizeof(PMKID) 16
		EAPOL_RSNA_RC4_KEY_STREAM_DISCARD_LENGTH                   = 256ul,
		EAPOL_RSNA_TKIP_PTK_LENGTH_BITS                            = 512ul,
		EAPOL_RSNA_CCMP_PTK_LENGTH_BITS                            = 384ul,
		EAPOL_RSNA_KCK_LENGTH_BYTES                                =  16ul,
		EAPOL_RSNA_KEK_LENGTH_BYTES                                =  16ul,
		EAPOL_RSNA_TK_LENGTH_BYTES								   =  32ul,
		EAPOL_RSNA_TKIP_TK_LENGTH_BYTES                            =  32ul,
		EAPOL_RSNA_CCMP_TK_LENGTH_BYTES                            =  16ul,
		EAPOL_RSNA_KCK_OFFSET_BYTES                                =   0ul,
		EAPOL_RSNA_KEK_OFFSET_BYTES                                = EAPOL_RSNA_KCK_OFFSET_BYTES + EAPOL_RSNA_KCK_LENGTH_BYTES,
		EAPOL_RSNA_TK_OFFSET_BYTES                                 = EAPOL_RSNA_KEK_OFFSET_BYTES + EAPOL_RSNA_KEK_LENGTH_BYTES,
	};


	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e trace_eapol_key_message(
		const i8_t * const prefix,
		eapol_RSNA_key_header_c * const eapol_key_message);

	eap_status_e trace_eapol_rsna_key_data_payload(
		const bool is_RSNA,
		const bool is_WPXM,
		const eapol_key_descriptor_type_e eapol_key_descriptor_type,
		const i8_t * const prefix,
		const eapol_rsna_key_data_header_c * const key_data_payload,
		const u32_t buffer_length);

#if defined(USE_EAP_TRACE)

	#define TRACE_EAPOL_KEY_MESSAGE(prefix, eapol_key_message) \
			trace_eapol_key_message(prefix, eapol_key_message)

	#define EAPOL_RSNA_KEY_DATA_TRACE_PAYLOAD(is_RSNA, is_WPXM, eapol_key_descriptor_type, prefix, key_data_payload, buffer_length) \
			trace_eapol_rsna_key_data_payload(is_RSNA, is_WPXM, eapol_key_descriptor_type, prefix, key_data_payload, buffer_length)

#else

	#define TRACE_EAPOL_KEY_MESSAGE(prefix, eapol_key_message)

	#define EAPOL_RSNA_KEY_DATA_TRACE_PAYLOAD(is_RSNA, is_WPXM, eapol_key_descriptor_type, prefix, key_data_payload, buffer_length)

#endif //#if defined(USE_EAP_TRACE) || defined(USE_EAP_TRACE_ALWAYS)


	eap_status_e handshake_failure_notification();

	eap_status_e set_mac_addresses(
		const eap_am_network_id_c * const receive_network_id);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e save_parameters(
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const authenticator_RSNA_IE,
		const eap_variable_data_c * const supplicant_RSNA_IE,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_pairwise_cipher,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_group_cipher);

	eap_status_e packet_data_session_key(
		eap_variable_data_c * const key, ///< Here is the key.
		const eapol_key_type_e key_type, ///< This the type of the key.
		const u32_t key_index, ///< This is the index of the key.
		const bool key_tx_bit, ///< This is the TX bit of the key.
		const u8_t * const key_RSC, ///< This is the RSC counter
		const u32_t key_RSC_size ///< This is the size of RSC counter
		);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e check_is_aes_key_wrap_padding(
		const eapol_RSNA_key_descriptor_type_e current_key_data_type,
		eapol_rsna_key_data_header_c * const key_data_payload,
		const u32_t key_data_max_length
		);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e parse_generic_key_data_payload(
		const eapol_key_descriptor_type_e key_descriptor_type,
		const eapol_RSNA_key_descriptor_type_e current_key_data_payload,
		eapol_rsna_key_data_header_c * const key_data_payload,
		u32_t * const key_data_max_length,
		eapol_rsna_key_data_payloads_c * const p_rsna_key_data_payloads,
		const eapol_key_state_e expected_key_message);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e parse_key_data(
		const eapol_key_descriptor_type_e key_descriptor_type,
		const eapol_rsna_key_data_header_c * const p_payload,
		u32_t * const buffer_length,
		eapol_rsna_key_data_payloads_c * const p_rsna_key_data_payloads,
		const eapol_key_state_e expected_key_message,
		const eapol_RSNA_key_header_c::key_descriptor_version_e key_descriptor_version);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e rsna_prf(
		const eap_variable_data_c * const key_K,
		const eap_variable_data_c * const label_A,
		const eap_variable_data_c * const input_B,
		const u32_t output_length,
		eap_variable_data_c * const output
		);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e select_minimum(
		const eap_variable_data_c * const input_a,
		const eap_variable_data_c * const input_b,
		const eap_variable_data_c ** const minimum,
		const eap_variable_data_c ** const maximum);


	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e create_PMKID();

	eap_status_e set_reassociation_parameters(
		const eap_variable_data_c * const pairwise_PMK_WPXK3,
		const eap_variable_data_c * const PMKID,
		const eap_variable_data_c * const transient_PTK,
		const eap_variable_data_c * const confirmation_KCK,
		const eap_variable_data_c * const encryption_KEK,
		const eap_variable_data_c * const temporal_TK,
		const eap_variable_data_c * const WPXM_WPXK1,
		const eap_variable_data_c * const WPXM_WPXK2,
		const u32_t WPXM_WPXC,
		const eapol_key_handshake_type_e eapol_key_handshake_type,
		const eapol_key_authentication_type_e authentication_type
		);

	eap_status_e send_RC4_eapol_key_message(
		const eapol_RC4_key_flags_e flags);

	void send_error_notification(const eap_status_e error);

	eap_status_e save_keys_for_test_use(
		const eap_variable_data_c * const confirmation_KCK,
		const eap_variable_data_c * const encryption_KEK,
		const eap_variable_data_c * const temporal_TK,
		const u32_t WPXM_WPXC);

EAP_KEY_TEST_PUBLIC_FUNCTION


	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e derive_PTK();


EAP_KEY_TEST_PRIVATE_FUNCTION


	eap_status_e derive_WPXM_WPXK1_WPXK2();

	eap_status_e derive_WPXM_PTK(const u32_t WPXM_WPXC);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e verify_field_is_zero(
		const u8_t * const field,
		const u32_t field_length);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e check_padding(
		const u8_t * const field,
		const u32_t field_length);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e encrypt_key_data(
		eapol_RSNA_key_header_c * const eapol_key_message);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e decrypt_key_data(
		eapol_RSNA_key_header_c * const eapol_key_message);


	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e create_key_mic(
		eapol_RSNA_key_header_c * const eapol_key_message,
		const eap_variable_data_c * const confirmation_key);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e verify_key_mic(
		eapol_RSNA_key_header_c * const eapol_key_message,
		const eap_variable_data_c * const confirmation_key);


	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e create_nonce(
		eap_variable_data_c * const nonce,
		const u32_t nonce_length);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e initialize_4_way_handshake(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_protocol_version_e received_eapol_version);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e create_4_way_handshake_message_1(
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t eapol_header_offset,
		u32_t * const data_length,
		u32_t * const buffer_length,
		const eapol_protocol_version_e received_eapol_version,
		const eapol_key_descriptor_type_e received_key_descriptor_type);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e create_4_way_handshake_message_2(
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t eapol_header_offset,
		u32_t * const data_length,
		u32_t * const buffer_length,
		const u64_t received_key_replay_counter,
		const eapol_protocol_version_e received_eapol_version,
		const eapol_key_descriptor_type_e received_key_descriptor_type);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e create_4_way_handshake_message_3(
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t eapol_header_offset,
		u32_t * const data_length,
		u32_t * const buffer_length,
		const eapol_protocol_version_e received_eapol_version,
		const eapol_key_descriptor_type_e received_key_descriptor_type);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e create_4_way_handshake_message_4(
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t eapol_header_offset,
		u32_t * const data_length,
		u32_t * const buffer_length,
		const u64_t received_key_replay_counter,
		const bool received_secure_bit,
		const eapol_protocol_version_e received_eapol_version,
		const eapol_key_descriptor_type_e received_key_descriptor_type);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e process_4_way_handshake_message_2_payloads(
		const eap_am_network_id_c * const receive_network_id,
		eapol_RSNA_key_header_c * const eapol_key_message,
		const u32_t packet_length);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e process_4_way_handshake_message_3_payloads_a(
		const eap_am_network_id_c * const receive_network_id,
		eapol_RSNA_key_header_c * const eapol_key_message,
		const u32_t packet_length,
		bool * const group_key_received);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e process_4_way_handshake_message_3_payloads_b(
		const eap_am_network_id_c * const receive_network_id,
		eapol_RSNA_key_header_c * const eapol_key_message,
		const u32_t packet_length,
		const bool group_key_received);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e process_4_way_handshake_message_0(
		const eap_am_network_id_c * const receive_network_id,
		eapol_RSNA_key_header_c * const eapol_key_message,
		const u32_t packet_length);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e process_4_way_handshake_message_1(
		const eap_am_network_id_c * const receive_network_id,
		eapol_RSNA_key_header_c * const eapol_key_message,
		const u32_t packet_length);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e process_4_way_handshake_message_2(
		const eap_am_network_id_c * const receive_network_id,
		eapol_RSNA_key_header_c * const eapol_key_message,
		const u32_t packet_length);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e process_4_way_handshake_message_3(
		const eap_am_network_id_c * const receive_network_id,
		eapol_RSNA_key_header_c * const eapol_key_message,
		const u32_t packet_length);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e process_4_way_handshake_message_4(
		const eap_am_network_id_c * const receive_network_id,
		eapol_RSNA_key_header_c * const eapol_key_message,
		const u32_t packet_length);


	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e start_group_key_handshake(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_protocol_version_e received_eapol_version,
		const eapol_key_descriptor_type_e received_key_descriptor_type);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e process_group_key_handshake_message_0(
		const eap_am_network_id_c * const receive_network_id,
		eapol_RSNA_key_header_c * const eapol_key_message,
		const u32_t packet_length);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e process_group_key_handshake_message_1(
		const eap_am_network_id_c * const receive_network_id,
		eapol_RSNA_key_header_c * const eapol_key_message,
		const u32_t packet_length);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e process_group_key_handshake_message_2(
		const eap_am_network_id_c * const receive_network_id,
		eapol_RSNA_key_header_c * const eapol_key_message,
		const u32_t packet_length);


	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e create_eapol_key_handshake_message_0(
		const bool true_when_4_way_handshake, ///< With false initiates Group Key Handshake.
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t eapol_header_offset,
		u32_t * const data_length,
		u32_t * const buffer_length,
		const u64_t received_key_replay_counter,
		const eapol_protocol_version_e received_eapol_version);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e create_group_key_handshake_message_1(
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t eapol_header_offset,
		u32_t * const data_length,
		u32_t * const buffer_length,
		const eapol_protocol_version_e received_eapol_version,
		const eapol_key_descriptor_type_e received_key_descriptor_type);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e create_group_key_handshake_message_2(
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t eapol_header_offset,
		u32_t * const data_length,
		u32_t * const buffer_length,
		const u64_t received_key_replay_counter,
		const eapol_protocol_version_e received_eapol_version,
		const eapol_key_descriptor_type_e received_key_descriptor_type);


	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e process_4_way_handshake_message(
		const eap_am_network_id_c * const receive_network_id,
		eapol_RSNA_key_header_c * const eapol_key_message,
		const u32_t packet_length);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e process_group_key_handshake_message(
		const eap_am_network_id_c * const receive_network_id,
		eapol_RSNA_key_header_c * const eapol_key_message,
		const u32_t packet_length);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e process_RSNA_key_descriptor(
		const eap_am_network_id_c * const receive_network_id,
		eap_general_header_base_c * const packet_data,
		const u32_t packet_length);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e process_RC4_key_descriptor(
		const eap_am_network_id_c * const receive_network_id,
		eap_general_header_base_c * const packet_data,
		const u32_t packet_length);

	// This is documented in abs_eap_stack_interface_c::set_is_valid().
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H void set_is_valid();

	// 
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_variable_data_c * get_authenticator_RSNA_IE();

	// 
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_variable_data_c * get_unicast_cipher_suite_RSNA_IE();

	// 
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_variable_data_c * get_supplicant_RSNA_IE();

	// 
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_variable_data_c * get_received_PMKID();

	// 
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_variable_data_c * get_supplicant_MAC_address();

	// 
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_variable_data_c * get_authenticator_MAC_address();

	// 
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H u64_t get_key_reply_counter();

	// 
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H void increase_key_reply_counter();

	//
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H void set_key_reply_counter(
		const u64_t reply_counter);

	//
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H u64_t get_client_send_key_reply_counter();

	//
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H void increase_client_send_key_reply_counter();

	//
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H void set_client_send_key_reply_counter(
		const u64_t reply_counter);

	// 
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_variable_data_c * get_ANonce();

	// 
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_variable_data_c * get_SNonce();

	// 
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_variable_data_c * get_confirmation_KCK();

	// 
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_variable_data_c * get_encryption_KEK();

	//
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H void set_eapol_key_state(const eapol_key_state_e state);

	//
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eapol_key_state_e get_eapol_key_state() const;

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e asynchronous_init_remove_eapol_key_state();

	//
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e packet_send(
		const eap_am_network_id_c * const send_network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length);

	//
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e resend_packet(
		const eap_am_network_id_c * const send_network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length);

	//
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e cancel_retransmission();


	//
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e cancel_handshake_timeout();

	//
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e init_handshake_timeout(
		const u32_t timeout);


	//
	eap_status_e cancel_reassociate_timeout();

	//
	eap_status_e init_reassociate_timeout(
		const u32_t timeout);


	eap_status_e cancel_4_way_handshake_start_timeout();

	eap_status_e init_4_way_handshake_start_timeout();

	//
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e cancel_pmksa_caching_timeout();

	//
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e init_retransmission(
		const eap_am_network_id_c * const send_network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const eap_code_value_e eap_code,
		const u8_t eap_identifier,
		const eap_type_value_e eap_type
		);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e cancel_group_key_update_timeout();

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e init_group_key_update_timeout(
		const u32_t timeout);

	//
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e create_tkip_mic_failure_message(
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t eapol_header_offset,
		u32_t * const data_length,
		u32_t * const buffer_length,
		const eapol_RSNA_key_header_c::eapol_tkip_mic_failure_type_e tkip_mic_failure_type,
		const eapol_protocol_version_e received_eapol_version);


	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H bool get_is_RSNA();

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H bool get_is_WPA();

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H bool get_is_WPXM();


	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e add_RSN_GTK_payload(
		const eapol_RSNA_key_header_c * const eapol_key_message,
		eap_variable_data_c * const group_GTK,
		u32_t * const eapol_data_length);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e add_RSN_IE_payload(
		const eapol_RSNA_key_header_c * const eapol_key_message,
		eap_variable_data_c * const RSNA_IE,
		u32_t * const eapol_data_length);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e get_key_length(
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e cipher,
		u16_t * const key_length);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e send_RC4_eapol_key_messages();

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H virtual ~eapol_key_state_c();

	// 
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eapol_key_state_c(
		abs_eap_am_tools_c * const tools,
		abs_eapol_key_state_c * const key_state_partner,
		abs_eapol_core_c * const eapol_partner,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const authenticator_RSNA_IE,
		const eap_variable_data_c * const supplicant_RSNA_IE,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_pairwise_cipher,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_group_cipher,
		const eap_variable_data_c * const pre_shared_key);

	// 
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eapol_key_state_c(
		abs_eap_am_tools_c * const tools,
		abs_eapol_key_state_c * const key_state_partner,
		abs_eapol_core_c * const eapol_partner,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type);


	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e initialize(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const authenticator_RSNA_IE,
		const eap_variable_data_c * const supplicant_RSNA_IE,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_pairwise_cipher,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_group_cipher,
		const eap_variable_data_c * const pre_shared_key);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e initialize(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eapol_key_state_c *copy(const eap_am_network_id_c * const receive_network_id);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H bool get_is_encryption_on();

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H bool get_is_associated();

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e started_eap_authentication();

	/**
	 * This function checks whether cached PMKSA have correct cipher suite.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e check_pmksa_cache(
		const eapol_key_authentication_type_e selected_eapol_key_authentication_type,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e initialize_preauthentication(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e read_reassociation_parameters(
		const eap_am_network_id_c * const receive_network_id, ///< source includes remote address, destination includes local address.
		const eapol_key_authentication_type_e authentication_type,
		eap_variable_data_c * const PMKID,
		const eap_variable_data_c * const received_WPA_ie,
		const eap_variable_data_c * const sent_WPA_ie);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e complete_reassociation(
		const eapol_wlan_authentication_state_e reassociation_result,
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const received_WPA_IE, // WLM must give only the WPA IE to EAPOL
		const eap_variable_data_c * const sent_WPA_IE,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
		const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e start_WPXM_reassociation(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		eap_variable_data_c * const send_reassociation_request_ie);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e complete_WPXM_reassociation(
		const eapol_wlan_authentication_state_e reassociation_result,
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const received_reassociation_ie);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e configure();

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e shutdown();

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e set_WPXM_parameters(
		const eap_am_network_id_c * const receive_network_id);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e set_s_nonce(
		const eap_variable_data_c * const s_nonce);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e set_pairwise_PMK(
		const eap_variable_data_c * const key,
		const eap_am_network_id_c * const send_network_id);

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e allow_4_way_handshake();

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e start_4_way_handshake(
		const eap_am_network_id_c * const receive_network_id);

	// 
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e process_eapol_key_frame(
		const eap_am_network_id_c * const receive_network_id,
		eap_general_header_base_c * const packet_data,
		const u32_t packet_length);

	// This is documented in abs_eap_stack_interface_c::get_is_valid().
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H bool get_is_valid();

	/**
	 * The object_increase_reference_count() function increases the reference count.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H void object_increase_reference_count();

	/**
	 * The object_decrease_reference_count () function decreases 
	 * the reference count and returns the remaining value.
	 * The EAP type is removed after there is no references to it.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H u32_t object_decrease_reference_count();

	// See abs_eap_base_timer_c::timer_expired().
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e timer_expired(
		const u32_t id, void *data);

	// See abs_eap_base_timer_c::timer_delete_data().
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e timer_delete_data(
		const u32_t id, void *data);

	/**
	 * Gets flag whether this session is marked removed.
	 * Session is removed later if it is not reused.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H bool get_marked_removed();

	/**
	 * Marks this session removed.
	 * Session is removed later if it is not reused.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H void set_marked_removed();

	/**
	 * Marks this session not removed.
	 * Session is not removed it is reused.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H void unset_marked_removed();

	/**
	 * This function resets object partially.
	 * Member attributes needed in reassociation are left untouched.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e reset_cached_pmksa();

	/**
	 * This function resets the full state of object to same as 
	 * state was after the configure() function call.
	 * If object reset succeeds this function must return eap_status_ok.
	 * If object reset fails this function must return corresponding error status.
	 * @return This function returns the status of reset operation.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e reset();

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e tkip_mic_failure(
		const bool fatal_failure_when_true,
		const eapol_RSNA_key_header_c::eapol_tkip_mic_failure_type_e tkip_mic_failure_type);

	//
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e init_pmksa_caching_timeout();

	//
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_H eap_status_e cancel_authentication_session();

	//--------------------------------------------------
}; // class eapol_key_state_c


//--------------------------------------------------

#endif //#if !defined(_EAPOL_KEY_STATE_H_)

//--------------------------------------------------


// End.
