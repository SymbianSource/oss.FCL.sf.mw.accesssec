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
* %version: 9 %
*/

#if !defined(_GSMSIM_CORE_H_)
#define _GSMSIM_CORE_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TYPE_GSMSIM_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H 
	#define EAP_FUNC_EXPORT_EAP_TYPE_GSMSIM_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_GSMSIM_H 
#elif defined(EAP_EXPORT_EAP_TYPE_GSMSIM_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_GSMSIM_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_GSMSIM_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_GSMSIM_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_GSMSIM_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_base_type.h"
#include "eap_variable_data.h"
#include "eap_type_gsmsim_types.h"
#include "eap_type_gsmsim_payloads.h"
#include "eap_type_gsmsim_state.h"
#include "abs_eap_base_timer.h"
#include "abs_eap_am_type_gsmsim.h"
#include "eap_master_session_key.h"


class eap_type_gsmsim_MAC_attributes_c;
class eap_am_type_gsmsim_c;
class crypto_hmac_c;

//#define USE_EAP_GSMSIM_VERIFY_STATES

//--------------------------------------------------


/// This class is implementation of GSMSIM EAP-type.
class EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_H eap_type_gsmsim_c
: public abs_eap_type_gsmsim_state_c
, public abs_eap_am_type_gsmsim_c
, public abs_eap_base_timer_c
, public eap_base_type_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	//--------------------------------------------------

#if !defined(NO_EAP_TYPE_GSMSIM_MESSAGE_STATE_CHECK)
	/// This attribute stores the valid GSMSIM states (eap_type_gsmsim_state_variable_e).
	/// Each eap_type_gsmsim_state_variable_parameters_c includes the valid 
	/// GSMSIM messages within the state.
	eap_type_gsmsim_state_variable_parameters_c m_parameters[eap_type_gsmsim_state_last_value];
#endif //#if !defined(NO_EAP_TYPE_GSMSIM_MESSAGE_STATE_CHECK)

	/// This is the current state.
	eap_type_gsmsim_state_variable_e m_state;

	/// This is the saved previous state. On error case this is the state where continue.
	eap_type_gsmsim_state_variable_e m_saved_previous_state;

	/// This is network identity of the sent packet from this handler.
	eap_am_network_id_c m_send_network_id;

	/// This is the NONCE_MT. Client generates NONCE_MT and sends it to server
	/// within the EAP-Response/SIM/Start message.
	eap_variable_data_c m_nonce_mt;

	/// This is the NONCE_S. Server generates NONCE_S and sends it to client
	/// within the EAP-Request/SIM/Re-authentication message.
	eap_variable_data_c m_nonce_s;

	// - - - - - - - - - - - - - - - - - - - -

	/// Server sends IV to client within EAP-Request/SIM/Challenge message.
	/// The AT_IV payload is optional.
	gsmsim_variable_data_c m_IV;

	/// EAP-Request/SIM/Challenge message must be saved until n*Kc and n*SRES are get from SIM.
	eap_variable_data_c m_saved_EAP_packet;

	// - - - - - - - - - - - - - - - - - - - -

	/// XKEY = SHA1(n*Kc| NONCE_MT)
	eap_variable_data_c m_XKEY;

	/// K_encr is the first 16 octets of generated Key_block:s.
	eap_variable_data_c m_K_encr;

	/// K_aut is the 16 octets after K_encr of generated Key_block:s.
	eap_variable_data_c m_K_aut;

	/// m_master_session_key is the 20 octets after m_K_aut of generated Key_block:s.
	eap_master_session_key_c m_master_session_key;

	// - - - - - - - - - - - - - - - - - - - -

	/// This is the real IMSI.
	eap_variable_data_c m_IMSI;

	/// This is the pseudonym for IMSI. This is used only if server supports use of pseudonym.
	eap_variable_data_c m_pseudonym;

	/// This is the reauthentication identity. This is used only if server supports use of reauthentication identity.
	eap_variable_data_c m_reauthentication_identity;

	/// This is the automatic realm generated in AM of EAP-SIM.
	/// Note this could be invalid data when automatic realm is not used.
	/// The m_automatic_realm_read flag tells whether m_automatic_realm is read from AM of EAP-SIM.
	eap_variable_data_c m_automatic_realm;

	/// This flag tells whether automatic realm is read from AM of EAP-SIM.
	/// Note the data of m_automatic_realm could be invalid data when it is not used.
	bool m_automatic_realm_read;

	/// This is identity used in authentication. This is real IMSI or pseudonym.
	/// Pseudonym is used only if server supports use of pseudonym.
	eap_variable_data_c m_identity;

	/// This is the NAI. Format is "username@realm".
	eap_variable_data_c m_NAI;

	eap_variable_data_c m_n_rands;

	eap_variable_data_c m_n_sres;

	/// This variable stores the received GSMSIM version list.
	eap_variable_data_c m_gsmsim_version_list;

#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	/// Here is stored the received triplets.
	eap_type_sim_triplet_array_c *m_triplets;
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


	u32_t m_reauthentication_counter;

	gsmsim_payload_AT_type_e m_include_identity_to_start_response;

	/// Identity of this type is included in start response.
	gsmsim_payload_AT_type_e m_start_response_includes_identity;

	/// This flag indicates whether the EAP-Failure was received.
	/// On successfull authentication bogus EAP-Failure is ignored.
	bool m_failure_message_received;
	/// This flag indicated whether the authentication was successfull (true).
	bool m_authentication_finished_successfully;

	/// This variable stores the last used EAP-Identifier.
	/// Client will always send EAP-Response with this identifier.
	/// Server will always send EAP-Request with this identifier increased by one.
	/// Server increase this identifier after successfull packet send.
	u8_t m_last_eap_identifier;

	eap_gsmsim_version m_gsmsim_selected_version;

	eap_variable_data_c m_2_digit_mnc_map_of_mcc_of_imsi_array;

	eap_variable_data_c m_uma_automatic_realm_prefix;

	bool m_use_uma_profile;

	//--------------------------------------------------

	/// This is pointer to adaptation module of GSMSIM EAP type.
	eap_am_type_gsmsim_c * const m_am_type_gsmsim;

#if defined(_DEBUG) && defined(USE_EAP_GSMSIM_TEST_VECTORS)
	eap_variable_data_c m_nonce_mt_file;
#endif //#if defined(_DEBUG) && defined(USE_EAP_GSMSIM_TEST_VECTORS)

	eap_variable_data_c m_manual_username;

	eap_variable_data_c m_manual_realm;

	/// This eap_gsmsim_version array is the supported GSMSIM version list.
	eap_gsmsim_version m_supported_versions[GSMSIM_LAST_VERSION];

	/// This is offset in bytes of the EAP-type header in the packet buffer.
	/// Offset is described in abs_eap_base_type_c::get_header_offset().
	u32_t m_gsmsim_header_offset;

	/// This is maximum transfer unit in bytes.
	/// MTU is described in abs_eap_base_type_c::get_header_offset().
	u32_t m_MTU;

	/// This is length of the trailer in bytes.
	/// Trailer length is described in abs_eap_base_type_c::get_header_offset().
	u32_t m_trailer_length;

	/// This is minimum count of RAND challenges accepted.
	u32_t m_minimum_rand_count;

	u32_t m_length_of_mnc;

	/// This stores the current authentication type.
	/// Look at the m_identity_type too.
	eap_gsmsim_authentication_type_e m_authentication_type;

	/// This stores the current identity type.
	/// NOTE there is one stupid case where m_identity_type is GSMSIM_IDENTITY_TYPE_RE_AUTH_ID
	/// and m_authentication_type is GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH.
	/// Look at the Chapter "Fast Re-authentication Procedure when Counter is Too Small"
	/// in the EAP-SIM specification.
	/// Because of that illogical specification we need separate 
	/// attributes for authentication type and identity type.
	eap_type_gsmsim_identity_type m_identity_type;

	/// This is the first client error.
	eap_gsmsim_client_error_code_e m_client_error_code;

	/// This is saved GSMSIM notificatoin code.
	/// If this value is eap_gsmsim_notification_none, no notification is stored.
	eap_gsmsim_notification_codes_e m_gsmsim_notification_code;

	u32_t m_failure_message_delay_time;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/// This indicates whether this object is client (true) or server (false).
	/// In terms of EAP-protocol whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	bool m_is_client;

	/// True value of this flag indicates the EAP-Success packet must be received
	/// in successfull authentication of clien.
	/// This value is configured with EAP_GSMSIM_wait_eap_success_packet.
	bool m_wait_eap_success_packet;

	/// True value of this flag indicates the identifier of the EAP-Response/Identity must be checked.
	/// This is not possible cases where identifier of the EAP-Request/Identity is generated by other network entities.
	bool m_check_identifier_of_eap_identity_response;


	/// True value means m_am_type_gsmsim is allocated within eap_type_gsmsim_c
	/// and m_am_type_gsmsim must be freed in destructor.
	bool m_free_am_type_gsmsim;

#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)
	/// True value means client responds to all re-transmitted EAP-SIM packets.
	/// False value means client does not respond to any re-transmitted EAP-SIM packets.
	bool m_client_responds_retransmitted_packets;
#endif //#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)

	/// True value means this is a test version of GSMSIM.
	bool m_gsmsim_test_version;

	/// True value means server refuses EAP-identity randomly.
	/// False value means does not refuse EAP-identity randomly.
	/// NOTE EAP_GSMSIM_test_version option must be true also.
	bool m_gsmsim_randomly_refuse_eap_identity;

	/// This flag forces check of NAI realm. Realm must be the same as given in EAP_GSMSIM_manual_realm configuration option.
	/// Default value is false, check is not done by default.
	bool m_check_nai_realm;

	/// This is for testing purposes. True value will cause failed test of re-authentication counter.
	bool m_fail_reauthentication_counter_check;

	/// True value of this flag allows acception of EAP-Response/Identity.
	/// False value does not accept EAP-Response/Identity. Instead identity is queried
	/// in EAP-Request/SIM/Start with AT_ANY_ID_REQ attribute.
	bool m_accept_eap_identity_response;

	/// True value of this flag returns random
	/// identity on EAP-Response/Identity.
	/// False value returns real identity
	/// (IMSI, pseudonym or re-authentication identity).
	bool m_use_random_identity_on_eap_identity_response;

	/// This flag is set true when shutdown() function is called.
	bool m_shutdown_was_called;

	/// This flag is set true when reset() function is called.
	/// This flag prevent multiple subsequent calls of rset() function.
	bool m_reset_was_called;

	/// This flag tells whether the client should check uniqueness of RANDs (true) or not (false).
	bool m_do_rand_uniqueness_check;

	/// This flag tells whether the pseudonym identity could be used (true) or not (false).
	bool m_use_pseudonym_identity;

	/// This flag tells whether the re-authentication identity could be used (true) or not (false).
	bool m_use_reauthentication_identity;

	/// This is set true when erroneus packet is received.
	bool m_erroneus_packet_received;

	/// This is set true when SIM notification packet is received.
	bool m_sim_notification_packet_received;

	/// This flag allows use of Windows RAS identity in EAP-Identity/Response.
	/// EAP-Request/Start will include identity query attribute.
	bool m_use_manual_username;

	/// Default value is false. That will cause use of automatic realm.
	/// If this is true then
	/// cf_str_EAP_GSMSIM_manual_realm is used as the realm.
	bool m_use_manual_realm;

	bool m_randomly_fail_successfull_authentication;

	bool m_allow_use_result_indication;

	bool m_use_result_indication;

	bool m_use_eap_expanded_type;

	//--------------------------------------------------

	/**
	 * This function stores the last encryption IV. In CBC-mode previous encrypted block is
	 * used as a IV of next block.
	 */
	eap_status_e store_last_encryption_iv(const eap_variable_data_c * const encryption_IV);

	/**
	 * This function selects best version from version list payload.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_gsmsim_version select_version(
		const gsmsim_variable_data_c * const version_payload,
		bool * const includes_other_version_than_1);

	/**
	 * This function returns string of the current state. This is for trace purposes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_const_string get_state_string() const;

	/**
	 * This function returns string of the current state. This is for trace purposes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_const_string get_saved_previous_state_string() const;

	/**
	 * This function sets the new state and notifies the lower layer of this change.
	 */
	void set_state(eap_type_gsmsim_state_variable_e state);

	#define GSMSIM_STATE_COUNT(array) (sizeof(array)/sizeof(array[0]))

	/**
	 * This function checks the valid states.
	 */
	bool verify_states(
		const eap_type_gsmsim_state_variable_e * const valid_states,
		const u32_t count) const;


#if !defined(NO_EAP_TYPE_GSMSIM_MESSAGE_STATE_CHECK)

	/**
	 * This function checks the received GSMSIM subtype is valid in current state.
	 * This is used for quick check.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e check_valid_state(gsmsim_subtype_e type);

	/**
	 * This function returns the eap_type_gsmsim_state_variable_parameters_c object of current state.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H const eap_type_gsmsim_state_variable_parameters_c * get_state_variable();

#endif //#if !defined(NO_EAP_TYPE_GSMSIM_MESSAGE_STATE_CHECK)


	/**
	 * This function saves the current m_state to m_saved_previous_state.
	 * The saved state is restored in error case.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H void save_current_state();

	/**
	 * This function restores the saved state.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H void restore_saved_previous_state();

	/**
	 * This function stores identity.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e store_identity(
		const eap_variable_data_c * const IMSI_or_pseudonym,
		const bool IMSI_is_used);

#if !defined(NO_EAP_TYPE_GSMSIM_MESSAGE_STATE_CHECK)
	/**
	 * This function initializes the allowed messages within one specific state.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H void initialize_state(
		const eap_type_gsmsim_state_variable_e state,
		const bool must_be_initiator,
		const bool must_be_responder,
		const gsmsim_subtype_e type0,
		const gsmsim_subtype_e type1,
		const gsmsim_subtype_e type2,
		const gsmsim_subtype_e type3);
#endif //#if !defined(NO_EAP_TYPE_GSMSIM_MESSAGE_STATE_CHECK)

	/**
	 * This function expands key and seed data to key_length of expansion.
	 *  expansion_0 = prf(key, seed | 0)
	 *  expansion_i = prf(key, expansion_i-1 | seed | i), where i = 1, 2...
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e data_exp(
		const u32_t key_length,
		eap_variable_data_c * const expansion,
		const eap_variable_data_c * const key,
		const eap_variable_data_c * const seed);

	/**
	 * This function generates K_encr, K_aut and master_session_key.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e generate_shared_secred_keys(
		const u32_t key_length,
		const eap_variable_data_c * const n_Kc,
		const eap_variable_data_c * const n_sres,
		eap_variable_data_c * const XKEY,
		eap_variable_data_c * const K_encr,
		eap_variable_data_c * const K_aut,
		eap_variable_data_c * const master_session_key);


	/**
	 * This function generates K_encr, K_aut and master_session_key.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e generate_reauth_shared_secred_keys(
		const u32_t key_length,
		const eap_variable_data_c * const orig_XKEY,
		const u32_t reauth_counter,
		const eap_variable_data_c * const reauth_identity,
		const eap_variable_data_c * const reauth_nonce_s,
		eap_variable_data_c * const master_session_key);

#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	/**
	 * This function stores pointer to the received triplet array.
	 */
	void set_triplets(eap_type_sim_triplet_array_c * const triplets);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)

	/**
	 * This function saves version list from version list payload.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e save_version(
		const u16_t * const payload_version_list,
		const u32_t version_count,
		const eap_gsmsim_version selected_version);

	/**
	 * This function generates a new NAI from domain and IMSI.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e generate_nai(
		eap_variable_data_c * const new_nai, ///< This is the new generated NAI.
		const bool use_manual_default_realm, ///< When true uses realm parameter, when false generates automatic realm.
		const eap_variable_data_c * const realm, ///< This is the domain part of the NAI.
		const eap_variable_data_c * const id_IMSI_or_pseydonym, ///< This is IMSI or pseudonym.
		const bool id_is_imsi, ///< This parameter tells whether id_IMSI_or_pseydonym is IMSI (true) or pseudonym (false).
		const eap_variable_data_c * const IMSI, ///< This parameter must be IMSI always.
		const eap_variable_data_c * const automatic_realm, ///< This could be zero pointer if this is not used.
		const u32_t length_of_mnc
		);

	/**
	 * This function adds generic attribute payload to GSMSIM message.
	 * @param gsmsim is pointer to EAP header including GSMSIM fields.
	 * @param maximum_buffer_size is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also gsmsim_header_c and eap_header_base_c.
	 * @param data_offset is the offset of inserted payloads in GSMSIM EAP packet.
	 * It is the value of GSMSIM sub-type data.
	 * @param data_free is the remaining free GSMSIM data buffer size.
	 * @param buffer_free is the remaining free packet buffer size.
	 * @param buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param data_payload is the new payload to be added.
	 * @param data_payload_type is the attribute payload type to be added.
	 *
	 * See also eap_type_gsmsim_c::update_payload_indexes().
	 *
	 * Format of the payload is as follows:
	 * @code
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * | AT type       | Payload Length|       Reserved                |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * | Any variable length payload                                   |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e add_variable_payload(
		gsmsim_header_c * const gsmsim,
		const u32_t maximum_buffer_size,
		const u32_t eap_header_size,
		u32_t * const data_offset,
		u32_t * const data_free,
		u32_t * const buffer_free,
		u32_t * const buffer_offset,
		const eap_variable_data_c * const data_payload,
		const gsmsim_payload_AT_type_e data_payload_type);


	/**
	 * This function adds IMSI or pseudonym attribute payload to GSMSIM message.
	 * @param gsmsim is pointer to EAP header including GSMSIM fields.
	 * @param maximum_buffer_size is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also gsmsim_header_c and eap_header_base_c.
	 * @param data_offset is the offset of inserted payloads in GSMSIM EAP packet.
	 * It is the value of GSMSIM sub-type data.
	 * @param data_free is the remaining free GSMSIM data buffer size.
	 * @param buffer_free is the remaining free packet buffer size.
	 * @param buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param pseudonym_or_imsi is the IMSI or pseudonym payload to be added.
	 * @param data_payload_type is the attribute payload type to be added.
	 *
	 * See also eap_type_gsmsim_c::update_payload_indexes().
	 *
	 * Format of the payload is as follows:
	 * @code
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * | AT_<type>     | Length        | Actual Pseudonym Length       |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                                                               |
	 * |                    Pseudonym or IMSI                          |
	 * |                                                               |
	 * |                                                               |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e add_pseudonym_or_imsi_payload(
		gsmsim_header_c * const gsmsim,
		const u32_t maximum_buffer_size,
		const u32_t eap_header_size,
		u32_t * const data_offset,
		u32_t * const data_free,
		u32_t * const buffer_free,
		u32_t * const buffer_offset,
		const eap_variable_data_c * const pseudonym_or_imsi,
		const gsmsim_payload_AT_type_e data_payload_type);


	/**
	 * This function adds version list attribute payload to GSMSIM message.
	 * @param gsmsim is pointer to EAP header including GSMSIM fields.
	 * @param maximum_buffer_size is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also gsmsim_header_c and eap_header_base_c.
	 * @param data_offset is the offset of inserted payloads in GSMSIM EAP packet.
	 * It is the value of GSMSIM sub-type data.
	 * @param data_free is the remaining free GSMSIM data buffer size.
	 * @param buffer_free is the remaining free packet buffer size.
	 * @param buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param gsmsim_versions is the version list (actually array) payload to be added.
	 * @param gsmsim_versions_count is the count versions in the array.
	 * @param data_payload_type is the attribute payload type to be added.
	 *
	 * See also eap_type_gsmsim_c::update_payload_indexes().
	 *
	 * Format of the payload is as follows:
	 * @code
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * | AT_VERSION_L..| Length        | Actual Version List Length    |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |  Supported Version 1          |  Padding                      |                        
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e add_version_list(
		gsmsim_header_c * const gsmsim,
		const u32_t gsmsim_buffer_length,
		const u32_t eap_header_size,
		u32_t * const gsmsim_data_offset,
		u32_t * const gsmsim_data_free,
		u32_t * const packet_buffer_free,
		u32_t * const packet_buffer_offset,
		const eap_gsmsim_version *gsmsim_versions,
		const u32_t gsmsim_versions_count,
		const gsmsim_payload_AT_type_e data_payload_type);


	/**
	 * This function adds selected version attribute payload to GSMSIM message.
	 * @param gsmsim is pointer to EAP header including GSMSIM fields.
	 * @param gsmsim_buffer_length is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also gsmsim_header_c and eap_header_base_c.
	 * @param gsmsim_data_offset is the offset of inserted payloads in GSMSIM EAP packet.
	 * It is the value of GSMSIM sub-type data.
	 * @param gsmsim_data_free is the remaining free GSMSIM data buffer size.
	 * @param packet_buffer_free is the remaining free packet buffer size.
	 * @param packet_buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param version is the selected GSMSIM version.
	 *
	 * See also eap_type_gsmsim_c::update_payload_indexes().
	 *
	 * Format of the payload is as follows:
	 * @code
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |AT_SELECTED_...| Length = 1    |      Notification Code        |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e add_version_payload(
		gsmsim_header_c * const gsmsim,
		const u32_t gsmsim_buffer_length,
		const u32_t eap_header_size,
		u32_t * const gsmsim_data_offset,
		u32_t * const gsmsim_data_free,
		u32_t * const packet_buffer_free,
		u32_t * const packet_buffer_offset,
		const eap_gsmsim_version version);

	/**
	 * This function adds selected version attribute payload to GSMSIM message.
	 * @param gsmsim is pointer to EAP header including GSMSIM fields.
	 * @param gsmsim_buffer_length is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also gsmsim_header_c and eap_header_base_c.
	 * @param gsmsim_data_offset is the offset of inserted payloads in GSMSIM EAP packet.
	 * It is the value of GSMSIM sub-type data.
	 * @param gsmsim_data_free is the remaining free GSMSIM data buffer size.
	 * @param packet_buffer_free is the remaining free packet buffer size.
	 * @param packet_buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param counter is the re-authentication counter.
	 *
	 * See also eap_type_gsmsim_c::update_payload_indexes().
	 *
	 * Format of the payload is as follows:
	 * @code
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |AT_COUNTER     | Length = 1    |      Counter                  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e add_counter_payload(
		gsmsim_header_c * const gsmsim,
		const u32_t gsmsim_buffer_length,
		const u32_t eap_header_size,
		u32_t * const gsmsim_data_offset,
		u32_t * const gsmsim_data_free,
		u32_t * const packet_buffer_free,
		u32_t * const packet_buffer_offset,
		u16_t counter);

	/**
	 * This function adds simple attribute payload to GSMSIM message.
	 * @param gsmsim is pointer to EAP header including GSMSIM fields.
	 * @param gsmsim_buffer_length is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also gsmsim_header_c and eap_header_base_c.
	 * @param gsmsim_data_offset is the offset of inserted payloads in GSMSIM EAP packet.
	 * It is the value of GSMSIM sub-type data.
	 * @param gsmsim_data_free is the remaining free GSMSIM data buffer size.
	 * @param packet_buffer_free is the remaining free packet buffer size.
	 * @param packet_buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param data_payload_type is the type of simple payload.
	 *
	 * See also eap_type_gsmsim_c::update_payload_indexes().
	 *
	 * Format of the payload is as follows:
	 * @code
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |AT_XXX         | Length = 1    |      Reserved                 |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e add_simple_payload(
		gsmsim_header_c * const gsmsim,
		const u32_t gsmsim_buffer_length,
		const u32_t eap_header_size,
		u32_t * const gsmsim_data_offset,
		u32_t * const gsmsim_data_free,
		u32_t * const packet_buffer_free,
		u32_t * const packet_buffer_offset,
		const gsmsim_payload_AT_type_e data_payload_type);

	/**
	 * This function adds Notification attribute payload to GSMSIM message.
	 * @param gsmsim is pointer to EAP header including GSMSIM fields.
	 * @param gsmsim_buffer_length is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also gsmsim_header_c and eap_header_base_c.
	 * @param gsmsim_data_offset is the offset of inserted payloads in GSMSIM EAP packet.
	 * It is the value of GSMSIM sub-type data.
	 * @param gsmsim_data_free is the remaining free GSMSIM data buffer size.
	 * @param packet_buffer_free is the remaining free packet buffer size.
	 * @param packet_buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param triplet_status is the notification.
	 *
	 * See also eap_type_gsmsim_c::update_payload_indexes().
	 *
	 * Format of the payload is as follows:
	 * @code
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |AT_NOTIFICATION| Length = 1    |      Notification Code        |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e add_notification_payload(
		gsmsim_header_c * const gsmsim,
		const u32_t gsmsim_buffer_length,
		const u32_t eap_header_size,
		u32_t * const gsmsim_data_offset,
		u32_t * const gsmsim_data_free,
		u32_t * const packet_buffer_free,
		u32_t * const packet_buffer_offset,
		const eap_gsmsim_notification_codes_e notification_code);

	/**
	 * This function adds AT_CLIENT_ERROR_CODE attribute payload to GSMSIM message.
	 * @param gsmsim is pointer to EAP header including GSMSIM fields.
	 * @param gsmsim_buffer_length is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also gsmsim_header_c and eap_header_base_c.
	 * @param gsmsim_data_offset is the offset of inserted payloads in GSMSIM EAP packet.
	 * It is the value of GSMSIM sub-type data.
	 * @param gsmsim_data_free is the remaining free GSMSIM data buffer size.
	 * @param packet_buffer_free is the remaining free packet buffer size.
	 * @param packet_buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param client_error_code is the error code to be sent.
	 *
	 * See also eap_type_gsmsim_c::update_payload_indexes().
	 *
	 * Format of the payload is as follows:
	 * @code
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |AT_CLIENT_ERR..| Length = 1    |      Client Error Code        |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e add_client_error_payload(
		gsmsim_header_c * const gsmsim,
		const u32_t gsmsim_buffer_length,
		const u32_t eap_header_size,
		u32_t * const gsmsim_data_offset,
		u32_t * const gsmsim_data_free,
		u32_t * const packet_buffer_free,
		u32_t * const packet_buffer_offset,
		const eap_gsmsim_client_error_code_e client_error_code);


	/**
	 * This function adds message authentication code (MAC) attribute payload to GSMSIM message.
	 * This MAC is written later in the create_message_authentication_code() function.
	 * MAC includes the whole EAP message.
	 * @param gsmsim is pointer to EAP header including GSMSIM fields.
	 * @param maximum_buffer_size is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also gsmsim_header_c and eap_header_base_c.
	 * @param data_offset is the offset of inserted payloads in GSMSIM EAP packet.
	 * It is the value of GSMSIM sub-type data.
	 * @param data_free is the remaining free GSMSIM data buffer size.
	 * @param buffer_free is the remaining free packet buffer size.
	 * @param buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param MAC_data is the start of the message authentication code (MAC) to be written.
	 * @param MAC_data_length is the length of the message authentication code (MAC) to be written.
	 *
	 * See also eap_type_gsmsim_c::update_payload_indexes().
	 *
	 * Format of the payload is as follows:
	 * @code
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * | AT_MAC        |  Length       |          Reserved             |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * | MAC                                                           |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e add_mac_payload(
		gsmsim_header_c * const gsmsim,
		const u32_t maximum_buffer_size,
		const u32_t eap_header_size,
		u32_t * const data_offset,
		u32_t * const data_free,
		u32_t * const buffer_free,
		u32_t * const buffer_offset,
		u8_t ** const MAC_data,
		u32_t * const MAC_data_length);

	/**
	 * This function adds message authentication code (MAC) attribute payload to GSMSIM message.
	 * This MAC is written later in the create_message_authentication_code() function.
	 * @param gsmsim is pointer to EAP header including GSMSIM fields.
	 * @param maximum_buffer_size is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also gsmsim_header_c and eap_header_base_c.
	 * @param data_offset is the offset of inserted payloads in GSMSIM EAP packet.
	 * It is the value of GSMSIM sub-type data.
	 * @param data_free is the remaining free GSMSIM data buffer size.
	 * @param buffer_free is the remaining free packet buffer size.
	 * @param buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param plaintext_length is the length of the plain text. Padding length is calculated from this.
	 *
	 * See also eap_type_gsmsim_c::update_payload_indexes().
	 *
	 * Format of the payload is as follows:
	 * @code
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * | AT_PADDING    |     Length    |     Padding set to zero       |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * | Zero or more padding octets. Padding octet is 0x00.           |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e add_padding_payload(
		gsmsim_header_c * const gsmsim_packet,
		const u32_t maximum_buffer_size,
		const u32_t eap_header_size,
		u32_t * const data_offset,
		u32_t * const data_free,
		u32_t * const buffer_free,
		u32_t * const buffer_offset,
		const u32_t plaintext_length);

	/**
	 * This function verifies the message authentication code (MAC) is correct.
	 * @see add_mac_payload().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e check_message_authentication_code(
		const eap_variable_data_c * const authentication_key,
		gsmsim_payloads_c * const p_gsmsim_payloads, ///< This is pointer to all payloads of the received EAP packet.
		const gsmsim_header_c * const gsmsim_packet,
		const u32_t gsmsim_packet_length);

	/**
	 * This function handles the received GSMSIM EAP packet.
	 *
	 * First is checked the valid massage is received in valid state.
	 * See also eap_type_gsmsim_state_c::check_valid_state().
	 *
	 * Second is parsed the payloads and checked syntax of the received GSMSIM EAP packet.
	 * See also parse_gsmsim_packet().
	 *
	 * Third is analysed the GSMSIM EAP packet. This includes the payload and values of each payload.
	 * See also analyse_gsmsim_packet().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_gsmsim_packet(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		gsmsim_header_c * const gsmsim, ///< This is pointer to EAP header including GSMSIM fields.
		const u32_t gsmsim_length, ///< This is length of received GSMSIM EAP packet.
		gsmsim_payloads_c * const p_gsmsim_payloads ///< This is pointer to all payloads of the received EAP packet.
		);

	/**
	 * This function analyses the received GSMSIM EAP packet.
	 * Each sub-type is handled in separate function.
	 * @see Client messages are handled in handle_start_request_message() and handle_challenge_request_message(). 
	 * @see Server messages are handled in handle_start_response_message() and handle_challenge_response_message(). 
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e analyse_gsmsim_packet(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		gsmsim_header_c * const received_gsmsim, ///< This is pointer to EAP header including GSMSIM fields.
		const u32_t gsmsim_packet_length, ///< This is length of received GSMSIM EAP packet.
		gsmsim_payloads_c * const p_gsmsim_payloads ///< This is pointer to all payloads of the received EAP packet.
		);

	/**
	 * This function parses the payloads starting from specified payload (p_payload).
	 * Function parses all payloads from the buffer.
	 * Payloads are stored to p_gsmsim_payloads.
	 * @return If the length of the buffer and sum of the length of all payloads does not match
	 * function returns eap_status_header_corrupted.
	 * Also error is returned when illegal payload attribute is recognised.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e parse_gsmsim_payload(
		const gsmsim_payload_AT_header_c * const p_payload, ///< This is the start of the buffer and the first parsed payload.
		u32_t * const buffer_length, ///< This is the length of the buffer. This must match with the length of all payloads.
		gsmsim_payloads_c * const p_gsmsim_payloads, ///< This is pointer to all payloads of the received EAP packet.
		const gsmsim_subtype_e subtype
		);

	/**
	 * This function checks the version list payload of the GSMSIM EAP packet is correct.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e check_version_list(
		const gsmsim_payload_AT_header_c * const payload,
		const u16_t version_list_length,
		u8_t * version_list,
		bool * const includes_other_version_than_1);

	/**
	 * This function parses all payloads of the whole GSMSIM EAP packet.
	 * Payloads are stored to p_gsmsim_payloads.
	 * @see parse_gsmsim_payload().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e parse_gsmsim_packet(
		gsmsim_header_c * const gsmsim, ///< This is pointer to EAP header including GSMSIM fields.
		const u32_t gsmsim_packet_length, ///< This is length of received GSMSIM EAP packet.
		gsmsim_payloads_c * const p_gsmsim_payloads ///< This is pointer to all payloads of the received EAP packet.
		);

	/**
	 * This function parses each payload attributes.
	 * @return If payload attribute is illegal function returns eap_status_header_corrupted.
	 * If payload attribute is unknown function returns eap_status_unsupported_gsmsim_payload.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e parse_generic_payload(
		const gsmsim_payload_AT_type_e current_payload, ///< This is the type of current payload attribute.
		const gsmsim_payload_AT_header_c * const payload, ///< This is the current parsed payload.
		gsmsim_payloads_c * const p_gsmsim_payloads, ///< This is pointer to all payloads of the received EAP packet.
		const gsmsim_subtype_e subtype);


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	/**
	 * This function sends the EAP-Request/SIM/Re-authentication message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e send_reauthentication_request_message(
		const eap_variable_data_c * const username,
		const bool pseudonym_decode_failed,
		const u8_t eap_identifier);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	/**
	 * This function sends the EAP-Request/SIM/Start message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e send_start_request_message(
		const bool pseudonym_decode_failed, ///< This identifies whether the pseudonym decode was failed (true). We must send a IMSI request.
		const u8_t eap_identifier ///< This is the EAP-Identifier used with this message.
		);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


	/**
	 * This function sends the EAP-Response/SIM/Start message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e send_start_response_message(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet. NOTE received.
		const u8_t received_eap_identifier, ///< This is the EAP-identifier of the received EAP-request message.
		const eap_gsmsim_version version, ///< This is the selected GSMSIM version.
		const gsmsim_payload_AT_type_e include_identity_to_start_response, ///< This is the queried identity type.
		const eap_variable_data_c * const automatic_realm, ///< This could be zero pointer if this is not used.
		const u32_t length_of_mnc
		);

	/**
	 * This function sends the EAP-Response/SIM/Notification message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e send_gsmsim_notification_response(
		const eap_gsmsim_notification_codes_e notification_code, ///< This is the status of the failed triplet query.
		const bool add_at_counter_attribute
		);

	/**
	 * This function sends the EAP-Response/SIM/Client-Error message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e send_gsmsim_client_error_response();


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	/**
	 * This function sends the EAP-Request/SIM/Challenge message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e send_challenge_request_message(
		const u8_t eap_identifier ///< This is the EAP-Identifier used with this message.
		);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


	/**
	 * This function sends the EAP-Response/SIM/Challenge message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e send_challenge_response_message(
		eap_variable_data_c * const K_aut);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e send_reauthentication_response_message(
		const eap_variable_data_c * const orig_XKEY,
		const eap_variable_data_c * const orig_K_aut,
		const eap_variable_data_c * const orig_K_encr,
		const eap_variable_data_c * const reauth_username,
		const eap_variable_data_c * const reauth_nonce_s,
		const u16_t reauth_counter,
		const u8_t eap_identifier,
		const bool include_at_counter_too_small);


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	/**
	 * This function sends the EAP-Request/SIM/Notification message.
	 * Message includes the localizable notification string.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e send_gsmsim_notification_request(
		const eap_gsmsim_notification_codes_e notification_code, ///< This is the status of the failed triplet query.
		const bool add_at_counter_attribute
		);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


	/**
	 * This function encrypts the payload.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e encrypt_DATA_payload(
		u8_t * const EAP_data, ///< This is pointer to the begin of the encrypted payload.
		const u32_t cbc_aes_data_length, ///< This is the length of the encrypted payload. This must be aligned to AES block length.
		const eap_variable_data_c * const IV,
		const eap_variable_data_c * const encryption_key
		);


	/**
	 * This function decrypts the payload.
	 * p_gsmsim_payloads->get_ENCR_DATA() points to the decrypted payload.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e decrypt_DATA_payload(
		gsmsim_payloads_c * const p_gsmsim_payloads, ///< This is pointer to all payloads of the received EAP packet.
		const eap_variable_data_c * const encryption_key
		);

	/**
	 * This function handles the received DATA payload attribute.
	 * The received encrypte payload have been decrypted before thiscall.
	 * p_gsmsim_payloads->get_ENCR_DATA() includes decrypted DATA payload.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_DATA_payload(
		const gsmsim_subtype_e subtype,
		gsmsim_payloads_c * const p_gsmsim_payloads ///< This is pointer to all payloads of the received EAP packet.
		);

	//--------------------------------------------------

	/**
	 * This function generate a new NONCE of nonce_size octets length.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e generate_nonce(
		const u32_t nonce_size,
		eap_variable_data_c * const nonce);

	/**
	 * This function returns the domain name.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_variable_data_c * get_nai_realm();

	/**
	 * This is the situation before the update_buffer_indexes() call.
	 * @code
	 * 
	 * |<---------buffer_offset-------->|<----------buffer_free----------------->|
	 * |                                |                                        |
	 * |          +-----+---------------+--------------------+                   |
	 * |          | EAP |  data         | new payload        |                   |
	 * |          +-----+---------------+--------------------+                   |
	 * |          |                                                              |
	 * |<-offset->|<----MTU----------------------------------------------------->|<-trailer->|
	 * |                                                                                     |
	 * |<-----------------------maximum_buffer_size----------------------------------------->|
	 *                                                                                    
	 * @endcode
	 *
	 * This is the situation after the update_buffer_indexes() call.
	 * @code
	 * 
	 * |<-----------------buffer_offset--------------------->|<---buffer_free--->|
	 * |                                                     |                   |
	 * |          +-----+---------------+--------------------+                   |
	 * |          | EAP |  data         | new payload        |                   |
	 * |          +-----+---------------+--------------------+                   |
	 * |          |                                                              |
	 * |<-offset->|<----MTU----------------------------------------------------->|<-trailer->|
	 * |                                                                                     |
	 * |<-----------------------maximum_buffer_size----------------------------------------->|
	 *
	 * @endcode
	 *
	 * Note maximum_buffer_size could be larger than (m_gsmsim_header_offset + m_MTU + m_trailer_length).
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H void update_buffer_indexes(
		const u32_t maximum_buffer_size,
		const u32_t payload_size,
		u32_t * const buffer_offset,
		u32_t * const buffer_free);

	/**
	 * This is the situation before the update_payload_indexes() call.
	 * @code
	 * 
	 * |<---------buffer_offset-------->|<----------buffer_free----------------->|
	 * |                                |                                        |
	 * |                |<-data_offset->|<--------data_free--------------------->|
	 * |                |               |                                        |
	 * |                |               |<---payload_size--->|                   |
	 * |                |               |                    |                   |
	 * |          +-----+---------------+--------------------+                   |
	 * |          | EAP |  data         | new payload        |                   |
	 * |          +-----+---------------+--------------------+                   |
	 * |          |                                                              |
	 * |<-offset->|<----MTU----------------------------------------------------->|<-trailer->|
	 * |                                                                                     |
	 * |<-----------------------maximum_buffer_size----------------------------------------->|
	 *                                                                                    
	 * @endcode
	 *
	 * This is the situation after the update_payload_indexes() call.
	 * @code
	 * 
	 * |<-----------------buffer_offset--------------------->|<---buffer_free--->|
	 * |                                                     |                   |
	 * |                |<----------data_offset------------->|<----data_free---->|
	 * |                |                                    |                   |
	 * |                |               |<---payload_size--->|                   |
	 * |                |               |                    |                   |
	 * |          +-----+---------------+--------------------+                   |
	 * |          | EAP |  data         | new payload        |                   |
	 * |          +-----+---------------+--------------------+                   |
	 * |          |                                                              |
	 * |<-offset->|<----MTU----------------------------------------------------->|<-trailer->|
	 * |                                                                                     |
	 * |<-----------------------maximum_buffer_size----------------------------------------->|
	 *
	 * @endcode
	 *
	 * Note maximum_buffer_size could be larger than (m_gsmsim_header_offset + m_MTU + m_trailer_length).
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H void update_payload_indexes(
		const u32_t maximum_buffer_size,
		const u32_t eap_header_size,
		const u32_t payload_size,
		u32_t * const data_offset,
		u32_t * const data_free,
		u32_t * const buffer_offset,
		u32_t * const buffer_free);

	/**
	 * This function queries the IMSI or saved pseudonym. IMSI is queried always. The optional
	 * pseudonym is returned if it has been received and it has been stored to GSMSIM AM.
	 * This function could be synchronous or asynchronous. Parameter must_be_synchronous could be
	 * used if only synchronous call is accepted.
	 *
	 * @return Successful syncronous call returns eap_status_ok.
	 * The process_SIM_IMSI() function must be called immediately.
	 *
	 * @return Successful asynchronous call returns eap_status_ok.
	 * This means call was indeed synchronous. 
	 * The process_SIM_IMSI() function must be called immediately.
	 *
	 * @return Pending asynchronous call returns eap_status_pending_request.
	 * AM will complete this call later by complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query() call.
	 *
	 * @return Immediately comleted asynchronous call returns eap_status_completed_request.
	 * AM already called the complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query().
	 *
	 * @return Other return values are errors.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e query_SIM_IMSI_or_pseudonym_or_reauthentication_id(
		eap_variable_data_c * const IMSI, ///< Pointer to IMSI. Buffer for IMSI is allocated during the call.
		eap_variable_data_c * const pseudonym_identity, ///< Pointer to pseudonym. Buffer for pseudonym is allocated during the call.
		eap_variable_data_c * const reauthentication_identity, ///< Pointer to reauthentication_identity. Buffer for reauthentication_identity is allocated during the call.
		eap_variable_data_c * const automatic_realm, ///< If this is not used, do not add any data to this parameter.
		u32_t * const length_of_mnc,
		const bool must_be_synchronous, ///< True value indicates only synchronous call is accepted.
		const gsmsim_payload_AT_type_e required_identity, ///< This parameter indicated the type of identity required.
		const eap_type_gsmsim_complete_e required_completion, ///< This parameter tells the required completion after this call is completed, if this is asyncronous. Use this value with abs_eap_am_type_gsmsim_c::complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query() function call.
		const u8_t received_eap_identifier ///< This is the EAP-identifier of the received EAP-request message. Use this value with abs_eap_am_type_gsmsim_c::complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query() function call.
		);

	/**
	 * This function queries KC and SRES. Each of them could include multiple concatenated items.
	 * This function could be synchronous or asynchronous.
	 *
	 * @return Successful call returns eap_status_ok.
	 * This means call was indeed synchronous. 
	 * The process_SIM_kc_sres() function must be called immediately.
	 *
	 * @return Pending asynchronous call returns eap_status_pending_request.
	 * AM will complete this call later by complete_SIM_kc_sres() call.
	 *
	 * @return Immediately comleted asynchronous call returns eap_status_completed_request.
	 * AM already called the complete_SIM_kc_sres().
	 *
	 * @return Other return values are errors.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e query_SIM_kc_sres(
		const eap_variable_data_c * const n_rands, ///< This includes concatenated n RAND as input.
		eap_variable_data_c * const n_kc, ///< This includes concatenated n KC as output.
		eap_variable_data_c * const n_sres ///< This includes concatenated n SRES as output.
		);


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	/**
	 * This function queries the triplets. The triplets are stored to handler->get_triplets().
	 * This function could be synchronous or asynchronous.
	 *
	 * @return Successful call returns eap_status_ok.
	 * This means call was indeed synchronous. 
	 * The send_challenge_request_message() function must be called immediately.
	 *
	 * @return Pending asynchronous call returns eap_status_pending_request.
	 * AM will complete this call later by complete_SIM_triplets() call.
	 *
	 * @return Immediately comleted asynchronous call returns eap_status_completed_request.
	 * AM already called the complete_SIM_triplets().
	 *
	 * @return Other return values are errors.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e query_SIM_triplets(
		eap_type_gsmsim_identity_type * const identity_type
		);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


	/**
	 * This function creates local copy of MAC_RAND and checks the received one match with local MAC_RAND.
	 * After succesfull MAC_RAND check function parses the GSMSIM payloads from saved GSMSIM EAP packet.
	 * This is because of the process_SIM_kc_sres() function could be called asynchronously and
	 * the received GSMSIM EAP packet is stored to handler->get_saved_EAP_packet().
	 * Also encrypted payload (l_gsmsim_payloads.get_ENCR_DATA()) is handled here.
	 * This is the first place where we have the K_encr (handler->get_K_encr()) available.
	 * The decrpted DATA payload is handled immediately in handle_DATA_payload() function.
	 * Then function calculates MAC_SRES and sends EAP-Response/SIM/Challenge.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e process_SIM_kc_sres(
		const eap_variable_data_c * const n_rand, ///< This includes concatenated n RAND.
		const eap_variable_data_c * const n_kc, ///< This includes concatenated n KC.
		const eap_variable_data_c * const n_sres ///< This includes concatenated n SRES.
		);

	/**
	 * This function selects whether to use pseudonym or IMSI.
	 * Function creates NAI and EAP-Response/Identity message.
	 * Message is sent immediately.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e process_SIM_IMSI(
		const eap_variable_data_c * const IMSI, ///< This is the IMSI.
		const eap_variable_data_c * const pseudonym ///< This is the pseudonym.
		);


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	/**
	 * This function adds RAND attribute payload to GSMSIM message.
	 * Payload includes one or more RANDs.
	 * @param gsmsim is pointer to EAP header including GSMSIM fields.
	 * @param maximum_buffer_size is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also gsmsim_header_c and eap_header_base_c.
	 * @param data_offset is the offset of inserted payloads in GSMSIM EAP packet.
	 * It is the value of GSMSIM sub-type data.
	 * @param data_free is the remaining free GSMSIM data buffer size.
	 * @param buffer_free is the remaining free packet buffer size.
	 * @param buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param triplets includes all triplets used in this authentication session.
	 * See also eap_type_sim_triplet_array_c.
	 *
	 * See also eap_type_gsmsim_c::update_payload_indexes().
	 *
	 * Format of the payload is as follows:
	 * @code
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * | AT_RAND       | Length        |           Reserved            |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                            n*RAND ...
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e add_n_rand_payload(
		gsmsim_header_c * const gsmsim,
		const u32_t maximum_buffer_size,
		const u32_t eap_header_size,
		u32_t * const data_offset,
		u32_t * const data_free,
		u32_t * const buffer_free,
		u32_t * const buffer_offset,
		eap_type_sim_triplet_array_c * const triplets);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


	/**
	 * This function calculates the MAC_SRES.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e calculate_MAC_SRES(
		eap_variable_data_c * const MAC_SRES, ///< This is the calculated MAC_SRES.
		const eap_variable_data_c * const n_kc, ///< This includes concatenated n KC.
		const eap_variable_data_c * const n_sres ///< This includes concatenated n SRES.
		);


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	/**
	 * This function reads the identity payload. Identity is stored to handler->get_identity().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e parse_identity(
		const u8_t * const identity, ///< This is pointer to received EAP-Identity buffer.
		const u32_t identity_length ///< This is length of received EAP-Identity buffer.
		//const u32_t eap_packet_length ///< This is length of received EAP-Identity buffer.
		);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_eap_identity_query(
		const eap_am_network_id_c * const send_network_id,
		eap_variable_data_c * const identity,
		const u8_t eap_identifier,
		const eap_variable_data_c * const IMSI,
		const eap_variable_data_c * const pseudonym,
		const eap_variable_data_c * const reauthentication_identity,
		const eap_variable_data_c * const automatic_realm, ///< This could be zero pointer if this is not used.
		const u32_t length_of_mnc,
		const bool must_be_synchronous
		);


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	/**
	 * This function handles the received EAP-Response/Identity message.
	 * First function parses the identity.
	 * Function queries the AM (query_imsi_from_username()) whether the pseudonym
	 * is known or should it query peer the IMSI.
	 * Currently the query_imsi_from_username() is synchronous call.
	 * The send_start_request_message() function will send the EAP-Request/SIM/Start message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_identity_response_message(
		eap_header_rd_c * const eap_header, ///< This is the received EAP-Identity packet, pointer points to the header.
		const u32_t gsmsim_packet_length ///< This is length of received GSMSIM EAP packet.
		);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


	/**
	 * This function handles the received EAP-Request/SIM/Start message.
	 * Function checks the valid payloads and calls send_start_response_message() that sends EAP-Response/SIM/Start message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_start_request_message(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		gsmsim_header_c * const received_gsmsim, ///< This is pointer to EAP header including GSMSIM fields.
		const u32_t gsmsim_packet_length, ///< This is length of received GSMSIM EAP packet.
		gsmsim_payloads_c * const p_gsmsim_payloads ///< This is pointer to all payloads of the received EAP packet.
		);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_gsmsim_notification_request_message_reauthentication(
		const eap_am_network_id_c * const receive_network_id,
		gsmsim_header_c * const received_gsmsim,
		const u32_t gsmsim_packet_length,
		gsmsim_payloads_c * const p_gsmsim_payloads);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_gsmsim_notification_request_message_full_authentication(
		const eap_am_network_id_c * const receive_network_id,
		gsmsim_header_c * const received_gsmsim,
		const u32_t gsmsim_packet_length,
		gsmsim_payloads_c * const p_gsmsim_payloads);

	/**
	 * This function handles the received EAP-Request/SIM/Notification message.
	 * Function checks the valid payloads and calls send_notification_response_message() that sends EAP-Response/SIM/Notification message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_gsmsim_notification_request_message(
		const eap_am_network_id_c * const receive_network_id,
		gsmsim_header_c * const received_gsmsim,
		const u32_t gsmsim_packet_length,
		gsmsim_payloads_c * const p_gsmsim_payloads);

	/**
	 * This function handles the received EAP-Request/SIM/Challenge message.
	 * Function checks the valid payloads. The whole EAP-Request/SIM/Challenge message is
	 * saved to handler->get_saved_EAP_packet() if there is encrypted payload.
	 * This is because the MAC could be checked and payload dercypted later
	 * after n*Kc and n*SRES is get from SIM.
	 * Function calls query_SIM_kc_sres(). The query_SIM_kc_sres() function
	 * is completed using complete_SIM_kc_sres() function. The complete_SIM_kc_sres()
	 * function will call process_SIM_kc_sres().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_challenge_request_message(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		gsmsim_header_c * const received_gsmsim, ///< This is pointer to EAP header including GSMSIM fields.
		const u32_t gsmsim_packet_length, ///< This is length of received GSMSIM EAP packet.
		gsmsim_payloads_c * const p_gsmsim_payloads ///< This is pointer to all payloads of the received EAP packet.
		);

	/**
	 * This function handles the received EAP-Request/SIM/Re-authentication message.
	 * Function checks the valid payloads. The whole EAP-Request/SIM/Challenge message is
	 * saved to handler->get_saved_EAP_packet() if there is encrypted payload.
	 * This is because the MAC could be checked and payload dercypted later
	 * after n*Kc and n*SRES is get from SIM.
	 * Function calls query_SIM_kc_sres(). The query_SIM_kc_sres() function
	 * is completed using complete_SIM_kc_sres() function. The complete_SIM_kc_sres()
	 * function will call process_SIM_kc_sres().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_reauthentication_request_message(
		const eap_am_network_id_c * const receive_network_id,
		gsmsim_header_c * const received_gsmsim,
		const u32_t gsmsim_packet_length,
		gsmsim_payloads_c * const p_gsmsim_payloads);


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e check_challenge_response_message(
		const eap_am_network_id_c * const receive_network_id,
		gsmsim_header_c * const received_gsmsim,
		const u32_t gsmsim_packet_length,
		gsmsim_payloads_c * const p_gsmsim_payloads);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	/**
	 * This function handles the received EAP-Response/SIM/Start message.
	 * Function checks the valid payloads. If IMSI is included it is copied to handler->get_IMSI().
	 * Also the included NONCE_MT is copied to handler->get_NONCE_MT().
	 * Function calls the query_SIM_triplets() of AM to get fresh triplets.
	 * The query_SIM_triplets() function is completed by AM using complete_SIM_triplets() function.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_start_response_message(
		gsmsim_header_c * const received_gsmsim, ///< This is pointer to EAP header including GSMSIM fields.
		const u32_t gsmsim_packet_length, ///< This is length of received GSMSIM EAP packet.
		gsmsim_payloads_c * const p_gsmsim_payloads ///< This is pointer to all payloads of the received EAP packet.
		);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_notification_response_message_reauthentication(
		const eap_am_network_id_c * const receive_network_id,
		gsmsim_header_c * const received_gsmsim,
		const u32_t gsmsim_packet_length,
		gsmsim_payloads_c * const p_gsmsim_payloads);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_notification_response_message_full_authentication(
		const eap_am_network_id_c * const receive_network_id,
		gsmsim_header_c * const received_gsmsim,
		const u32_t gsmsim_packet_length,
		gsmsim_payloads_c * const p_gsmsim_payloads);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	/**
	 * This function handles the received EAP-Response/SIM/Notification message.
	 * Function checks the valid payloads.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_notification_response_message(
		const eap_am_network_id_c * const receive_network_id,
		gsmsim_header_c * const received_gsmsim,
		const u32_t gsmsim_packet_length,
		gsmsim_payloads_c * const p_gsmsim_payloads);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	/**
	 * This function handles the received EAP-Response/SIM/Challenge message.
	 * Function checks the valid payloads. The analyse_MAC_SRES_payload() function is
	 * called to check MAC_SRES. If it returns eap_status_success the authentication was succesfull
	 * and this function calls the send_eap_success() to send EAP-Success message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_challenge_response_message(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		gsmsim_header_c * const received_gsmsim, ///< This is pointer to EAP header including GSMSIM fields.
		const u32_t gsmsim_packet_length, ///< This is length of received GSMSIM EAP packet.
		gsmsim_payloads_c * const p_gsmsim_payloads ///< This is pointer to all payloads of the received EAP packet.
		);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_reauthentication_response_message(
		const eap_am_network_id_c * const /* receive_network_id */,
		gsmsim_header_c * const received_gsmsim,
		const u32_t gsmsim_packet_length,
		gsmsim_payloads_c * const p_gsmsim_payloads);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_client_error_response_message(
		const eap_am_network_id_c * const /* receive_network_id */,
		gsmsim_header_c * const received_gsmsim,
		const u32_t gsmsim_packet_length,
		gsmsim_payloads_c * const p_gsmsim_payloads);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


	/**
	 * This function sends and traces all messages.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e packet_send(
		const eap_am_network_id_c * const network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length);


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	/**
	 * This function chechs NAI.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e check_NAI(
		const u8_t * const identity,
		const u32_t identity_length,
		const u8_t * const at_character);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


	/**
	 * This function traces the EAP packet.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H void packet_trace(
		eap_const_string prefix,
		const eap_am_network_id_c * const receive_network_id,
		eap_header_wr_c * const received_eap,
		const u32_t eap_packet_length);

#if defined(USE_EAP_TRACE)

	#define EAP_GSMSIM_PACKET_TRACE(prefix, receive_network_id, received_eap, eap_packet_length) \
			packet_trace((prefix), (receive_network_id), (received_eap), (eap_packet_length))

#else

	#define EAP_GSMSIM_PACKET_TRACE(prefix, receive_network_id, received_eap, eap_packet_length)

#endif //#if !defined(USE_EAP_TRACE)


	/**
	 * This function finishes the successfull authentication.
	 * Generated keys are offered to lower layer.
	 * Connection handle is initialised.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e finish_successful_authentication(
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * This function sends a notification of possible failed authentication
	 * to lower layer.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e send_final_notification();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e new_handler(
		const eap_am_network_id_c * const receive_network_id,
		const bool is_client_when_true);

#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H bool randomly_refuse_eap_identity();
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e check_rands(
		const eap_variable_data_c * const n_rands
		);

	/**
	 * This function processes the GSMSIM packets.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e gsmsim_packet_process(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		gsmsim_header_c * const received_gsmsim, ///< This is pointer to EAP header including GSMSIM fields.
		const u32_t gsmsim_packet_length, ///< This is length of received GSMSIM EAP packet.
		const bool is_client_when_true ///< Indicates whether this is client (true) or server (false).
		);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e cancel_error_message_delay_timer();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e set_error_message_delay_timer();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_error_packet();

	/**
	 * This function initializes the error message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e initialize_error_message(
		const eap_status_e error_status
		);


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_start_response_message_completion(
		const u8_t next_eap_identifier,
		const eap_status_e identity_status,
		const eap_type_gsmsim_identity_type identity_type,
		const bool identity_payload_was_included);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e initialize_notification_message();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e cancel_notification_message_delay_timer();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e set_notification_message_delay_timer();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_notification_packet();

	const bool get_gsmsim_notification_code_F_bit(const eap_gsmsim_notification_codes_e notification_code)
	{
		return ((notification_code & gsmsim_notification_code_bit_f) != 0);
	}

	const bool get_gsmsim_notification_code_P_bit(const eap_gsmsim_notification_codes_e notification_code)
	{
		return ((notification_code & gsmsim_notification_code_bit_p) != 0);
	}

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H bool random_selection();

	u32_t get_mnc_length(const u32_t mcc);

	eap_status_e create_uma_realm(
		eap_variable_data_c * const automatic_realm,
		const eap_variable_data_c * const IMSI,
		const u32_t length_of_mnc);

	void set_start_response_includes_identity(gsmsim_payload_AT_type_e type);

	void set_identity_type(eap_type_gsmsim_identity_type type);

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * Destructor cancels all timers and deletes member attributes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H virtual ~eap_type_gsmsim_c();

	/**
	 * Constructor initializes all member attributes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_type_gsmsim_c(
		abs_eap_am_tools_c * const tools, ///< This is pointer to the tools AM of current platform.
		abs_eap_base_type_c * const partner, ///< This is back pointer to object which created this object.
		eap_am_type_gsmsim_c * const am_type_gsmsim, ///< This is pointer to adaptation module of GSMSIM EAP type.
		const bool free_am_type_gsmsim, ///< True value means m_am_type_gsmsim is allocated within eap_type_gsmsim_c and m_am_type_gsmsim must be freed in destructor.
		const bool is_client_when_true, ///< Indicates whether this is client (true) or server (false).
		const eap_am_network_id_c * const receive_network_id);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H static eap_const_string get_identity_string(const eap_type_gsmsim_identity_type identity_type);

	/**
	 * This function returns string of the state. This is for trace purposes.
	 * NOTE this is static member function.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H static eap_const_string get_state_string(eap_type_gsmsim_state_variable_e state);

	/**
	 * This function tells if the object is a client or a server..
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H bool get_is_client();

	// This is commented in abs_eap_am_type_gsmsim_c::complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query().
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query(
		const eap_variable_data_c * const IMSI, ///< This is the IMSI.
		const eap_variable_data_c * const pseudonym, ///< This is the pseudonym.
		const eap_variable_data_c * const reauthentication_identity, ///< This is the re-authentication identity.
		const eap_variable_data_c * const automatic_realm, ///< This could be zero pointer if this is not used.
		const u32_t length_of_mnc,
		const eap_type_gsmsim_complete_e required_completion, ///< This parameter tells the required completion
		const u8_t received_eap_identifier, ///< This parameter is the EAP-identifier of EAP-request
		const eap_status_e completion_status
		);


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	// This is commented in abs_eap_am_type_gsmsim_c::complete_SIM_triplets().
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e complete_SIM_triplets(
		eap_type_sim_triplet_array_c * const triplets, ///< triplets includes all triplets used in this authentication session.
		const eap_variable_data_c * const IMSI, ///< IMSI may be queried during query_SIM_triplets() function call. It must be copied to state.
		const eap_gsmsim_triplet_status_e triplet_status,  ///< This is the status of the failed triplet query.
		const eap_type_gsmsim_identity_type type, ///< This is type of the identity.
		const eap_status_e completion_status
		);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


	// This is commented in abs_eap_am_type_gsmsim_c::complete_SIM_kc_sres().
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e complete_SIM_kc_sres(
		const eap_variable_data_c * const n_rand, ///< This includes concatenated n RAND.
		const eap_variable_data_c * const n_kc, ///< This includes concatenated n KC.
		const eap_variable_data_c * const n_sres, ///< This includes concatenated n SRES.
		const eap_status_e completion_status
		);


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	/** Client calls this function.
	 *  This function IMSI and username to GSMSIM EAP type.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e handle_imsi_from_username(
		const u8_t next_eap_identifier,
		const eap_am_network_id_c * const network_id,
		const eap_variable_data_c * const username,
		const eap_variable_data_c * const imsi, ///< The result is stored to imsi parameter.
		const eap_type_gsmsim_identity_type identity_type);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	// This is commented in abs_eap_am_type_gsmsim_c::complete_imsi_from_username().
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e complete_imsi_from_username(
		const u8_t next_eap_identifier,
		const eap_am_network_id_c * const network_id,
		const eap_variable_data_c * const username,
		const eap_variable_data_c * const imsi, ///< The result is stored to imsi parameter.
		const eap_type_gsmsim_identity_type type,
		const eap_status_e completion_status,
		const eap_type_gsmsim_complete_e completion_action);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


	/**
	 * The partner class calls this function when EAP/GSMSIM packet is received.
	 * see also eap_base_type_c::packet_process().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		eap_header_wr_c * const eap, ///< This is pointer to EAP header and data.
		const u32_t eap_packet_length ///< This is length of received EAP packet.
		);

	/**
	 * This function obtains header offset, MTU and trailer length.
	 * See also abs_eap_base_type_c::get_header_offset().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length
		);

	/**
	 * This function creates a message authentication code (MAC)
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e create_message_authentication_code(
		eap_type_gsmsim_MAC_attributes_c *MAC_attributes, ///< This includes required parameters.
		const gsmsim_subtype_e subtype,
		const eap_code_value_e code,
		const eap_variable_data_c * const authentication_key
		);

	/**
	 * This function adds addiditional data to MAC calculation.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e extra_message_authentication_code_bytes(
		const gsmsim_subtype_e subtype,
		const eap_code_value_e code,
		crypto_hmac_c *hmac_sha1);

	// This is commented in abs_eap_base_timer_c::timer_delete_data().
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e timer_expired(
		const u32_t id, void *data
		);

	// This is commented in abs_eap_base_timer_c::timer_delete_data().
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e timer_delete_data(
		const u32_t id, void *data
		);

	// This is commented in eap_base_type_c::set_is_valid().
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H void set_is_valid();

	// This is commented in eap_base_type_c::get_is_valid().
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H bool get_is_valid();

	// This is commented in eap_base_type_c::configure().
	/**
	 * EAP-type GSMSIM reads configuration.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e configure();

	// This is commented in eap_base_type_c::shutdown().
	/**
	 * The shutdown() function is called before the destructor of the 
	 * object is executed. During the function call the object 
	 * could shutdown the operations, for example cancel timers.
	 * Each derived class must define this function.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e shutdown();

	/**
	 * The read_configure() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H virtual eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data
		);

	/**
	 * The write_configure() function writes the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the action to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H virtual eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data
		);

	// See abs_eap_base_type_c::state_notification().
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H void state_notification(
		const abs_eap_state_notification_c * const state
		);

	// This is commented in eap_base_type_c::query_eap_identity().
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e query_eap_identity(
		const bool must_be_synchronous,
		eap_variable_data_c * const identity,
		const eap_am_network_id_c * const receive_network_id,
		const u8_t eap_identifier);

	// This is commented in eap_base_type_c::query_eap_identity().
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e set_initial_eap_identifier(
		const eap_am_network_id_c * const receive_network_id,
		const u8_t initial_identifier);

	// This is commented in eap_base_type_c::eap_acknowledge().
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e eap_acknowledge(
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * This function must reset the state of object to same as 
	 * state was after the configure() function call.
	 * If object reset succeeds this function must return eap_status_ok.
	 * If object reset fails this function must return corresponding error status.
	 * @return This function returns the status of reset operation.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e reset();

	//
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e set_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id, 
		void * const p_data,
		const u32_t p_time_ms);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_H eap_status_e cancel_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id);

	//--------------------------------------------------
}; // class eap_type_gsmsim_c

#endif //#if !defined(_GSMSIM_CORE_H_)

//--------------------------------------------------



// End.
