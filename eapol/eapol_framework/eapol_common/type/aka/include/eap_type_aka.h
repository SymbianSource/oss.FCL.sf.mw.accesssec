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
* %version: 23 %
*/

#if !defined(_AKA_CORE_H_)
#define _AKA_CORE_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TYPE_AKA_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_AKA_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_AKA_H 
	#define EAP_FUNC_EXPORT_EAP_TYPE_AKA_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_AKA_H 
#elif defined(EAP_EXPORT_EAP_TYPE_AKA_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_AKA_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_AKA_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_AKA_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_AKA_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_AKA_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_AKA_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_AKA_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_AKA_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_base_type.h"
#include "eap_variable_data.h"
#include "eap_type_aka_header.h"
#include "eap_type_aka_types.h"
#include "eap_type_aka_payloads.h"
#include "eap_type_aka_state.h"
#include "eap_type_aka_initialized.h"
#include "abs_eap_base_timer.h"
#include "abs_eap_am_type_aka.h"
#include "eap_am_type_aka.h"
#include "eap_crypto_api.h"
#include "eap_master_session_key.h"


//--------------------------------------------------


/// This class is implementation of AKA EAP-type.
class EAP_CLASS_VISIBILITY_EAP_TYPE_AKA_H eap_type_aka_c
: public abs_eap_am_type_aka_c
, public abs_eap_base_timer_c
, public eap_base_type_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is pointer to adaptation module of AKA EAP type.
	eap_am_type_aka_c * const m_am_type_aka;


	/// HASH over all AKA-Identity messages.
	crypto_sha1_c m_checkcode;

	u32_t m_checkcode_update_count;

	eap_variable_data_c m_received_checkcode;

	eap_variable_data_c m_checkcode_saved_message;

	eap_array_c<eap_variable_data_c> m_all_payloads;


	eap_variable_data_c m_nonce_mt_file;

	eap_variable_data_c m_manual_username;

	eap_variable_data_c m_manual_realm;

	/// This is the automatic realm generated in AM of EAP-SIM.
	/// Note this could be invalid data when automatic realm is not used.
	/// The m_automatic_realm_read flag tells whether m_automatic_realm is read from AM of EAP-SIM.
	eap_variable_data_c m_automatic_realm;

	/// This flag tells whether automatic realm is read from AM of EAP-SIM.
	/// Note the data of m_automatic_realm could be invalid data when it is not used.
	bool m_automatic_realm_read;

	/// This is offset in bytes of the EAP-type header in the packet buffer.
	/// Offset is described in abs_eap_base_type_c::get_header_offset().
	u32_t m_aka_header_offset;

	/// This is maximum transfer unit in bytes.
	/// MTU is described in abs_eap_base_type_c::get_header_offset().
	u32_t m_MTU;

	/// This is length of the trailer in bytes.
	/// Trailer length is described in abs_eap_base_type_c::get_header_offset().
	u32_t m_trailer_length;

	u32_t m_length_of_mnc;

	/// This stores the current authentication type.
	/// Look at the m_identity_type too.
	eap_aka_authentication_type_e m_authentication_type;

	/// This stores the current identity type.
	/// NOTE there is one stupid case where m_identity_type is AKA_IDENTITY_TYPE_RE_AUTH_ID
	/// and m_authentication_type is AKA_AUTHENTICATION_TYPE_FULL_AUTH.
	/// Look at the Chapter "Fast Re-authentication Procedure when Counter is Too Small"
	/// in the EAP-SIM specification.
	/// Because of that illogical specification we need separate 
	/// attributes for authentication type and identity type.
	eap_type_aka_identity_type m_identity_type;

	/// This is the first client error.
	eap_aka_client_error_code_e m_client_error_code;

	/// This is saved AKA notificatoin code.
	/// If this value is eap_aka_notification_none, no notification is stored.
	eap_aka_notification_codes_e m_aka_notification_code;

	u32_t m_failure_message_delay_time;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/// This indicates whether this object is client (true) or server (false).
	/// In terms of EAP-protocol whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	bool m_is_client;

	/// True value of this flag indicates the EAP-Success packet must be received
	/// in successfull authentication of clien.
	/// This value is configured with EAP_AKA_wait_eap_success_packet.
	bool m_wait_eap_success_packet;

	/// True value of this flag indicates the identifier of the EAP-Response/Identity must be checked.
	/// This is not possible cases where identifier of the EAP-Request/Identity is generated by other network entities.
	bool m_check_identifier_of_eap_identity_response;


	/// True value means m_am_type_aka is allocated within eap_type_aka_c
	/// and m_am_type_aka must be freed in destructor.
	bool m_free_am_type_aka;

	/// True value means client responds to all re-transmitted EAP-AKA packets.
	/// False value means client does not respond to any re-transmitted EAP-AKA packets.
	bool m_client_responds_retransmitted_packets;

	/// True value means this is a test version of AKA.
	bool m_aka_test_version;

	/// True value means server refuses EAP-identity randomly.
	/// False value means does not refuse EAP-identity randomly.
	/// NOTE EAP_AKA_test_version option must be true also.
	bool m_aka_randomly_refuse_eap_identity;

	/// This flag forces check of NAI realm. Realm must be the same as given in EAP_AKA_manual_realm configuration option.
	/// Default value is false, check is not done by default.
	bool m_check_nai_realm;

	/// This is for testing purposes. True value will cause failed test of re-authentication counter.
	bool m_fail_reauthentication_counter_check;

	/// True value of this flag allows acception of EAP-Response/Identity.
	/// False value does not accept EAP-Response/Identity. Instead identity is queried
	/// in EAP-Request/AKA/Start with AT_ANY_ID_REQ attribute.
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

	/// This flag tells whether the pseudonym identity could be used (true) or not (false).
	bool m_use_pseudonym_identity;

	/// This flag tells whether the re-authentication identity could be used (true) or not (false).
	bool m_use_reauthentication_identity;

	/// This is set true when erroneus packet is received.
	bool m_erroneus_packet_received;

	/// This is set true when AKA notification packet is received.
	bool m_aka_notification_packet_received;

	/// This flag allows use of Windows RAS identity in EAP-Identity/Response.
	/// EAP-Request/Start will include identity query attribute.
	bool m_use_manual_username;

	/// Default value is false. That will cause use of automatic realm.
	/// If this is true then
	/// cf_str_EAP_AKA_manual_realm is used as the realm.
	bool m_use_manual_realm;

	bool m_randomly_fail_successfull_authentication;

	bool m_allow_use_result_indication;

	bool m_use_result_indication;

	//--------------------------------------------------
	//--------------------------------------------------

	/// This attribute stores the valid AKA states (eap_type_aka_state_variable_e).
	/// Each eap_type_aka_state_variable_parameters_c includes the valid 
	/// AKA messages within the state.
	eap_type_aka_state_variable_parameters_c m_parameters[eap_type_aka_state_last_value];

	/// This is the current state.
	eap_type_aka_state_variable_e m_state;

	/// This is the saved previous state. On error case this is the state where continue.
	eap_type_aka_state_variable_e m_saved_previous_state;

	/// This is network identity of the sent packet from this handler.
	eap_am_network_id_c m_send_network_id;

	/// This is the NONCE_S. Server generates NONCE_S and sends it to client
	/// within the EAP-Request/AKA/Re-authentication message.
	eap_variable_data_c m_nonce_s;

	// - - - - - - - - - - - - - - - - - - - -

	/// Server sends IV to client within EAP-Request/AKA/Challenge message.
	/// The AT_IV payload is optional.
	aka_variable_data_c m_IV;

	/// EAP-Request/AKA/Challenge message must be saved until n*Kc and n*SRES are get from AKA.
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

	/// This is identity used in authentication. This is real IMSI or pseudonym.
	/// Pseudonym is used only if server supports use of pseudonym.
	eap_variable_data_c m_identity;

	/// This is the NAI. Format is "username@realm".
	eap_variable_data_c m_NAI;

	eap_variable_data_c m_RAND;

	eap_variable_data_c m_AUTN;

	eap_variable_data_c m_RES;

	eap_variable_data_c m_2_digit_mnc_map_of_mcc_of_imsi_array;

	eap_variable_data_c m_uma_automatic_realm_prefix;

	bool m_use_uma_profile;

	/// Here is stored the received authentication vector.
	eap_type_aka_authentication_vector_c *m_authentication_vector;

	u32_t m_reauthentication_counter;

	aka_payload_AT_type_e m_include_identity_to_aka_identity_response;

	/// Identity of this type is included in start response.
	aka_payload_AT_type_e m_aka_identity_response_includes_identity;

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

	bool m_use_eap_expanded_type;

	//--------------------------------------------------
	//--------------------------------------------------

	/**
	 * This function initializes the allowed messages within one specific state.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H void initialize_state(
				const eap_type_aka_state_variable_e state,
				const bool must_be_initiator,
				const bool must_be_responder,
				const aka_subtype_e type0,
				const aka_subtype_e type1,
				const aka_subtype_e type2,
				const aka_subtype_e type3,
				const aka_subtype_e type4);

	/**
	 * This function expands key and seed data to key_length of expansion.
	 *  expansion_0 = prf(key, seed | 0)
	 *  expansion_i = prf(key, expansion_i-1 | seed | i), where i = 1, 2...
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e data_exp(
		const u32_t key_length,
		eap_variable_data_c * const expansion,
		const eap_variable_data_c * const key,
		const eap_variable_data_c * const seed);

	/**
	 * This function returns the eap_type_aka_state_variable_parameters_c object of current state.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H const eap_type_aka_state_variable_parameters_c * get_state_variable();


	//--------------------------------------------------
	//--------------------------------------------------

	/**
	 * This function generates a new NAI from domain and IMSI.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e generate_nai(
		eap_variable_data_c * const new_nai, ///< This is the new generated NAI.
		const bool use_manual_default_realm, ///< When true uses realm parameter, when false generates automatic realm.
		const eap_variable_data_c * const realm, ///< This is the domain part of the NAI.
		const eap_variable_data_c * const id_IMSI_or_pseydonym, ///< This is IMSI or pseudonym.
		const bool id_is_imsi, ///< This parameter tells whether id_IMSI_or_pseydonym is IMSI (true) or pseudonym (false).
		const eap_variable_data_c * const IMSI, ///< This parameter must be IMSI always.
		const eap_variable_data_c * const automatic_realm,
		const u32_t length_of_mnc
		);

	/**
	 * This function adds generic attribute payload to AKA message.
	 * @param aka is pointer to EAP header including AKA fields.
	 * @param maximum_buffer_size is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also aka_header_c and eap_header_base_c.
	 * @param data_offset is the offset of inserted payloads in AKA EAP packet.
	 * It is the value of AKA sub-type data.
	 * @param data_free is the remaining free AKA data buffer size.
	 * @param buffer_free is the remaining free packet buffer size.
	 * @param buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param data_payload is the new payload to be added.
	 * @param data_payload_type is the attribute payload type to be added.
	 *
	 * See also eap_type_aka_c::update_payload_indexes().
	 *
	 * Format of the payload is as follows:
	 * @code
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * | AT type       | Payload Length|           Reserved            |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * | Any variable length payload                                   |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e add_variable_payload(
		aka_header_c * const aka,
		const u32_t maximum_buffer_size,
		const u32_t eap_header_size,
		u32_t * const data_offset,
		u32_t * const data_free,
		u32_t * const buffer_free,
		u32_t * const buffer_offset,
		const eap_variable_data_c * const data_payload,
		const aka_payload_AT_type_e data_payload_type);

	/**
	 * This function adds AUTS attribute payload to AKA message.
	 * @param aka is pointer to EAP header including AKA fields.
	 * @param maximum_buffer_size is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also aka_header_c and eap_header_base_c.
	 * @param data_offset is the offset of inserted payloads in AKA EAP packet.
	 * It is the value of AKA sub-type data.
	 * @param data_free is the remaining free AKA data buffer size.
	 * @param buffer_free is the remaining free packet buffer size.
	 * @param buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param data_payload is the new payload to be added.
	 * @param data_payload_type is the attribute payload type to be added.
	 *
	 * See also eap_type_aka_c::update_payload_indexes().
	 *
	 * Format of the payload is as follows:
	 * @code
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * | AT type       | Payload Length|       AUTS ...                |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * | ... AUTS                                                      |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e add_AUTS_payload(
		aka_header_c * const aka,
		const u32_t aka_buffer_length,
		const u32_t eap_header_size,
		u32_t * const aka_data_offset,
		u32_t * const aka_data_free,
		u32_t * const packet_buffer_free,
		u32_t * const packet_buffer_offset,
		const eap_variable_data_c * const data_payload,
		const aka_payload_AT_type_e data_payload_type);

	/**
	 * This function adds RES attribute payload to AKA message.
	 * @param aka is pointer to EAP header including AKA fields.
	 * @param maximum_buffer_size is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also aka_header_c and eap_header_base_c.
	 * @param data_offset is the offset of inserted payloads in AKA EAP packet.
	 * It is the value of AKA sub-type data.
	 * @param data_free is the remaining free AKA data buffer size.
	 * @param buffer_free is the remaining free packet buffer size.
	 * @param buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param RES is the RES payload to be added.
	 * @param data_payload_type is the attribute payload type to be added.
	 *
	 * See also eap_type_aka_c::update_payload_indexes().
	 *
	 * Format of the payload is as follows:
	 * @code
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * | AT_RES        | Length        |       RES Length in bits      |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                              RES ...
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e add_RES_payload(
		aka_header_c * const aka,
		const u32_t aka_buffer_length,
		const u32_t eap_header_size,
		u32_t * const aka_data_offset,
		u32_t * const aka_data_free,
		u32_t * const packet_buffer_free,
		u32_t * const packet_buffer_offset,
		const eap_variable_data_c * const RES,
		const aka_payload_AT_type_e data_payload_type);

	/**
	 * This function adds IMSI or pseudonym attribute payload to AKA message.
	 * @param aka is pointer to EAP header including AKA fields.
	 * @param maximum_buffer_size is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also aka_header_c and eap_header_base_c.
	 * @param data_offset is the offset of inserted payloads in AKA EAP packet.
	 * It is the value of AKA sub-type data.
	 * @param data_free is the remaining free AKA data buffer size.
	 * @param buffer_free is the remaining free packet buffer size.
	 * @param buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param pseudonym_or_imsi is the IMSI or pseudonym payload to be added.
	 * @param data_payload_type is the attribute payload type to be added.
	 *
	 * See also eap_type_aka_c::update_payload_indexes().
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
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e add_pseudonym_or_imsi_payload(
		aka_header_c * const aka,
		const u32_t maximum_buffer_size,
		const u32_t eap_header_size,
		u32_t * const data_offset,
		u32_t * const data_free,
		u32_t * const buffer_free,
		u32_t * const buffer_offset,
		const eap_variable_data_c * const pseudonym_or_imsi,
		const aka_payload_AT_type_e data_payload_type);


	/**
	 * This function adds selected version attribute payload to AKA message.
	 * @param aka is pointer to EAP header including AKA fields.
	 * @param aka_buffer_length is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also aka_header_c and eap_header_base_c.
	 * @param aka_data_offset is the offset of inserted payloads in AKA EAP packet.
	 * It is the value of AKA sub-type data.
	 * @param aka_data_free is the remaining free AKA data buffer size.
	 * @param packet_buffer_free is the remaining free packet buffer size.
	 * @param packet_buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param counter is the re-authentication counter.
	 *
	 * See also eap_type_aka_c::update_payload_indexes().
	 *
	 * Format of the payload is as follows:
	 * @code
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |AT_COUNTER     | Length = 1    |      Counter                  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e add_counter_payload(
		aka_header_c * const aka,
		const u32_t aka_buffer_length,
		const u32_t eap_header_size,
		u32_t * const aka_data_offset,
		u32_t * const aka_data_free,
		u32_t * const packet_buffer_free,
		u32_t * const packet_buffer_offset,
		u16_t counter);


	/**
	 * This function adds akaple attribute payload to AKA message.
	 * @param aka is pointer to EAP header including AKA fields.
	 * @param aka_buffer_length is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also aka_header_c and eap_header_base_c.
	 * @param aka_data_offset is the offset of inserted payloads in AKA EAP packet.
	 * It is the value of AKA sub-type data.
	 * @param aka_data_free is the remaining free AKA data buffer size.
	 * @param packet_buffer_free is the remaining free packet buffer size.
	 * @param packet_buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param data_payload_type is the type of akaple payload.
	 *
	 * See also eap_type_aka_c::update_payload_indexes().
	 *
	 * Format of the payload is as follows:
	 * @code
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |AT_XXX         | Length = 1    |      Reserved                 |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e add_simple_payload(
		aka_header_c * const aka,
		const u32_t aka_buffer_length,
		const u32_t eap_header_size,
		u32_t * const aka_data_offset,
		u32_t * const aka_data_free,
		u32_t * const packet_buffer_free,
		u32_t * const packet_buffer_offset,
		const aka_payload_AT_type_e data_payload_type);

	/**
	 * This function adds Notification attribute payload to AKA message.
	 * @param aka is pointer to EAP header including AKA fields.
	 * @param aka_buffer_length is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also aka_header_c and eap_header_base_c.
	 * @param aka_data_offset is the offset of inserted payloads in AKA EAP packet.
	 * It is the value of AKA sub-type data.
	 * @param aka_data_free is the remaining free AKA data buffer size.
	 * @param packet_buffer_free is the remaining free packet buffer size.
	 * @param packet_buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 *
	 * See also eap_type_aka_c::update_payload_indexes().
	 *
	 * Format of the payload is as follows:
	 * @code
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |AT_NOTIFICATION| Length = 1    |      Notification Code        |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e add_notification_payload(
		aka_header_c * const aka,
		const u32_t aka_buffer_length,
		const u32_t eap_header_size,
		u32_t * const aka_data_offset,
		u32_t * const aka_data_free,
		u32_t * const packet_buffer_free,
		u32_t * const packet_buffer_offset,
		const eap_aka_notification_codes_e notification_code);

	/**
	 * This function adds AT_CLIENT_ERROR_CODE attribute payload to AKA message.
	 * @param aka is pointer to EAP header including AKA fields.
	 * @param aka_buffer_length is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also aka_header_c and eap_header_base_c.
	 * @param aka_data_offset is the offset of inserted payloads in AKA EAP packet.
	 * It is the value of AKA sub-type data.
	 * @param aka_data_free is the remaining free AKA data buffer size.
	 * @param packet_buffer_free is the remaining free packet buffer size.
	 * @param packet_buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param client_error_code is the error code to be sent.
	 *
	 * See also eap_type_aka_c::update_payload_indexes().
	 *
	 * Format of the payload is as follows:
	 * @code
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |AT_CLIENT_ERR..| Length = 1    |      Client Error Code        |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e add_client_error_payload(
		aka_header_c * const aka,
		const u32_t aka_buffer_length,
		const u32_t eap_header_size,
		u32_t * const aka_data_offset,
		u32_t * const aka_data_free,
		u32_t * const packet_buffer_free,
		u32_t * const packet_buffer_offset,
		const eap_aka_client_error_code_e client_error_code);

	/**
	 * This function adds message authentication code (MAC) attribute payload to AKA message.
	 * This MAC is written later in the create_message_authentication_code() function.
	 * MAC includes the whole EAP message.
	 * @param aka is pointer to EAP header including AKA fields.
	 * @param maximum_buffer_size is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also aka_header_c and eap_header_base_c.
	 * @param data_offset is the offset of inserted payloads in AKA EAP packet.
	 * It is the value of AKA sub-type data.
	 * @param data_free is the remaining free AKA data buffer size.
	 * @param buffer_free is the remaining free packet buffer size.
	 * @param buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param MAC_data is the start of the message authentication code (MAC) to be written.
	 * @param MAC_data_length is the length of the message authentication code (MAC) to be written.
	 *
	 * See also eap_type_aka_c::update_payload_indexes().
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
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e add_mac_payload(
		aka_header_c * const aka,
		const u32_t maximum_buffer_size,
		const u32_t eap_header_size,
		u32_t * const data_offset,
		u32_t * const data_free,
		u32_t * const buffer_free,
		u32_t * const buffer_offset,
		u8_t ** const MAC_data,
		u32_t * const MAC_data_length);

	/**
	 * This function adds message authentication code (MAC) attribute payload to AKA message.
	 * This MAC is written later in the create_message_authentication_code() function.
	 * @param aka is pointer to EAP header including AKA fields.
	 * @param maximum_buffer_size is the maximum length of sent packet.
	 * @param eap_header_size is length of EAP header.
	 * See also aka_header_c and eap_header_base_c.
	 * @param data_offset is the offset of inserted payloads in AKA EAP packet.
	 * It is the value of AKA sub-type data.
	 * @param data_free is the remaining free AKA data buffer size.
	 * @param buffer_free is the remaining free packet buffer size.
	 * @param buffer_offset is the offset from the begin of the packet buffer
	 * to the end of the last data payload.
	 * @param plaintext_length is the length of the plain text. Padding length is calculated from this.
	 *
	 * See also eap_type_aka_c::update_payload_indexes().
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
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e add_padding_payload(
		aka_header_c * const aka_packet,
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
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e check_message_authentication_code(
		const eap_variable_data_c * const authentication_key,
		aka_payloads_c * const p_aka_payloads, ///< This is pointer to all payloads of the received EAP packet.
		const aka_header_c * const aka_packet,
		const u32_t aka_packet_length);

	/**
	 * This function handles the received AKA EAP packet.
	 *
	 * First is checked the valid massage is received in valid state.
	 * See also check_valid_state().
	 *
	 * Second is parsed the payloads and checked syntax of the received AKA EAP packet.
	 * See also parse_aka_packet().
	 *
	 * Third is analysed the AKA EAP packet. This includes the payload and values of each payload.
	 * See also analyse_aka_packet().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_aka_packet(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		aka_header_c * const aka, ///< This is pointer to EAP header including AKA fields.
		const u32_t aka_length, ///< This is length of received AKA EAP packet.
		aka_payloads_c * const p_aka_payloads ///< This is pointer to all payloads of the received EAP packet.
		);

	/**
	 * This function analyses the received AKA EAP packet.
	 * Each sub-type is handled in separate function.
	 * @see Client messages are handled in handle_aka_identity_request_message() and handle_challenge_request_message(). 
	 * @see Server messages are handled in handle_aka_identity_response_message() and handle_challenge_response_message(). 
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e analyse_aka_packet(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		aka_header_c * const received_aka, ///< This is pointer to EAP header including AKA fields.
		const u32_t aka_packet_length, ///< This is length of received AKA EAP packet.
		aka_payloads_c * const p_aka_payloads ///< This is pointer to all payloads of the received EAP packet.
		);

	/**
	 * This function parses the payloads starting from specified payload (p_payload).
	 * Function parses all payloads from the buffer.
	 * Payloads are stored to p_aka_payloads.
	 * @return If the length of the buffer and sum of the length of all payloads does not match
	 * function returns eap_status_header_corrupted.
	 * Also error is returned when illegal payload attribute is recognised.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e parse_aka_payload(
		const aka_payload_AT_header_c * const p_payload, ///< This is the start of the buffer and the first parsed payload.
		u32_t * const buffer_length, ///< This is the length of the buffer. This must match with the length of all payloads.
		aka_payloads_c * const p_aka_payloads, ///< This is pointer to all payloads of the received EAP packet.
		const aka_subtype_e subtype
		);

	/**
	 * This function parses all payloads of the whole AKA EAP packet.
	 * Payloads are stored to p_aka_payloads.
	 * @see parse_aka_payload().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e parse_aka_packet(
		aka_header_c * const aka, ///< This is pointer to EAP header including AKA fields.
		const u32_t aka_packet_length, ///< This is length of received AKA EAP packet.
		aka_payloads_c * const p_aka_payloads ///< This is pointer to all payloads of the received EAP packet.
		);

	/**
	 * This function parses each payload attributes.
	 * @return If payload attribute is illegal function returns eap_status_header_corrupted.
	 * If payload attribute is unknown function returns eap_status_unsupported_aka_payload.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e parse_generic_payload(
		const aka_payload_AT_type_e current_payload, ///< This is the type of current payload attribute.
		const aka_payload_AT_header_c * const payload, ///< This is the current parsed payload.
		aka_payloads_c * const p_aka_payloads, ///< This is pointer to all payloads of the received EAP packet.
		const aka_subtype_e subtype);

	/**
	 * This function sends the EAP-Request/AKA/Re-authentication message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e send_reauthentication_request_message(
		const eap_variable_data_c * const username,
		const bool pseudonym_decode_failed,
		const u8_t eap_identifier);

	/**
	 * This function sends the EAP-Request/AKA/Start message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e send_aka_identity_request_message(
		const bool pseudonym_decode_failed, ///< This identifies whether the pseudonym decode was failed (true). We must send a IMSI request.
		const u8_t eap_identifier ///< This is the EAP-Identifier used with this message.
		);

	/**
	 * This function sends the EAP-Response/AKA/Start message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e send_aka_identity_response_message(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet. NOTE received.
		const u8_t received_eap_identifier, ///< This is the EAP-identifier of the received EAP-request message.
		const aka_payload_AT_type_e include_identity_to_aka_identity_response, ///< This is the queried identity type.
		const eap_variable_data_c * const automatic_realm
		);

	/**
	 * This function sends the EAP-Response/AKA/Notification message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e send_aka_notification_response(
		const eap_aka_notification_codes_e notification_code,
		const bool add_at_counter_attribute
		);

	/**
	 * This function sends the EAP-Response/AKA/Client-Error message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e send_aka_client_error_response();

	/**
	 * This function sends the EAP-Request/AKA/Challenge message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e send_challenge_request_message(
		const u8_t eap_identifier ///< This is the EAP-Identifier used with this message.
		);

	/**
	 * This function sends the EAP-Response/AKA/Challenge message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e send_challenge_response_message(
		eap_variable_data_c * const K_aut);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e send_reauthentication_response_message(
		const eap_variable_data_c * const orig_XKEY,
		const eap_variable_data_c * const orig_K_aut,
		const eap_variable_data_c * const orig_K_encr,
		const eap_variable_data_c * const reauth_username,
		const eap_variable_data_c * const reauth_nonce_s,
		const u16_t reauth_counter,
		const u8_t eap_identifier,
		const bool include_at_counter_too_small);

	/**
	 * This function sends the EAP-Request/AKA/Notification message.
	 * Message includes the localizable notification string.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e send_aka_notification_request(
		const eap_aka_notification_codes_e notification_code,
		const bool add_at_counter_attribute
		);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e send_aka_synchronization_failure_response_message(
		const eap_type_aka_authentication_vector_c * const authentication_vector
		);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e send_aka_authentication_reject_response_message(
		const eap_type_aka_authentication_vector_c * const authentication_vector
		);

	/**
	 * This function encrypts the payload.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e encrypt_DATA_payload(
		u8_t * const EAP_data, ///< This is pointer to the begin of the encrypted payload.
		const u32_t cbc_aes_data_length, ///< This is the length of the encrypted payload. This must be aligned to AES block length.
		const eap_variable_data_c * const IV,
		const eap_variable_data_c * const encryption_key
		);

	/**
	 * This function decrypts the payload.
	 * p_aka_payloads->get_ENCR_DATA() points to the decrypted payload.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e decrypt_DATA_payload(
		aka_payloads_c * const p_aka_payloads, ///< This is pointer to all payloads of the received EAP packet.
		const eap_variable_data_c * const encryption_key
		);

	/**
	 * This function handles the received DATA payload attribute.
	 * The received encrypte payload have been decrypted before thiscall.
	 * p_aka_payloads->get_ENCR_DATA() includes decrypted DATA payload.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_DATA_payload(
		const aka_subtype_e subtype,
		aka_payloads_c * const p_aka_payloads ///< This is pointer to all payloads of the received EAP packet.
		);

	//--------------------------------------------------

	/**
	 * This function generate a new NONCE of nonce_size octets length.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e generate_nonce(
		const u32_t nonce_size,
		eap_variable_data_c * const nonce);

	/**
	 * This function returns the domain name.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_variable_data_c * get_nai_realm();

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
	 * Note maximum_buffer_size could be larger than (m_aka_header_offset + m_MTU + m_trailer_length).
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H void update_buffer_indexes(
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
	 * Note maximum_buffer_size could be larger than (m_aka_header_offset + m_MTU + m_trailer_length).
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H void update_payload_indexes(
		const u32_t maximum_buffer_size,
		const u32_t eap_header_size,
		const u32_t payload_size,
		u32_t * const data_offset,
		u32_t * const data_free,
		u32_t * const buffer_offset,
		u32_t * const buffer_free);

	/**
	 * This function queries the IMSI or saved pseudonym. IMSI is queried always. The optional
	 * pseudonym is returned if it has been received and it has been stored to AKA AM.
	 * This function could be synchronous or asynchronous. Parameter must_be_synchronous could be
	 * used if only synchronous call is accepted.
	 *
	 * @return Successful syncronous call returns eap_status_ok.
	 * The process_AKA_IMSI() function must be called immediately.
	 *
	 * @return Successful asynchronous call returns eap_status_ok.
	 * This means call was indeed synchronous. 
	 * The process_AKA_IMSI() function must be called immediately.
	 *
	 * @return Pending asynchronous call returns eap_status_pending_request.
	 * AM will complete this call later by complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() call.
	 *
	 * @return Immediately comleted asynchronous call returns eap_status_completed_request.
	 * AM already called the complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query().
	 *
	 * @return Other return values are errors.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e query_AKA_IMSI_or_pseudonym_or_reauthentication_id(
		eap_variable_data_c * const IMSI, ///< Pointer to IMSI. Buffer for IMSI is allocated during the call.
		eap_variable_data_c * const pseudonym_identity, ///< Pointer to pseudonym. Buffer for pseudonym is allocated during the call.
		eap_variable_data_c * const reauthentication_identity, ///< Pointer to reauthentication_identity. Buffer for reauthentication_identity is allocated during the call.
		eap_variable_data_c * const automatic_realm, ///< If this is not used, do not add any data to this parameter.
		u32_t * const length_of_mnc,
		const bool must_be_synchronous, ///< True value indicates only synchronous call is accepted.
		const aka_payload_AT_type_e required_identity, ///< This parameter indicated the type of identity required.
		const eap_type_aka_complete_e required_completion, ///< This parameter tells the required completion after this call is completed, if this is asyncronous. Use this value with abs_eap_am_type_aka_c::complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() function call.
		const u8_t received_eap_identifier ///< This is the EAP-identifier of the received EAP-request message. Use this value with abs_eap_am_type_aka_c::complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() function call.
		);

	/**
	 * This function queries KC and SRES. Each of them could include multiple concatenated items.
	 * This function could be synchronous or asynchronous.
	 *
	 * @return Successful call returns eap_status_ok.
	 * This means call was indeed synchronous. 
	 * The process_AKA_kc_sres() function must be called immediately.
	 *
	 * @return Pending asynchronous call returns eap_status_pending_request.
	 * AM will complete this call later by complete_AKA_RES_query() call.
	 *
	 * @return Immediately comleted asynchronous call returns eap_status_completed_request.
	 * AM already called the complete_AKA_RES_query().
	 *
	 * @return Other return values are errors.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e query_AKA_RES(
		eap_type_aka_authentication_vector_c * const authentication_vector
		);

	/**
	 * This function queries the authentication_vector.
	 * This function could be synchronous or asynchronous.
	 *
	 * @return Successful call returns eap_status_ok.
	 * This means call was indeed synchronous. 
	 * The send_challenge_request_message() function must be called immediately.
	 *
	 * @return Pending asynchronous call returns eap_status_pending_request.
	 * AM will complete this call later by complete_AKA_authentication_vector_query() call.
	 *
	 * @return Immediately comleted asynchronous call returns eap_status_completed_request.
	 * AM already called the complete_AKA_authentication_vector_query().
	 *
	 * @return Other return values are errors.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e query_AKA_authentication_vector(
		const u8_t next_eap_identifier,
		eap_type_aka_identity_type * const identity_type
		);

	/**
	 * This function creates local copy of MAC_RAND and checks the received one match with local MAC_RAND.
	 * After succesfull MAC_RAND check function parses the AKA payloads from saved AKA EAP packet.
	 * This is because of the process_AKA_kc_sres() function could be called asynchronously and
	 * the received AKA EAP packet is stored to get_saved_EAP_packet().
	 * Also encrypted payload (l_aka_payloads.get_ENCR_DATA()) is handled here.
	 * This is the first place where we have the K_encr (get_K_encr()) available.
	 * The decrpted DATA payload is handled immediately in handle_DATA_payload() function.
	 * Then function calculates MAC_SRES and sends EAP-Response/AKA/Challenge.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e process_AKA_kc_sres(
		const eap_type_aka_authentication_vector_c * const authentication_vector
		);

	/**
	 * This function selects whether to use pseudonym or IMSI.
	 * Function creates NAI and EAP-Response/Identity message.
	 * Message is sent immediately.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e process_AKA_IMSI(
		const eap_variable_data_c * const IMSI, ///< This is the IMSI.
		const eap_variable_data_c * const pseudonym ///< This is the pseudonym.
		);


	/**
	 * This function calculates the MAC_SRES.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e calculate_MAC_SRES(
		eap_variable_data_c * const MAC_SRES, ///< This is the calculated MAC_SRES.
		const eap_variable_data_c * const n_kc, ///< This includes concatenated n KC.
		const eap_variable_data_c * const n_sres ///< This includes concatenated n SRES.
		);

	/**
	 * This function reads the identity payload. Identity is stored to get_identity().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e parse_identity(
		const u8_t * const identity, ///< This is pointer to received EAP-Identity buffer.
		const u32_t identity_length ///< This is length of received EAP-Identity buffer.
		);


	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_eap_identity_query(
		const eap_am_network_id_c * const send_network_id,
		eap_variable_data_c * const identity,
		const u8_t eap_identifier,
		const eap_variable_data_c * const IMSI,
		const eap_variable_data_c * const pseudonym,
		const eap_variable_data_c * const reauthentication_identity,
		const eap_variable_data_c * const automatic_realm, ///< If this is not used, do not add any data to this parameter.
		const u32_t length_of_mnc,
		const bool must_be_synchronous
		);

	/**
	 * This function handles the received EAP-Response/Identity message.
	 * First function parses the identity.
	 * Function queries the AM (query_imsi_from_username()) whether the pseudonym
	 * is known or should it query peer the IMSI.
	 * Currently the query_imsi_from_username() is synchronous call.
	 * The send_aka_identity_request_message() function will send the EAP-Request/AKA/Start message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_identity_response_message(
		eap_header_rd_c * const eap_header, ///< This is the received EAP-Identity packet, pointer points to the header.
		const u32_t aka_packet_length ///< This is length of received AKA EAP packet.
		);

	/**
	 * This function handles the received EAP-Request/AKA/Start message.
	 * Function checks the valid payloads and calls send_aka_identity_response_message() that sends EAP-Response/AKA/Start message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_aka_identity_request_message(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		aka_header_c * const received_aka, ///< This is pointer to EAP header including AKA fields.
		const u32_t aka_packet_length, ///< This is length of received AKA EAP packet.
		aka_payloads_c * const p_aka_payloads ///< This is pointer to all payloads of the received EAP packet.
		);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_aka_notification_request_message_reauthentication(
		const eap_am_network_id_c * const receive_network_id,
		aka_header_c * const received_aka,
		const u32_t aka_packet_length,
		aka_payloads_c * const p_aka_payloads);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_aka_notification_request_message_full_authentication(
		const eap_am_network_id_c * const receive_network_id,
		aka_header_c * const received_aka,
		const u32_t aka_packet_length,
		aka_payloads_c * const p_aka_payloads);

	/**
	 * This function handles the received EAP-Request/AKA/Notification message.
	 * Function checks the valid payloads and calls send_notification_response_message() that sends EAP-Response/AKA/Notification message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_aka_notification_request_message(
		const eap_am_network_id_c * const receive_network_id,
		aka_header_c * const received_aka,
		const u32_t aka_packet_length,
		aka_payloads_c * const p_aka_payloads);

	/**
	 * This function handles the received EAP-Request/AKA/Challenge message.
	 * Function checks the valid payloads. The whole EAP-Request/AKA/Challenge message is
	 * saved to get_saved_EAP_packet() if there is encrypted payload.
	 * This is because the MAC could be checked and payload dercypted later
	 * after n*Kc and n*SRES is get from AKA.
	 * Function calls query_AKA_RES(). The query_AKA_kc_sres() function
	 * is completed using complete_AKA_RES_query() function. The complete_AKA_RES_query()
	 * function will call process_AKA_kc_sres().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_challenge_request_message(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		aka_header_c * const received_aka, ///< This is pointer to EAP header including AKA fields.
		const u32_t aka_packet_length, ///< This is length of received AKA EAP packet.
		aka_payloads_c * const p_aka_payloads ///< This is pointer to all payloads of the received EAP packet.
		);

	/**
	 * This function handles the received EAP-Request/AKA/Re-authentication message.
	 * Function checks the valid payloads. The whole EAP-Request/AKA/Challenge message is
	 * saved to get_saved_EAP_packet() if there is encrypted payload.
	 * This is because the MAC could be checked and payload dercypted later
	 * after n*Kc and n*SRES is get from AKA.
	 * Function calls query_AKA_RES(). The query_AKA_RES() function
	 * is completed using complete_AKA_RES_query() function. The complete_AKA_RES_query()
	 * function will call process_AKA_kc_sres().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_reauthentication_request_message(
		const eap_am_network_id_c * const receive_network_id,
		aka_header_c * const received_aka,
		const u32_t aka_packet_length,
		aka_payloads_c * const p_aka_payloads);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e check_challenge_response_message(
		const eap_am_network_id_c * const receive_network_id,
		aka_header_c * const received_aka,
		const u32_t aka_packet_length,
		aka_payloads_c * const p_aka_payloads);

	/**
	 * This function handles the received EAP-Response/AKA/Start message.
	 * Function checks the valid payloads. If IMSI is included it is copied to get_IMSI().
	 * Also the included NONCE_MT is copied to get_NONCE_MT().
	 * Function calls the query_AKA_authentication_vector() of AM to get fresh authentication_vector.
	 * The query_AKA_authentication_vector() function is completed by AM using complete_AKA_authentication_vector_query() function.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_aka_identity_response_message(
		aka_header_c * const received_aka, ///< This is pointer to EAP header including AKA fields.
		const u32_t aka_packet_length, ///< This is length of received AKA EAP packet.
		aka_payloads_c * const p_aka_payloads ///< This is pointer to all payloads of the received EAP packet.
		);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_notification_response_message_reauthentication(
		const eap_am_network_id_c * const receive_network_id,
		aka_header_c * const received_aka,
		const u32_t aka_packet_length,
		aka_payloads_c * const p_aka_payloads);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_notification_response_message_full_authentication(
		const eap_am_network_id_c * const receive_network_id,
		aka_header_c * const received_aka,
		const u32_t aka_packet_length,
		aka_payloads_c * const p_aka_payloads);

	/**
	 * This function handles the received EAP-Response/AKA/Notification message.
	 * Function checks the valid payloads.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_notification_response_message(
		const eap_am_network_id_c * const receive_network_id,
		aka_header_c * const received_aka,
		const u32_t aka_packet_length,
		aka_payloads_c * const p_aka_payloads);

	/**
	 * This function handles the received EAP-Response/AKA/Challenge message.
	 * Function checks the valid payloads. The analyse_MAC_SRES_payload() function is
	 * called to check MAC_SRES. If it returns eap_status_success the authentication was succesfull
	 * and this function calls the send_eap_success() to send EAP-Success message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_challenge_response_message(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		aka_header_c * const received_aka, ///< This is pointer to EAP header including AKA fields.
		const u32_t aka_packet_length, ///< This is length of received AKA EAP packet.
		aka_payloads_c * const p_aka_payloads ///< This is pointer to all payloads of the received EAP packet.
		);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_reauthentication_response_message(
		const eap_am_network_id_c * const /* receive_network_id */,
		aka_header_c * const received_aka,
		const u32_t aka_packet_length,
		aka_payloads_c * const p_aka_payloads);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_client_error_response_message(
		const eap_am_network_id_c * const /* receive_network_id */,
		aka_header_c * const received_aka,
		const u32_t aka_packet_length,
		aka_payloads_c * const p_aka_payloads);

	/**
	 * This function sends and traces all messages.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e packet_send(
		const eap_am_network_id_c * const network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length);

	/**
	 * This function chechs NAI.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e check_NAI(
		const u8_t * const identity,
		const u32_t identity_length,
		const u8_t * const at_character);

	/**
	 * This function traces the EAP packet.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H void packet_trace(
		eap_const_string prefix,
		const eap_am_network_id_c * const receive_network_id,
		eap_header_wr_c * const received_eap,
		const u32_t eap_packet_length);

#if defined(USE_EAP_TRACE)

	#define EAP_AKA_PACKET_TRACE(prefix, receive_network_id, received_eap, eap_packet_length) \
			packet_trace((prefix), (receive_network_id), (received_eap), (eap_packet_length))

#else

	#define EAP_AKA_PACKET_TRACE(prefix, receive_network_id, received_eap, eap_packet_length)

#endif //#if defined(_DEBUG)


	/**
	 * This function finishes the successfull authentication.
	 * Generated keys are offered to lower layer.
	 * Connection handle is initialised.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e finish_successful_authentication(
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * This function sends a notification of possible failed authentication
	 * to lower layer.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e send_final_notification();

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e new_handler(
		const eap_am_network_id_c * const receive_network_id,
		const bool is_client_when_true);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H bool randomly_refuse_eap_identity();

	/**
	 * This function processes the AKA packets.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e aka_packet_process(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		aka_header_c * const received_aka, ///< This is pointer to EAP header including AKA fields.
		const u32_t aka_packet_length, ///< This is length of received AKA EAP packet.
		const bool is_client_when_true ///< Indicates whether this is client (true) or server (false).
		);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e cancel_error_message_delay_timer();

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e set_error_message_delay_timer();

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_error_packet();

	/**
	 * This function initializes the error message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e initialize_error_message(
		const eap_status_e error_status
		);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e check_synchronization_failure_response_message(
		const eap_am_network_id_c * const /* receive_network_id */,
		aka_header_c * const received_aka,
		const u32_t aka_packet_length,
		aka_payloads_c * const p_aka_payloads);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e complete_re_syncronization_query(
		const u8_t next_eap_identifier,
		const eap_type_aka_authentication_vector_c * const authentication_vector);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e process_re_syncronization(
		const u8_t next_eap_identifier,
		const eap_type_aka_authentication_vector_c * const authentication_vector);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_synchronization_failure_response_message(
		const eap_am_network_id_c * const /* receive_network_id */,
		aka_header_c * const received_aka,
		const u32_t aka_packet_length,
		aka_payloads_c * const p_aka_payloads);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_aka_identity_response_message_completion(
		const u8_t next_eap_identifier,
		const eap_status_e identity_status,
		const eap_type_aka_identity_type identity_type,
		const bool identity_payload_was_included);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e initialize_notification_message();

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e cancel_notification_message_delay_timer();

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e set_notification_message_delay_timer();

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_notification_packet();

	bool get_aka_notification_code_F_bit(const eap_aka_notification_codes_e notification_code);

	bool get_aka_notification_code_P_bit(const eap_aka_notification_codes_e notification_code);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H bool random_selection();


	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e checkcode_init();

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H static bool compare_payload_first_is_less(
		const aka_payload_AT_type_e * const first,
		const aka_payload_AT_type_e * const second,
		abs_eap_am_tools_c * const m_am_tools);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e checkcode_verify_payloads(
		aka_payloads_c * const p_aka_payloads);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e checkcode_save_message_client(
		const void * const data,
		const u32_t data_length,
		aka_payloads_c * const p_aka_payloads);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e checkcode_save_message_server(
		const void * const data,
		const u32_t data_length);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e checkcode_update_saved_message();

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e checkcode_update(
		const void * const data,
		const u32_t data_length);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e checkcode_final(
		eap_variable_data_c * const digest);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e checkcode_verify(
		const eap_variable_data_c * const received_digest);

	/**
	 * This function stores identity.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e store_identity(
		const eap_variable_data_c * const IMSI_or_pseudonym,
		const bool IMSI_is_used);

	/**
	 * eap_core_map_c class increases reference count each time reference to stored object is get.
	 * Here is always just one state for one session so no references are used.
	 */
	void object_increase_reference_count();

	/**
	 * eap_core_map_c class increases reference count each time reference to stored object is get.
	 *  Here is always just one state for one session so no references are used.
	 */
	u32_t object_decrease_reference_count();

	/**
	 * This function stores pointer to the received authentication vector.
	 */
	void set_authentication_vector(eap_type_aka_authentication_vector_c * const authentication_vector);


	void set_reauthentication_counter(const u32_t reauthentication_counter);

	u32_t get_reauthentication_counter();


	/**
	 * This function returns pointer to the stored authentication_vector.
	 */
	eap_type_aka_authentication_vector_c * get_authentication_vector();

	const eap_variable_data_c * get_RAND() const;

	eap_status_e set_RAND(const eap_variable_data_c * const RAND);

	const eap_variable_data_c * get_AUTN() const;

	eap_status_e set_AUTN(const eap_variable_data_c * const AUTN);

	/**
	 * This function stores the last EAP-Identifier.
	 */
	void set_last_eap_identifier(const u8_t last_eap_identifier);

	/**
	 * This function returns the last stored EAP-Identifier.
	 */
	u8_t get_last_eap_identifier();


	void set_include_identity_to_aka_identity_response(const aka_payload_AT_type_e id_type_required);

	aka_payload_AT_type_e get_include_identity_to_aka_identity_response();


	void set_aka_identity_response_includes_identity(const aka_payload_AT_type_e id_type_required);

	aka_payload_AT_type_e get_aka_identity_response_includes_identity();

	/**
	 * This function sets the m_failure_message_received flag true.
	 */
	void set_failure_message_received();

	/**
	 * This function sets the m_failure_message_received flag false.
	 */
	void unset_failure_message_received();

	/**
	 * This function returns the m_failure_message_received flag.
	 */
	bool get_failure_message_received();

	/**
	 * This function returns the current state.
	 */
	eap_type_aka_state_variable_e get_state();

	/**
	 * This function returns the saved previous state.
	 */
	eap_type_aka_state_variable_e get_saved_previous_state();

	/**
	 * This function saves the current m_state to m_saved_previous_state.
	 * The saved state is restored in error case.
	 */
	void save_current_state();

	/**
	 * This function restores the saved state.
	 */
	void restore_saved_previous_state();

	/**
	 * This function returns the send network identity of this session.
	 */
	eap_am_network_id_c * get_send_network_id();

	/**
	 * This function checks the received AKA subtype is valid in current state.
	 * This is used for quick check.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e check_valid_state(aka_subtype_e type);

	/**
	 * This function sets the m_authentication_finished_successfully flag true.
	 */
	void set_authentication_finished_successfully();

	/**
	 * This function returns the m_authentication_finished_successfully flag.
	 */
	bool get_authentication_finished_successfully();

	/**
	 * This function sets the new state and notifies the lower layer of this change.
	 */
	void set_state(eap_type_aka_state_variable_e state);

	//--------------------------------------------------

	/**
	 * This function generates K_encr, K_aut and master_session_key.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e generate_shared_secred_keys(
		const u32_t key_length,
		const eap_variable_data_c * const CK,
		const eap_variable_data_c * const IK,
		eap_variable_data_c * const XKEY,
		eap_variable_data_c * const K_encr,
		eap_variable_data_c * const K_aut,
		eap_variable_data_c * const master_session_key);


	//--------------------------------------------------

	/**
	 * This function generates K_encr, K_aut and master_session_key.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e generate_reauth_shared_secred_keys(
		const u32_t key_length,
		const eap_variable_data_c * const orig_XKEY,
		const u32_t reauth_counter,
		const eap_variable_data_c * const reauth_identity,
		const eap_variable_data_c * const reauth_nonce_s,
		eap_variable_data_c * const master_session_key);

	//--------------------------------------------------

	/**
	 * This function returns m_nonce_S.
	 */
	eap_variable_data_c * get_NONCE_S();

	//--------------------------------------------------

	/**
	 * This function returns m_IMSI.
	 */
	eap_variable_data_c * get_IMSI();

	//--------------------------------------------------

	/**
	 * This function returns m_username.
	 */
	eap_variable_data_c * get_identity();

	//--------------------------------------------------

	/**
	 * This function returns m_NAI.
	 */
	eap_variable_data_c * get_NAI();

	//--------------------------------------------------

	/**
	 * This function returns m_n_sres.
	 */
	eap_variable_data_c * get_RES();

	//--------------------------------------------------

	/**
	 * This function returns m_pseudonym.
	 */
	eap_variable_data_c * get_pseudonym();

	//--------------------------------------------------

	/**
	 * This function returns m_reauthentication_identity.
	 */
	eap_variable_data_c * get_reauthentication_identity();

	//--------------------------------------------------

	/**
	 * This function returns m_IV.
	 */
	aka_variable_data_c * get_IV();

	/**
	 * This function returns m_saved_EAP_packet.
	 */
	eap_variable_data_c * get_saved_EAP_packet();

	//--------------------------------------------------

	/**
	 * This function returns m_XKEY.
	 */
	eap_variable_data_c * get_XKEY();

	/**
	 * This function returns m_K_encr.
	 */
	eap_variable_data_c * get_K_encr();

	/**
	 * This function returns m_K_aut.
	 */
	eap_variable_data_c * get_K_aut();

	/**
	 * This function returns m_master_session_key.
	 */
	eap_master_session_key_c * get_master_session_key();

	/**
	 * This function stores the last encryption IV. In CBC-mode previous encrypted block is
	 * used as a IV of next block.
	 */
	eap_status_e store_last_encryption_iv(const eap_variable_data_c * const encryption_IV);

	/**
	 * Currently this does nothing and this is not called anywhere.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H void delete_unused_keys();


	/**
	 * This function returns string of the current state. This is for trace purposes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_const_string get_state_string() const;

	/**
	 * This function returns string of the current state. This is for trace purposes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_const_string get_saved_previous_state_string() const;

	/**
	 * This function initializes a timer to sends the EAP-Request/Failure message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e initialize_eap_failure_timer();

	/**
	 * This function cancels a timer to sends the EAP-Request/Failure message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e cancel_eap_failure_timer();

	/**
	 * This function initializes a timer to sends the EAP-Response/Notification message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e initialize_eap_notification_timer();

	/**
	 * This function cancels a timer to sends the EAP-Response/Notification message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e cancel_eap_notification_timer();

	/**
	 * This function initializes a timer to sends the EAP-Response/Failure message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e initialize_failure_message_received_timer();

	/**
	 * This function cancels a timer to sends the EAP-Response/Failure message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e cancel_failure_message_received_timer();

	u32_t get_mnc_length(const u32_t mcc);

	eap_status_e create_uma_realm(
		eap_variable_data_c * const automatic_realm,
		const eap_variable_data_c * const IMSI,
		const u32_t length_of_mnc);

	void set_identity_type(eap_type_aka_identity_type  type);

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * Destructor cancels all timers and deletes member attributes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H virtual ~eap_type_aka_c();

	/**
	 * Constructor initializes all member attributes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_type_aka_c(
		abs_eap_am_tools_c * const tools, ///< This is pointer to the tools AM of current platform.
		abs_eap_base_type_c * const partner, ///< This is back pointer to object which created this object.
		eap_am_type_aka_c * const am_type_aka, ///< This is pointer to adaptation module of AKA EAP type.
		const bool free_am_type_aka, ///< True value means m_am_type_aka is allocated within eap_type_aka_c and m_am_type_aka must be freed in destructor.
		const bool is_client_when_true, ///< Indicates whether this is client (true) or server (false).
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * This function tells if the object is a client or a server..
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H bool get_is_client();

	// This is commented in abs_eap_am_type_aka_c::complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query().
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query(
		const eap_variable_data_c * const IMSI, ///< This is the IMSI.
		const eap_variable_data_c * const pseudonym, ///< This is the pseudonym.
		const eap_variable_data_c * const reauthentication_identity, ///< This is the re-authentication identity.
		const eap_variable_data_c * const automatic_realm,
		const u32_t length_of_mnc,
		const eap_type_aka_complete_e required_completion, ///< This parameter tells the required completion
		const u8_t received_eap_identifier, ///< This parameter is the EAP-identifier of EAP-request
		const eap_status_e completion_status
		);

	// This is commented in abs_eap_am_type_aka_c::complete_AKA_authentication_vector_query().
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e complete_AKA_authentication_vector_query(
		eap_type_aka_authentication_vector_c * const authentication_vector, ///< authentication_vector includes all AKA parametrs used in this authentication session.
		const eap_variable_data_c * const IMSI, ///< IMSI may be queried during query_AKA_authentication_vector() function call. It must be copied to state.
		const eap_aka_authentication_vector_status_e authentication_vector_status,  ///< This is the status of the failed authentication_vector query.
		const eap_type_aka_identity_type type, ///< This is type of the identity.
		const eap_status_e completion_status,
		const u8_t next_eap_identifier
		);

	// This is commented in abs_eap_am_type_aka_c::complete_AKA_RES_query().
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e complete_AKA_RES_query(
		const eap_type_aka_authentication_vector_c * const authentication_vector,
		const eap_status_e completion_status
		);

	/** Client calls this function.
	 *  This function IMSI and username to AKA EAP type.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e handle_imsi_from_username(
		const u8_t next_eap_identifier,
		const eap_am_network_id_c * const network_id,
		const eap_variable_data_c * const username,
		const eap_variable_data_c * const imsi, ///< The result is stored to imsi parameter.
		const eap_type_aka_identity_type identity_type);

	// This is commented in abs_eap_am_type_aka_c::complete_imsi_from_username().
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e complete_imsi_from_username(
		const u8_t next_eap_identifier,
		const eap_am_network_id_c * const network_id,
		const eap_variable_data_c * const username,
		const eap_variable_data_c * const imsi, ///< The result is stored to imsi parameter.
		const eap_type_aka_identity_type type,
		const eap_status_e completion_status,
		const eap_type_aka_complete_e completion_action);

	/**
	 * The partner class calls this function when EAP/AKA packet is received.
	 * see also eap_base_type_c::packet_process().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		eap_header_wr_c * const eap, ///< This is pointer to EAP header and data.
		const u32_t eap_packet_length ///< This is length of received EAP packet.
		);

	/**
	 * This function obtains header offset, MTU and trailer length.
	 * See also abs_eap_base_type_c::get_header_offset().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length
		);

	/**
	 * This function creates a message authentication code (MAC)
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e create_message_authentication_code(
		eap_type_aka_MAC_attributes_c *MAC_attributes, ///< This includes required parameters.
		const aka_subtype_e subtype,
		const eap_code_value_e code,
		const eap_variable_data_c * const authentication_key
		);

	/**
	 * This function adds addiditional data to MAC calculation.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e extra_message_authentication_code_bytes(
		const aka_subtype_e subtype,
		const eap_code_value_e code,
		crypto_hmac_c *hmac_sha1);

	// This is commented in abs_eap_base_timer_c::timer_delete_data().
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e timer_expired(
		const u32_t id, void *data
		);

	// This is commented in abs_eap_base_timer_c::timer_delete_data().
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e timer_delete_data(
		const u32_t id, void *data
		);

	// This is commented in eap_base_type_c::set_is_valid().
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H void set_is_valid();

	// This is commented in eap_base_type_c::get_is_valid().
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H bool get_is_valid();

	// This is commented in eap_base_type_c::configure().
	/**
	 * EAP-type AKA reads configuration.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e configure();

	// This is commented in eap_base_type_c::shutdown().
	/**
	 * The shutdown() function is called before the destructor of the 
	 * object is executed. During the function call the object 
	 * could shutdown the operations, for example cancel timers.
	 * Each derived class must define this function.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e shutdown();

	/**
	 * The read_configure() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H virtual eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data
		);

	/**
	 * The write_configure() function writes the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the action to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H virtual eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data
		);

	// See abs_eap_base_type_c::state_notification().
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H void state_notification(
		const abs_eap_state_notification_c * const state
		);

	// This is commented in eap_base_type_c::query_eap_identity().
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e query_eap_identity(
		const bool must_be_synchronous,
		eap_variable_data_c * const identity,
		const eap_am_network_id_c * const receive_network_id,
		const u8_t eap_identifier);

	// This is commented in eap_base_type_c::set_initial_eap_identifier().
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e set_initial_eap_identifier(
		const eap_am_network_id_c * const receive_network_id,
		const u8_t initial_identifier);

	// This is commented in eap_base_type_c::eap_acknowledge().
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e eap_acknowledge(
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * This function must reset the state of object to same as 
	 * state was after the configure() function call.
	 * If object reset succeeds this function must return eap_status_ok.
	 * If object reset fails this function must return corresponding error status.
	 * @return This function returns the status of reset operation.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e reset();

	//
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e set_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id, 
		void * const p_data,
		const u32_t p_time_ms);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H eap_status_e cancel_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H static eap_const_string get_identity_string(const eap_type_aka_identity_type identity_type);

	/**
	 * This function returns string of the state. This is for trace purposes.
	 * NOTE this is static member function.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_H static eap_const_string get_state_string(eap_type_aka_state_variable_e state);

	//--------------------------------------------------

}; // class eap_type_aka_c

#endif //#if !defined(_AKA_CORE_H_)

//--------------------------------------------------



// End.
