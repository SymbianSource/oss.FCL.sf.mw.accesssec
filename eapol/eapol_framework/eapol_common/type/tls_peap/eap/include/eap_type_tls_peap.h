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

#if !defined(_EAP_TYPE_TLS_PEAP_H_)
#define _EAP_TYPE_TLS_PEAP_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TYPE_TLS_PEAP_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_TLS_PEAP_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H 
	#define EAP_FUNC_EXPORT_EAP_TYPE_TLS_PEAP_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_TLS_PEAP_H 
#elif defined(EAP_EXPORT_EAP_TYPE_TLS_PEAP_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_TLS_PEAP_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_TLS_PEAP_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_TLS_PEAP_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_TLS_PEAP_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_TLS_PEAP_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_TLS_PEAP_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_am_type_tls_peap.h"
#include "eap_am_network_id.h"
#include "abs_eap_base_type.h"
#include "eap_base_type.h"
#include "eap_variable_data.h"
#include "abs_eap_base_timer.h"
#include "eap_crypto_api.h"
#include "eap_protocol_layer.h"
#include "eap_type_tls_peap_types.h"
#include "abs_tls_base_record.h"
#include "tls_record_header.h"
#include "eap_master_session_key.h"

class eap_tls_peap_header_c;
class abs_eap_am_tools_c;
class abs_eap_base_type_c;
class eap_am_type_tls_peap_c;
class tls_base_record_c;

//--------------------------------------------------


/// This class is implementation of TLS/PEAP EAP type. See more detailed design and architecture document <a href="../../type/tls_peap/documentation/EAP_TLS_PEAP.doc">EAP_TLS_PEAP.doc</a>.
class EAP_CLASS_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_type_tls_peap_c
: public abs_eap_base_timer_c
, public eap_base_type_c
, public abs_eap_am_type_tls_peap_c
, public abs_tls_base_record_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is pointer to adaptation module of TLS/PEAP EAP type.
	eap_am_type_tls_peap_c * m_am_type_tls_peap;

	/// This is pointer to TLS implementation.
	tls_base_record_c * m_tls_record;

	/// This is the realm part of NAI of the authenticator.
	/// Client uses this as a realm part on the NAI.
	eap_variable_data_c m_nai_realm;

	/// This is the full NAI of the client.
	eap_variable_data_c m_NAI;

	/// This is the identity used in EAP-Identity.
	eap_variable_data_c m_current_identity;

	/// This is network identity of the sent packet from this authentication session.
	eap_am_network_id_c m_send_network_id;

	/// This is offset in bytes of the EAP-type header in the packet buffer.
	/// Offset is described in abs_eap_base_type_c::get_header_offset().
	u32_t m_tls_peap_header_offset;

	/// This is maximum transfer unit in bytes.
	/// MTU is described in abs_eap_base_type_c::get_header_offset().
	u32_t m_MTU;

	/// This is length of the trailer in bytes.
	/// Trailer length is described in abs_eap_base_type_c::get_header_offset().
	u32_t m_trailer_length;

	/// This is the state of this authentication session.
	eap_type_tls_peap_state_variable_e m_state;

	/// This is the saved previous state of this authentication session.
	eap_type_tls_peap_state_variable_e m_saved_previous_state;

	/// This is the state of reassembly.
	eap_type_tls_peap_reassembly_state_e m_reassembly_state;

	/// This is the saved previous state of reassembly.
	eap_type_tls_peap_reassembly_state_e m_saved_previous_reassembly_state;

	/// This is the offset of next fragment to be send from m_tls_message_buffer.
	u32_t m_tls_message_send_offset;

	/// This is the buffer for TLS-message reassembly and fragmentation.
	eap_variable_data_c m_tls_message_buffer;

	/// m_master_session_key.
	eap_master_session_key_c m_master_session_key;

	/// This is u32_t array of accepted PEAP versions.
	eap_variable_data_c m_accepted_PEAP_versions;

	/// This the current EAP-type (TLS, PEAP or TTLS).
	const eap_type_value_e m_current_eap_type;

	/// This separates different PEAP versions.
	/// This is the configured default PEAP version.
	peap_version_e m_configured_peap_version;

	/// This separates different PEAP versions.
	/// This is the current active PEAP version.
	peap_version_e m_current_peap_version;

	u8_t m_first_fragment_eap_identifier;

	tls_session_type_e m_tls_session_type;

	bool m_tunneled_eap_type_active;

	eap_state_variable_e m_tunneled_eap_type_authentication_state;


	bool m_free_am_type_tls_peap;

	bool m_free_tls_record;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/// This indicates whether this object is client (true) or server (false).
	/// In terms of EAP-protocol whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	bool m_is_client;

	/// True value of this flag indicates the EAP-Success packet must be received
	/// in successfull authentication of clien.
	/// This value is configured with EAP_TLS_PEAP_wait_eap_success_packet.
	bool m_wait_eap_success_packet;

	/// True value of this flag indicates the identifier of the EAP-Response/Identity must be checked.
	/// This is not possible cases where identifier of the EAP-Request/Identity is generated by other network entities.
	bool m_check_identifier_of_eap_identity_response;


	/// True value means this is a test version of TLS/PEAP.
	bool m_tls_peap_test_version;

	/// This flag forces check of NAI realm. Realm must be the same as given in EAP_TLS_PEAP_manual_realm configuration option.
	/// Default value is false, check is not done by default.
	bool m_check_nai_realm;

#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	/// Flag causes TLS to use identity privacy.
	bool m_tls_use_identity_privacy;
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)


	/// This flag indicates whether the EAP-Failure was received.
	/// On successfull authentication bogus EAP-Failure is ignored.
	bool m_failure_message_received;

	/// This variable is set true when authentication finished successfully.
	bool m_authentication_finished_successfully;

	/// This variable stores the last used EAP-Identifier.
	/// Client will always send EAP-Response with this identifier.
	/// Server will always send EAP-Request with this identifier increased by one.
	/// Server increase this identifier after successfull packet send.
	u8_t m_last_eap_identifier;

	/// This flag is set true when shutdown is called.
	/// This is for internal sanity check.
	bool m_shutdown_was_called;

	/// This configurable option selects whether the TLS/PEAP version of Tppd
	/// is used, the length field is added to all message fragments
	/// even the message fits to one fragment except EAP-TLS-start, EAP-TLS-Acknowledge and
	/// PEAP-application data. The client acknowledges tunneled EAP-Success message
	/// with empty PEAP message.
	bool m_use_tppd_tls_peap;

	/// On fast session resume server does not send tunneled EAP-Success.
	/// Instead it sends plain EAP-Success.
	/// True value of this flag allows this plain EAP-Success.
	bool m_use_tppd_peapv1_acknowledge_hack;

	/// This flag tells the send message includes TLS-Handshake message.
	/// Note the received messages are not marked.
	/// This information is needed in some PEAP versions.
	/// All messages including TLS-Handshake message must have PEAP L bit and four octet TLS message length field.
	bool m_includes_tls_handshake_message;

	bool m_use_eap_expanded_type;

	//--------------------------------------------------

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e select_peap_version(const u32_t proposed_peap_version);

	/**
	 * This function generates a new NAI from domain and identity.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e generate_nai(
		eap_variable_data_c * const new_nai, ///< This is the new generated NAI.
		const eap_variable_data_c * const domain, ///< This is the domain part of the NAI.
		const eap_variable_data_c * const identity ///< This is identity.
		);

	/**
	 * This function handles the received TLS/PEAP EAP packet.
	 *
	 * First is checked the valid massage is received in valid state.
	 *
	 * Second is parsed the payloads and checked syntax of the received TLS/PEAP EAP packet.
	 * See also parse_tls_peap_packet().
	 *
	 * Third is analysed the TLS/PEAP EAP packet. This includes the payload and values of each payload.
	 * See also analyse_tls_peap_packet().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e handle_tls_peap_packet(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		eap_tls_peap_header_c * const tls_peap, ///< This is pointer to EAP header including EAP-TLS/PEAP fields.
		const u32_t tls_peap_length ///< This is length of received TLS/PEAP EAP packet.
		);

	/**
	 * This function analyses the received TLS/PEAP EAP packet.
	 * Each sub-type is handled in separate function.
	 * @see Client messages are handled in handle_start_request_message() and handle_challenge_request_message(). 
	 * @see Server messages are handled in handle_start_response_message() and handle_challenge_response_message(). 
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e analyse_tls_peap_packet(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		eap_tls_peap_header_c * const received_tls_peap, ///< This is pointer to EAP header including EAP-TLS/PEAP fields.
		const u32_t tls_peap_packet_length ///< This is length of received TLS/PEAP EAP packet.
		);

	/**
	 * This function parses the payloads starting from specified payload (p_payload).
	 * Function parses all payloads from the buffer.
	 * Payloads are stored to p_tls_peap_payloads.
	 * @return If the length of the buffer and sum of the length of all payloads does not match
	 * function returns eap_status_header_corrupted.
	 * Also error is returned when illegal payload attribute is recognised.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e parse_tls_peap_payload(
		u32_t * const buffer_length ///< This is the length of the buffer. This must match with the length of all payloads.
		);

	/**
	 * This function checks the version list payload of the TLS/PEAP EAP packet is correct.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e check_version_list(
		const u16_t version_list_length,
		u8_t * version_list);

	/**
	 * This function parses all payloads of the whole TLS/PEAP EAP packet.
	 * Payloads are stored to p_tls_peap_payloads.
	 * @see parse_tls_peap_payload().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e parse_tls_peap_packet(
		eap_tls_peap_header_c * const tls_peap, ///< This is pointer to EAP header including EAP-TLS/PEAP fields.
		const u32_t tls_peap_packet_length ///< This is length of received TLS/PEAP EAP packet.
		);

	//--------------------------------------------------

	/**
	 * This function returns the domain name, realm part of NAI.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_variable_data_c * get_nai_realm();

	/**
	 * This function returns the full NAI.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_variable_data_c * get_NAI();

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
	 * Note maximum_buffer_size could be larger than (m_tls_peap_header_offset + m_MTU + m_trailer_length).
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H void update_buffer_indexes(
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
	 * Note maximum_buffer_size could be larger than (m_tls_peap_header_offset + m_MTU + m_trailer_length).
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H void update_payload_indexes(
		const u32_t maximum_buffer_size,
		const u32_t eap_header_size,
		const u32_t payload_size,
		u32_t * const data_offset,
		u32_t * const data_free,
		u32_t * const buffer_offset,
		u32_t * const buffer_free);

	/**
	 * This function reads the identity payload. Identity is stored to handler->get_identity().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e parse_identity(
		const u8_t * const identity, ///< This is pointer to received EAP-Identity buffer.
		const u32_t identity_length ///< This is length of received EAP-Identity buffer.
		);

	/**
	 * This function handles the received EAP-Response/Identity message.
	 * First function parses the identity.
	 * The send_start_request_message() function will send the EAP-Request/SIM/Start message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e handle_identity_response_message(
		eap_header_rd_c * const eap_header, ///< This is the received EAP-Identity packet, pointer points to the header.
		const u32_t tls_peap_packet_length ///< This is length of received TLS/PEAP EAP packet.
		);

	/**
	 * This function chechs NAI.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e check_NAI(
		const u8_t * const identity,
		const u32_t identity_length,
		const u8_t * const at_character);

	/**
	 * This function traces the EAP packet.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H void packet_trace(
		eap_const_string prefix,
		const eap_am_network_id_c * const receive_network_id,
		eap_header_wr_c * const received_eap,
		const u32_t eap_packet_length);

	/**
	 * This function returns m_master_session_key.
	 */
	eap_master_session_key_c * get_master_session_key();

	/**
	 * This function finishes the successfull authentication.
	 * Generated keys are offered to lower layer.
	 * Connection handle is initialised.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e finish_successful_authentication(
		const bool send_tppd_peapv1_empty_acknowledge,
		const bool do_quiet_finish,
		const bool do_send_empty_acknowledge);

	/**
	 * This function sends a notification of possible failed authentication
	 * to lower layer.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e send_final_notification();


	/**
	 * This function returns the state of this authentication session.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_type_tls_peap_state_variable_e get_state() const;

	/**
	 * This function sets the new state and notifies the lower layer of this change.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H void set_state(const eap_type_tls_peap_state_variable_e state);

	/**
	 * This function saves the current m_state to m_saved_previous_state.
	 * The saved state is restored in error case.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H void save_current_state();

	/**
	 * This function restores the saved state.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H void restore_saved_previous_state();


	/**
	 * This function returns the state of reassembly.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_type_tls_peap_reassembly_state_e get_reassembly_state() const;

	/**
	 * This function sets the new reassembly state.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H void set_reassembly_state(const eap_type_tls_peap_reassembly_state_e state);

	/**
	 * This function saves the current m_reassembly_state to m_saved_previous_reassembly_state.
	 * The saved state is restored in error case.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H void save_current_reassembly_state();

	/**
	 * This function restores the saved reassembly state.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H void restore_saved_reassembly_state();


	/**
	 * This function returns the send network identity of this session.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_am_network_id_c * get_send_network_id();

	/**
	 * This function stores the last EAP-Identifier.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H void set_last_eap_identifier(const u8_t last_eap_identifier);

	/**
	 * This function returns the last stored EAP-Identifier.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H u8_t get_last_eap_identifier() const;

	eap_status_e check_received_eap_identifier(
		const eap_header_wr_c * const eap_header);


	/**
	 * This function returns string of the current state. This is for trace purposes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_const_string get_state_string() const;

	/**
	 * This function returns string of the current state. This is for trace purposes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_const_string get_saved_previous_state_string() const;

	/**
	 * This function returns string of the current reassembly state. This is for trace purposes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_const_string get_reassembly_state_string() const;


	/**
	 * This function sets the m_failure_message_received flag true.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H void set_failure_message_received();

	/**
	 * This function sets the m_failure_message_received flag false.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H void unset_failure_message_received();

	/**
	 * This function returns the m_failure_message_received flag.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H bool get_failure_message_received() const;

	/**
	 * This function sends an empty EAP-packet.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e send_empty_eap_ack();

	/**
	 * This function sends EAP-TLS/PEAP start message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e send_tls_peap_start_message(
		const u8_t next_eap_identifier, ///< This is EAP-Identifier of next EAP packet.
		const eap_variable_data_c * const authority_identity_payload
		);

	/**
	 * This function sends starts EAP-TLS/PEAP after a start message is received.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e start_tls_peap_authentication(
		const eap_variable_data_c * const received_authority_identity_payload
		);

	/**
	 * This function extracts the TLS-record message from m_tls_message_buffer and forwards it to tls_base_record_c object.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e tls_message_process(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		eap_tls_peap_header_c * const received_tls_peap, ///< This is pointer to EAP header including EAP-TLS/PEAP fields.
		const u32_t tls_peap_packet_length ///< This is length of received TLS/PEAP EAP packet.
		);

	/**
	 * This function sends the EAP-TLS/PEAP message from rm_tls_reassembly_buffer.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e eap_tls_peap_fragment_send();

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e create_random_eap_identity(
		eap_variable_data_c * const local_identity);

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e create_eap_fast_mac_identity(
		const eap_am_network_id_c * const send_network_id,
		eap_variable_data_c * const mac_identity);

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e handle_eap_identity_query(
		const eap_variable_data_c * const user_certificate_identity,
		const eap_am_network_id_c * const receive_network_id,
		const u8_t eap_identifier,
		const bool use_manual_username,
		const eap_variable_data_c * const manual_username,
		const bool use_manual_realm,
		const eap_variable_data_c * const manual_realm
		);

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H tls_session_type_e get_tls_session_type();

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * Destructor cancels all timers and deletes member attributes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H virtual ~eap_type_tls_peap_c();

	/**
	 * Constructor initializes all member attributes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_type_tls_peap_c(
		abs_eap_am_tools_c * const tools, ///< This is pointer to the tools AM of current platform.
		abs_eap_base_type_c * const partner, ///< This is back pointer to object which created this object.
		eap_am_type_tls_peap_c * const am_type_tls_peap, ///< This is pointer to adaptation module of TLS/PEAP EAP type.
		const bool free_am_type_tls_peap,
		tls_base_record_c * const tls_record, /// This is pointer to TLS implementation.
		const bool free_tls_record,
		const bool is_client_when_true, ///< Indicates whether this is client (true) or server (false).
		const eap_type_value_e current_eap_type, ///< This the current EAP-type (TLS or PEAP).
		const eap_am_network_id_c * const receive_network_id ///< The network id used for this session.
		);

	/**
	 * This function creates reassembly state string.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H static eap_const_string get_reassembly_state_string(eap_type_tls_peap_reassembly_state_e state);

	/**
	 * This function creates state string.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H static eap_const_string get_state_string(eap_type_tls_peap_state_variable_e state);


	/**
	 * This function tells if the object is a client or a server..
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H bool get_is_client();

	// This is commented in abs_eap_am_type_tls_peap_c::complete_eap_identity_query().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e complete_eap_identity_query(
		const eap_variable_data_c * const user_certificate_identity,
		const eap_am_network_id_c * const receive_network_id,
		const u8_t eap_identifier,
		const eap_status_e completion_status,
		const bool use_manual_username,
		const eap_variable_data_c * const manual_username,
		const bool use_manual_realm,
		const eap_variable_data_c * const manual_realm
		);

	/**
	 * The partner class calls this function when EAP/TLS/PEAP packet is received.
	 * see also eap_base_type_c::packet_process().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		eap_header_wr_c * const eap, ///< This is pointer to EAP header and data.
		const u32_t eap_packet_length ///< This is length of received EAP packet.
		);

	/**
	 * This function processes the EAP-Response/Identity.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e eap_identity_response_packet_process(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		eap_header_wr_c * const received_eap, ///< This is pointer to EAP header and data.
		const u32_t eap_packet_length ///< This is length of received EAP packet.
		);

	/**
	 * This function processes the TLS/PEAP packets.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e tls_peap_packet_process(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		eap_tls_peap_header_c * const received_tls_peap, ///< This is pointer to EAP header including EAP-TLS/PEAP fields.
		const u32_t tls_peap_packet_length ///< This is length of received TLS/PEAP EAP packet.
		);

	// This is commented in abs_eap_base_timer_c::timer_delete_data().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e timer_expired(
		const u32_t id, void *data
		);

	// This is commented in abs_eap_base_timer_c::timer_delete_data().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e timer_delete_data(
		const u32_t id, void *data
		);

	// This is commented in eap_base_type_c::set_is_valid().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H void set_is_valid();

	// This is commented in eap_base_type_c::get_is_valid().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H bool get_is_valid();

	// This is commented in eap_base_type_c::configure().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e configure();

	// This is commented in eap_base_type_c::shutdown().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e shutdown();

	// This is commented in eap_base_type_c::query_eap_identity().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e query_eap_identity(
		const bool must_be_synchronous,
		eap_variable_data_c * const identity,
		const eap_am_network_id_c * const receive_network_id,
		const u8_t eap_identifier);

	// This is commented in eap_base_type_c::query_eap_identity().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e set_initial_eap_identifier(
		const eap_am_network_id_c * const receive_network_id,
		const u8_t initial_identifier);

	// This is commented in eap_base_type_c::eap_acknowledge().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e eap_acknowledge(
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * This function must reset the state of object to same as 
	 * state was after the configure() function call.
	 * If object reset succeeds this function must return eap_status_ok.
	 * If object reset fails this function must return corresponding error status.
	 * @return This function returns the status of reset operation.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e reset();

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e set_tls_master_secret(
		const eap_variable_data_c * const eap_tls_master_session_key);

	/// @see abs_tls_base_record_c::state_notification().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H void state_notification(
		const abs_eap_state_notification_c * const state
		);

	/// @see abs_tls_base_record_c::packet_send().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e tls_peap_packet_send(
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length,
		const bool includes_tls_handshake_message);

	/// @see abs_tls_base_record_c::packet_send().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e packet_send(
		const eap_am_network_id_c * const network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length);

	/// @see abs_tls_base_record_c::get_header_offset().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length
		);

	/// @see abs_tls_base_record_c::restart_authentication().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e restart_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const bool is_client_when_true,
		const bool force_clean_restart,
		const bool from_timer);

	/// @see abs_tls_base_record_c::read_configure().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H virtual eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data
		);

	/// @see abs_tls_base_record_c::write_configure().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H virtual eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data
		);

	/// @see abs_tls_base_record_c::set_timer().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e set_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id, 
		void * const p_data,
		const u32_t p_time_ms);

	/// @see abs_tls_base_record_c::cancel_timer().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e cancel_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id);

	/// @see abs_tls_base_record_c::load_module().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e /* tunneling_type */,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id);

	/// @see abs_tls_base_record_c::unload_module().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e unload_module(const eap_type_value_e type);

	/// @see abs_tls_base_record_c::packet_data_crypto_keys().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e packet_data_crypto_keys(
		const eap_am_network_id_c * const send_network_id,
		const eap_master_session_key_c * const master_session_key);

	/// @see abs_tls_base_record_c::check_is_valid_eap_type().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e check_is_valid_eap_type(const eap_type_value_e eap_type);

	/// @see abs_tls_base_record_c::get_eap_type_list().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e get_eap_type_list(
		eap_array_c<eap_type_value_e> * const eap_type_list);

	/// @see abs_tls_base_record_c::set_session_timeout().
	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e set_session_timeout(
		const u32_t session_timeout_ms);

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e add_rogue_ap(eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list);

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e peap_tunnel_ready();

	EAP_FUNC_VISIBILITY_EAP_TYPE_TLS_PEAP_H eap_status_e set_tls_session_type(const tls_session_type_e tls_session_type);

	//--------------------------------------------------
}; // class eap_type_tls_peap_c

#endif //#if !defined(_EAP_TYPE_TLS_PEAP_H_)

//--------------------------------------------------



// End.
