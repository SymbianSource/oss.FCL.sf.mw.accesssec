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

#if !defined(_TLS_APPLICATION_EAP_CORE_H_)
#define _TLS_APPLICATION_EAP_CORE_H_

#include "abs_eap_core.h"
#include "tls_base_application.h"
#include "tls_peap_types.h"
#include "tls_peap_tlv_header.h"
#include "tls_peap_tlv_payloads.h"
#include "eap_master_session_key.h"
#include "eap_diameter_payloads.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_TLS_APPLICATION_EAP_CORE_H)
	#define EAP_CLASS_VISIBILITY_TLS_APPLICATION_EAP_CORE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H 
	#define EAP_C_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H 
	#define EAP_FUNC_EXPORT_TLS_APPLICATION_EAP_CORE_H 
	#define EAP_C_FUNC_EXPORT_TLS_APPLICATION_EAP_CORE_H 
#elif defined(EAP_EXPORT_TLS_APPLICATION_EAP_CORE_H)
	#define EAP_CLASS_VISIBILITY_TLS_APPLICATION_EAP_CORE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_TLS_APPLICATION_EAP_CORE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_TLS_APPLICATION_EAP_CORE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_TLS_APPLICATION_EAP_CORE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_TLS_APPLICATION_EAP_CORE_H 
	#define EAP_C_FUNC_EXPORT_TLS_APPLICATION_EAP_CORE_H 
#endif
// End: added by script change_export_macros.sh.


class abs_tls_base_application_c;
class abs_eap_am_tools_c;
class eap_am_network_id_c;
class tls_record_header_c;
class eap_core_c;
class peap_tlv_payloads_c;
class eap_diameter_payloads_c;


/// The tls_application_eap_core_c class is a implementation of tls_base_application_c.
class EAP_CLASS_VISIBILITY_TLS_APPLICATION_EAP_CORE_H tls_application_eap_core_c
: public tls_base_application_c
, public abs_eap_core_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class. @see abs_eap_am_tools_c.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is pointer to EAP-core.
	eap_core_c * m_eap_core;

	/// This flag tells whether the m_eap_core must be freed in destructor (true) or not (false).
	const bool m_free_eap_core;

	/// This is pointer to TLS-application.
	abs_tls_base_application_c * m_application_partner;

	/// This is network identity of the received packet.
	eap_am_network_id_c m_receive_network_id;

	/// This is the EAP-type which creates the tunnel (PEAP or TTLS).
	eap_type_value_e m_eap_type;

	/// This separates different PEAP versions (PEAPv2, PEAPv1 or XP PEAPv0).
	peap_version_e m_peap_version;

	/// This is the EAP-type which is tunneled inside PEAP.
	eap_type_value_e m_peap_tunneled_eap_type;

	/// This variable saves the state of the tunneled EAP-type.
	/// State is changed during packet_process() and state_notification() function calls.
	eap_state_variable_e m_tunneled_eap_type_authentication_state;


	peap_tlv_payloads_c m_peapv2_tlv_payloads;

	eap_variable_data_c m_peap_v2_client_nonce;

	eap_variable_data_c m_peap_v2_server_nonce;

	eap_variable_data_c m_peap_v2_IPMKn;

	eap_variable_data_c m_peap_v2_ISKn;

	eap_variable_data_c m_peap_v2_CMK_B1_server;

	eap_variable_data_c m_peap_v2_CMK_B2_client;

	eap_master_session_key_c m_peap_v2_CSK;


	eap_array_c<eap_type_value_e> m_accepted_tunneled_eap_types;

	eap_variable_data_c m_pseudo_ethernet_header;

	eap_diameter_payloads_c m_ttls_received_payloads;

	eap_ttls_tunneled_message_type_e m_ttls_message_type;


	eap_variable_data_c m_ttls_sent_eap_packet;

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

	eap_variable_data_c m_ttls_user_name;

	eap_variable_data_c m_ttls_implicit_challenge;

	eap_ttls_tunneled_message_state_e m_ttls_tunneled_message_state;

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)


	u32_t m_error_probability;

	u8_t m_received_eap_identifier;

	/// This flag activates error manipulation to send tunneled packets.
	bool m_enable_random_errors;

	/// This flag activates error manipulation to send tunneled packets.
	bool m_manipulate_only_tunneled_messages;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/// This indicates whether this object is client (true) or server (false).
	/// In terms of EAP-protocol whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	bool m_is_client;

	/// This flag tells whether the shutdown() function was called (true) or not (false).
	bool m_shutdown_was_called;

	tls_session_type_e m_tls_session_type;

	bool m_peap_allow_tunneled_session_resumption;

	/// This configurable option selects whether the special style of TLS/PEAP 
	/// is used, the length field is added to all message fragments
	/// even the message fits to one fragment except EAP-TLS-start, EAP-TLS-Acknowledge and
	/// PEAP-application data. The client acknowledges tunneled EAP-Success message
	/// with empty PEAP message.
	bool m_use_tppd_tls_peap;

	/// On fast session resume server does not send tunneled EAP-Success.
	/// Instead it sends plain EAP-Success.
	/// True value of this flag allows this plain EAP-Success.
	bool m_use_tppd_peapv1_acknowledge_hack;


#if defined(USE_EAP_PEAPV1_EXTENSIONS)
	bool m_server_use_peapv1_extensions_request;
	bool m_client_send_peapv1_extensions_response;
#endif //#if defined(USE_EAP_PEAPV1_EXTENSIONS)


#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

	bool m_tunneled_eap_in_ttls;

	u8_t m_ttls_plain_ms_chap_v2_eap_identifier;

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

	bool m_use_eap_expanded_type;

	bool m_wait_plain_eap_success;

	/**
	 * The set_is_valid() function sets the state of the object valid.
	 * The creator of this object calls this function after it is initialized. 
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H void set_is_valid();

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e create_eap_success_failure_in_forward_to_tunnel(
		const eap_am_network_id_c * const receive_network_id,
		const eap_code_value_e forwarded_eap_code,
		const u8_t received_eap_identifier);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e check_ttls_eap_payloads(
		eap_diameter_payloads_c * const payloads,
		eap_ttls_tunneled_message_type_e * const message_type);


	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e ttls_server_handles_pap_response(
		eap_diameter_payloads_c * const payloads,
		const u8_t received_eap_identifier);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e ttls_server_handles_pap_reply_message(
		eap_diameter_payloads_c * const payloads,
		const u8_t received_eap_identifier);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e check_ttls_plain_pap_payloads(
		eap_diameter_payloads_c * const payloads,
		eap_ttls_tunneled_message_type_e * const message_type);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e handle_ttls_plain_pap_payloads(
		eap_diameter_payloads_c * const payloads,
		const eap_ttls_tunneled_message_type_e message_type,
		const u8_t received_eap_identifier);


#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e create_ttls_diameter_avp(
		eap_variable_data_c * const avp,
		const eap_variable_data_c * const data,
		eap_diameter_avp_code_c code,
		const bool include_vendor_id);


	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e check_ttls_plain_mschapv2_payloads(
		eap_diameter_payloads_c * const payloads,
		eap_ttls_tunneled_message_type_e * const message_type);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e handle_ttls_plain_mschapv2_payloads(
		eap_diameter_payloads_c * const payloads,
		const eap_ttls_tunneled_message_type_e message_type,
		const u8_t received_eap_identifier);


	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e ttls_server_handles_ms_chapv2_response(
		eap_diameter_payloads_c * const payloads,
		const u8_t received_eap_identifier);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e ttls_server_handles_ms_chapv2_change_password(
		eap_diameter_payloads_c * const payloads,
		const u8_t received_eap_identifier);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e ttls_client_handles_ms_chapv2_success(
		eap_diameter_payloads_c * const payloads,
		const u8_t received_eap_identifier);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e ttls_client_handles_ms_chapv2_error(
		eap_diameter_payloads_c * const payloads,
		const u8_t received_eap_identifier);


	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e send_ttls_ms_chapv2_packet(
		eap_header_wr_c * const sent_eap_packet);


	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e ttls_tunneled_message_state_process_identity_response(
		eap_header_wr_c * const sent_eap_packet);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e ttls_tunneled_message_state_process_response(
		eap_header_wr_c * const sent_eap_packet);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e ttls_tunneled_message_state_process_change_password_response(
		eap_header_wr_c * const sent_eap_packet);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e ttls_tunneled_message_state_process_identity_request(
		eap_header_wr_c * const sent_eap_packet);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e ttls_tunneled_message_state_process_challenge_request(
		eap_header_wr_c * const sent_eap_packet);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e ttls_tunneled_message_state_process_success_request(
		eap_header_wr_c * const sent_eap_packet);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e ttls_tunneled_message_state_complete_success_request(
		eap_header_wr_c * const sent_eap_packet);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e ttls_tunneled_message_state_process_error_request(
		eap_header_wr_c * const sent_eap_packet);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e ttls_tunneled_message_state_complete_error_request(
		eap_header_wr_c * const sent_eap_packet);


#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)


	/**
	 * This function processes the received packet of TTLS.
	 * @param packet includes the received packet.
	 * @param received_eap_identifier is the EAP-identifier field of the PEAP packet.
	 * @param forwarded_eap_packet includes created EAP-packet that is forwarded to eap_core_c object.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e packet_process_ttls(
		eap_variable_data_c * const received_eap_message,
		const u8_t received_eap_identifier,
		u32_t * const eap_packet_length);

	/**
	 * This function processes the received packet of XP PEAPv0.
	 * @param packet includes the received packet.
	 * @param received_eap_identifier is the EAP-identifier field of the PEAP packet.
	 * @param forwarded_eap_packet includes created EAP-packet that is forwarded to eap_core_c object.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e packet_process_xp_peap_v0(
		eap_variable_data_c * const packet,
		const u8_t received_eap_identifier,
		u32_t * const eap_packet_length);

	/**
	 * This function processes the received packet of PEAPv1.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e packet_process_peap_v1(
		eap_variable_data_c * const received_eap_message,
		const u8_t received_eap_identifier,
		u32_t * const eap_packet_length);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e finish_successfull_authentication_peap_v2(
		const u8_t received_eap_identifier);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e store_nonce_peap_v2(
		const bool is_client_when_true,
		peap_tlv_payloads_c * const peapv2_tlv_payloads);

	/**
	 * This function processes the received packet of PEAPv2.
	 * @param packet includes the received packet.
	 * @param received_eap_identifier is the EAP-identifier field of the PEAP packet.
	 * @param forwarded_eap_packet includes created EAP-packet that is forwarded to eap_core_c object.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e packet_process_peap_v2(
		eap_variable_data_c * const packet,
		const u8_t received_eap_identifier,
		u32_t * const eap_packet_length);

	/**
	 * This function verifies the previously received and parsed packet of PEAPv2.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e verify_tunneled_acknowledge_peap_v2();


	/**
	 * This function sends XP-PEAPv0 protected EAP-Success or EAP-Failure messages.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e send_tunneled_acknowledge_xp_peap_v0(
		const eap_code_value_e result_eap_code,
		const u8_t eap_identifier);

	/**
	 * This function sends PEAPv2 protected EAP-Success or EAP-Failure messages.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e send_tunneled_acknowledge_peap_v2(
		const eap_code_value_e result_eap_code,
		const u8_t eap_identifier);


	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e create_nonce(
		eap_variable_data_c * const nonce);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e create_nonce_peap_v2(
		const bool create_client_nonce_when_true);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e create_compound_mac_key_peap_v2(
		const bool create_client_CMK_when_true);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e create_compound_session_key_peap_v2();


	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e create_crypto_binding_compound_mac(
		const eap_variable_data_c * const peap_v2_CMK,
		const tls_peap_tlv_header_c * const crypto_binding_tlv,
		eap_variable_data_c * const mac_data);


	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e create_result_tlv_message(
		eap_buf_chain_wr_c * const packet,
		const eap_code_value_e result_eap_code,
		const u8_t eap_identifier,
		const tls_peap_tlv_type_e tlv_type);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e create_intermediate_result_tlv_message(
		eap_buf_chain_wr_c * const packet,
		const eap_code_value_e result_eap_code,
		const u8_t eap_identifier);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e create_eap_payload_tlv_message(
		eap_buf_chain_wr_c * const packet,
		const eap_header_wr_c * const sent_eap_packet,
		const u8_t eap_identifier);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e create_crypto_binding_tlv_message(
		eap_buf_chain_wr_c * const packet,
		const eap_code_value_e result_eap_code,
		const u8_t eap_identifier,
		const eap_variable_data_c * const nonce,
		const u8_t received_version);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e create_eap_diameter_avp_message(
		eap_buf_chain_wr_c * const packet,
		const eap_header_wr_c * const sent_eap_packet,
		const u8_t eap_identifier);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e parse_generic_payload(
		const tls_peap_tlv_type_e current_payload,
		const tls_peap_tlv_header_c * const payload,
		peap_tlv_payloads_c * const p_peap_tlv_payloads);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e parse_peap_tlv_payload(
		u8_t * const buffer,
		u32_t * const buffer_length,
		peap_tlv_payloads_c * const peap_tlv_payloads);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H void trace_tunneled_packet(
		eap_const_string prefix,
		const eap_header_wr_c * const eap_packet);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e packet_forward_to_tunnel(
		const eap_am_network_id_c * const receive_network_id,
		eap_header_wr_c * const forwarded_eap_packet,
		const u32_t eap_packet_length);

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

	eap_ttls_tunneled_message_state_e get_ttls_tunneled_message_state();

	void set_ttls_tunneled_message_state(eap_ttls_tunneled_message_state_e ttls_state);

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the tls_application_eap_core_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H virtual ~tls_application_eap_core_c();

	/**
	 * The constructor of the tls_application_eap_core_c class simply initializes the attributes.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 * @param partner is back pointer to object which created this object.
	 * @param eap_core is pointer to EAP-core object.
	 * The tls_application_eap_core_c object sends packets to the network using m_type_partner object.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H tls_application_eap_core_c(
		abs_eap_am_tools_c * const tools,
		eap_core_c * const eap_core,
		const bool free_eap_core,
		const bool is_client_when_true,
		const eap_type_value_e eap_type,
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * This function sets the PEAP version.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H void set_peap_version(
		const peap_version_e peap_version,
		const bool use_tppd_tls_peap,
		const bool use_tppd_peapv1_acknowledge_hack);

	/**
	 * The configure() function is called after the constructor of the 
	 * object is successfully executed. During the function call the object 
	 * could query the configuration. Each derived class must define this function.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e configure();

	/**
	 * The shutdown() function is called before the destructor of the 
	 * object is executed. During the function call the object 
	 * could shutdown the operations, for example cancel timers.
	 * Each derived class must define this function.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e shutdown();

	/**
	 * This function processes the received packet.
	 * @param packet includes the received packet.
	 * @param received_eap_identifier is the EAP-identifier field of the PEAP packet.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e packet_process(
		eap_variable_data_c * const packet,
		const u8_t received_eap_identifier);

	/**
	 * This function indicates the plain text EAP-Success or EAP-Failure packet is received.
	 * @param receive_network_id includes the addresses (network identity) and packet type.
	 * @param received_eap_identifier is the EAP-Identifier of the received EAP-Success packet.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e plain_eap_success_failure_packet_received(
		const eap_am_network_id_c * const receive_network_id,
		const eap_code_value_e received_eap_code,
		const u8_t received_eap_identifier);

	/**
	 * This function indicates the empty Ack packet is received.
	 * This is used in TTLS.
	 * @param receive_network_id includes the addresses (network identity) and packet type.
	 * @param received_eap_identifier is the EAP-Identifier of the received EAP-Success packet.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e empty_ack_packet_received(
		const eap_am_network_id_c * const receive_network_id,
		const u8_t received_eap_identifier);

	/**
	 * This function starts TTLS tunneled authentication.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e start_ttls_tunneled_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const u8_t received_eap_identifier);

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H bool get_is_valid();

	/**
	 * This function must reset the state of object to same as 
	 * state was after the configure() function call.
	 * If object reset succeeds this function must return eap_status_ok.
	 * If object reset fails this function must return corresponding error status.
	 * @return This function returns the status of reset operation.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e reset();


	/**
	 * This function starts the tunneled EAP-type within PEAP.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e start_peap_tunneled_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const bool is_client_when_true,
		const u8_t received_eap_identifier,
		const tls_session_type_e tls_session_type,
		const bool tls_peap_server_authenticates_client_action);

	/// @see abs_eap_core_c::packet_send().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e packet_send(
		const eap_am_network_id_c * const network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length);

	/// @see abs_eap_core_c::get_header_offset().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length);

	/// @see abs_eap_core_c::load_module().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e /* tunneling_type */,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id);

	/// @see abs_eap_core_c::unload_module().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e unload_module(const eap_type_value_e type);

	/// @see abs_eap_core_c::restart_authentication().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e restart_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const bool is_client_when_true,
		const bool force_clean_restart,
		const bool from_timer = false);

	/// @see abs_eap_core_c::packet_data_crypto_keys().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e packet_data_crypto_keys(
		const eap_am_network_id_c * const send_network_id,
		const eap_master_session_key_c * const master_session_key
		);

	/// @see abs_eap_core_c::read_configure().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	/// @see abs_eap_core_c::write_configure().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	/// @see abs_eap_core_c::state_notification().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H void state_notification(
		const abs_eap_state_notification_c * const state);

	/// @see abs_eap_core_c::asynchronous_init_remove_eap_session().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e asynchronous_init_remove_eap_session(
		const eap_am_network_id_c * const send_network_id);

	/// @see abs_eap_core_c::set_timer().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e set_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id, 
		void * const data,
		const u32_t p_time_ms);

	/// @see abs_eap_core_c::cancel_timer().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e cancel_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id);

	/// @see abs_eap_core_c::check_is_valid_eap_type().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e check_is_valid_eap_type(const eap_type_value_e eap_type);

	/// @see abs_eap_core_c::get_eap_type_list().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e get_eap_type_list(
		eap_array_c<eap_type_value_e> * const eap_type_list);

	/// @see tls_base_application_c::get_application_partner().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H abs_tls_base_application_c * get_application_partner();

	/// @see tls_base_application_c::set_application_partner().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e set_application_partner(abs_tls_base_application_c * const partner);

	/// @see tls_base_application_c::peap_tunnel_ready().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e peap_tunnel_ready();

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e add_rogue_ap(eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list);

	// This is documented in tls_base_application_c::set_session_timeout().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e set_session_timeout(
		const u32_t session_timeout_ms);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H void set_tunneled_state(
		const tls_session_type_e tls_session_type);

	// This is commented in tls_base_record_c::read_authority_identity().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e read_authority_identity(eap_variable_data_c * const authority_identity_payload);

	// This is commented in tls_base_record_c::save_user_authorization_pac_opaque().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e save_user_authorization_pac_opaque(const tls_extension_c * const extension);

	// This is commented in tls_base_record_c::query_tunnel_PAC().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e query_tunnel_PAC(
		const eap_fast_variable_data_c * const in_A_ID_TLV);

	// This is commented in tls_base_record_c::cancel_query_tunnel_PAC().
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e cancel_query_tunnel_PAC();

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e complete_query_ttls_pap_username_and_password(
		const eap_variable_data_c * const ttls_pap_username,
		const eap_variable_data_c * const ttls_pap_password,
		const eap_status_e query_result);

	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e complete_verify_ttls_pap_username_and_password(
		const eap_status_e authentication_result,
		const eap_variable_data_c * const ttls_pap_reply_message);

	/**
	 * This function is called when TLS-Alert message is received.
	 * Adaptation module could record this event.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_EAP_CORE_H eap_status_e alert_received(
		const tls_alert_level_e alert_level,
		const tls_alert_description_e alert_description);

	//--------------------------------------------------
}; // class tls_application_eap_core_c

#endif //#if !defined(_TLS_APPLICATION_EAP_CORE_H_)

//--------------------------------------------------



// End.
