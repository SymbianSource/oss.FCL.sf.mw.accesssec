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

#if !defined(_ABS_TLS_BASE_APPLICATION_H_)
#define _ABS_TLS_BASE_APPLICATION_H_

#if defined(USE_FAST_EAP_TYPE)
	#include "eap_fast_tlv_header.h"
#endif //#if defined(USE_FAST_EAP_TYPE)

#include "tls_record_header.h"
#include "tls_handshake_header.h"

class eap_buf_chain_wr_c;
class eap_variable_data_c;
class abs_eap_state_notification_c;
class abs_eap_base_timer_c;
class abs_eap_base_type_c;
class eap_base_type_c;
class eap_network_id_selector_c;
class eap_fast_variable_data_c;


/// The class is the interface to partner class of the tls_base_application_c class.
/// This declares the pure virtual member functions tls_base_application_c class could call.
class EAP_EXPORT abs_tls_base_application_c
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the abs_tls_base_application_c class does nothing special.
	 */
	virtual ~abs_tls_base_application_c()
	{
	}

	/**
	 * The constructor of the abs_tls_base_application_c class does nothing special.
	 */
	abs_tls_base_application_c()
	{
	}

	/**
	 * The derived class could send packets to partner class with this function.
	 * @param sent_packet includes the buffer for the whole packet and initialized 
	 * TLS-packet in correct offset.
	 * @param header_offset is offset of the TLS-header within the sent_packet.
	 * @param data_length is length in bytes of the TLS-packet.
	 * @param buffer_length is length in bytes of the whole packet buffer.
	 */
	virtual eap_status_e packet_send(
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length) = 0;

	/**
	 * The get_header_offset() function obtains the header offset of PEAP-packet.
	 * @param MTU_length is pointer to variable to store the maximum transfer unit (MTU).
	 * MTU is the maximum PEAP-packet length in bytes
	 * @param trailer_length is pointer to the variable to store length
	 * of trailer needed by lower levels.
	 * @return Function returns the offset of PEAP-header.
	 *
	 * The needed buffer length is ((offset) + (PEAP-packet length) + (trailer)) bytes.
	 * Each layer adds the length of the header to offset.
	 * Each layer removes the length of the header and trailer from MTU.
	 *
	 * Now some ascii graphics follows.
	 * @code
	 * |<-------------------------buffer length----------------------------------------->|
	 * |                                                                                 |
	 * |                                  +-----+--------------------------+             |
	 * |                                  | EAP | data                     |             |
	 * |                                  +-----+--------------------------+             |
	 * |<----offset---------------------->|<----MTU----------------------->|<--trailer-->|
	 * |                                  |                                |             |
	 * |                           +------+--------------------------------+             |
	 * |                           | PEAP | data                           |             |
	 * |                           +------+--------------------------------+             |
	 * |<----offset--------------->|<----MTU------------------------------>|<--trailer-->|
	 * |                           |                                       |             |
	 * |                     +-----+---------------------------------------+             |
	 * |                     | EAP |  data                                 |             |
	 * |                     +-----+---------------------------------------+             |
	 * |<----offset--------->|<----MTU------------------------------------>|<--trailer-->|
	 * |                     |                                             |             |
	 * |             +-------+---------------------------------------------+             |
	 * |             | EAPOL |  data                                       |             |
	 * |             +-------+---------------------------------------------+             |
	 * |<--offset--->|<----MTU-------------------------------------------->|<--trailer-->|
	 * |             |                                                     |             |
	 * +-------------+-----------------------------------------------------+-------------+
	 * |  ETHERNET   |  data                                               |  trailer    |
	 * +-------------+-----------------------------------------------------+-------------+
	 * |<----MTU------------------------------------------------------------------------>|
	 * @endcode
	 *
	 */
	virtual u32_t get_header_offset(
		u32_t * const MTU_length,
		u32_t * const trailer_length) = 0;

	/**
	 * This function restarts authentication to receive_network_id.
	 * @param receive_network_id is network identity of target.
	 * @param is_client_when_true indicates whether this object should act as a client (true)
	 * or server (false), in terms of EAP-protocol whether this network entity is EAP-supplicant (true)
	 * or EAP-authenticator (false).
	 */
	virtual eap_status_e restart_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const bool is_client_when_true,
		const bool force_clean_restart,
		const bool from_timer) = 0;

	/**
	 * The read_configure() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 * 
	 * EAP-type should store it's parameters to an own database. The own database should be accessed
	 * through adaptation module of EAP-type. See eap_am_type_tls_peap_simulator_c::type_configure_read.
	 */
	virtual eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	/**
	 * The write_configure() function writes the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the action to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 * 
	 * EAP-type should store it's parameters to an own database. The own database should be accessed
	 * through adaptation module of EAP-type. See eap_am_type_tls_peap_simulator_c::type_configure_write.
	 */
	virtual eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	/**
	 * This is notification of internal state transition.
	 * This is used for notifications, debugging and protocol testing.
	 * The primal notifications are eap_state_variable_e::eap_state_authentication_finished_successfully
	 * and eap_state_variable_e::eap_state_authentication_terminated_unsuccessfully. EAP-type MUST send these
	 * two notifications to lower layer.
	 * These two notifications are sent using EAP-protocol layer (eap_protocol_layer_e::eap_protocol_layer_eap).
	 * See also eap_state_notification_c.
	 */
	virtual void state_notification(
		const abs_eap_state_notification_c * const state) = 0;

	/**
	 * The set_timer() function initializes timer to be elapsed after p_time_ms milliseconds.
	 * @param initializer is pointer to object which timer_expired() function will
	 * be called after timer elapses.
	 * @param id is identifier which will be returned in timer_expired() function.
	 * The user selects and interprets the id for this timer.
	 * @param data is pointer to any user selected data which will be returned in timer_expired() function.
	 *
	 * Adaptation module internally implements the timer.
	 */
	virtual eap_status_e set_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id, 
		void * const data,
		const u32_t p_time_ms) = 0;

	/**
	 * The cancel_timer() function cancels the timer id initiated by initializer.
	 *
	 * Adaptation module internally implements the timer.
	 */
	virtual eap_status_e cancel_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id) = 0;

	/**
	 * This is needed by PEAP type.
	 * The load_module() function function indicates the lower level to
	 * load new module of EAP-type.
	 * @param type is the requested EAP-type.
	 * @param partner is pointer to the caller object.
	 * The partner of the new created EAP-type object is the caller object.
	 * @param eap_type is a pointer to a pointer of EAP-type object.
	 * Adaptation module sets eap_type pointer to created EAP-type object.
	 * @param is_client_when_true parameter indicates whether the network entity should
	 * act as a client (true) or server (false), in terms of EAP-protocol whether
	 * this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	 */
	virtual eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e /* tunneling_type */,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id) = 0;

	/**
	 * This is needed by PEAP type.
	 * The unload_module() function unloads the module of a EAP-type. 
	 * @param type is the requested EAP-type.
	 */
	virtual eap_status_e unload_module(const eap_type_value_e type) = 0;

	/**
	 * Note this function is just an example. Parameters will change later.
	 * The packet_data_crypto_keys() function gives the generated keys to lower level.
	 * After EAP-authentication has generated the keys it calls this function
	 * to offer the keys to lower level.
	 * @see abs_eap_base_type_c::packet_data_crypto_keys().
	 */
	virtual eap_status_e packet_data_crypto_keys(
		const eap_am_network_id_c * const send_network_id,
		const eap_master_session_key_c * const master_session_key
		) = 0;

	/**
	 * This is needed by PEAP type.
	 * This function queries the validity of EAP-type.
	 * Lower layer should return eap_status_ok if this EAP-type is supported.
	 */
	virtual eap_status_e check_is_valid_eap_type(const eap_type_value_e eap_type) = 0;

	/**
	 * This function queries the list of supported EAP-types.
	 * Lower layer should return eap_status_ok if this call succeeds.
	 * @param eap_type_list will include the list of supported EAP-types. Each value in list
	 * is type of u32_t and represent one supported EAP-type. List consists of subsequent u32_t type values.
	 */
	virtual eap_status_e get_eap_type_list(
		eap_array_c<eap_type_value_e> * const eap_type_list) = 0;

	/**
	 * The get_tls_master_secret() function copies the EAP-TLS master session key.
	 */
	virtual eap_status_e get_eap_tls_master_session_key(
		eap_variable_data_c * const eap_tls_master_session_key,
		eap_variable_data_c * const mschapv2_challenges
		) = 0;

	/**
	 * This function gets the TTLS implicit challenge from TLS.
	 */
	virtual eap_status_e get_ttls_implicit_challenge(
		eap_variable_data_c * const ttls_implicit_challenge,
		const u32_t required_ttls_implicit_challenge_length) = 0;

	virtual eap_status_e add_rogue_ap(eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list) = 0;

	/**
	 * The set_session_timeout() function changes the session timeout timer to be elapsed after session_timeout_ms milliseconds.
	 */
	virtual eap_status_e set_session_timeout(
		const u32_t session_timeout_ms) = 0;

#if defined(USE_FAST_EAP_TYPE)

	virtual eap_status_e complete_query_tunnel_PAC(
		const eap_status_e in_completion_status,
		const eap_fast_pac_type_e in_pac_type,
		const eap_fast_variable_data_c * const in_tunnel_PAC_key_tlv,
		const eap_fast_variable_data_c * const in_tunnel_PAC_opaque_tlv) = 0;

#endif //#if defined(USE_FAST_EAP_TYPE)


	virtual eap_status_e query_ttls_pap_username_and_password(
		const eap_variable_data_c * const reply_message) = 0;

	virtual eap_status_e verify_ttls_pap_username_and_password(
		const eap_variable_data_c * const user_name,
		const eap_variable_data_c * const user_password) = 0;

	// This is used in EAP-FAST to see the next TLS-handshake message protocol.
	virtual tls_record_protocol_e get_next_tls_record_message_protocol() = 0;

	// This is used in EAP-FAST to see the next TLS-handshake message type.
	virtual tls_handshake_type_e get_next_tls_handshake_message_type() = 0;

	//--------------------------------------------------
}; // class abs_tls_base_application_c

#endif //#if !defined(_ABS_TLS_BASE_APPLICATION_H_)

//--------------------------------------------------



// End.
