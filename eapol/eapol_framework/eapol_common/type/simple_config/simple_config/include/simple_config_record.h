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

#if !defined(_SIMPLE_CONFIG_RECORD_H_)
#define _SIMPLE_CONFIG_RECORD_H_


#include "abs_simple_config_am_services.h"
#include "simple_config_base_record.h"
#include "eap_array_algorithms.h"
#include "simple_config_types.h"
#include "simple_config_completion.h"
#include "simple_config_types.h"
#include "simple_config_attribute_type.h"
#include "simple_config_payloads.h"
#include "simple_config_message.h"
#include "eap_am_network_id.h"
#include "eap_automatic_variable.h"
#include "eap_master_session_key.h"
#include "abs_eap_base_timer.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_SIMPLE_CONFIG_RECORD_H)
	#define EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_RECORD_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H 
	#define EAP_C_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H 
	#define EAP_FUNC_EXPORT_SIMPLE_CONFIG_RECORD_H 
	#define EAP_C_FUNC_EXPORT_SIMPLE_CONFIG_RECORD_H 
#elif defined(EAP_EXPORT_SIMPLE_CONFIG_RECORD_H)
	#define EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_RECORD_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_SIMPLE_CONFIG_RECORD_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_SIMPLE_CONFIG_RECORD_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_RECORD_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_SIMPLE_CONFIG_RECORD_H 
	#define EAP_C_FUNC_EXPORT_SIMPLE_CONFIG_RECORD_H 
#endif
// End: added by script change_export_macros.sh.



class abs_simple_config_base_record_c;
class abs_eap_am_tools_c;
class eap_am_network_id_c;
class simple_config_record_header_c;
class simple_config_am_services_c;
class abs_crypto_cbc_block_algorithm_c;
class abs_crypto_block_algorithm_c;
class abs_crypto_stream_algorithm_c;

//--------------------------------------------------------------------

/**
 * This is the timer ID used with abs_eap_am_tools_c::set_timer() and abs_eap_am_tools_c::cancel_timer().
 */
enum simple_config_record_timer_id_e
{
	SIMPLE_CONFIG_RECORD_ERROR_MESSAGE_RECEIVED_ID, ///< This is timer ID after a Failure message is handled.
	SIMPLE_CONFIG_RECORD_M2D_RECEIVED_ID, ///< This is timer ID after a M2D messages are used.
};


enum simple_config_record_timer_timeouts_e
{
	/**
	 * This is time after a Failure message is handled.
	 */
	SIMPLE_CONFIG_RECORD_ERROR_MESSAGE_RECEIVED_TIMEOUT = 15000ul,
};


//--------------------------------------------------------------------


/**
 * The simple_config_record_c class implements simple_config_base_record_c.
 * See more detailed design and architecture document <a href="../../type/simple_config/documentation/EAP_SIMPLE_CONFIG.doc">EAP_SIMPLE_CONFIG.doc</a>
 * and <a href="../../type/simple_config/documentation/rfc2246.txt">RFC 2246</a>.
 */
class EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_RECORD_H simple_config_record_c
: public simple_config_base_record_c
, public abs_simple_config_am_services_c
, public abs_eap_base_timer_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class. @see abs_eap_am_tools_c.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is pointer to adaptation module of SIMPLE_CONFIG.
	simple_config_am_services_c * m_am_simple_config_services;

	/// This flag tells whether the m_am_simple_config_services must be freed in destructor.
	const bool m_free_am_simple_config_services;


	/// This object includes pending asyncronous actions or it may be empty.
	/// The check_sent_simple_config_message() function call will check and complete pending actions.
	eap_array_c<simple_config_completion_c> m_completion_queue;


	/// This object stores all received M2D payloads. If nothing else is received
	/// adaptation layer could show this information to user.
	eap_array_c<simple_config_payloads_c> m_M2D_payloads;


	/// This object includes received message.
	simple_config_message_c m_received_simple_config_message;

	/// This object includes all received payloads.
	simple_config_payloads_c m_received_payloads;


	/// This object includes the previous sent message.
	/// The send message will be generated from this.
	simple_config_message_c m_previous_simple_config_message;

	/// This object includes the new created message.
	/// The send message will be generated from this.
	simple_config_message_c m_new_simple_config_message;
	
	/// This object cotains the type of the new message.
    /// The type will be indicated to the lower layer for adding correct Op-Code.
	simple_config_Message_Type_e m_current_simple_config_message_type;

	/// This object includes Enrollee Nonce.
	eap_variable_data_c m_enrollee_nonce;

	/// This object includes Enrollee MAC.
	eap_variable_data_c m_enrollee_mac;

	/// This object includes Registrar Nonce.
	eap_variable_data_c m_registrar_nonce;


	/// This object is the Simple Config device password.
	eap_variable_data_c m_device_password;

	/// This object is the Simple Config PSK1.
	eap_variable_data_c m_PSK1;

	/// This object is the Simple Config PSK2.
	eap_variable_data_c m_PSK2;


	/// This object is the Simple Config E-SNonce1 (E-S1).
	eap_variable_data_c m_E_SNonce1;

	/// This object is the Simple Config E-SNonce2 (E-S2).
	eap_variable_data_c m_E_SNonce2;

	/// This object is the Simple Config E-Hash1.
	eap_variable_data_c m_EHash1;

	/// This object is the Simple Config E-Hash1.
	eap_variable_data_c m_EHash2;


	/// This object is the Simple Config R-SNonce1 (R-S1).
	eap_variable_data_c m_R_SNonce1;

	/// This object is the Simple Config R-SNonce2 (R-S2).
	eap_variable_data_c m_R_SNonce2;

	/// This object is the Simple Config R-Hash1.
	eap_variable_data_c m_RHash1;

	/// This object is the Simple Config R-Hash1.
	eap_variable_data_c m_RHash2;


	/// This object includes Diffie-Hellman private key of this SIMPLE_CONFIG end point.
	eap_variable_data_c m_own_private_dhe_key;

	/// This object includes Diffie-Hellman public key of this SIMPLE_CONFIG end point.
	eap_variable_data_c m_own_public_dhe_key;

	/// This object includes Diffie-Hellman public key of other SIMPLE_CONFIG end point.
	eap_variable_data_c m_peer_public_dhe_key;

	/// This object includes Diffie-Hellman shared key of the SIMPLE_CONFIG session.
	eap_variable_data_c m_shared_dh_key;

	/// This object includes Diffie-Hellman prime of the SIMPLE_CONFIG session.
	eap_variable_data_c m_dhe_prime;

	/// This object includes Diffie-Hellman group generator of the SIMPLE_CONFIG session.
	eap_variable_data_c m_dhe_group_generator;

	/// This object includes Simple Config KDK.
	eap_variable_data_c m_kdk;

	/// These are the additional keys of Simple Config.
	eap_variable_data_c m_auth_key;
	eap_variable_data_c m_key_wrap_key;
	eap_variable_data_c m_EMSK;

	eap_variable_data_c m_SSID;

	/// This object includes signed HASH. This is needed to store asyncronously completed signature creation.
	eap_variable_data_c m_signed_message_hash;

	/// This is the full NAI of the client.
	eap_variable_data_c m_NAI;

	/// This is the realm part of the NAI of the client.
	eap_variable_data_c m_NAI_realm;

	/// This is network identity of the sent packet from this authentication session.
	eap_am_network_id_c m_send_network_id;

#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)
	eap_variable_data_c m_network_key;
	simple_config_Authentication_Type_e m_authentication_type;
#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

	/// This variable stored the internal state of SIMPLE_CONFIG-session. See simple_config_state_e.
	simple_config_state_e m_simple_config_state;

	/// This variable stores the first error on handshake.
	eap_status_e m_handshake_error;

	/// This object stores the universally unique identifier of Enrollee.
	eap_variable_data_c m_UUID_E;

	/// This object stores the universally unique identifier of Registrar.
	eap_variable_data_c m_UUID_R;

	/// These are the RF-Bands this entity supports.
	simple_config_RF_Bands_e m_Rf_Bands;

	/// This object includes the MAC address of the new configuration.
	eap_variable_data_c m_MAC_address;

	/// This variable stores the Device Password ID that this entity uses.
	simple_config_Device_Password_ID_e m_local_Device_Password_ID;

	/// This variable stores the Device Password ID that other entity uses.
	simple_config_Device_Password_ID_e m_received_Device_Password_ID;

	/// This object stores the new password the Enrollee should use. This is optional.
	eap_variable_data_c m_new_password;

	/// This object stores the new Device Password ID the Enrollee should use. This is optional.
	simple_config_Device_Password_ID_e m_new_Device_Password_ID;

	/// This is the timeout in milli seconds after the error message is processed.
	/// This allows correct message to be processed before session is terminated.
	u32_t m_error_message_received_timeout;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/// This indicates whether this object is client (true) or server (false).
	const bool m_is_client;

	/// This flag tells whether messages could be send in the check_sent_simple_config_message() function.
	bool m_allow_message_send;

	/// This flag prevents recursive calls of the completion_action_check() function.
	bool m_already_in_completion_action_check;

	/// This flag tells whether this function call is pending (true value).
	/// After this function call is completed with appropriate completion function flag is set to false value.
	bool m_pending_query_network_and_device_parameters;

	/// This flag tells whether this instance is test version (true) or real version (false).
	/// Test version allows many subsequent SIMPLE_CONFIG-sessions.
	bool m_simple_config_test_version;

	/// The flag prevents multiple call of generate_key_material() function.
	bool m_key_material_generated;

	/// This flag tells whether the check_sent_simple_config_message() must send SIMPLE_CONFIG-alert message (true) or not (false).
	/// This flag is set after the SIMPLE_CONFIG-alert message is generated. This flag forses send of the SIMPLE_CONFIG-alert message.
	bool m_force_simple_config_message_send;

	/// This flag tells whether the shutdown() function was called (true) or not (false).
	bool m_shutdown_was_called;

	/// This flag tells whether the SIMPLE_CONFIG_RECORD_M2D_RECEIVED_ID timeout is active (true) or not (false).
	bool m_M2D_received_timeout_active;

	//--------------------------------------------------

	/**
	 * The set_is_valid() function sets the state of the object valid.
	 * The creator of this object calls this function after it is initialized. 
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H void set_is_valid();


	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e add_common_attributes(
		simple_config_payloads_c * const payloads,
		const simple_config_Message_Type_e message_type,
		const bool add_enrollee_nonce,
		const bool add_registrar_nonce);


	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e send_M1(
		const simple_config_payloads_c * const network_and_device_parameters);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e send_M3();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e send_M5();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e send_M7();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e send_WSC_ACK();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e send_WSC_NACK();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e send_WSC_Done();


#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e send_M2(
		const simple_config_payloads_c * const network_and_device_parameters);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e send_M2D(
		const simple_config_payloads_c * const network_and_device_parameters);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e send_M4();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e send_M6();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e send_M8();

#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)


	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e process_M2(
		const simple_config_payloads_c * const payloads);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e process_M2D(
		const simple_config_payloads_c * const payloads);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e process_M4(
		const simple_config_payloads_c * const payloads);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e process_M6(
		const simple_config_payloads_c * const payloads);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e process_M8(
		const simple_config_payloads_c * const payloads);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e process_WSC_ACK(
		const simple_config_payloads_c * const payloads);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e process_WSC_NACK(
		const simple_config_payloads_c * const payloads);

#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e process_M1(
		const simple_config_payloads_c * const payloads);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e process_M3(
		const simple_config_payloads_c * const payloads);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e process_M5(
		const simple_config_payloads_c * const payloads);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e process_M7(
		const simple_config_payloads_c * const payloads);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e process_WSC_DONE(
		const simple_config_payloads_c * const payloads);

#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H void send_error_notification(const eap_status_e error);


	/**
	 * This function processes received SIMPLE_CONFIG attributes.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e process_simple_config_attributes(
		const simple_config_payloads_c * const payloads);

	/**
	 * This function processes received SIMPLE_CONFIG message.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e process_simple_config_message();


	/**
	 * This function initialises timeout for received erroneous message.
	 * If no correct message is received before this timeout the authentication
	 * is terminated.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e initalize_error_message_timeout();

	/**
	 * This function cancels timeout for received erroneous message.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e cancel_error_message_timeout();


	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e initialize_M2D_received_timeout();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e cancel_M2D_received_timeout();


	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e timer_expired(
		const u32_t id,
		void * data);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e timer_delete_data(
		const u32_t id,
		void * data);

	/**
	 * This function verifies the Authenticator of received SIMPLE_CONFIG message.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e verify_nonces_and_authenticator(
		const eap_variable_data_c * const auth_key,
		const eap_variable_data_c * const registrar_nonce,
		const eap_variable_data_c * const enrollee_nonce,
		const simple_config_payloads_c * const payloads,
		const bool check_enrollee_nonce,
		const bool check_registrar_nonce,
		const bool check_authenticator);

	/**
	 * This function checks whether all pending queries are completed.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e are_pending_queries_completed();

	/**
	 * This function indicates state to lower layer.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e indicate_state_to_lower_layer(
		const simple_config_state_e indicated_state);

	/**
	 * This function indicates all message processed to lower layer.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e indicate_messages_processed();

	/**
	 * This function combines SIMPLE_CONFIG-protocols data to a buffer and sends SIMPLE_CONFIG-message.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e send_simple_config_message();

	/**
	 * This function checks all queries are completed.
	 * If all queries are completed this function send the pending LS-messages.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e check_sent_simple_config_message();

	/**
	 * This function generates ephemeral Diffie-Hellman keys.
	 * Keys are stored to m_own_private_dhe_key and m_own_public_dhe_key.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e generate_dhe_keys();

	/**
	 * This function generates ephemeral Diffie-Hellman shared secret.
	 * Shared secret is stored to dhe_shared_secret.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e generate_dhe_shared_secret(
		const eap_variable_data_c * const registrar_public_key_data,
		eap_variable_data_c * const dhe_shared_secret);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e generate_nonce(
		eap_variable_data_c * const nonce,
		const u32_t nonce_length);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e generate_erhash(
		const bool verify,
		const eap_variable_data_c * const half_of_device_password,
		const eap_variable_data_c * const PKE,
		const eap_variable_data_c * const PKR,
		eap_variable_data_c * const PSKn,
		eap_variable_data_c * const ERSn,
		eap_variable_data_c * const ERHash);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e generate_er_hashs(
		const bool verify,
		const eap_variable_data_c * const device_password,
		const eap_variable_data_c * const PKE,
		const eap_variable_data_c * const PKR,
		eap_variable_data_c * const PSK1,
		eap_variable_data_c * const ER_S1,
		eap_variable_data_c * const ER_Hash1,
		eap_variable_data_c * const PSK2,
		eap_variable_data_c * const ER_S2,
		eap_variable_data_c * const ER_Hash2);


	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e keyed_hmac(
		const eap_variable_data_c * const key,
		const eap_variable_data_c * const input,
		eap_variable_data_c * const output);

	/**
	 * This function generates KDK of Simple Config.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e generate_kdk(
		const eap_variable_data_c * const dhe_shared_secret,
		const eap_variable_data_c * const nonce_1,
		const eap_variable_data_c * const enrollee_mac,
		const eap_variable_data_c * const nonce_2,
		eap_variable_data_c * const kdk);

	/**
	 * This is key derivation function of Simple Config.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e key_derivation_function(
		const eap_variable_data_c * const key,
		const eap_variable_data_c * const personalization_string,
		const u32_t total_key_bits,
		eap_variable_data_c * const result);

	/**
	 * This function derives additional keys of Simple Config.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e derive_additional_keys(
		const eap_variable_data_c * const kdk,
		eap_variable_data_c * const auth_key,
		eap_variable_data_c * const key_wrap_key,
		eap_variable_data_c * const EMSK);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e generate_authenticator(
		const eap_variable_data_c * const received_simple_config_message,
		const eap_variable_data_c * const new_simple_config_message_data,
		eap_variable_data_c * const authenticator);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e add_authenticator_attribute(
		simple_config_message_c * const received_simple_config_message,
		simple_config_message_c * const new_simple_config_message);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e encrypt_payloads(
		const eap_variable_data_c * const auth_key,
		const eap_variable_data_c * const key_wrap_key,
		simple_config_payloads_c * const plaintext_payloads,
		simple_config_variable_data_c * const encrypted_settings);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e decrypt_payloads(
		const eap_variable_data_c * const auth_key,
		const eap_variable_data_c * const key_wrap_key,
		simple_config_variable_data_c * const encrypted_settings,
		simple_config_payloads_c * const plaintext_payloads);

	/**
	 * This function adds new completion action to the end of the m_completion_queue.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e completion_action_add(
		simple_config_completion_action_e action);

	/**
	 * This function verifies all completion actions are completed.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e completion_action_clenup();

	/**
	 * This function checks and completes completion actions.
	 * This function could return eap_status_pending_request if the
	 * first completion action cannot be completed yet.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e completion_action_check();

	/**
	 * This function sets the state of SIMPLE_CONFIG.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H simple_config_state_e get_state() const;

	/**
	 * This function gets the state of SIMPLE_CONFIG.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H void set_state(const simple_config_state_e state);

	/**
	 * This function verified the current state of SIMPLE_CONFIG and parameter state are equal.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H bool verify_state(const simple_config_state_e state);

	eap_status_e fix_incorrect_network_key(
		eap_variable_data_c * const network_key, 
		const simple_config_Authentication_Type_e authentication_type);

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the simple_config_record_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H virtual ~simple_config_record_c();

	/**
	 * The constructor of the simple_config_record_c class simply initializes the attributes.
	 * The simple_config_record_c object sends packets to the network using simple_config_base_record_c::get_type_partner() object.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H simple_config_record_c(
		abs_eap_am_tools_c * const tools, ///< tools is pointer to the tools class. @see abs_eap_am_tools_c.
		simple_config_am_services_c * const am_simple_config_services, ///< This is pointer to adaoptation module of SIMPLE_CONFIG.
		const bool free_am_simple_config_services,
		const bool is_client_when_true, ///< Indicates whether this is client (true) or server (false).
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * The configure() function is called after the constructor of the 
	 * object is successfully executed. During the function call the object 
	 * could query the configuration. Each derived class must define this function.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e configure();

	/**
	 * The shutdown() function is called before the destructor of the 
	 * object is executed. During the function call the object 
	 * could shutdown the operations, for example cancel timers.
	 * Each derived class must define this function.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e shutdown();

	/**
	 * This function sets the NAI realm.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e set_nai_realm(
		const eap_variable_data_c * const NAI_realm ///< This is the full NAI realm.
		);

	// This is commented in abs_simple_config_base_application_c.
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	// This is commented in abs_simple_config_base_application_c.
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	/**
	 * This function sends starts EAP-SIMPLE_CONFIG/PEAP after a start message is received.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e start_simple_config_authentication(
		const eap_variable_data_c * const NAI ///< This is the full NAI of the client.
		);

	/**
	 * This function processes the received packet.
	 * @param simple_config_packet includes the buffer of the whole reassembled SIMPLE_CONFIG-packet.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e packet_process(
		eap_variable_data_c * const simple_config_packet,
		const u8_t received_eap_identifier);

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H bool get_is_valid();

	/**
	 * This function must reset the state of object to same as 
	 * state was after the configure() function call.
	 * If object reset succeeds this function must return eap_status_ok.
	 * If object reset fails this function must return corresponding error status.
	 * @return This function returns the status of reset operation.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e reset();

	// This is commented in abs_simple_config_am_services_c::complete_query_network_and_device_parameters().
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_RECORD_H eap_status_e complete_query_network_and_device_parameters(
		const simple_config_state_e state,
		simple_config_payloads_c * const network_and_device_parameters,
		const eap_status_e completion_status);

	//--------------------------------------------------
}; // class simple_config_record_c

#endif //#if !defined(_SIMPLE_CONFIG_RECORD_H_)

//--------------------------------------------------



// End.
