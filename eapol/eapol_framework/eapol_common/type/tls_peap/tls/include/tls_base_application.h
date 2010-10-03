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
* %version: 23.1.2 %
*/

#if !defined(_TLS_BASE_APPLICATION_H_)
#define _TLS_BASE_APPLICATION_H_

#include "tls_peap_types.h"
#include "eap_header.h"
#include "eap_protocol_layer.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_TLS_BASE_APPLICATION_H)
	#define EAP_CLASS_VISIBILITY_TLS_BASE_APPLICATION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_TLS_BASE_APPLICATION_H 
	#define EAP_C_FUNC_VISIBILITY_TLS_BASE_APPLICATION_H 
	#define EAP_FUNC_EXPORT_TLS_BASE_APPLICATION_H 
	#define EAP_C_FUNC_EXPORT_TLS_BASE_APPLICATION_H 
#elif defined(EAP_EXPORT_TLS_BASE_APPLICATION_H)
	#define EAP_CLASS_VISIBILITY_TLS_BASE_APPLICATION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_TLS_BASE_APPLICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_BASE_APPLICATION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_TLS_BASE_APPLICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_TLS_BASE_APPLICATION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_TLS_BASE_APPLICATION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_TLS_BASE_APPLICATION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_BASE_APPLICATION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_TLS_BASE_APPLICATION_H 
	#define EAP_C_FUNC_EXPORT_TLS_BASE_APPLICATION_H 
#endif
// End: added by script change_export_macros.sh.


class abs_tls_base_application_c;
class abs_eap_am_tools_c;
class eap_am_network_id_c;
class tls_record_header_c;
class abs_eap_state_notification_c;
class tls_extension_c;
class eap_fast_variable_data_c;


/// The tls_base_application_c class declares pure virtual functions 
/// a user class of TLS-application class could call.
class EAP_CLASS_VISIBILITY_TLS_BASE_APPLICATION_H tls_base_application_c
{
private:
	//--------------------------------------------------

	/**
	 * The set_is_valid() function sets the state of the object valid.
	 * The creator of this object calls this function after it is initialized. 
	 */
	virtual void set_is_valid() = 0;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * Destructor does nothing special.
	 */
	EAP_FUNC_VISIBILITY_TLS_BASE_APPLICATION_H virtual ~tls_base_application_c();

	/**
	 * Application partner is object below the tls_base_application_c object.
	 * @return The get_application_partner() function returns the pointer to the partner class.
	 */
	virtual abs_tls_base_application_c * get_application_partner() = 0;

	/**
	 * This function sets pointer to the partner class.
	 * The partner that instantiates object of this type must call this function
	 * to tell pointer to partner of this object.
	 */
	virtual eap_status_e set_application_partner(abs_tls_base_application_c * const partner) = 0;

	/**
	 * This function sets the PEAP version.
	 */
	virtual void set_peap_version(
		const peap_version_e peap_version,
		const bool use_tppd_tls_peap,
		const bool use_tppd_peapv1_acknowledge_hack) = 0;

	/**
	 * The configure() function is called after the constructor of the 
	 * object is successfully executed. During the function call the object 
	 * could query the configuration. Each derived class must define this function.
	 */
	virtual eap_status_e configure() = 0;

	/**
	 * The shutdown() function is called before the destructor of the 
	 * object is executed. During the function call the object 
	 * could shutdown the operations, for example cancel timers.
	 * Each derived class must define this function.
	 */
	virtual eap_status_e shutdown() = 0;

	/**
	 * This function starts the tunneled EAP-type within PEAP.
	 */
	virtual eap_status_e start_peap_tunneled_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const bool is_client_when_true,
		const u8_t received_eap_identifier,
		const tls_session_type_e tls_session_type,
		const bool tls_peap_server_authenticates_client_action) = 0;

	/**
	 * This function processes the received packet.
	 * @param receive_network_id carries the addresses and type of the received packet.
	 * @param packet includes the buffer of the whole reassembled EAP-packet.
	 */
	virtual eap_status_e packet_process(
		eap_variable_data_c * const packet,
		const u8_t received_eap_identifier) = 0;

	/**
	 * This function indicates the plain text EAP-Success or EAP-Failure packet is received.
	 * @param receive_network_id includes the addresses (network identity) and packet type.
	 * @param received_eap_identifier is the EAP-Identifier of the received EAP-Success packet.
	 */
	virtual eap_status_e plain_eap_success_failure_packet_received(
		const eap_am_network_id_c * const receive_network_id,
		const eap_code_value_e received_eap_code,
		const u8_t received_eap_identifier) = 0;

	/**
	 * This function indicates the empty Ack packet is received.
	 * This is used in TTLS.
	 * @param receive_network_id includes the addresses (network identity) and packet type.
	 * @param received_eap_identifier is the EAP-Identifier of the received EAP-Success packet.
	 */
	virtual eap_status_e empty_ack_packet_received(
		const eap_am_network_id_c * const receive_network_id,
		const u8_t received_eap_identifier) = 0;

	/**
	 * This function starts TTLS tunneled authentication.
	 */
	virtual eap_status_e start_ttls_tunneled_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const u8_t received_eap_identifier) = 0;

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	virtual bool get_is_valid() = 0;

	/**
	 * This function resets the reused tls_base_application_c object.
	 */
	virtual eap_status_e reset() = 0;

	virtual eap_status_e peap_tunnel_ready() = 0;

	/**
	 * This is notification of internal state transition.
	 * This is used for telling tunneled EAP-type the TLS/PEAP-session was resumed.
	 */
	virtual void set_tunneled_state(
		const tls_session_type_e tls_session_type) = 0;

	/**
	 * This function reads the authority identity (A-ID) of server.
	 * This is used in EAP-FAST.
	 */
	virtual eap_status_e read_authority_identity(
		eap_variable_data_c * const authority_identity_payload) = 0;

	/**
	 * This function saves the received User Authorization PAC-Opaque.
	 * This is used in EAP-FAST.
	 */
	virtual eap_status_e save_user_authorization_pac_opaque(const tls_extension_c * const extension) = 0;

	/**
	 * Function queries tunnel PAC TLV for A-ID.
	 * This function is completed by complete_query_tunnel_PAC() function call.
	 */
	virtual eap_status_e query_tunnel_PAC(
		const eap_fast_variable_data_c * const in_A_ID_TLV) = 0;

	/**
	 * Function cancels query of tunnel PAC TLV for A-ID.
	 */
	virtual eap_status_e cancel_query_tunnel_PAC() = 0;

	virtual eap_status_e complete_query_ttls_pap_username_and_password(
		const eap_variable_data_c * const ttls_pap_username,
		const eap_variable_data_c * const ttls_pap_password,
		const eap_status_e query_result) = 0;

	virtual eap_status_e complete_verify_ttls_pap_username_and_password(
		const eap_status_e authentication_result,
		const eap_variable_data_c * const ttls_pap_reply_message) = 0;

	/**
	 * This function is called when TLS-Alert message is received.
	 * TLS-application module could record this event.
	 */
	virtual eap_status_e alert_received(
		const tls_alert_level_e alert_level,
		const tls_alert_description_e alert_description) = 0;

	//--------------------------------------------------
}; // class tls_base_application_c

#endif //#if !defined(_TLS_BASE_APPLICATION_H_)

//--------------------------------------------------



// End.
