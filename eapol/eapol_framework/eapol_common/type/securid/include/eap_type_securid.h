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
* %version: 10.1.4 %
*/

#ifndef EAP_TYPE_SECURID_H
#define EAP_TYPE_SECURID_H

#include "eap_base_type.h"

#include "abs_eap_am_type_securid.h"
#include "eap_am_type_securid.h"
#include "eap_am_network_id.h"

#include "eap_type_securid_state.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TYPE_SECURID_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_SECURID_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_SECURID_H 
	#define EAP_FUNC_EXPORT_EAP_TYPE_SECURID_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_SECURID_H 
#elif defined(EAP_EXPORT_EAP_TYPE_SECURID_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_SECURID_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_SECURID_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_SECURID_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_SECURID_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_SECURID_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_SECURID_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_SECURID_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_SECURID_H 
#endif
// End: added by script change_export_macros.sh.


/// This class is implementation of SecurID EAP-type.
class EAP_CLASS_VISIBILITY_EAP_TYPE_SECURID_H eap_type_securid_c
: public abs_eap_am_type_securid_c 
, public eap_base_type_c
{

private:

	/// This is pointer to adaptation module of SecurID EAP type.
	eap_am_type_securid_c * const m_am_type_securid;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/// This indicates whether this object is client (true) or server (false).
	/// In terms of EAP-protocol whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	bool m_is_client;

	eap_type_value_e m_eap_type;

	bool m_free_am_type_securid;

	bool m_use_EAP_FAST_response;

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	eap_am_network_id_c m_send_network_id;

	u8_t m_identifier;

	eap_variable_data_c m_identity;

	// Server only:
	eap_variable_data_c m_passcode;
	eap_variable_data_c m_pincode;

	bool m_is_first_passcode_query;
	bool m_is_first_pincode_query;

	bool m_identity_asked;
	bool m_is_pending;

	eap_type_securid_state_c m_state;

	bool m_is_reauthentication;

	u32_t m_offset, m_mtu_length, m_trailer_length;

	bool m_use_eap_expanded_type;

#if defined(USE_EAP_CONFIGURATION_TO_SKIP_USER_INTERACTIONS)
	bool m_skip_user_interactions;
#endif //#if defined(USE_EAP_CONFIGURATION_TO_SKIP_USER_INTERACTIONS)


	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H eap_status_e finish_successful_authentication();

	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H eap_status_e finish_unsuccessful_authentication(
		const bool authentication_cancelled);

	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H eap_status_e complete_eap_identity_query(
		const eap_variable_data_c * const identity);

	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H eap_status_e client_securid_complete_passcode_query(
		const eap_variable_data_c * const passcode);

	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H eap_status_e client_securid_complete_pincode_query(
		const eap_variable_data_c * const pincode,
		const eap_variable_data_c * const passcode);

	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H eap_status_e client_gtc_complete_user_input_query(
		const eap_variable_data_c * const identity_utf8,
		const eap_variable_data_c * const input);

	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H eap_status_e remove_username_store();

	/**
	 * This function processes the SecurID packets.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H eap_status_e securid_packet_process(
		eap_header_wr_c * const eap, ///< This is pointer to EAP header and data.
		const u32_t eap_packet_length ///< This is length of received EAP packet.
		);

	/**
	 * This function tells if the object is a client or a server..
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H bool get_is_client();

	eap_buf_chain_wr_c * create_send_packet(u32_t length);

	eap_status_e packet_send(
		eap_buf_chain_wr_c * const data,
		const u32_t data_length);

	eap_status_e client_packet_process(
		eap_header_wr_c * const received_eap,
		const u32_t eap_packet_length);

	eap_status_e client_securid_packet_process(
		eap_header_wr_c * const eap,
		const u32_t eap_packet_length);

	eap_status_e client_gtc_packet_process(
		eap_header_wr_c * const eap,
		const u32_t eap_packet_length);

#ifdef EAP_SECURID_SERVER

	eap_status_e server_packet_process(
		eap_header_wr_c * const received_eap,
		const u32_t eap_packet_length);

#endif

protected:

public:

	/**
	 * Destructor cancels all timers and deletes member attributes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H virtual ~eap_type_securid_c();

	/**
	 * Constructor initializes all member attributes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H eap_type_securid_c(
		abs_eap_am_tools_c * const tools,
		abs_eap_base_type_c * const partner,
		eap_am_type_securid_c * const am_type_securid,
		const bool free_am_type_securid,
		const eap_type_value_e current_eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * The partner class calls this function when EAP/SecurID packet is received.
	 * see also eap_base_type_c::packet_process().
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id, ///< This is the network identity of the received EAP packet.
		eap_header_wr_c * const eap, ///< This is pointer to EAP header and data.
		const u32_t eap_packet_length ///< This is length of received EAP packet.
		);


	// This is commented in eap_base_type_c::get_is_valid().
	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H bool get_is_valid();
	
	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H void set_is_valid();

	/**
	 * This function resets the reused eap_type_securid_c object.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H eap_status_e reset();

	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H eap_status_e shutdown();

	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H eap_status_e configure();

	// This is commented in eap_base_type_c::query_eap_identity().
	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H eap_status_e query_eap_identity(
		const bool must_be_synchronous,
		eap_variable_data_c * const identity,
		const eap_am_network_id_c * const receive_network_id,
		const u8_t eap_identifier);

	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H eap_status_e set_initial_eap_identifier(
		const eap_am_network_id_c * const receive_network_id,
		const u8_t initial_identifier);

	// This is commented in eap_base_type_c::eap_acknowledge().
	EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_H eap_status_e eap_acknowledge(
		const eap_am_network_id_c * const receive_network_id);

}; // class eap_type_securid_c

#endif // EAP_TYPE_SECURID_H

//--------------------------------------------------


// End.
