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
* %version: 32 %
*/

#if !defined(EAPOL_MESSAGE_WLAN_AUTHENTICATION_H)
#define EAPOL_MESSAGE_WLAN_AUTHENTICATION_H


#include "eapol_wlan_authentication.h"
#include "eapol_ethernet_header.h"
#include "eap_file_config.h"
//#include <eap_am_file_input_stdio.h>
#include "abs_eap_database_reference_if.h"
#include "abs_eapol_message_wlan_authentication.h"
#include "eapol_handle_tlv_message_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H 
	#define EAP_FUNC_EXPORT_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H 
#elif defined(EAP_EXPORT_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H 
#endif
// End: added by script change_export_macros.sh.


/** @file */

class eap_tlv_header_c;

/// This class is the common part of EAPOL message interface.
/// This class implements the message creation and parsing function.
class eapol_message_wlan_authentication_c
: public abs_eapol_wlan_authentication_c
, public abs_eap_base_timer_c
{

private:

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * m_am_tools;

	/// This is pointer to the WLAN authentication implementation.
	eapol_wlan_authentication_c * m_wauth;

	/// Pointer to the lower layer in the stack
	abs_eapol_message_wlan_authentication_c * m_partner;

	eap_variable_data_c m_wlan_database_reference;

	u32_t m_header_offset;
	u32_t m_MTU;
	u32_t m_trailer_length;

	wlan_eap_if_send_status_e m_error_code;

	eap_tlv_message_type_function_e m_error_function;

	bool m_use_asyncronous_test;

	bool m_is_valid;

	// ----------------------------------------------------------------------

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e check_pmksa_cache(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const tlv_blocks);

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e start_authentication(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e complete_association(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e disassociation(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e start_preauthentication(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e start_reassociation(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e complete_reassociation(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e start_WPXM_reassociation(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e complete_WPXM_reassociation(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e packet_process(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e tkip_mic_failure(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e eap_acknowledge(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e update_header_offset(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e update_wlan_database_reference_values(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e send_error_message(
		const eap_status_e status,
		const eap_tlv_message_type_function_e function);

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e process_message_type_error(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e process_message(eapol_handle_tlv_message_data_c * const message);

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e send_message(eapol_handle_tlv_message_data_c * const message);

	// ----------------------------------------------------------------------

public:

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H virtual ~eapol_message_wlan_authentication_c();

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eapol_message_wlan_authentication_c(
		abs_eap_am_tools_c * const tools,
		abs_eapol_message_wlan_authentication_c * const partner);


	/// This function configures the object and sets the initial values
	/// of header offset, MTU and trailer length.
	/// Look at the abs_eap_base_type_c::get_header_offset()
	/// for description of header_offset, MTU and trailer_length.
	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e configure(
		const u32_t header_offset,
		const u32_t MTU,
		const u32_t trailer_length);

	// Look at abs_eap_stack_interface_c::shutdown().
	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e shutdown();

	// Look at abs_eap_stack_interface_c::get_is_valid().
	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H bool get_is_valid();



	// ------------------------------------------------------
	// The following functions are from abs_eap_base_timer_c.

	// Look at abs_eap_base_timer_c::timer_expired().
	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e timer_expired(
		const u32_t id,
		void *data);

	// Look at abs_eap_base_timer_c::timer_delete_data().
	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e timer_delete_data(
		const u32_t id,
		void *data);

	// The previous functions are from abs_eap_base_timer_c.
	// ------------------------------------------------------


	// ----------------------------------------------------------------
	// The following functions are from abs_eapol_wlan_authentication_c.

	// Look at abs_eapol_wlan_authentication_c::packet_send().
	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e packet_send(
		const eap_am_network_id_c * const send_network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length);

	// Look at abs_eapol_wlan_authentication_c::get_header_offset().
	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length);

	// Look at abs_eapol_wlan_authentication_c::associate().
	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e associate(
		eapol_key_802_11_authentication_mode_e authentication_mode);

	// Look at abs_eapol_wlan_authentication_c::disassociate().
	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e disassociate(
		const eap_am_network_id_c * const receive_network_id, ///< source includes remote address, destination includes local address.
		const bool self_disassociation);

	// Look at abs_eapol_wlan_authentication_c::packet_data_session_key().
	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e packet_data_session_key(
		const eap_am_network_id_c * const send_network_id,
		const eapol_session_key_c * const key);

	// Look at abs_eapol_wlan_authentication_c::state_notification().
	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H void state_notification(
		const abs_eap_state_notification_c * const state);

	// Look at abs_eapol_wlan_authentication_c::add_rogue_ap().
	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e add_rogue_ap(eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list);

	// Look at abs_eapol_wlan_authentication_c::reassociate().
	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e reassociate(
		const eap_am_network_id_c * const send_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const PMKID);

	// The previous functions are from abs_eapol_wlan_authentication_c.
	// ----------------------------------------------------------------


	/// Function receives the data message from lower layer.
	/// Data is formatted to Attribute-Value Pairs.
	/// Look at eap_tlv_header_c and eap_tlv_message_data_c.
	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H wlan_eap_if_send_status_e process_data(const void * const data, const u32_t length);

	// ----------------------------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e save_simple_config_session(
		const simple_config_state_e state,
		EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
		const eap_variable_data_c * const new_password,
		const simple_config_Device_Password_ID_e Device_Password_ID,
		const simple_config_payloads_c * const other_configuration);

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e complete_check_pmksa_cache(
		EAP_TEMPLATE_CONST eap_array_c<eap_am_network_id_c> * const bssid_sta_receive_network_ids);

	EAP_FUNC_VISIBILITY_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H eap_status_e complete_disassociation(
		const eap_am_network_id_c * const receive_network_id);

	// ----------------------------------------------------------------------
};

#endif //#if !defined(EAPOL_MESSAGE_WLAN_AUTHENTICATION_H)


//--------------------------------------------------
