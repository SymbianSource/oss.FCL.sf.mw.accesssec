/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/wapi_message_wlan_authentication.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 9.1.1 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.2
*/


#if !defined(WAPI_MESSAGE_WLAN_AUTHENTICATION_H)
#define WAPI_MESSAGE_WLAN_AUTHENTICATION_H

// exports for ECOM plugin
#if defined(__SYMBIAN32__)
#undef EAP_NO_EXPORTS
#endif

#include "eap_am_export.h"
#include "wapi_wlan_authentication.h"
#include "eapol_ethernet_header.h"
#include "eap_file_config.h"
#include "abs_eapol_wlan_database_reference_if.h"
#include "abs_wapi_message_wlan_authentication.h"
// The same TLVs used as in EAPOL
// so that WLAN engine can use existing functions (e.g. packet_send)
#include "eapol_handle_tlv_message_data.h"  

/** @file */

class eap_tlv_header_c;

/// This class is the common part of WAPI message interface.
/// This class implements the message creation and parsing function.
class EAP_EXPORT_INTERFACE wapi_message_wlan_authentication_c
: public abs_wapi_wlan_authentication_c
, public abs_eap_base_timer_c
, public abs_eapol_wlan_database_reference_if_c
{

private:

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * m_am_tools;

	/// This is pointer to the WLAN authentication implementation.
	wapi_wlan_authentication_c * m_wauth;

	/// Pointer to the lower layer in the stack
	abs_wapi_message_wlan_authentication_c * m_partner;

	eap_variable_data_c m_wlan_database_reference;

	u32_t m_header_offset;
	u32_t m_MTU;
	u32_t m_trailer_length;

	wlan_eap_if_send_status_e m_error_code;

	eapol_tlv_message_type_function_e m_error_function;

	bool m_is_valid;

	// ----------------------------------------------------------------------

	// This is used for checking BKSA cache in WAPI
	// The function name is kept the same as in EAPOL.
	EAP_FUNC_IMPORT eap_status_e check_bksa_cache(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const tlv_blocks);
	
	EAP_FUNC_IMPORT eap_status_e start_authentication(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_IMPORT eap_status_e complete_association(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_IMPORT eap_status_e disassociation(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_IMPORT eap_status_e start_reassociation(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_IMPORT eap_status_e complete_reassociation(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_IMPORT eap_status_e packet_process(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_IMPORT eap_status_e update_header_offset(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_IMPORT eap_status_e update_wlan_database_reference_values(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_IMPORT eap_status_e send_error_message(
		const eap_status_e status,
		const eapol_tlv_message_type_function_e function);

	EAP_FUNC_IMPORT eap_status_e process_message_type_error(
		EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters);

	EAP_FUNC_IMPORT eap_status_e process_message(eapol_handle_tlv_message_data_c * const message);

	EAP_FUNC_IMPORT eap_status_e send_message(eapol_handle_tlv_message_data_c * const message);

	// ----------------------------------------------------------------------

public:

	EAP_FUNC_IMPORT_INTERFACE ~wapi_message_wlan_authentication_c();

	EAP_FUNC_IMPORT_INTERFACE wapi_message_wlan_authentication_c(
		abs_eap_am_tools_c * const tools,
		abs_wapi_message_wlan_authentication_c * const partner);


	/// This function configures the object and sets the initial values
	/// of header offset, MTU and trailer length.
	/// Look at the abs_eap_base_type_c::get_header_offset()
	/// for description of header_offset, MTU and trailer_length.
	EAP_FUNC_IMPORT_INTERFACE eap_status_e configure(
		const u32_t header_offset,
		const u32_t MTU,
		const u32_t trailer_length);

	// Look at abs_eap_stack_interface_c::shutdown().
	EAP_FUNC_IMPORT_INTERFACE eap_status_e shutdown();

	// Look at abs_eap_stack_interface_c::get_is_valid().
	EAP_FUNC_IMPORT_INTERFACE bool get_is_valid();



	// ------------------------------------------------------
	// The following functions are from abs_eap_base_timer_c.

	// Look at abs_eap_base_timer_c::timer_expired().
	EAP_FUNC_IMPORT_INTERFACE eap_status_e timer_expired(
		const u32_t id,
		void *data);

	// Look at abs_eap_base_timer_c::timer_delete_data().
	EAP_FUNC_IMPORT_INTERFACE eap_status_e timer_delete_data(
		const u32_t id,
		void *data);

	// The previous functions are from abs_eap_base_timer_c.
	// ------------------------------------------------------


	// ----------------------------------------------------------------
	// The following functions are from abs_wapi_wlan_authentication_c.

	// Look at abs_eapol_wlan_authentication_c::packet_send().
	EAP_FUNC_IMPORT_INTERFACE eap_status_e packet_send(
		const eap_am_network_id_c * const send_network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length);

	// Look at abs_wapi_wlan_authentication_c::get_header_offset().
	EAP_FUNC_IMPORT_INTERFACE u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length);

	// Look at abs_wapi_wlan_authentication_c::associate().
	// WAPI uses always open 802.11 authentication mode.
	EAP_FUNC_IMPORT_INTERFACE eap_status_e associate(
		eapol_key_802_11_authentication_mode_e authentication_mode);

	// Look at abs_wapi_wlan_authentication_c::disassociate().
	EAP_FUNC_IMPORT_INTERFACE eap_status_e disassociate(
		const eap_am_network_id_c * const receive_network_id, ///< source includes remote address, destination includes local address.
		const bool self_disassociation);

	// Look at abs_wapi_wlan_authentication_c::packet_data_session_key().
	EAP_FUNC_IMPORT_INTERFACE eap_status_e packet_data_session_key(
		const eap_am_network_id_c * const send_network_id,
		const eapol_session_key_c * const key);

	// Look at abs_wapi_wlan_authentication_c::state_notification().
	EAP_FUNC_IMPORT_INTERFACE void state_notification(
		const abs_eap_state_notification_c * const state);

	// Look at abs_wapi_wlan_authentication_c::reassociate().
	EAP_FUNC_IMPORT_INTERFACE eap_status_e reassociate(
		const eap_am_network_id_c * const send_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const BKID);


	// ----------------------------------------------------------------------
	// The following function is from abs_eapol_wlan_database_reference_if_c.

	// Look at abs_eapol_wlan_database_reference_if_c::get_wlan_database_reference_values().
	EAP_FUNC_IMPORT_INTERFACE eap_status_e get_wlan_database_reference_values(
		eap_variable_data_c * const reference) const;

	// The previous function is from abs_eapol_wlan_database_reference_if_c.
	// ----------------------------------------------------------------------


	/// Function receives the data message from lower layer.
	/// Data is formatted to Attribute-Value Pairs.
	/// Look at eap_tlv_header_c and eap_tlv_message_data_c.
	EAP_FUNC_IMPORT_INTERFACE wlan_eap_if_send_status_e process_data(const void * const data, const u32_t length);

	// ----------------------------------------------------------------------
};

#endif //#if !defined(WAPI_MESSAGE_WLAN_AUTHENTICATION_H)


//--------------------------------------------------

