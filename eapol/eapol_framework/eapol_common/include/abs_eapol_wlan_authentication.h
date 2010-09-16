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

#if !defined(_ABS_WLAN_AUTHENTICATION_H_)
#define _ABS_WLAN_AUTHENTICATION_H_

#include "eap_header.h"
#include "eap_array.h"
#include "eapol_key_state.h"

#if defined(USE_EAP_SIMPLE_CONFIG)
#include "simple_config_types.h"
#include "simple_config_credential.h"
#include "simple_config_payloads.h"
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAPOL_WLAN_AUTHENTICATION_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAPOL_WLAN_AUTHENTICATION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAPOL_WLAN_AUTHENTICATION_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAPOL_WLAN_AUTHENTICATION_H 
	#define EAP_FUNC_EXPORT_ABS_EAPOL_WLAN_AUTHENTICATION_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAPOL_WLAN_AUTHENTICATION_H 
#elif defined(EAP_EXPORT_ABS_EAPOL_WLAN_AUTHENTICATION_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAPOL_WLAN_AUTHENTICATION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAPOL_WLAN_AUTHENTICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAPOL_WLAN_AUTHENTICATION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAPOL_WLAN_AUTHENTICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAPOL_WLAN_AUTHENTICATION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAPOL_WLAN_AUTHENTICATION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAPOL_WLAN_AUTHENTICATION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAPOL_WLAN_AUTHENTICATION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAPOL_WLAN_AUTHENTICATION_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAPOL_WLAN_AUTHENTICATION_H 
#endif
// End: added by script change_export_macros.sh.

class abs_eapol_core_c;
class eap_am_network_id_c;
class eap_buf_chain_wr_c;
class abs_eap_base_type_c;
class eap_base_type_c;
class eapol_session_key_c;
class abs_eap_state_notification_c;
class eap_rogue_ap_entry_c;
class eapol_wlan_state_c;

/// The abs_eapol_wlan_authentication_c class defines the interface the eapol_wlan_authentication_c class
/// will use with the partner class.
class EAP_CLASS_VISIBILITY_ABS_EAPOL_WLAN_AUTHENTICATION_H abs_eapol_wlan_authentication_c
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~abs_eapol_wlan_authentication_c()
	{
	}

	// 
	abs_eapol_wlan_authentication_c()
	{
	}

	// Look at abs_eap_base_type_c::packet_send().
	virtual eap_status_e packet_send(
		const eap_am_network_id_c * const send_network_id, ///< source includes local address, destination includes remote address.
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length) = 0;

	// Look at abs_eap_base_type_c::get_header_offset().
	virtual u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length) = 0;

	/**
	 * This function call tells lower layer to associate with the selected 802.11 authentication mode.
	 */
	virtual eap_status_e associate(
		eapol_key_802_11_authentication_mode_e authentication_mode) = 0;

	/**
	 * Lower layer must return value of self_disassociation when
	 * it calls eapol_wlan_authentication_c::disassociation().
	 * This tells eapol_wlan_authentication_c object the cause
	 * of disassociation.
	 */
	virtual eap_status_e disassociate(
		const eap_am_network_id_c * const receive_network_id, ///< source includes remote address, destination includes local address.
		const bool self_disassociation) = 0;

	/**
	 * The packet_data_session_key() function passes one traffic encryption key to 
	 * the lower layers. Ultimately the key can end up to the WLAN hardware.
	 * @see abs_eapol_core_c::packet_data_session_key(). 
	 */
	virtual eap_status_e packet_data_session_key(
		const eap_am_network_id_c * const send_network_id, ///< source includes local address, destination includes remote address.
		const eapol_session_key_c * const key
		) = 0;

	/**
	 * This is notification of internal state transition.
	 * This is used for notifications, debugging and protocol testing.
	 * The primal notifications are eap_state_variable_e::eap_state_authentication_finished_successfully
	 * and eap_state_variable_e::eap_state_authentication_terminated_unsuccessfully.
	 * These two notifications are sent from EAP-protocol layer (eap_protocol_layer_e::eap_protocol_layer_eap).
	 */
	virtual void state_notification(
		const abs_eap_state_notification_c * const state) = 0;

	// Look at abs_eap_base_type_c::add_rogue_ap().
	virtual eap_status_e add_rogue_ap(
		eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list) = 0;

	/**
	 * This function call tells lower layer to re-associate with the selected network ID,
	 * authentication type and PMKID.
	 */
	virtual eap_status_e reassociate(
		const eap_am_network_id_c * const send_network_id,
		const eapol_key_authentication_type_e authentication_type,
		const eap_variable_data_c * const PMKID) = 0;

#if defined(USE_EAP_SIMPLE_CONFIG)
	/**
	 * This function call tells new network settings received from WFA Protected Setup Registrar.
	 */
	virtual eap_status_e save_simple_config_session(
		const simple_config_state_e state,
		EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
		const eap_variable_data_c * const new_password,
		const simple_config_Device_Password_ID_e Device_Password_ID,
		const simple_config_payloads_c * const other_configuration) = 0;
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

	virtual eap_status_e complete_check_pmksa_cache(
		EAP_TEMPLATE_CONST eap_array_c<eap_am_network_id_c> * const bssid_sta_receive_network_ids) = 0;

	virtual eap_status_e complete_disassociation(
		const eap_am_network_id_c * const receive_network_id) = 0;

	//--------------------------------------------------
}; // class abs_eapol_wlan_authentication_c

#endif //#if !defined(_ABS_WLAN_AUTHENTICATION_H_)

//--------------------------------------------------


// End.
