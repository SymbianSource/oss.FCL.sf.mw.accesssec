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

#if !defined(_ABS_EAPOL_AM_CORE_SYMBIAN_H_)
#define _ABS_EAPOL_AM_CORE_SYMBIAN_H_

#if defined(USE_EAPOL_LLC_INTERFACE)
	#include <es_mbuf.h>
#endif

#include "eap_tools.h"
#include "eap_variable_data.h"
#include "eap_buffer.h"
#include "eap_base_type.h"
#include "eap_config.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H 
	#define EAP_FUNC_EXPORT_ABS_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H 
#elif defined(EAP_EXPORT_ABS_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H 
#endif
// End: added by script change_export_macros.sh.


class abs_ethernet_core_c;


// 
class EAP_CLASS_VISIBILITY_ABS_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H abs_eapol_am_core_symbian_c
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
	virtual ~abs_eapol_am_core_symbian_c()
	{
	}

	// 
	abs_eapol_am_core_symbian_c()
	{
	}

#if defined(USE_EAPOL_LLC_INTERFACE) & 0
	//
	virtual TInt packet_send(RMBufChain &aFrame) = 0;
#endif //#if defined(USE_EAPOL_LLC_INTERFACE)

	// 
	virtual eap_status_e packet_send(
		const eap_am_network_id_c * const network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length,
		abs_ethernet_core_c *sender,
		const bool when_true_do_length_checks,
		const u32_t packet_index) = 0;

	//
	virtual u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length) = 0;

	//
	virtual eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e /* tunneling_type */,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id) = 0;

	//
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

	virtual eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	virtual eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	/**
	 * This is notification of internal state transition.
	 * This is used for notifications, debugging and protocol testing.
	 * The primal notifications are eap_state_variable_e::eap_state_authentication_finished_successfully
	 * and eap_state_variable_e::eap_state_authentication_terminated_unsuccessfully.
	 * These two notifications are sent from EAP-protocol layer (eap_protocol_layer_e::eap_protocol_layer_eap).
	 */
	virtual void state_notification(
		const abs_eap_state_notification_c * const state) = 0;

	//--------------------------------------------------
}; // class abs_eapol_am_core_symbian_c

#endif //#if !defined(_ABS_EAPOL_AM_CORE_SYMBIAN_H_)

//--------------------------------------------------



// End.
