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

#if !defined(_EAP_AM_SYMBIAN_H_)
#define _EAP_AM_SYMBIAN_H_

#if defined(USE_EAPOL_LLC_INTERFACE)
	#include <es_mbuf.h>
#endif

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H 
	#define EAP_FUNC_EXPORT_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H 
#elif defined(EAP_EXPORT_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eapol_am_core_symbian_simulator.h"
#include "abs_ethernet_core.h"
#include "ethernet_core.h"
#include "eap_base_type.h"
#include "eap_variable_data.h"
#include "eap_core_map.h"

class CEapType;

// 
class EAP_CLASS_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eapol_am_core_symbian_c
: public abs_ethernet_core_c
{
private:
	//--------------------------------------------------

	abs_eapol_am_core_symbian_c *m_partner;

	ethernet_core_c *m_ethernet_core;

	abs_eap_am_tools_c * const m_am_tools;

	eap_variable_data_c m_own_address;

	u32_t m_error_probability;

	u32_t m_authentication_counter;

	bool m_is_valid;

	bool m_is_client;

	bool m_enable_random_errors;

	bool m_shutdown_was_called;

	RPointerArray<CEapType> m_plugin_if_array;
	RArray<eap_type_value_e> m_eap_type_array;

	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_status_e random_error(
		eap_buf_chain_wr_c * const sent_packet);

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H virtual ~eapol_am_core_symbian_c();

	// 
	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eapol_am_core_symbian_c(
		abs_eap_am_tools_c * const m_am_tools,
		abs_eapol_am_core_symbian_c * const partner,
		const bool is_client_when_true);

	//
	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_base_type_c * load_type(const eap_type_value_e type);

#if defined(USE_EAPOL_LLC_INTERFACE)
	//
	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_status_e packet_process(
		RMBufChain& aPdu);
#endif //#if defined(USE_EAPOL_LLC_INTERFACE)

	//
	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id,
		eapol_ethernet_header_wr_c * const eth_header,
		const u32_t packet_length); 

	//
	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_status_e packet_send(
		const eap_am_network_id_c * const send_network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length); 

	eap_status_e set_address(
		const u8_t * const address,
		const u32_t length)
	{
		return m_own_address.set_copy_of_buffer(address, length);
	}

	//
	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length);

	//
	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_status_e eap_acknowledge(const eap_am_network_id_c * const receive_network_id); 

	//
	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e /* tunneling_type */,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id);

	//
	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_status_e unload_module(const eap_type_value_e type); 

	/**
	 * This function starts the EAP-authentication.
	 * The first parameter includes the network addresses of the protocol
	 * over the EAP-packets are transmitted.
	 * The type attribute of the eap_am_network_id_c object MUST be set
	 * either eapol_ethernet_type_e::eapol_ethernet_type_pae
	 * or eapol_ethernet_type_e::eapol_ethernet_type_preauthentication.
	 * Value eapol_ethernet_type_e::eapol_ethernet_type_pae starts normal EA-authentication.
	 * Value eapol_ethernet_type_e::eapol_ethernet_type_preauthentication starts 802.11i preauthentication.
	 * The second parameter is_client_when_true tells whether this stack
	 * is client (true) or server (false).
	 */ 
	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_status_e start_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const bool is_client_when_true);

	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_status_e send_logoff(const eap_am_network_id_c * const receive_network_id);

	EAP_FUNC_IMPORT_EMPTY void set_is_valid()
	{
		m_is_valid = true;
	}

	EAP_FUNC_IMPORT_EMPTY bool get_is_valid()
	{
		return m_is_valid;
	}

	const eap_variable_data_c * const get_own_address()
	{
		return &m_own_address;
	}

	void increment_authentication_counter()
	{
		++m_authentication_counter;
	}

	const u32_t get_authentication_counter()
	{
		return m_authentication_counter;
	}

	bool get_is_client()
	{
		return m_is_client;
	}

	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_status_e configure();

	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_status_e shutdown();

	/**
	 * Note this function is just an example. Parameters will change later.
	 * The packet_data_crypto_keys() function gives the generated keys to lower level.
	 * After EAP-authentication has generated the keys it calls this function
	 * to offer the keys to lower level.
	 * @see abs_eap_base_type_c::packet_data_crypto_keys().
	 */
	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_status_e packet_data_crypto_keys(
		const eap_am_network_id_c * const send_network_id,
		const eap_master_session_key_c * const master_session_key);

	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	// See abs_eap_base_type_c::state_notification().
	void state_notification(
		const abs_eap_state_notification_c * const state)
	{
		m_partner->state_notification(state);
	}

	//
	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_status_e set_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id, 
		void * const p_data,
		const u32_t p_time_ms);

	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_status_e cancel_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id);

	//
	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_status_e cancel_all_timers();

	//
	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_status_e check_is_valid_eap_type(const eap_type_value_e eap_type);

	//
	EAP_FUNC_VISIBILITY_EAPOL_AM_CORE_SYMBIAN_SIMULATOR_H eap_status_e get_eap_type_list(
		eap_array_c<eap_type_value_e> * const eap_type_list);

	eap_status_e packet_data_session_key(
		const eap_am_network_id_c * const send_network_id,
		const eapol_session_key_c * const key);

	//--------------------------------------------------
}; // class eapol_am_core_symbian_c

#endif //#if !defined(_EAP_AM_SYMBIAN_H_)

//--------------------------------------------------



// End.
