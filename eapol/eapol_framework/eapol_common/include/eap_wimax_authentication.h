/*
* Copyright (c) 2007 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  EAP stack interface for Wimax.
*
*/

/*
* %version: %
*/

#if !defined(_EAP_WIMAX_AUTHENTICATION_H_)
#define _EAP_WIMAX_AUTHENTICATION_H_

#include <eap_am_wimax_authentication.h>
#include <abs_eap_am_wimax_authentication.h>
#include <abs_eap_core.h>
#include <abs_eap_wimax_authentication.h>
#include <eap_type_selection.h>
#include <eap_array.h>
#include <abs_eap_am_tools.h>
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_WIMAX_AUTHENTICATION_H)
	#define EAP_CLASS_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H 
	#define EAP_FUNC_EXPORT_EAP_WIMAX_AUTHENTICATION_H 
	#define EAP_C_FUNC_EXPORT_EAP_WIMAX_AUTHENTICATION_H 
#elif defined(EAP_EXPORT_EAP_WIMAX_AUTHENTICATION_H)
	#define EAP_CLASS_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_WIMAX_AUTHENTICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_WIMAX_AUTHENTICATION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_WIMAX_AUTHENTICATION_H 
	#define EAP_C_FUNC_EXPORT_EAP_WIMAX_AUTHENTICATION_H 
#endif
// End: added by script change_export_macros.sh.


// FORWARD DECLARATIONS
class eap_session_core_c;
class eap_am_tools_symbian_c;
class eap_file_config_c;


// CLASS DECLARATION
class EAP_CLASS_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_wimax_authentication_c
: public abs_eap_am_wimax_authentication_c
, public abs_eap_core_c
{
public:

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_wimax_authentication_c(
		abs_eap_am_tools_c* const tools, 
		abs_eap_wimax_authentication_c* const partner,
		eap_am_wimax_authentication_c* const am_wauth,
		const bool is_client_when_true);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H virtual ~eap_wimax_authentication_c();  // For GCC compilation

	///////////////////////////////////
	/* These are called by the lower */
	/* layer (= Wimax engine).       */

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H static eap_wimax_authentication_c* new_eap_wimax_authentication_c(
		abs_eap_am_tools_c* const tools,
		abs_eap_wimax_authentication_c* const partner,
		const bool is_client_when_true);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e shutdown();

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e cancel_all_authentication_sessions();

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id,
		eap_general_header_base_c * const packet_data,
		const u32_t packet_length);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e eap_acknowledge(
		const eap_am_network_id_c * const receive_network_id);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e configure();

	
	/**
	 * This function indicates the routing realms and NAI decoration
	 * to the adaptation module. The values are needed in the generation of 
	 * EAP (outer) Identity Response and need to be dynamically obtained from 
	 * the Wimax engine scanning results. The EAP stack requests these values
	 * from the default EAP type when it needs to respond to an EAP Identity
	 * Request. More info (e.g. the allowed character set) is available 
	 * in RFC 4242.
	 *
   * @param routing_info is a null pointer if RoutingRealm is not used. Otherwise it contains
	 * a string in the format "RoutingRealm1!RoutingRealm2!RoutingRealm3" (no null termination)
	 * in which RoutingRealm1 is the 1st location on the route, RoutingRealm2 is the 2nd 
	 * location and so on. The parameter does not contain the home realm, as the home realm 
	 * is static and requested from the adapatation module separately (obtained from the 
	 * provisioning data). From this info, the EAP stack generates a NAI such as
	 * "RoutingRealm2!RoutingRealm3!HomeRealm!{nai_decoration}username@RoutingRealm1".
	 *
	 * @param nai_decoration is null if NAI decoration is not used. Otherwise it contains
	 * a string in the format "{avp1|avp2|avp3}", which the EAP stack copies to NAI. The NAI 
	 * above becomes
	 * "RoutingRealm2!RoutingRealm3!HomeRealm!{avp1|avp2|avp3}username@RoutingRealm1".
	 */

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e set_wimax_parameters(
		eap_variable_data_c* const routing_info,
		eap_variable_data_c* const nai_decoration);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H bool get_is_valid();

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H bool get_is_client();


	//--------------------------------------------------


	///////////////////////////////////////////
	/* These are called by eap_session_core. */
    /* See abs_eap_core.h for descriptions.  */

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e packet_send(
		const eap_am_network_id_c * const network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e /* tunneling_type */,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e unload_module(const eap_type_value_e eap_type);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e restart_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const bool is_client_when_true,
		const bool force_clean_restart,
		const bool from_timer = false);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e packet_data_crypto_keys(
		const eap_am_network_id_c * const send_network_id,
		const eap_master_session_key_c * const master_session_key
		);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H void state_notification(
		const abs_eap_state_notification_c * const state);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e asynchronous_init_remove_eap_session(
		const eap_am_network_id_c * const send_network_id);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e set_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id, 
		void * const data,
		const u32_t time_ms);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e cancel_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e cancel_all_timers();

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e check_is_valid_eap_type(const eap_type_value_e eap_type);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e get_eap_type_list(
		eap_array_c<eap_type_value_e> * const eap_type_list);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e add_rogue_ap(eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list);

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e set_session_timeout(
		const u32_t session_timeout_ms);

	//--------------------------------------------------

private:

	EAP_FUNC_VISIBILITY_EAP_WIMAX_AUTHENTICATION_H eap_status_e create_upper_stack();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	/// Pointer to the tools class
	abs_eap_am_tools_c * m_am_tools;

	/// Pointer to the lower layer in the stack
	abs_eap_wimax_authentication_c * m_partner;

	/// Pointer to the AM of WAUTH.
	eap_am_wimax_authentication_c * m_am_wauth;

	/// Pointer to the upper layer in the stack
	eap_session_core_c * m_eap_core;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	bool m_is_valid;

	bool m_is_client;

	bool m_shutdown_was_called;

	bool m_block_state_notifications;

}; // class eap_wimax_authentication_c


#endif //#if !defined(_EAP_WIMAX_AUTHENTICATION_H_)

//--------------------------------------------------


// End of file

