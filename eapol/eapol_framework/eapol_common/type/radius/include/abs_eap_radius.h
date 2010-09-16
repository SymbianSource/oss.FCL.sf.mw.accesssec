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

#if !defined(_ABS_EAP_RADIUS_H_)
#define _ABS_EAP_RADIUS_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_RADIUS_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_RADIUS_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_RADIUS_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_RADIUS_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_RADIUS_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_RADIUS_H 
#elif defined(EAP_EXPORT_ABS_EAP_RADIUS_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_RADIUS_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_RADIUS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_RADIUS_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_RADIUS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_RADIUS_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_RADIUS_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_RADIUS_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_RADIUS_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_RADIUS_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_RADIUS_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_header.h"
#include "eap_array.h"

class eap_base_type_c;
class eap_am_network_id_c;
class eap_network_id_selector_c;
class eap_configuration_field_c;
class abs_eap_state_notification_c;
class eap_rogue_ap_entry_c;


/// The class is the interface to partner class of the eap_base_type class.
/// This declares the pure virtual member functions EAP-type class could call.
class EAP_CLASS_VISIBILITY_ABS_EAP_RADIUS_H abs_eap_radius_c
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
	 * The destructor of the abs_eap_radius_c class does nothing special.
	 */
	virtual ~abs_eap_radius_c()
	{
	}

	/**
	 * The constructor of the abs_eap_radius_c class does nothing special.
	 */
	abs_eap_radius_c()
	{
	}

	/**
	 * The derived class could send packets to partner class with this function.
	 * @param network_id carries the addresses (network identity) and type of the packet.
	 * @param sent_packet includes the buffer for the whole packet and initialized 
	 * EAP-packet in correct offset.
	 * @param header_offset is offset of the EAP-header within the sent_packet.
	 * @param data_length is length in bytes of the EAP-packet.
	 * @param buffer_length is length in bytes of the whole packet buffer.
	 *
	 * Now some ascii graphics follows.
	 * @code
	 *                                                                                    
	 * +---------------------+-----+---------------------------------------+-------------+
	 * |                     | EAP |  data                                 |             |
	 * +---------------------+-----+---------------------------------------+-------------+
	 * |                     |                                             |             |
	 * |<---header_offset--->|<-------------data_length------------------->|<--trailer-->|
	 * |                                                                                 |
	 * |<------------------------buffer_length------------------------------------------>|
	 *
	 * trailer is the free space in the end of the packet buffer.
	 * @endcode
	 *
	 */
	virtual eap_status_e packet_send(
		const eap_am_network_id_c * const network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length) = 0;

	/**
	 * The get_header_offset() function obtains the header offset of EAP-packet.
	 * @param MTU_length is pointer to variable to store the maximum transfer unit (MTU).
	 * MTU is the maximum EAP-packet length in bytes
	 * @param trailer_length is pointer to the variable to store length
	 * of trailer needed by lower levels.
	 * @return Function returns the offset of EAP-header.
	 *
	 * The needed buffer length is ((offset) + (EAP-packet length) + (trailer)) bytes.
	 * Each layer adds the length of the header to offset.
	 * Each layer removes the length of the header and trailer from MTU.
	 *
	 * Now some ascii graphics follows.
	 * @code
	 * |<-------------------------buffer length----------------------------------------->|
	 * |                                                                                 |
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
	 * Note this function is just an example. Parameters will change later.
	 * The packet_data_crypto_keys() function gives the generated keys to lower level.
	 * After EAP-authentication has generated the keys it calls this function
	 * to offer the keys to lower level.
	 * @param master_session_key is pointer to the first byte of the master session key.
	 * @param master_session_length is count of bytes in the master session key.
	 */
	virtual eap_status_e packet_data_crypto_keys(
		const eap_am_network_id_c * const send_network_id,
		const eap_master_session_key_c * const master_session_key
		) = 0;

	/**
	 * The read_configure() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 * 
	 * EAP-type should store it's parameters to an own database. The own database should be accessed
	 * through adaptation module of EAP-type. See eap_am_type_gsmsim_simulator_c::type_configure_read.
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
	 * through adaptation module of EAP-type. See eap_am_type_gsmsim_simulator_c::type_configure_write.
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
	 * The set_timer() function initializes timer to be elapsed after time_ms milliseconds.
	 * @param initializer is pointer to object which timer_expired() function will
	 * be called after timer elapses.
	 * @param id is identifier which will be returned in timer_expired() function.
	 * The user selects and interprets the id for this timer.
	 * @param data is pointer to any user selected data which will be returned in timer_expired() function.
	 * @param time_ms is the time of timer in milli seconds.
	 *
	 * Adaptation module internally implements the timer.
	 */
	virtual eap_status_e set_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id, 
		void * const data,
		const u32_t time_ms) = 0;

	/**
	 * The cancel_timer() function cancels the timer id initiated by initializer.
	 * @param initializer is pointer to object which set the cancelled timer.
	 * @param id is identifier which will be returned in timer_expired() function.
	 * The user selects and interprets the id for this timer.
	 *
	 * Adaptation module internally implements the timer.
	 */
	virtual eap_status_e cancel_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id) = 0;

	/**
	 * The cancel_all_timers() function cancels all timers.
	 * User should use this in termination of the stack before
	 * the adaptation module of tools is deleted.
	 * Preferred mode is to cancel each timer directly
	 * using cancel_timer() function.
	 *
	 * Adaptation module internally implements the timer.
	 */
	virtual eap_status_e cancel_all_timers() = 0;

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
	 * @param receive_network_id includes the addresses (network identity) and packet type.
	 */
	virtual eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e tunneling_type,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id) = 0;

	/**
	 * This is needed by PEAP type.
	 * The unload_module() function unloads the module of a EAP-type. 
	 * @param eap_type is the requested EAP-type.
	 */
	virtual eap_status_e unload_module(const eap_type_value_e eap_type) = 0;

	/**
	 * This is needed by PEAP type.
	 * This function queries the validity of EAP-type.
	 * Lower layer should return eap_status_ok if this EAP-type is supported.
	 * @param eap_type is the requested EAP-type.
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

	virtual eap_status_e add_rogue_ap(eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list) = 0;

	//--------------------------------------------------
}; // class abs_eap_radius_c

#endif //#if !defined(_ABS_EAP_RADIUS_H_)

//--------------------------------------------------



// End.
