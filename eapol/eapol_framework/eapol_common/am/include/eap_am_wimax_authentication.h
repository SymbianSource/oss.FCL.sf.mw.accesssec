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

#if !defined(_EAP_AM_WIMAX_AUTHENTICATION_H_)
#define _EAP_AM_WIMAX_AUTHENTICATION_H_

#include <eap_am_export.h>
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_WIMAX_AUTHENTICATION_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_WIMAX_AUTHENTICATION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_WIMAX_AUTHENTICATION_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_WIMAX_AUTHENTICATION_H 
	#define EAP_FUNC_EXPORT_EAP_AM_WIMAX_AUTHENTICATION_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_WIMAX_AUTHENTICATION_H 
#elif defined(EAP_EXPORT_EAP_AM_WIMAX_AUTHENTICATION_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_WIMAX_AUTHENTICATION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_WIMAX_AUTHENTICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_WIMAX_AUTHENTICATION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_WIMAX_AUTHENTICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_WIMAX_AUTHENTICATION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_WIMAX_AUTHENTICATION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_WIMAX_AUTHENTICATION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_WIMAX_AUTHENTICATION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_WIMAX_AUTHENTICATION_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_WIMAX_AUTHENTICATION_H 
#endif
// End: added by script change_export_macros.sh.
#include <eap_status.h>
#include <eap_header.h>
#include <eap_array.h>

class abs_eap_am_wimax_authentication_c;
class abs_eap_am_tools_c;
class abs_eap_base_type_c;
class eap_base_type_c;
class eap_am_network_id_c;
class eap_type_selection_c;
class abs_eap_state_notification_c;

/// This is interface to adaptation module of class eap_wimax_authentication_c.
class EAP_CLASS_VISIBILITY_EAP_AM_WIMAX_AUTHENTICATION_H eap_am_wimax_authentication_c
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
	virtual ~eap_am_wimax_authentication_c();

	EAP_FUNC_VISIBILITY_EAP_AM_WIMAX_AUTHENTICATION_H static eap_am_wimax_authentication_c* new_eap_am_wimax_authentication(
		abs_eap_am_tools_c * const tools,
		const bool is_client_when_true
		);

	/// This is documented in abs_eap_stack_interface_c::get_is_valid().
	virtual bool get_is_valid() = 0;

	/// This is documented in abs_eap_stack_interface_c::configure().
	virtual eap_status_e configure() = 0;

	/// This is documented in abs_eap_stack_interface_c::shutdown().
	virtual eap_status_e shutdown() = 0;

	/// Function sets the parther object of this object.
	virtual eap_status_e set_am_partner(
		abs_eap_am_wimax_authentication_c * am_partner
		) = 0;

	/// Function resets current EAP-configuration.
	virtual eap_status_e reset_eap_configuration() = 0;

	/// This is documented in eap_wimax_authentication.h.
	virtual eap_status_e set_wimax_parameters(
		eap_variable_data_c* const routing_info,
		eap_variable_data_c* const nai_decoration) = 0;

	/**
	 * The load_module() function function indicates the lower level to
	 * load new module of EAP-type.
	 * @param type is the requested EAP-type.
	 * @param tunneling_type is the EAP-type that tunnels the type. When plain EAP-type is used this parameter is eap_type_none.
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
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		) = 0;

	/**
	 * The unload_module() function unloads the module of a EAP-type. 
	 * @param eap_type is the requested EAP-type.
	 */
	virtual eap_status_e unload_module(
		const eap_type_value_e type) = 0;

	/**
	 * The read_configure() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @see abs_eap_base_type_c::read_configure().
	 */
	virtual eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	/**
	 * The write_configure() function writes the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the action to some persistent store.
	 * @see abs_eap_base_type_c::write_configure().
	 */
	virtual eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	/**
	 * This function queries the validity of EAP-type.
	 * Lower layer should return eap_status_ok if this EAP-type is supported.
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
}; // class eap_am_wimax_authentication_c

#endif //#if !defined(_EAP_AM_WIMAX_AUTHENTICATION_H_)

//--------------------------------------------------



// End.

