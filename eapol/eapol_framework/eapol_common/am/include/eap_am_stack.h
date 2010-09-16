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
* %version: 11 %
*/

#if !defined(_EAP_AM_STACK_H_)
#define _EAP_AM_STACK_H_

#include "eap_tools.h"
#include "eap_status.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_STACK_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_STACK_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_STACK_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_STACK_H 
	#define EAP_FUNC_EXPORT_EAP_AM_STACK_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_STACK_H 
#elif defined(EAP_EXPORT_EAP_AM_STACK_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_STACK_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_STACK_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_STACK_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_STACK_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_STACK_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_STACK_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_STACK_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_STACK_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_STACK_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_STACK_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_expanded_type.h"
#include "eap_array.h"
#include "eap_database_reference_if.h"
#include "eapol_key_types.h"

class abs_eap_am_message_if_c;
class eap_configuration_field_c;
class eap_variable_data_c;
class abs_eap_am_tools_c;
class abs_eap_base_type_c;
class eap_base_type_c;
class eap_am_network_id_c;
class abs_eap_am_stack_c;
class abs_eap_configuration_if_c;

/** @file */

/// This class is the common part of EAP message interface.
/// This class is interface to the message creation and parsing function.
class EAP_CLASS_VISIBILITY_EAP_AM_STACK_H eap_am_stack_c
: public eap_database_reference_if_c 
{

private:

	// ----------------------------------------------------------------------

public:

	virtual ~eap_am_stack_c()
	{
	}

	virtual bool get_is_valid() = 0;

	virtual eap_status_e set_partner(
		abs_eap_am_stack_c * const partner
#if defined(USE_EAP_SIMPLE_CONFIG)
		, abs_eap_configuration_if_c * const configuration_if
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)
		) = 0;

	// This is documented in abs_eap_stack_interface_c::configure().
	virtual eap_status_e configure(
		const eap_variable_data_c * const client_configuration) = 0;

	// This is documented in abs_eap_stack_interface_c::shutdown().
	virtual eap_status_e shutdown() = 0;

	virtual eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	virtual eap_status_e set_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id, 
		void * const p_data,
		const u32_t p_time_ms) = 0;

	virtual eap_status_e cancel_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id) = 0;

	virtual eap_status_e check_is_valid_eap_type(
		const eap_type_value_e eap_type) = 0;

	virtual eap_status_e get_eap_type_list(
		eap_array_c<eap_type_value_e> * const eap_type_list) = 0;

	virtual eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e tunneling_type,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id) = 0;

	virtual eap_status_e get_802_11_authentication_mode(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type) = 0;

	// ----------------------------------------------------------------------
};

EAP_FUNC_VISIBILITY_EAP_AM_STACK_H eap_am_stack_c * new_eap_am_stack_c(
	abs_eap_am_tools_c * const tools,
	const bool is_client_when_true);

#endif //#if !defined(_EAP_AM_STACK_H_)


//--------------------------------------------------
// End
