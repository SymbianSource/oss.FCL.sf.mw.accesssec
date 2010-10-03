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

#if !defined(_EAP_AM_MESSAGE_IF_H_)
#define _EAP_AM_MESSAGE_IF_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_MESSAGE_IF_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_MESSAGE_IF_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_H 
	#define EAP_FUNC_EXPORT_EAP_AM_MESSAGE_IF_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_MESSAGE_IF_H 
#elif defined(EAP_EXPORT_EAP_AM_MESSAGE_IF_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_MESSAGE_IF_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_MESSAGE_IF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_MESSAGE_IF_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_MESSAGE_IF_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_MESSAGE_IF_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_MESSAGE_IF_H 
#endif
// End: added by script change_export_macros.sh.

class abs_eap_general_settings_message_c;

/** @file */

/// This class is the common part of EAP message interface.
/// This class is interface to the message creation and parsing function.
class EAP_CLASS_VISIBILITY_EAP_AM_MESSAGE_IF_H eap_am_message_if_c
{

private:

	// ----------------------------------------------------------------------

public:

	virtual ~eap_am_message_if_c()
	{
	}

	virtual bool get_is_valid() = 0;

	virtual void set_partner(abs_eap_am_message_if_c * const client) = 0;

	/// Function receives the data message from lower layer.
	/// Data is formatted to Attribute-Value Pairs.
	/// Look at eap_tlv_header_c and eap_tlv_message_data_c.
	virtual eap_status_e process_data(const void * const data, const u32_t length) = 0;

	// This is documented in abs_eap_stack_interface_c::configure().
	virtual eap_status_e configure(
		const eap_variable_data_c * const client_configuration) = 0;

	// This is documented in abs_eap_stack_interface_c::shutdown().
	virtual eap_status_e shutdown() = 0;

	static eap_am_message_if_c * new_eap_am_server_message_if_c(
		abs_eap_am_tools_c * const tools,
		const bool is_client_when_true,
		const u32_t MTU);

	static eap_am_message_if_c * new_eap_plugin_server_message_if_c(
		abs_eap_am_tools_c * const tools);

	static eap_am_message_if_c * new_eap_am_server_general_settings_c(
		abs_eap_am_tools_c * const tools);

	static eap_am_message_if_c * new_eap_general_settings_server_message_if_c(
		abs_eap_am_tools_c * const tools);

	static eap_am_message_if_c * new_eap_am_message_if_c(
		abs_eap_am_tools_c * const tools);
	
	// ----------------------------------------------------------------------
};

EAP_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_H eap_am_message_if_c * new_eap_am_client_message_if_c(
	abs_eap_am_tools_c * const tools,
	const bool is_client_when_true,
	const u32_t MTU);


#endif //#if !defined(_EAP_AM_MESSAGE_IF_H_)


//--------------------------------------------------
// End
