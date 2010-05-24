/*
* Copyright (c) 2009-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  EAP-plugin adaptation.
*
*/

/*
* %version: 16 %
*/

#if !defined(_EAP_AM_PLUGIN_SYMBIAN_H_)
#define _EAP_AM_PLUGIN_SYMBIAN_H_

#include "eap_tools.h"
#include "eap_status.h"
#include "eap_am_export.h"
#include "eap_expanded_type.h"
#include "eap_array.h"
#include "eap_database_reference_if.h"
#include "eap_am_plugin.h"
#include "eap_process_tlv_message_data.h"
#include "eap_loaded_type.h"

class eap_method_settings_c;
class abs_eap_am_plugin_c;
class CEapTypePlugin;

/** @file */

/// This class is EAP-plugin adaptation.
class EAP_EXPORT eap_am_plugin_symbian_c
: public eap_am_plugin_c
{

private:

	// ----------------------------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	abs_eap_am_plugin_c * m_partner;

	eap_array_c<eap_loaded_type_c> m_loaded_types;

	bool m_is_valid;

	bool m_shutdown_was_called;

	// ----------------------------------------------------------------------

	eap_status_e error_complete(
		const eap_status_e completion_status,
		const eap_method_settings_c * const internal_settings,
		const eap_tlv_message_type_function_e completion_function);

	CEapTypePlugin * get_eap_type(
		const eap_type_value_e eap_type,
		u32_t index_type,
		u32_t index);

	// ----------------------------------------------------------------------

public:

	// ----------------------------------------------------------------------

	eap_am_plugin_symbian_c(
		abs_eap_am_tools_c * const tools,
		abs_eap_am_plugin_c * const partner);

	virtual ~eap_am_plugin_symbian_c();

	bool get_is_valid();

	// This is documented in abs_eap_stack_interface_c::configure().
	eap_status_e configure();

	// This is documented in abs_eap_stack_interface_c::shutdown().
	eap_status_e shutdown();

	eap_status_e get_configuration(const eap_method_settings_c * const internal_settings);

	eap_status_e set_configuration(const eap_method_settings_c * const internal_settings);

	eap_status_e copy_configuration(const eap_method_settings_c * const internal_settings);

	eap_status_e delete_configuration(const eap_method_settings_c * const internal_settings);

	eap_status_e set_index(const eap_method_settings_c * const internal_settings);

	eap_status_e get_type_info(const eap_method_settings_c * const internal_settings);



	// ----------------------------------------------------------------------
};

#endif //#if !defined(_EAP_AM_PLUGIN_SYMBIAN_H_)


//--------------------------------------------------
// End
