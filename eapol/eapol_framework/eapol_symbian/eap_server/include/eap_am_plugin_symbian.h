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
* %version: 23 %
*/

#if !defined(_EAP_AM_PLUGIN_SYMBIAN_H_)
#define _EAP_AM_PLUGIN_SYMBIAN_H_

#include "eap_tools.h"
#include "eap_status.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_PLUGIN_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_PLUGIN_SYMBIAN_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_PLUGIN_SYMBIAN_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_PLUGIN_SYMBIAN_H 
	#define EAP_FUNC_EXPORT_EAP_AM_PLUGIN_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_PLUGIN_SYMBIAN_H 
#elif defined(EAP_EXPORT_EAP_AM_PLUGIN_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_PLUGIN_SYMBIAN_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_PLUGIN_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_PLUGIN_SYMBIAN_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_PLUGIN_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_PLUGIN_SYMBIAN_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_PLUGIN_SYMBIAN_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_PLUGIN_SYMBIAN_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_PLUGIN_SYMBIAN_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_PLUGIN_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_PLUGIN_SYMBIAN_H 
#endif
// End: added by script change_export_macros.sh.
#if defined(USE_FAST_EAP_TYPE)
	#include "AbsPacStoreInitializer.h"
#endif //#if defined(USE_FAST_EAP_TYPE)
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
class EAP_CLASS_VISIBILITY_EAP_AM_PLUGIN_SYMBIAN_H eap_am_plugin_symbian_c
: public eap_am_plugin_c
#if defined(USE_FAST_EAP_TYPE)
, public AbsPacStoreInitializer
#endif //#if defined(USE_FAST_EAP_TYPE)
{

private:

	// ----------------------------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	abs_eap_am_plugin_c * m_partner;

	eap_array_c<eap_loaded_type_c> m_loaded_types;

	eap_method_settings_c * m_internal_settings;

	eap_tlv_message_type_function_e m_completion_function;

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

#if defined(USE_FAST_EAP_TYPE)
	eap_status_e initialize_pac_store(
		const eap_method_settings_c * const internal_settings,
		const eap_tlv_message_type_function_e completion_function);
#endif //#if defined(USE_FAST_EAP_TYPE)

	eap_status_e internal_complete_get_configuration(const eap_method_settings_c * const internal_settings);

	eap_status_e internal_complete_set_configuration(const eap_method_settings_c * const internal_settings);

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


#if defined(USE_FAST_EAP_TYPE)

	TInt CompleteInitialisePacStore();

#endif //#if defined(USE_FAST_EAP_TYPE)


	// ----------------------------------------------------------------------
};

#endif //#if !defined(_EAP_AM_PLUGIN_SYMBIAN_H_)


//--------------------------------------------------
// End
