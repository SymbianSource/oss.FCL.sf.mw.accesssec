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
* %version: 34 %
*/

#include "eap_tools.h"
#include "eap_status.h"
#include "eap_am_export.h"
#include "eap_expanded_type.h"
#include "eap_array.h"
#include "eap_database_reference_if.h"
#include "eap_am_plugin_symbian.h"
#include "eap_automatic_variable.h"
#include <EapTypePlugin.h>
#include <EapSettings.h>
#include <EapTypeInfo.h>
#include "EapConversion.h"
#include "abs_eap_am_plugin.h"
#include "AbsPacStoreInitializer.h"

/** @file */

// ----------------------------------------------------------------------

eap_am_plugin_symbian_c::eap_am_plugin_symbian_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_am_plugin_c * const partner)
	: m_am_tools(tools)
	, m_partner(partner)
	, m_loaded_types(tools)
	, m_internal_settings(0)
	, m_completion_function(eap_tlv_message_type_function_none)
	, m_is_valid(false)
	, m_shutdown_was_called(false)
{
	if (m_am_tools == 0
		|| m_am_tools->get_is_valid() == false
		|| m_partner == 0)
	{
		return;
	}

	m_is_valid = true;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_plugin_symbian_c::eap_am_plugin_symbian_c(): this=0x%08x.\n"),
		this));
}

// ----------------------------------------------------------------------

eap_am_plugin_symbian_c::~eap_am_plugin_symbian_c()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_plugin_symbian_c::~eap_am_plugin_symbian_c(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_plugin_symbian_c::~eap_am_plugin_symbian_c()");

	EAP_ASSERT(m_shutdown_was_called == true);

	delete m_internal_settings;
	m_internal_settings = 0;
}

// ----------------------------------------------------------------------

bool eap_am_plugin_symbian_c::get_is_valid()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_plugin_symbian_c::get_is_valid(): this=0x%08x, m_is_valid=%d.\n"),
		this,
		m_is_valid));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_plugin_symbian_c::get_is_valid()");

	return m_is_valid;
}

// ----------------------------------------------------------------------

// This is documented in abs_eap_stack_interface_c::configure().
eap_status_e eap_am_plugin_symbian_c::configure()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_plugin_symbian_c::configure(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_plugin_symbian_c::configure()");

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

// ----------------------------------------------------------------------

// This is documented in abs_eap_stack_interface_c::shutdown().
eap_status_e eap_am_plugin_symbian_c::shutdown()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_plugin_symbian_c::shutdown(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_plugin_symbian_c::shutdown()");

	m_shutdown_was_called = true;

	delete m_internal_settings;
	m_internal_settings = 0;

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

// ----------------------------------------------------------------------

eap_status_e eap_am_plugin_symbian_c::error_complete(
	const eap_status_e completion_status,
	const eap_method_settings_c * const internal_settings,
	const eap_tlv_message_type_function_e error_completion_function)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_plugin_symbian_c::error_complete(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_plugin_symbian_c::error_complete()");

	eap_method_settings_c * const complete_settings = new eap_method_settings_c(m_am_tools, internal_settings);

	eap_automatic_variable_c<eap_method_settings_c> automatic_complete_settings(
		m_am_tools,
		complete_settings);

	if (complete_settings == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	complete_settings->m_completion_status = completion_status;

	eap_status_e status(eap_status_not_supported);

	switch(error_completion_function)
	{
	case eap_tlv_message_type_function_plugin_complete_get_configuration:
		status = m_partner->complete_get_configuration(complete_settings);
		break;
	case eap_tlv_message_type_function_plugin_complete_set_configuration:
		status = m_partner->complete_set_configuration(complete_settings);
		break;
	case eap_tlv_message_type_function_plugin_complete_copy_configuration:
		status = m_partner->complete_copy_configuration(complete_settings);
		break;
	case eap_tlv_message_type_function_plugin_complete_delete_configuration:
		status = m_partner->complete_delete_configuration(complete_settings);
		break;
	case eap_tlv_message_type_function_plugin_complete_set_index:
		status = m_partner->complete_set_index(complete_settings);
		break;
	case eap_tlv_message_type_function_plugin_complete_get_type_info:
		status = m_partner->complete_get_type_info(complete_settings);
		break;

	default:
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: eap_am_plugin_symbian_c::error_complete(): unknown function %d.\n"),
			 error_completion_function));

		EAP_ASSERT_ANYWAY_TOOLS(m_am_tools);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

// ----------------------------------------------------------------------

CEapTypePlugin * eap_am_plugin_symbian_c::get_eap_type(
	const eap_type_value_e eap_type,
	u32_t index_type,
	u32_t index)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_plugin_symbian_c::get_eap_type(): this=0x%08x, index_type=%d, index=%d, EAP-type=0xfe%06x%08x.\n"),
		this,
		index_type,
		index,
		eap_type.get_vendor_id(),
		eap_type.get_vendor_type()));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_plugin_symbian_c::get_eap_type()");

	CEapTypePlugin *eap_plugin = 0;

	eap_loaded_type_c search(
		m_am_tools,
		0,
		eap_type,
		index_type,
		index);

	i32_t found_index = find<eap_loaded_type_c>(&m_loaded_types, &search, m_am_tools);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_plugin_symbian_c::get_eap_type(): this=0x%08x, found_index=%d.\n"),
		this,
		found_index));

	if (found_index >= 0)
	{
		// OK, EAP-type for index_type and index is already loaded.
		eap_loaded_type_c * const loaded_type = m_loaded_types.get_object(found_index);
		if (loaded_type == 0)
		{
			(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			return 0;
		}

		eap_plugin = loaded_type->get_type_plugin();

		return eap_plugin;
	}
	else
	{
		// Load a new instance of EAP-type.

		TEapExpandedType expanded_type;

		eap_variable_data_c eap_data(m_am_tools);

		eap_status_e status = eap_type.get_expanded_type_data(
			m_am_tools,
			&eap_data);
		if (status != eap_status_ok)
		{
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return 0;
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_data"),
			eap_data.get_data(),
			eap_data.get_data_length()));

		TInt error = expanded_type.SetValue(
			eap_data.get_data(),
			eap_data.get_data_length());
		if (error != KErrNone)
		{
			(void) EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));
			return 0;
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("expanded_type.GetValue()"),
			expanded_type.GetValue().Ptr(),
			expanded_type.GetValue().Length()));

		TIndexType IndexType(static_cast<TIndexType>(index_type));
		TUint Index(static_cast<TUint>(index));

		TRAP(error, (eap_plugin = CEapTypePlugin::NewL(
			expanded_type.GetValue(),
			IndexType,
			Index,
			m_am_tools)));
		if (error != KErrNone
			|| eap_plugin == 0)
		{
			// Interface not found or implementation creation function failed
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: ECom could not find/initiate implementation for EAP-type=0xfe%06x%08x, index_type=%d, index=%d, error = %d.\n"),
				eap_type.get_vendor_id(),
				eap_type.get_vendor_type(),
				index_type,
				index,
				error));
			(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			return 0;
		}

		eap_loaded_type_c * const new_eap_plugin = new eap_loaded_type_c(
			m_am_tools,
			eap_plugin,
			eap_type,
			index_type,
			index);
		if (new_eap_plugin == 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: Could not allocate EAP-type=0xfe%06x%08x, index_type=%d, index=%d.\n"),
				eap_type.get_vendor_id(),
				eap_type.get_vendor_type(),
				index_type,
				index));
			(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			delete eap_plugin;
			return 0;
		}

		status = m_loaded_types.add_object(
			new_eap_plugin,
			true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: Could not add EAP-type=0xfe%06x%08x, index_type=%d, index=%d to array.\n"),
				eap_type.get_vendor_id(),
				eap_type.get_vendor_type(),
				index_type,
				index));
			(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			return 0;
		}

		return eap_plugin;
	}
}

// ----------------------------------------------------------------------

#if defined(USE_FAST_EAP_TYPE)

eap_status_e eap_am_plugin_symbian_c::initialize_pac_store(
	const eap_method_settings_c * const internal_settings,
	const eap_tlv_message_type_function_e completion_function)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_plugin_symbian_c::initialize_pac_store(): this=0x%08x, completion_function=%d=%s.\n"),
		this,
		completion_function,
		eap_process_tlv_message_data_c::get_function_string(completion_function)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_plugin_symbian_c::initialize_pac_store()");

	if (m_completion_function != eap_tlv_message_type_function_none)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: eap_am_plugin_symbian_c::initialize_pac_store(): this=0x%08x, m_completion_function=%d=%s\n"),
			this,
			m_completion_function,
			eap_process_tlv_message_data_c::get_function_string(m_completion_function)));
		EAP_ASSERT_ANYWAY_TOOLS(m_am_tools);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	delete m_internal_settings;

	m_internal_settings = new eap_method_settings_c(
		m_am_tools,
		internal_settings);
	if (m_internal_settings == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	CEapTypePlugin* const eapType = get_eap_type(internal_settings->m_EAPType, internal_settings->m_IndexType, internal_settings->m_Index);
	if (eapType == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	m_completion_function = completion_function;

	TInt error = eapType->InitialisePacStore(this);
	if (error == KErrCompletion)
	{
		// This is asynchronous call which will be completed by CompleteInitialisePacStore() function.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_pending_request);
	}
	else if (error != KErrNone)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			m_am_tools->convert_am_error_to_eapol_error(error));
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
}

#endif //#if defined(USE_FAST_EAP_TYPE)

// ----------------------------------------------------------------------

eap_status_e eap_am_plugin_symbian_c::get_configuration(const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_plugin_symbian_c::get_configuration(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_plugin_symbian_c::get_configuration()");

	eap_status_e status(eap_status_ok);

	delete m_internal_settings;
	m_internal_settings = 0;

#if defined(USE_FAST_EAP_TYPE)

	if (internal_settings->m_EAPType == eap_type_fast)
	{
		const eap_tlv_message_type_function_e error_completion_function(eap_tlv_message_type_function_plugin_complete_get_configuration);

		status = initialize_pac_store(
			internal_settings,
			error_completion_function);
		if (status == eap_status_pending_request)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(
				m_am_tools,
				error_complete(
					eap_status_illegal_parameter,
					internal_settings,
					error_completion_function));
		}
	}

#endif //#if defined(USE_FAST_EAP_TYPE)


	status = internal_complete_get_configuration(internal_settings);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

// ----------------------------------------------------------------------

eap_status_e eap_am_plugin_symbian_c::internal_complete_get_configuration(const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_plugin_symbian_c::internal_complete_get_configuration(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_plugin_symbian_c::internal_complete_get_configuration()");

	const eap_tlv_message_type_function_e error_completion_function(eap_tlv_message_type_function_plugin_complete_get_configuration);

	eap_status_e status(eap_status_ok);
	TInt error(KErrNone);

	CEapTypePlugin* const eapType = get_eap_type(internal_settings->m_EAPType, internal_settings->m_IndexType, internal_settings->m_Index);
	if (eapType == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	if (internal_settings->m_TunnelingTypePresent == true)
	{
		TEapExpandedType aExpandedType;
    
		TInt err = CEapConversion::ConvertInternalTypeToExpandedEAPType(
				&(internal_settings->m_TunnelingType),
				&aExpandedType);

		eapType->SetTunnelingType(aExpandedType);
	}

	EAPSettings * local_settings = new EAPSettings;

	eap_automatic_variable_c<EAPSettings> automatic_aSettings(
		m_am_tools,
		local_settings);

	if (local_settings == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	TRAP(error, (eapType->GetConfigurationL(*local_settings)));
	if (error != KErrNone)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: Cannot read configuration from EAP-type=0xfe%06x%08x, index_type=%d, index=%d.\n"),
			internal_settings->m_EAPType.get_vendor_id(),
			internal_settings->m_EAPType.get_vendor_type(),
			internal_settings->m_IndexType,
			internal_settings->m_Index));

		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	eap_method_settings_c * const complete_settings = new eap_method_settings_c(m_am_tools);

	eap_automatic_variable_c<eap_method_settings_c> automatic_complete_settings(
		m_am_tools,
		complete_settings);

	if (complete_settings == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	complete_settings->m_EAPType = internal_settings->m_EAPType;
	complete_settings->m_IndexType = internal_settings->m_IndexType;
	complete_settings->m_Index = internal_settings->m_Index;
	complete_settings->m_completion_status = eap_status_ok;

	error = CEapConversion::ConvertEAPSettingsToInternalType(
		m_am_tools,
		local_settings,
		complete_settings);
	if (error != KErrNone)
	{
		complete_settings->m_completion_status = m_am_tools->convert_am_error_to_eapol_error(error);

		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	status = m_partner->complete_get_configuration(complete_settings);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

// ----------------------------------------------------------------------

eap_status_e eap_am_plugin_symbian_c::set_configuration(const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_plugin_symbian_c::set_configuration(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_plugin_symbian_c::set_configuration()");

	eap_status_e status(eap_status_ok);

	delete m_internal_settings;
	m_internal_settings = 0;

#if defined(USE_FAST_EAP_TYPE)

	if (internal_settings->m_EAPType == eap_type_fast)
	{
		const eap_tlv_message_type_function_e error_completion_function(eap_tlv_message_type_function_plugin_complete_set_configuration);

		status = initialize_pac_store(
			internal_settings,
			error_completion_function);
		if (status == eap_status_pending_request)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(
				m_am_tools,
				error_complete(
					eap_status_illegal_parameter,
					internal_settings,
					error_completion_function));
		}
	}

#endif //#if defined(USE_FAST_EAP_TYPE)


	status = internal_complete_set_configuration(internal_settings);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

// ----------------------------------------------------------------------

eap_status_e eap_am_plugin_symbian_c::internal_complete_set_configuration(const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_plugin_symbian_c::set_configuration(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_plugin_symbian_c::set_configuration()");

	const eap_tlv_message_type_function_e error_completion_function(eap_tlv_message_type_function_plugin_complete_set_configuration);

	CEapTypePlugin* const eapType = get_eap_type(internal_settings->m_EAPType, internal_settings->m_IndexType, internal_settings->m_Index);
	if (eapType == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	if (internal_settings->m_TunnelingTypePresent == true)
	{
		TEapExpandedType aExpandedType;
    
		TInt err = CEapConversion::ConvertInternalTypeToExpandedEAPType(
				&(internal_settings->m_TunnelingType),
				&aExpandedType);

		eapType->SetTunnelingType(aExpandedType);
	}

	EAPSettings * local_settings = new EAPSettings;

	eap_automatic_variable_c<EAPSettings> automatic_aSettings(
		m_am_tools,
		local_settings);

	if (local_settings == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	TInt error = CEapConversion::ConvertInternalTypeToEAPSettings(
		m_am_tools,
		internal_settings,
		local_settings);
	if (error != KErrNone)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	TRAP(error, (eapType->SetConfigurationL(*local_settings)));
	if (error != KErrNone)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: Cannot write configuration to EAP-type=0xfe%06x%08x, index_type=%d, index=%d.\n"),
			internal_settings->m_EAPType.get_vendor_id(),
			internal_settings->m_EAPType.get_vendor_type(),
			internal_settings->m_IndexType,
			internal_settings->m_Index));

		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	eap_method_settings_c * const complete_settings = new eap_method_settings_c(m_am_tools, internal_settings);

	eap_automatic_variable_c<eap_method_settings_c> automatic_complete_settings(
		m_am_tools,
		complete_settings);

	if (complete_settings == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	complete_settings->m_completion_status = eap_status_ok;

	eap_status_e status = m_partner->complete_set_configuration(complete_settings);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

// ----------------------------------------------------------------------

eap_status_e eap_am_plugin_symbian_c::copy_configuration(const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_plugin_symbian_c::set_configuration(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_plugin_symbian_c::set_configuration()");

	const eap_tlv_message_type_function_e error_completion_function(eap_tlv_message_type_function_plugin_complete_copy_configuration);

	CEapTypePlugin* const eapType = get_eap_type(internal_settings->m_EAPType, internal_settings->m_IndexType, internal_settings->m_Index);
	if (eapType == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	if (internal_settings->m_TunnelingTypePresent == true)
	{
		TEapExpandedType aExpandedType;
    
		TInt err = CEapConversion::ConvertInternalTypeToExpandedEAPType(
				&(internal_settings->m_TunnelingType),
				&aExpandedType);

		eapType->SetTunnelingType(aExpandedType);
	}

	EAPSettings * local_settings = new EAPSettings;

	eap_automatic_variable_c<EAPSettings> automatic_aSettings(
		m_am_tools,
		local_settings);

	if (local_settings == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	TInt error = CEapConversion::ConvertInternalTypeToEAPSettings(
		m_am_tools,
		internal_settings,
		local_settings);
	if (error != KErrNone)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	if (internal_settings->m_DestinationIndexAndTypePresent == false)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_illegal_parameter,
				internal_settings,
				error_completion_function));
	}

	TIndexType aDestinationIndexType(static_cast<TIndexType>(internal_settings->m_DestinationIndexType));
	TUint aDestinationIndex(static_cast<TUint>(internal_settings->m_DestinationIndex));

	TRAP(error, (eapType->CopySettingsL(
		aDestinationIndexType, 
		aDestinationIndex)));
	if (error != KErrNone)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: Cannot copy configuration from EAP-type=0xfe%06x%08x, (index_type=%d, index=%d) to (index_type=%d, index=%d).\n"),
			internal_settings->m_EAPType.get_vendor_id(),
			internal_settings->m_EAPType.get_vendor_type(),
			internal_settings->m_IndexType,
			internal_settings->m_Index,
			internal_settings->m_DestinationIndexType,
			internal_settings->m_DestinationIndex));

		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	eap_method_settings_c * const complete_settings = new eap_method_settings_c(m_am_tools, internal_settings);

	eap_automatic_variable_c<eap_method_settings_c> automatic_complete_settings(
		m_am_tools,
		complete_settings);

	if (complete_settings == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	complete_settings->m_completion_status = eap_status_ok;

	eap_status_e status = m_partner->complete_copy_configuration(complete_settings);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

// ----------------------------------------------------------------------

eap_status_e eap_am_plugin_symbian_c::delete_configuration(const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_plugin_symbian_c::delete_configuration(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_plugin_symbian_c::delete_configuration()");

	const eap_tlv_message_type_function_e error_completion_function(eap_tlv_message_type_function_plugin_complete_delete_configuration);

	CEapTypePlugin* const eapType = get_eap_type(internal_settings->m_EAPType, internal_settings->m_IndexType, internal_settings->m_Index);
	if (eapType == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	if (internal_settings->m_TunnelingTypePresent == true)
	{
		TEapExpandedType aExpandedType;
    
		TInt err = CEapConversion::ConvertInternalTypeToExpandedEAPType(
				&(internal_settings->m_TunnelingType),
				&aExpandedType);

		eapType->SetTunnelingType(aExpandedType);
	}

	EAPSettings * local_settings = new EAPSettings;

	eap_automatic_variable_c<EAPSettings> automatic_aSettings(
		m_am_tools,
		local_settings);

	if (local_settings == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	TInt error = CEapConversion::ConvertInternalTypeToEAPSettings(
		m_am_tools,
		internal_settings,
		local_settings);
	if (error != KErrNone)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	TRAP(error, (eapType->DeleteConfigurationL()));
	if (error != KErrNone)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: Cannot delete configuration from EAP-type=0xfe%06x%08x, (index_type=%d, index=%d).\n"),
			internal_settings->m_EAPType.get_vendor_id(),
			internal_settings->m_EAPType.get_vendor_type(),
			internal_settings->m_IndexType,
			internal_settings->m_Index));

		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	eap_method_settings_c * const complete_settings = new eap_method_settings_c(m_am_tools, internal_settings);

	eap_automatic_variable_c<eap_method_settings_c> automatic_complete_settings(
		m_am_tools,
		complete_settings);

	if (complete_settings == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	complete_settings->m_completion_status = eap_status_ok;

	eap_status_e status = m_partner->complete_delete_configuration(complete_settings);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

// ----------------------------------------------------------------------

eap_status_e eap_am_plugin_symbian_c::set_index(const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_plugin_symbian_c::set_index(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_plugin_symbian_c::set_index()");

	const eap_tlv_message_type_function_e error_completion_function(eap_tlv_message_type_function_plugin_complete_set_index);

	CEapTypePlugin* const eapType = get_eap_type(internal_settings->m_EAPType, internal_settings->m_IndexType, internal_settings->m_Index);
	if (eapType == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	if (internal_settings->m_TunnelingTypePresent == true)
	{
		TEapExpandedType aExpandedType;
    
		TInt err = CEapConversion::ConvertInternalTypeToExpandedEAPType(
				&(internal_settings->m_TunnelingType),
				&aExpandedType);

		eapType->SetTunnelingType(aExpandedType);
	}

	EAPSettings * local_settings = new EAPSettings;

	eap_automatic_variable_c<EAPSettings> automatic_aSettings(
		m_am_tools,
		local_settings);

	if (local_settings == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	TInt error = CEapConversion::ConvertInternalTypeToEAPSettings(
		m_am_tools,
		internal_settings,
		local_settings);
	if (error != KErrNone)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	if (internal_settings->m_DestinationIndexAndTypePresent == false)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_illegal_parameter,
				internal_settings,
				error_completion_function));
	}

	TIndexType aDestinationIndexType(static_cast<TIndexType>(internal_settings->m_DestinationIndexType));
	TUint aDestinationIndex(static_cast<TUint>(internal_settings->m_DestinationIndex));

	TRAP(error, (eapType->SetIndexL(
		aDestinationIndexType, 
		aDestinationIndex)));
	if (error != KErrNone)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: Cannot copy configuration from EAP-type=0xfe%06x%08x, (index_type=%d, index=%d) to (index_type=%d, index=%d).\n"),
			internal_settings->m_EAPType.get_vendor_id(),
			internal_settings->m_EAPType.get_vendor_type(),
			internal_settings->m_IndexType,
			internal_settings->m_Index,
			internal_settings->m_DestinationIndexType,
			internal_settings->m_DestinationIndex));

		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	eap_method_settings_c * const complete_settings = new eap_method_settings_c(m_am_tools, internal_settings);

	eap_automatic_variable_c<eap_method_settings_c> automatic_complete_settings(
		m_am_tools,
		complete_settings);

	if (complete_settings == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	complete_settings->m_completion_status = eap_status_ok;

	eap_status_e status = m_partner->complete_set_index(complete_settings);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

// ----------------------------------------------------------------------

eap_status_e eap_am_plugin_symbian_c::get_type_info(const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_plugin_symbian_c::get_type_info(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_plugin_symbian_c::get_type_info()");

	const eap_tlv_message_type_function_e error_completion_function(eap_tlv_message_type_function_plugin_complete_get_type_info);

	CEapTypePlugin* const eapType = get_eap_type(internal_settings->m_EAPType, internal_settings->m_IndexType, internal_settings->m_Index);
	if (eapType == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	if (internal_settings->m_TunnelingTypePresent == true)
	{
		TEapExpandedType aExpandedType;
    
		TInt err = CEapConversion::ConvertInternalTypeToExpandedEAPType(
				&(internal_settings->m_TunnelingType),
				&aExpandedType);

		eapType->SetTunnelingType(aExpandedType);
	}

	EAPSettings * local_settings = new EAPSettings;

	eap_automatic_variable_c<EAPSettings> automatic_aSettings(
		m_am_tools,
		local_settings);

	if (local_settings == 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	TInt error = CEapConversion::ConvertInternalTypeToEAPSettings(
		m_am_tools,
		internal_settings,
		local_settings);
	if (error != KErrNone)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	if (internal_settings->m_DestinationIndexAndTypePresent == false)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_illegal_parameter,
				internal_settings,
				error_completion_function));
	}

	CEapTypeInfo * type_info = 0;

	TRAP(error, (type_info = eapType->GetInfoL()));
	if (error != KErrNone
		|| type_info == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: Cannot get type info configuration from EAP-type=0xfe%06x%08x, (index_type=%d, index=%d).\n"),
			internal_settings->m_EAPType.get_vendor_id(),
			internal_settings->m_EAPType.get_vendor_type(),
			internal_settings->m_IndexType,
			internal_settings->m_Index));

		if (type_info != 0)
		{
			delete type_info;
			type_info = 0;
		}

		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	eap_method_settings_c * const complete_settings = new eap_method_settings_c(m_am_tools, internal_settings);

	eap_automatic_variable_c<eap_method_settings_c> automatic_complete_settings(
		m_am_tools,
		complete_settings);

	if (complete_settings == 0)
	{
		delete type_info;
		type_info = 0;
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				eap_status_allocation_error,
				internal_settings,
				error_completion_function));
	}

	error = CEapConversion::ConvertFromTDesCToInternal(
		m_am_tools,
		type_info->ReleaseDate(),
		&(complete_settings->m_KReleaseDate));

	if(error == KErrNone)
	{
		error = CEapConversion::ConvertFromTDesCToInternal(
			m_am_tools,
			type_info->Version(),
			&(complete_settings->m_KEapTypeVersion));
	}

	if(error == KErrNone)
	{
		error = CEapConversion::ConvertFromTDesCToInternal(
			m_am_tools,
			type_info->Manufacturer(),
			&(complete_settings->m_KManufacturer));
	}

	delete type_info;
	type_info = 0;

	if(error != KErrNone)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			error_complete(
				m_am_tools->convert_am_error_to_eapol_error(error),
				internal_settings,
				error_completion_function));
	}

	complete_settings->m_completion_status = eap_status_ok;

	eap_status_e status = m_partner->complete_get_type_info(complete_settings);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_FAST_EAP_TYPE)

TInt eap_am_plugin_symbian_c::CompleteInitialisePacStore()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("this = 0x%08x, message_function: starts: eap_am_plugin_symbian_c::CompleteInitialisePacStore(), completion_function=%d=%s\n"),
		 this,
		 m_completion_function,
		 eap_process_tlv_message_data_c::get_function_string(m_completion_function)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_plugin_symbian_c::CompleteInitialisePacStore()");

	eap_status_e status(eap_status_process_general_error);

	const eap_tlv_message_type_function_e completion_function = m_completion_function;
	m_completion_function = eap_tlv_message_type_function_none;

	switch (completion_function)
	{
	case eap_tlv_message_type_function_plugin_complete_get_configuration:
		status = internal_complete_get_configuration(m_internal_settings);
		break;
	case eap_tlv_message_type_function_plugin_complete_set_configuration:
		status = internal_complete_set_configuration(m_internal_settings);
		break;
	default:
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: this = 0x%08x, message_function: starts: eap_am_plugin_symbian_c::CompleteInitialisePacStore(), Illegal completion_function=%d=%s\n"),
			 this,
			 completion_function,
			 eap_process_tlv_message_data_c::get_function_string(completion_function)));
		EAP_ASSERT_ANYWAY_TOOLS(m_am_tools);
		break;
	}

	delete m_internal_settings;
	m_internal_settings = 0;

	return m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status));
}

#endif //#if defined(USE_FAST_EAP_TYPE)

// ----------------------------------------------------------------------
// End
