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

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 30 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_export.h"
#include "eap_variable_data.h"
#include "eap_network_id_selector.h"


//--------------------------------------------------

EAP_FUNC_EXPORT eap_network_id_selector_c::~eap_network_id_selector_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_network_id_selector_c::eap_network_id_selector_c(
	abs_eap_am_tools_c * const tools)
	: eap_variable_data_c(tools)
	, m_am_tools(tools)
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_network_id_selector_c::eap_network_id_selector_c(
	abs_eap_am_tools_c * const tools,
	const eap_am_network_id_c * const network_id)
	: eap_variable_data_c(tools)
	  , m_am_tools(tools)
{
	if (eap_variable_data_c::get_is_valid() == false)
	{
		return;
	}

	eap_status_e status = set_selector(network_id);
	if (status != eap_status_ok)
	{
		return;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_network_id_selector_c::set_selector(
	const eap_am_network_id_c * const network_id)
{
	eap_status_e status = eap_status_process_general_error;

	if (network_id == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	
	// Pre-allocates buffer for ID.
	status = set_buffer_length(network_id->get_source_id()->get_data_length() + network_id->get_destination_id()->get_data_length());
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_copy_of_buffer(network_id->get_source_id());
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	status = add_data(network_id->get_destination_id());
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_network_id_selector_c::eap_network_id_selector_c(
	abs_eap_am_tools_c * const tools,
	const eap_network_id_selector_c * const selector)
	: eap_variable_data_c(tools)
	  , m_am_tools(tools)
{
	eap_status_e status = set_copy_of_buffer(
		selector->get_data(selector->get_data_length()),
		selector->get_data_length());
	if (status != eap_status_ok)
	{
		return;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_network_id_selector_c * eap_network_id_selector_c::copy() const
{
	eap_network_id_selector_c * const new_selector
		= new eap_network_id_selector_c(m_am_tools, this);
	
	return new_selector;
}

//--------------------------------------------------



// End.
