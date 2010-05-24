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
	#define EAP_FILE_NUMBER_ENUM 12 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eapol_key_types.h"
#include "eap_am_network_id.h"


//--------------------------------------------------

eap_am_network_id_c::eap_am_network_id_impl_str::~eap_am_network_id_impl_str()
{
}

//--------------------------------------------------

eap_am_network_id_c::eap_am_network_id_impl_str::eap_am_network_id_impl_str(
	abs_eap_am_tools_c * const tools)
	: m_source(tools)
	, m_destination(tools)
	, m_type(eapol_ethernet_type_none)
	, m_is_valid(false)
{
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

// 
eap_status_e eap_am_network_id_c::initialize_members()
{
	m_data = new eap_am_network_id_impl_str(m_am_tools);
	if (m_data == 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_network_id_c::initialize_members(): Cannot allocate %d bytes.\n"),
			sizeof(eap_am_network_id_impl_str)));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_am_network_id_c::~eap_am_network_id_c()
{
	if (m_data != 0)
	{
		delete m_data;
		m_data = 0;
	}
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_am_network_id_c::eap_am_network_id_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_data(0)
{
	eap_status_e status = initialize_members();
	if (status != eap_status_ok)
	{
		// ERROR.
		return;
	}

	set_is_valid();
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_am_network_id_c::eap_am_network_id_c(
	abs_eap_am_tools_c * const tools,
	const void * const source,
	const u32_t source_length,
	const void * const destination,
	const u32_t destination_length,
	const u16_t type,
	const bool free_id,
	const bool writable_id)
	: m_am_tools(tools)
	, m_data(0)
{
	eap_status_e status = initialize_members();
	if (status != eap_status_ok)
	{
		// ERROR.
		return;
	}

	status = m_data->m_source.set_buffer(
		source,
		source_length,
		free_id,
		writable_id);
	if (status != eap_status_ok
		|| m_data->m_source.get_is_valid_data() == false)
	{
		return;
	}

	status = m_data->m_destination.set_buffer(
		destination,
		destination_length,
		free_id,
		writable_id);
	if (status != eap_status_ok
		|| m_data->m_destination.get_is_valid_data() == false)
	{
		return;
	}

	m_data->m_type = type;

	set_is_valid();
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_am_network_id_c::eap_am_network_id_c(
	abs_eap_am_tools_c * const tools,
	const eap_variable_data_c * const source,
	const eap_variable_data_c * const destination,
	const u16_t type)
	: m_am_tools(tools)
	, m_data(0)
{
	eap_status_e status = initialize_members();
	if (status != eap_status_ok)
	{
		// ERROR.
		return;
	}

	status = m_data->m_source.set_buffer(
		source->get_data(source->get_data_length()),
		source->get_data_length(),
		false,
		false);
	if (status != eap_status_ok
		|| m_data->m_source.get_is_valid_data() == false)
	{
		return;
	}

	status = m_data->m_destination.set_buffer(
		destination->get_data(destination->get_data_length()),
		destination->get_data_length(),
		false,
		false);
	if (status != eap_status_ok
		|| m_data->m_destination.get_is_valid_data() == false)
	{
		return;
	}

	m_data->m_type = type;

	set_is_valid();
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_am_network_id_c::eap_am_network_id_c(
	abs_eap_am_tools_c * const tools,
	const eap_am_network_id_c * const network_id)
	: m_am_tools(tools)
	, m_data(0)
{
	eap_status_e status = initialize_members();
	if (status != eap_status_ok)
	{
		// ERROR.
		return;
	}

	status = m_data->m_source.set_copy_of_buffer(
		network_id->get_source_id());

	if (status != eap_status_ok
		|| m_data->m_source.get_is_valid_data() == false)
	{
		return;
	}

	status = m_data->m_destination.set_copy_of_buffer(
		network_id->get_destination_id());

	if (status != eap_status_ok
		|| m_data->m_destination.get_is_valid_data() == false)
	{
		return;
	}

	m_data->m_type = network_id->get_type();

	set_is_valid();
}


//--------------------------------------------------

// 
EAP_FUNC_EXPORT void eap_am_network_id_c::set_is_valid()
{
	if (m_data != 0)
	{
		m_data->m_is_valid = true;
	}
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eap_am_network_id_c::set_copy_of_network_id(
	const eap_am_network_id_c * const network_id)
{
	eap_status_e status;

	if (get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = m_data->m_source.set_copy_of_buffer(
		network_id->get_source_id());
	if (m_data->m_source.get_is_valid_data() == false)
	{
		return status;
	}

	status = m_data->m_destination.set_copy_of_buffer(
		network_id->get_destination_id());
	if (m_data->m_destination.get_is_valid_data() == false)
	{
		return status;
	}

	m_data->m_type = network_id->get_type();

	return status;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eap_am_network_id_c::set_copy_of_am_network_id(
	const void * const source,
	const u32_t source_length,
	const void * const destination,
	const u32_t destination_length,
	const u16_t type)
{
	if (get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = m_data->m_source.set_copy_of_buffer(
		source,
		source_length);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (m_data->m_source.get_is_valid_data() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = m_data->m_destination.set_copy_of_buffer(
		destination,
		destination_length);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (m_data->m_destination.get_is_valid_data() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	m_data->m_type = type;

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT bool eap_am_network_id_c::get_is_valid() const
{
	if (m_data == 0)
	{
		return false;
	}
	return m_data->m_is_valid;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT bool eap_am_network_id_c::get_is_valid_data() const
{
	return m_data != 0
		&& m_data->m_source.get_is_valid() == true
		&& m_data->m_destination.get_is_valid() == true
		&& m_data->m_type != eapol_ethernet_type_none;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT const eap_variable_data_c * eap_am_network_id_c::get_source_id() const
{
	if (m_data == 0)
	{
		return 0;
	}
	return &(m_data->m_source);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT const u8_t * eap_am_network_id_c::get_source() const
{
	if (m_data == 0
		|| m_data->m_source.get_is_valid_data() == false)
	{
		return 0;
	}
	return m_data->m_source.get_data(m_data->m_source.get_data_length());
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT const eap_variable_data_c * eap_am_network_id_c::get_destination_id() const
{
	if (m_data == 0)
	{
		return 0;
	}
	return &(m_data->m_destination);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT const u8_t * eap_am_network_id_c::get_destination() const
{
	if (m_data == 0
		|| m_data->m_destination.get_is_valid_data() == false)
	{
		return 0;
	}
	return m_data->m_destination.get_data(m_data->m_destination.get_data_length());
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT u32_t eap_am_network_id_c::get_source_length() const
{
	if (m_data == 0
		|| m_data->m_source.get_is_valid_data() == false)
	{
		return 0;
	}
	return m_data->m_source.get_data_length();
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT u32_t eap_am_network_id_c::get_destination_length() const
{
	if (m_data == 0
		|| m_data->m_destination.get_is_valid_data() == false)
	{
		return 0;
	}
	return m_data->m_destination.get_data_length();
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT u16_t eap_am_network_id_c::get_type() const
{
	if (m_data == 0)
	{
		return 0;
	}
	return m_data->m_type;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT const eap_am_network_id_c * eap_am_network_id_c::get_network_id() const
{
	return this;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_am_network_id_c * eap_am_network_id_c::copy() const
{
	if (get_is_valid() == false)
	{
		return 0;
	}

	u8_t *source = new u8_t[get_source_length()];
	if (source == 0
		|| get_source() == 0)
	{
		delete [] source;
		return 0;
	}
	m_am_tools->memmove(source, get_source(), get_source_length());

	u8_t *destination = new u8_t[get_destination_length()];
	if (destination == 0
		|| get_destination() == 0)
	{
		delete [] source;
		delete [] destination;
		return 0;
	}
	m_am_tools->memmove(destination, get_destination(), get_destination_length());

	eap_am_network_id_c * const new_id = new eap_am_network_id_c(
		m_am_tools,
		source,
		get_source_length(),
		destination,
		get_destination_length(),
		get_type(),
		true,
		true);

	if (new_id == 0)
	{
		delete [] source;
		delete [] destination;
		return 0;
	}

	if (new_id->get_is_valid() == false)
	{
		delete new_id;
		return 0;
	}

	return new_id;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT bool eap_am_network_id_c::compare_network_id(const eap_am_network_id_c * const network_id) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("compare_network_id(), NOTE source and destination are compared:\n")));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("p     source"),
		network_id->get_source(),
		network_id->get_source_length()));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("p destination"),
		network_id->get_destination(),
		network_id->get_destination_length()));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("       source"),
		get_source(),
		get_source_length()));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("  destination"),
		get_destination(),
		get_destination_length()));

	if (network_id->get_source_length()
			!= get_source_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_network_id);
		return false;
	}

	if (network_id->get_destination_length()
			!= get_destination_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_network_id);
		return false;
	}

	if (m_am_tools->memcmp(
			network_id->get_source(),
			get_source(),
			network_id->get_source_length()) != 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_network_id);
		return false;
	}

	if (m_am_tools->memcmp(
			network_id->get_destination(),
			get_destination(),
			network_id->get_destination_length()) != 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_network_id);
		return false;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return true;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT void eap_am_network_id_c::set_type(const u16_t type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (get_is_valid() == false)
	{
		return;
	}

	m_data->m_type = type;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT void eap_am_network_id_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (get_is_valid() == false)
	{
		return;
	}

	m_data->m_source.reset();
	m_data->m_destination.reset();

	m_data->m_type = eapol_ethernet_type_none;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------



// End.
