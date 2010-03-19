/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/ec_cs_data.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 8 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.1.1
*/

// This is enumeration of WAPI source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 701 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#if defined(USE_WAPI_CORE)

#include "eap_automatic_variable.h"
#include "ec_cs_types.h"
#include "ec_cs_data.h"
#include "ec_cs_strings.h"

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT ec_cs_data_c::~ec_cs_data_c()
{
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT ec_cs_data_c::ec_cs_data_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_change_status(ec_cs_data_change_status_none)
	, m_type(ec_cs_data_type_none)
	, m_reference(tools)
	, m_data(tools)
	, m_data_references_read(false)
{
	eap_status_e status = m_reference.set_copy_of_buffer(
		EC_CS_ZERO_REFERENCE,
		sizeof(EC_CS_ZERO_REFERENCE));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, status);
		return;
	}
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT bool ec_cs_data_c::get_is_valid() const
{
	return(m_reference.get_is_valid() && m_data.get_is_valid());
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT bool ec_cs_data_c::get_is_valid_data() const
{
	return(m_reference.get_is_valid_data() && m_data.get_is_valid_data());
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT ec_cs_data_change_status_e ec_cs_data_c::get_change_status() const
{
	return m_change_status;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT void ec_cs_data_c::set_change_status(const ec_cs_data_change_status_e change_status)
{
	m_change_status = change_status;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT ec_cs_data_type_e ec_cs_data_c::get_type() const
{
	return m_type;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT void ec_cs_data_c::set_type(const ec_cs_data_type_e type)
{
	m_type = type;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT const eap_variable_data_c * ec_cs_data_c::get_reference() const
{
	return &m_reference;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT const eap_variable_data_c * ec_cs_data_c::get_data() const
{
	return &m_data;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * ec_cs_data_c::get_writable_reference()
{
	return &m_reference;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * ec_cs_data_c::get_writable_data()
{
	return &m_data;
}

//----------------------------------------------------------------------------

ec_cs_data_c * ec_cs_data_c::copy() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	ec_cs_data_c * const data = new ec_cs_data_c(m_am_tools);

	eap_automatic_variable_c<ec_cs_data_c> automatic_data(m_am_tools, data);

	if (data == 0)
	{
		return 0;
	}

	data->set_change_status(get_change_status());

	data->set_type(get_type());

	eap_status_e status = data->get_writable_data()->set_copy_of_buffer(get_data());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, status);
		return 0;
	}

	status = data->get_writable_reference()->set_copy_of_buffer(get_reference());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, status);
		return 0;
	}

	automatic_data.do_not_free_variable();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC-CS: ec_cs_data_c::copy(): type %d=%s, change status %d=%s\n"),
		data->get_type(),
		ec_cs_strings_c::get_ec_cs_store_data_string(data->get_type()),
		data->get_change_status(),
		ec_cs_strings_c::get_ec_cs_store_data_change_status_string(data->get_change_status())));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC-CS: ec_cs_data_c::copy(): reference"),
		 data->get_reference()->get_data(),
		 data->get_reference()->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC-CS: ec_cs_data_c::copy(): data"),
		 data->get_data()->get_data(),
		 data->get_data()->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return data;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT i32_t ec_cs_data_c::compare(const ec_cs_data_c * const data) const
{
	return get_reference()->compare(data->get_reference());
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_data_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_change_status = ec_cs_data_change_status_none;

	m_type = ec_cs_data_type_none;

	(void)m_reference.reset();

	(void)m_data.reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_data_c::set_copy_of_buffer(const ec_cs_data_c * const source)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_change_status = source->get_change_status();

	m_type = source->get_type();

	eap_status_e status = m_reference.set_copy_of_buffer(source->get_reference());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_data.set_copy_of_buffer(source->get_data());

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT bool ec_cs_data_c::get_data_references_read()
{
	return m_data_references_read;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT void ec_cs_data_c::set_data_references_read()
{
	m_data_references_read = true;
}

//----------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

// End.
