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

#if defined(USE_EAP_TLS_SESSION_TICKET)

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 762 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include "tls_extension.h"

/** @file */

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT void tls_extension_c::set_is_valid()
{
	m_is_valid = true;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT tls_extension_c::~tls_extension_c()
{
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT tls_extension_c::tls_extension_c(
	abs_eap_am_tools_c * const tools)
	: eap_variable_data_c(tools)
	  , m_am_tools(tools)
	  , m_lifetime_hint(0ul)
	  , m_type(tls_extension_type_none)
#if defined(USE_FAST_EAP_TYPE)
	  , m_pac_type(eap_fast_pac_type_none)
#endif //#if defined(USE_FAST_EAP_TYPE)
	  , m_is_valid(false)
{
	if (eap_variable_data_c::get_is_valid() == false)
	{
		return;
	}

	set_is_valid();
}

//----------------------------------------------------------------------------

tls_extension_c * tls_extension_c::copy() const
{
	tls_extension_c * const copy_object = new tls_extension_c(m_am_tools);

	if (copy_object == 0
		|| copy_object->get_is_valid() == false)
	{
		delete copy_object;
		return 0;
	}

	copy_object->set_type(get_type());

#if defined(USE_FAST_EAP_TYPE)
	copy_object->set_pac_type(get_pac_type());
#endif //#if defined(USE_FAST_EAP_TYPE)

	eap_status_e status = copy_object->set_copy_of_buffer(this);

	if (status != eap_status_ok)
	{
		delete copy_object;
		return 0;
	}

	return copy_object;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT bool tls_extension_c::get_is_valid()
{
	return m_is_valid;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT void tls_extension_c::set_lifetime_hint(const u32_t lifetime_hint)
{
	m_lifetime_hint = lifetime_hint;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT u32_t tls_extension_c::get_lifetime_hint() const
{
	return m_lifetime_hint;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT void tls_extension_c::set_type(const tls_extension_type_e type)
{
	m_type = type;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT tls_extension_type_e tls_extension_c::get_type() const
{
	return m_type;
}

//----------------------------------------------------------------------------

#if defined(USE_FAST_EAP_TYPE)

EAP_FUNC_EXPORT void tls_extension_c::set_pac_type(const eap_fast_pac_type_e pac_type)
{
	m_pac_type = pac_type;
}

#endif //#if defined(USE_FAST_EAP_TYPE)

//----------------------------------------------------------------------------

#if defined(USE_FAST_EAP_TYPE)

EAP_FUNC_EXPORT eap_fast_pac_type_e tls_extension_c::get_pac_type() const
{
	return m_pac_type;
}

#endif //#if defined(USE_FAST_EAP_TYPE)

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_const_string  tls_extension_c::get_type_string(tls_extension_type_e type)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(type, tls_extension_type_none)
	else EAP_IF_RETURN_STRING(type, tls_extension_type_server_name)
	else EAP_IF_RETURN_STRING(type, tls_extension_type_max_frame_length)
	else EAP_IF_RETURN_STRING(type, tls_extension_type_client_certificate_url)
	else EAP_IF_RETURN_STRING(type, tls_extension_type_trusted_ca_keys)
	else EAP_IF_RETURN_STRING(type, tls_extension_type_truncated_hmac)
	else EAP_IF_RETURN_STRING(type, tls_extension_type_status_request)
	else EAP_IF_RETURN_STRING(type, tls_extension_type_session_ticket)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(type);
		return EAPL("Unknown TLS extension type");
	}
}

//----------------------------------------------------------------------------

const tls_extension_c * tls_extension_c::get_tls_extension(
	const tls_extension_type_e tls_extension_type,
	EAP_TEMPLATE_CONST eap_array_c<tls_extension_c> * const tls_extensions,
	abs_eap_am_tools_c * const am_tools)
{
	if (tls_extensions == 0)
	{
		EAP_UNREFERENCED_PARAMETER(am_tools);
		(void) EAP_STATUS_RETURN(am_tools, eap_status_not_found);
		return 0;
	}

	for (u32_t ind = 0ul; ind < tls_extensions->get_object_count(); ++ind)
	{
		const tls_extension_c * extension = tls_extensions->get_object(ind);

		if (extension == 0)
		{
			(void) EAP_STATUS_RETURN(am_tools, eap_status_not_found);
			return 0;
		}

		if (extension->get_type() == tls_extension_type)
		{
			return extension;
		}
	} // for()

	(void) EAP_STATUS_RETURN(am_tools, eap_status_not_found);
	return 0;
}

//----------------------------------------------------------------------------

#if defined(USE_FAST_EAP_TYPE)

const tls_extension_c * tls_extension_c::get_tls_extension(
	const tls_extension_type_e tls_extension_type,
	const eap_fast_pac_type_e pac_type,
	EAP_TEMPLATE_CONST eap_array_c<tls_extension_c> * const tls_extensions,
	abs_eap_am_tools_c * const am_tools)
{
	if (tls_extensions == 0)
	{
		EAP_UNREFERENCED_PARAMETER(am_tools);
		(void) EAP_STATUS_RETURN(am_tools, eap_status_not_found);
		return 0;
	}

	for (u32_t ind = 0ul; ind < tls_extensions->get_object_count(); ++ind)
	{
		const tls_extension_c * extension = tls_extensions->get_object(ind);

		if (extension == 0)
		{
			(void) EAP_STATUS_RETURN(am_tools, eap_status_not_found);
			return 0;
		}

		if (extension->get_type() == tls_extension_type)
		{
			if (pac_type == eap_fast_pac_type_none
				|| pac_type == extension->get_pac_type())
			{
				return extension;
			}
		}
	} // for()

	(void) EAP_STATUS_RETURN(am_tools, eap_status_not_found);
	return 0;
}

#endif //#if defined(USE_FAST_EAP_TYPE)

//----------------------------------------------------------------------------

#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)

// End.
