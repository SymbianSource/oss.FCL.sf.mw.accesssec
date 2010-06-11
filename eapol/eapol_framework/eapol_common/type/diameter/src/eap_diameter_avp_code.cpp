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
	#define EAP_FILE_NUMBER_ENUM 573 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_diameter_avp_code.h"

//--------------------------------------------------

EAP_FUNC_EXPORT eap_diameter_avp_code_c::~eap_diameter_avp_code_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_diameter_avp_code_c::eap_diameter_avp_code_c()
{
	m_vendor_id = eap_diameter_vendor_id_of_ietf;
	m_vendor_code = static_cast<u32_t>(eap_diameter_avp_code_none);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_diameter_avp_code_c::eap_diameter_avp_code_c(
	const eap_diameter_vendor_id_e vendor_id,
	const u32_t vendor_type)
{
	m_vendor_id = vendor_id;
	m_vendor_code = vendor_type;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_diameter_avp_code_c::eap_diameter_avp_code_c(
	const eap_diameter_avp_code_of_ietf_e type)
{
	m_vendor_id = eap_diameter_vendor_id_of_ietf;
	m_vendor_code = static_cast<u32_t>(type);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_diameter_avp_code_c::is_ietf_code(const eap_diameter_avp_code_c avp_code)
{
	return (avp_code.get_vendor_id() == eap_diameter_vendor_id_of_ietf);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_diameter_avp_code_c::get_code_data(
	abs_eap_am_tools_c * const am_tools,
	eap_diameter_avp_code_of_ietf_e * const type)
{
	if (type == 0)
	{
		EAP_UNREFERENCED_PARAMETER(am_tools);
		return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
	}

	if (m_vendor_id == eap_diameter_vendor_id_of_ietf)
	{
		*type = static_cast<eap_diameter_avp_code_of_ietf_e>(m_vendor_code);
	}
	else 
	{
		// This is EAP type of other vendor than IETF.
		// This cannot be denoted in eap_diameter_avp_code_of_ietf_e.
		*type = static_cast<eap_diameter_avp_code_of_ietf_e>(eap_diameter_avp_code_none);
	}

	return EAP_STATUS_RETURN(am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_diameter_avp_code_c::get_code_data(
	abs_eap_am_tools_c * const am_tools,
	eap_diameter_avp_code_c * const type)
{
	if (type == 0)
	{
		EAP_UNREFERENCED_PARAMETER(am_tools);
		return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
	}

	*type = *this;

	return EAP_STATUS_RETURN(am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_diameter_avp_code_c::set_code_values(
	const eap_diameter_vendor_id_e vendor_id,
	const u32_t vendor_type)
{
	m_vendor_id = vendor_id;
	m_vendor_code = vendor_type;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_diameter_vendor_id_e eap_diameter_avp_code_c::get_vendor_id() const
{
	return m_vendor_id;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_diameter_avp_code_c::get_vendor_code() const
{
	return m_vendor_code;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_diameter_avp_code_c::operator == (const eap_diameter_avp_code_of_ietf_e right_type_value) const
{
	if (m_vendor_id != eap_diameter_vendor_id_of_ietf)
	{
		return false;
	}
	else if (m_vendor_code != static_cast<u32_t>(right_type_value))
	{
		return false;
	}
	else
	{
		return true;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_diameter_avp_code_c::operator != (const eap_diameter_avp_code_of_ietf_e right_type_value) const
{
	return !(*this == right_type_value);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_diameter_avp_code_c::operator == (const eap_diameter_avp_code_c &right_type_value) const
{
	if (m_vendor_id != right_type_value.get_vendor_id())
	{
		return false;
	}
	else if (m_vendor_code != right_type_value.get_vendor_code())
	{
		return false;
	}
	else
	{
		return true;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_diameter_avp_code_c::operator != (const eap_diameter_avp_code_c &right_type_value) const
{
	return !(*this == right_type_value);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_diameter_avp_code_c &eap_diameter_avp_code_c::operator = (const eap_diameter_avp_code_of_ietf_e right_type_value)
{
	m_vendor_id = eap_diameter_vendor_id_of_ietf; ///< Here we use only 24 least significant bits.
	m_vendor_code = static_cast<u32_t>(right_type_value);

	return *this;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_diameter_avp_code_c &eap_diameter_avp_code_c::operator = (const eap_diameter_avp_code_c &right_type_value)
{
	m_vendor_id = right_type_value.get_vendor_id(); ///< Here we use only 24 least significant bits.
	m_vendor_code = right_type_value.get_vendor_code();

	return *this;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_diameter_avp_code_c *eap_diameter_avp_code_c::operator & ()
{
	return this;
}

//--------------------------------------------------

EAP_FUNC_EXPORT const eap_diameter_avp_code_c *eap_diameter_avp_code_c::operator & () const
{
	return this;
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT const eap_diameter_avp_code_c &eap_static_diameter_vendor_code_c::get_code() const
{
	return *reinterpret_cast<const eap_diameter_avp_code_c *>(this);
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_C_FUNC_EXPORT u32_t convert_eap_diameter_avp_code_to_u32_t(eap_diameter_avp_code_c code)
{
	// NOTE, this returns only 8 least significant bits of vendor type.
	return static_cast<u32_t>(code.get_vendor_id() << sizeof(u8_t)*8ul
							  | (0xff & code.get_vendor_code()));
}

EAP_C_FUNC_EXPORT u64_t convert_eap_diameter_avp_code_to_u64_t(eap_diameter_avp_code_c code)
{
	return static_cast<u64_t>(code.get_vendor_id()) << sizeof(u32_t)*8ul
		| static_cast<u64_t>(code.get_vendor_code());
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------



// End.
