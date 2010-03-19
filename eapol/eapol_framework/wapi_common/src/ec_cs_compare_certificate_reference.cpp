/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/ec_cs_compare_certificate_reference.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 7 % << Don't touch! Updated by Synergy at check-out.
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
	#define EAP_FILE_NUMBER_ENUM 700 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#if defined(USE_WAPI_CORE)

#include "eap_automatic_variable.h"
#include "ec_cs_types.h"
#include "ec_cs_data.h"
#include "ec_cs_compare_certificate_reference.h"
#include "wapi_certificate_asn1_der_parser.h"
#include "wapi_asn1_der_parser.h"
#include "ec_cs_tlv_header.h"
#include "ec_cs_tlv_payloads.h"

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT ec_cs_compare_certificate_reference_c::~ec_cs_compare_certificate_reference_c()
{
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT ec_cs_compare_certificate_reference_c::ec_cs_compare_certificate_reference_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
{
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT i32_t ec_cs_compare_certificate_reference_c::compare(
	const ec_cs_data_c * const certificate_from_array,
	const ec_cs_data_c * const certificate_reference) const
{
	// certificate_from_array includes data of Certificate Data which include full certificate in ASN.1/DER encoded and Certificate-Reference TLV.
	// certificate_reference includes Certificate-Reference TLV.

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("ec_cs_compare_certificate_reference_c::compare(): certificate_from_array"),
		 certificate_from_array->get_data()->get_data(),
		 certificate_from_array->get_data()->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("ec_cs_compare_certificate_reference_c::compare(): certificate_reference"),
		 certificate_reference->get_data()->get_data(),
		 certificate_reference->get_data()->get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c certificate_issuer_name(m_am_tools);
	if (certificate_issuer_name.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		ec_cs_tlv_payloads_c parser(
			m_am_tools,
			true);
		if (parser.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t length(certificate_from_array->get_data()->get_data_length());
		u32_t padding_length(0ul);

		eap_status_e status = parser.parse_ec_cs_payloads(
			certificate_from_array->get_data()->get_data(), ///< This is the start of the message buffer.
			&length, ///< This is the length of the buffer. This must match with the length of all payloads.
			&padding_length ///< Length of possible padding is set to this variable.
			);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		const ec_cs_variable_data_c * const reference = parser.get_tlv_pointer(ec_cs_tlv_type_CS_certificate_reference);
		if (reference == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		return reference->get_full_tlv_buffer()->compare(certificate_reference->get_data());
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

}

//----------------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

// End.
