/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/ec_cs_compare_reference_id.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 6 % << Don't touch! Updated by Synergy at check-out.
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
#include "ec_cs_compare_reference_id.h"
#include "wapi_certificate_asn1_der_parser.h"
#include "wapi_asn1_der_parser.h"
#include "ec_cs_tlv_header.h"
#include "ec_cs_tlv_payloads.h"

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT ec_cs_compare_reference_id_c::~ec_cs_compare_reference_id_c()
{
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT ec_cs_compare_reference_id_c::ec_cs_compare_reference_id_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
{
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT i32_t ec_cs_compare_reference_id_c::compare(
	const ec_cs_data_c * const reference_tlv_from_array,
	const ec_cs_data_c * const certificate_identity) const
{
	// reference_tlv_from_array includes ID-Reference TLV which includes ASU-ID TLV and Certificate-reference TLV.
	// certificate_identity includes identity of certificate. Data is concatenation of subject name, issuer name and serial number, each ASN.1/DER encoded.

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("ec_cs_compare_reference_id_c::compare(): reference_tlv_from_array"),
		 reference_tlv_from_array->get_data()->get_data(),
		 reference_tlv_from_array->get_data()->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("ec_cs_compare_reference_id_c::compare(): certificate_identity"),
		 certificate_identity->get_data()->get_data(),
		 certificate_identity->get_data()->get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c certificate_id(m_am_tools);
	if (certificate_id.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	ec_cs_tlv_header_c id_reference_tlv(
		m_am_tools,
		reference_tlv_from_array->get_data()->get_data(),
		reference_tlv_from_array->get_data()->get_data_length());
	if (id_reference_tlv.get_is_valid() == false)
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

		u32_t length(id_reference_tlv.get_data_length());
		u32_t padding_length(0ul);

		eap_status_e status = parser.parse_ec_cs_payloads(
			id_reference_tlv.get_data(length), ///< This is the start of the message buffer.
			&length, ///< This is the length of the buffer. This must match with the length of all payloads.
			&padding_length ///< Length of possible padding is set to this variable.
			);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		const ec_cs_variable_data_c * const asu_id = parser.get_tlv_pointer(ec_cs_tlv_type_CS_ASU_ID);
		if (asu_id == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		{
			wapi_asn1_der_parser_c parser(m_am_tools);
			if (parser.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			eap_variable_data_c id_data(
				m_am_tools,
				asu_id->get_data(asu_id->get_data_length()),
				asu_id->get_data_length(),
				false,
				false);
			if (id_data.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			eap_status_e status = parser.decode(&id_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = parser.get_wapi_identity(
				&certificate_id);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	return certificate_id.compare(certificate_identity->get_data());
}

//----------------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

// End.
