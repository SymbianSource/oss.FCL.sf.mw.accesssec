/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/ec_cs_compare_certificate_issuer_name.cpp
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
#include "ec_cs_compare_certificate_issuer_name.h"
#include "wapi_certificate_asn1_der_parser.h"
#include "wapi_asn1_der_parser.h"
#include "ec_cs_tlv_header.h"
#include "ec_cs_tlv_payloads.h"
#include "ec_cs_tlv.h"

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT ec_cs_compare_certificate_issuer_name_c::~ec_cs_compare_certificate_issuer_name_c()
{
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT ec_cs_compare_certificate_issuer_name_c::ec_cs_compare_certificate_issuer_name_c(
	abs_eap_am_tools_c * const tools,
	const eap_variable_data_c * const PAC_store_master_key,
	const eap_variable_data_c * const PAC_store_device_seed)
	: m_am_tools(tools)
	, m_PAC_store_master_key(PAC_store_master_key)
	, m_PAC_store_device_seed(PAC_store_device_seed)
{
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT i32_t ec_cs_compare_certificate_issuer_name_c::compare(
	const ec_cs_data_c * const certificate_from_array,
	const ec_cs_data_c * const issuer_name) const
{
	// certificate_from_array includes data of Certificate Data which include full certificate in ASN.1/DER encoded and certificate reference.
	// issuer_name includes issuer name ASN.1/DER encoded.

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("ec_cs_compare_certificate_issuer_name_c::compare(): certificate_from_array"),
		 certificate_from_array->get_data()->get_data(),
		 certificate_from_array->get_data()->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("ec_cs_compare_certificate_issuer_name_c::compare(): issuer_name"),
		 issuer_name->get_data()->get_data(),
		 issuer_name->get_data()->get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c certificate_issuer_name(m_am_tools);
	if (certificate_issuer_name.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		ec_cs_tlv_c handler(m_am_tools, true);
		if (handler.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_variable_data_c certificate_reference(m_am_tools);
		if (certificate_reference.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_status_e status = handler.parse_encrypted_certificate(
			certificate_from_array->get_type(),
			m_PAC_store_master_key,
			certificate_from_array->get_reference(),
			m_PAC_store_device_seed,
			certificate_from_array->get_data(),
			&certificate_reference);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		const ec_cs_variable_data_c * const certificate_data_tlv = handler.get_payloads()->get_tlv_pointer(ec_cs_tlv_type_CS_certificate_data);
		if (certificate_data_tlv == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		{
			wapi_certificate_asn1_der_parser_c parser(m_am_tools);
			if (parser.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			eap_variable_data_c id_data(
				m_am_tools,
				certificate_data_tlv->get_data(certificate_data_tlv->get_data_length()),
				certificate_data_tlv->get_data_length(),
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

			eap_variable_data_c certificate_subject_name(m_am_tools);
			eap_variable_data_c certificate_sequence_number(m_am_tools);

			status = parser.read_certificate_id(
				&certificate_subject_name,
				&certificate_issuer_name,
				&certificate_sequence_number);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	return certificate_issuer_name.compare(issuer_name->get_data());
}

//----------------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

// End.
