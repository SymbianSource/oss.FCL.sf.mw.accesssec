/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/wapi_certificate_asn1_der_parser.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 3 % << Don't touch! Updated by Synergy at check-out.
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

#include "wapi_certificate_asn1_der_parser.h"
#include "eap_automatic_variable.h"
#include "wapi_types.h"

//--------------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT wapi_certificate_asn1_der_parser_c::~wapi_certificate_asn1_der_parser_c()
{
}

//--------------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT wapi_certificate_asn1_der_parser_c::wapi_certificate_asn1_der_parser_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_is_valid(false)
	, m_parser(tools)
{
	m_is_valid = true;
}

//--------------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT bool wapi_certificate_asn1_der_parser_c::get_is_valid() const
{
	return m_is_valid;
}

//--------------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_certificate_asn1_der_parser_c::decode(const eap_variable_data_c * const asn1_der_certificate)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	ASN1_TYPE_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x: wapi_certificate_asn1_der_parser_c::decode()\n"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_certificate_asn1_der_parser_c::decode()");

	eap_status_e status(eap_status_process_general_error);

	if (asn1_der_certificate == 0
		|| asn1_der_certificate->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_parser.decode(asn1_der_certificate);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_certificate_asn1_der_parser_c::read_certificate_id(
	eap_variable_data_c * const asn1_der_subject_name,
	eap_variable_data_c * const asn1_der_issuer_name,
	eap_variable_data_c * const asn1_der_sequence_number)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x: wapi_certificate_asn1_der_parser_c::read_certificate_id():\n"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_certificate_asn1_der_parser_c::read_certificate_id()");

	eap_status_e status(eap_status_not_supported);

	if (asn1_der_subject_name == 0
		|| asn1_der_subject_name->get_is_valid() == false
		|| asn1_der_issuer_name == 0
		|| asn1_der_issuer_name->get_is_valid() == false
		|| asn1_der_sequence_number == 0
		|| asn1_der_sequence_number->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_parser.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_certificate);
	}

	{
		const asn1_type_const_c type_subject_name[] =
			{
				ASN1_TYPE_OBJECT(
					asn1_der_type_c::asn1_class_universal,
					asn1_der_type_c::asn1_tag_sequence,
					0),                                       // Certificate  ::=  SEQUENCE
				ASN1_TYPE_OBJECT(
					asn1_der_type_c::asn1_class_universal,
					asn1_der_type_c::asn1_tag_sequence,
					0),                                       // TBSCertificate  ::=  SEQUENCE
				ASN1_TYPE_OBJECT(
					asn1_der_type_c::asn1_class_universal,
					asn1_der_type_c::asn1_tag_sequence,
					5),                                       // subject Name, Name ::= CHOICE { RDNSequence }, RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
				ASN1_TYPE_OBJECT_TERMINATOR
			};

		eap_status_e status(eap_status_not_supported);

		const asn1_der_type_c * const type = m_parser.get_sub_type(type_subject_name);

		if (type == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_identity_query_failed);
		}

		status = asn1_der_subject_name->set_copy_of_buffer(
			type->get_full_data(),
			type->get_full_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("asn1_der_subject_name"),
			asn1_der_subject_name->get_data(),
			asn1_der_subject_name->get_data_length()));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		const asn1_type_const_c type_issuer_name[] =
			{
				ASN1_TYPE_OBJECT(
					asn1_der_type_c::asn1_class_universal,
					asn1_der_type_c::asn1_tag_sequence,
					0),                                       // Certificate  ::=  SEQUENCE
				ASN1_TYPE_OBJECT(
					asn1_der_type_c::asn1_class_universal,
					asn1_der_type_c::asn1_tag_sequence,
					0),                                       // TBSCertificate  ::=  SEQUENCE
				ASN1_TYPE_OBJECT(
					asn1_der_type_c::asn1_class_universal,
					asn1_der_type_c::asn1_tag_sequence,
					3),                                       // issuer Name, Name ::= CHOICE { RDNSequence }, RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
				ASN1_TYPE_OBJECT_TERMINATOR
			};

		const asn1_der_type_c * const type = m_parser.get_sub_type(type_issuer_name);

		if (type == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_identity_query_failed);
		}

		status = asn1_der_issuer_name->set_copy_of_buffer(
			type->get_full_data(),
			type->get_full_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("asn1_der_issuer_name"),
			asn1_der_issuer_name->get_data(),
			asn1_der_issuer_name->get_data_length()));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		const asn1_type_const_c type_serial_number[] =
			{
				ASN1_TYPE_OBJECT(
					asn1_der_type_c::asn1_class_universal,
					asn1_der_type_c::asn1_tag_sequence,
					0),                                       // Certificate  ::=  SEQUENCE
				ASN1_TYPE_OBJECT(
					asn1_der_type_c::asn1_class_universal,
					asn1_der_type_c::asn1_tag_sequence,
					0),                                       // TBSCertificate  ::=  SEQUENCE
				ASN1_TYPE_OBJECT(
					asn1_der_type_c::asn1_class_universal,
					asn1_der_type_c::asn1_tag_integer,
					1),                                       // serialNumber CertificateSerialNumber, CertificateSerialNumber  ::=  INTEGER
				ASN1_TYPE_OBJECT_TERMINATOR
			};

		const asn1_der_type_c * const type = m_parser.get_sub_type(type_serial_number);

		if (type == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_identity_query_failed);
		}

		status = asn1_der_sequence_number->set_copy_of_buffer(
			type->get_full_data(),
			type->get_full_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("asn1_der_sequence_number"),
			asn1_der_sequence_number->get_data(),
			asn1_der_sequence_number->get_data_length()));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_certificate_asn1_der_parser_c::read_certificate_id(
	eap_variable_data_c * const identity)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x: wapi_certificate_asn1_der_parser_c::read_certificate_id():\n"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_certificate_asn1_der_parser_c::read_certificate_id()");

	eap_status_e status(eap_status_not_supported);

	if (identity == 0
		|| identity->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c certificate_subject_name(m_am_tools);
	eap_variable_data_c certificate_issuer_name(m_am_tools);
	eap_variable_data_c certificate_sequence_number(m_am_tools);

	status = read_certificate_id(
		&certificate_subject_name,
		&certificate_issuer_name,
		&certificate_sequence_number);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = identity->set_copy_of_buffer(&certificate_subject_name);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = identity->add_data(&certificate_issuer_name);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = identity->add_data(&certificate_sequence_number);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------------------------------------------------------

// End.
