/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/wapi_asn1_der_parser.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 12 % << Don't touch! Updated by Synergy at check-out.
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

#include "wapi_asn1_der_parser.h"
#include "eap_automatic_variable.h"
#include "wapi_types.h"

//--------------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT wapi_asn1_der_parser_c::~wapi_asn1_der_parser_c()
{
}

//--------------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT wapi_asn1_der_parser_c::wapi_asn1_der_parser_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_is_valid(false)
	, m_objects(tools)
{
	m_is_valid = true;
}

//--------------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT bool wapi_asn1_der_parser_c::get_is_valid() const
{
	return m_is_valid;
}

//--------------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_asn1_der_parser_c::decode(const eap_variable_data_c * const asn1_der_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	ASN1_TYPE_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x: wapi_asn1_der_parser_c::decode()\n"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_asn1_der_parser_c::decode()");

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	bool data_continues(true);

	status = m_objects.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c input(m_am_tools);
	if (input.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t input_offset(0ul);
	const u32_t input_length(asn1_der_data->get_data_length());
	u32_t input_remain_length(input_length);

	while(data_continues == true)
	{
		asn1_der_type_c * const asn1_der_object = new asn1_der_type_c(m_am_tools);

		eap_automatic_variable_c<asn1_der_type_c> automatic_asn1_der_object(m_am_tools, asn1_der_object);

		if (asn1_der_object == 0
			|| asn1_der_object->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = input.set_buffer(
			asn1_der_data->get_data_offset(input_offset, input_remain_length),
			input_remain_length,
			false,
			false);

		status = asn1_der_object->decode(&input);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		automatic_asn1_der_object.do_not_free_variable();

		status = m_objects.add_object(asn1_der_object, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		input_offset += asn1_der_object->get_full_data_length();

		if (input_remain_length < asn1_der_object->get_full_data_length())
		{
			data_continues = false;
		}
		else
		{
			input_remain_length -= asn1_der_object->get_full_data_length();

			if (input_remain_length >= input_length
				|| input_offset >= input_length)
			{
				data_continues = false;
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT const asn1_der_type_c * wapi_asn1_der_parser_c::get_object(const u32_t index) const
{
	if (m_objects.get_object_count() <= index)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_index);
		return 0;
	}

	return m_objects.get_object(index);
}

//--------------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT u32_t wapi_asn1_der_parser_c::get_object_count() const
{
	return m_objects.get_object_count();
}

//--------------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_asn1_der_parser_c::get_wapi_identity(
	eap_variable_data_c * const subject_name,
	eap_variable_data_c * const issuer_name,
	eap_variable_data_c * const sequence_number)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	ASN1_TYPE_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x: wapi_asn1_der_parser_c::get_wapi_identity()\n"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_asn1_der_parser_c::get_wapi_identity()");

	eap_status_e status(eap_status_process_general_error);

	if (subject_name == 0
		|| issuer_name == 0
		|| sequence_number == 0
		|| subject_name->get_is_valid() == false
		|| issuer_name->get_is_valid() == false
		|| sequence_number->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	const asn1_type_const_c type_object_identifier[] =
		{
			ASN1_TYPE_OBJECT(
				asn1_der_type_c::asn1_class_universal,
				asn1_der_type_c::asn1_tag_sequence,
				0),										// Name ::= CHOICE { RDNSequence } 
														// ::= RDNSequence 
														// ::= SEQUENCE OF RelativeDistinguishedName
														// ::= {organizationalUnitName[0], commonName[1]}
			ASN1_TYPE_OBJECT(
				asn1_der_type_c::asn1_class_universal,
				asn1_der_type_c::asn1_tag_set,
				1),										// commonName ::= SET OF AttributeTypeAndValue
			ASN1_TYPE_OBJECT(
				asn1_der_type_c::asn1_class_universal,
				asn1_der_type_c::asn1_tag_sequence,
				0),										// AttributeTypeAndValue ::= SEQUENCE {
														//		type     AttributeType,
														//		value    AttributeValue }
			ASN1_TYPE_OBJECT(
				asn1_der_type_c::asn1_class_universal,
				asn1_der_type_c::asn1_tag_object_identifier,
				0),										// AttributeType ::= OBJECT IDENTIFIER
			ASN1_TYPE_OBJECT_TERMINATOR
		};

	u32_t index(0ul);

	{
		const asn1_der_type_c * const der_subject_name = get_object(index);

		if (der_subject_name == 0
			|| der_subject_name->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_index);
		}

		const asn1_der_type_c * const der_object_identifier = der_subject_name->get_sub_type(type_object_identifier);

		if (der_object_identifier == 0
			|| der_object_identifier->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_index);
		}

		if (der_object_identifier->get_full_data_length() != sizeof(WAPI_COMMON_NAME_OID_PARAMETER)
			|| m_am_tools->memcmp(WAPI_COMMON_NAME_OID_PARAMETER,
			der_object_identifier->get_full_data(),
			sizeof(WAPI_COMMON_NAME_OID_PARAMETER)) != 0)
		{
			// ERROR: wrong payload.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_data_payload);
		}

		status = subject_name->set_copy_of_buffer(
			der_subject_name->get_full_data(),
			der_subject_name->get_full_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("subject_name"),
			subject_name->get_data(),
			subject_name->get_data_length()));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++index;

	{
		const asn1_der_type_c * const der_issuer_name = get_object(index);

		if (der_issuer_name == 0
			|| der_issuer_name->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_index);
		}

		const asn1_der_type_c * const der_object_identifier = der_issuer_name->get_sub_type(type_object_identifier);

		if (der_object_identifier == 0
			|| der_object_identifier->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_index);
		}

		if (der_object_identifier->get_full_data_length() != sizeof(WAPI_COMMON_NAME_OID_PARAMETER)
			|| m_am_tools->memcmp(WAPI_COMMON_NAME_OID_PARAMETER,
			der_object_identifier->get_full_data(),
			sizeof(WAPI_COMMON_NAME_OID_PARAMETER)) != 0)
		{
			// ERROR: wrong payload.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_data_payload);
		}

		status = issuer_name->set_copy_of_buffer(
			der_issuer_name->get_full_data(),
			der_issuer_name->get_full_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("issuer_name"),
			issuer_name->get_data(),
			issuer_name->get_data_length()));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++index;

	{
		const asn1_der_type_c * const der_sequence_number = get_object(index);

		if (der_sequence_number == 0
			|| der_sequence_number->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_index);
		}

		switch(der_sequence_number->get_tag())
		{
		case asn1_der_type_c::asn1_tag_integer:
			// OK
			break;
		default:
			// ERROR: wrong payload.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_data_payload);
		};

		status = sequence_number->set_copy_of_buffer(
			der_sequence_number->get_full_data(),
			der_sequence_number->get_full_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("sequence_number"),
			sequence_number->get_data(),
			sequence_number->get_data_length()));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_asn1_der_parser_c::get_wapi_identity(
	eap_variable_data_c * const wapi_identity)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	ASN1_TYPE_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x: wapi_asn1_der_parser_c::get_wapi_identity()\n"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_asn1_der_parser_c::get_wapi_identity()");

	eap_status_e status(eap_status_process_general_error);

	if (wapi_identity == 0
		|| wapi_identity->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c subject_name(m_am_tools);
	eap_variable_data_c issuer_name(m_am_tools);
	eap_variable_data_c sequence_number(m_am_tools);

	if (subject_name.get_is_valid() == false
		|| issuer_name.get_is_valid() == false
		|| sequence_number.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = get_wapi_identity(
		&subject_name,
		&issuer_name,
		&sequence_number);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = wapi_identity->set_copy_of_buffer(&subject_name);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = wapi_identity->add_data(&issuer_name);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = wapi_identity->add_data(&sequence_number);
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

EAP_FUNC_EXPORT eap_status_e wapi_asn1_der_parser_c::get_decoded_subject_name(
    eap_variable_data_c * const identity_data,
    eap_variable_data_c * const decoded_data)
{
    
    eap_status_e status = eap_status_ok;
    eap_variable_data_c subject_name(m_am_tools);
   
	if ( subject_name.get_is_valid() == false )
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
    
    // The data is stored to this objects internal variables with decode
    status = decode(identity_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
    
	const asn1_type_const_c type_name_sequence[] =
		{
			ASN1_TYPE_OBJECT(
				asn1_der_type_c::asn1_class_universal,
				asn1_der_type_c::asn1_tag_sequence,
				0),										// Name ::= CHOICE { RDNSequence } 
														// ::= RDNSequence 
														// ::= SEQUENCE OF RelativeDistinguishedName
														// ::= {organizationalUnitName[0], commonName[1]}
			ASN1_TYPE_OBJECT(
				asn1_der_type_c::asn1_class_universal,
				asn1_der_type_c::asn1_tag_set,
				1),										// commonName ::= SET OF AttributeTypeAndValue
			ASN1_TYPE_OBJECT(
				asn1_der_type_c::asn1_class_universal,
				asn1_der_type_c::asn1_tag_sequence,
				0),										// AttributeTypeAndValue ::= SEQUENCE {
														//		type     AttributeType,
														//		value    AttributeValue }
#if 0
			// This last object is variable type and it is handled later.
			ASN1_TYPE_OBJECT(
				asn1_der_type_c::asn1_class_universal,
				asn1_der_type_c::asn1_tag_printable_string,
				0),										// AttributeValue ::= ANY DEFINED BY AttributeType
														// ::= DirectoryString ::= CHOICE {
														// teletexString           TeletexString (SIZE (1..MAX)),
														// printableString         PrintableString (SIZE (1..MAX)),
														// universalString         UniversalString (SIZE (1..MAX)),
														// utf8String              UTF8String (SIZE (1..MAX)),
														// bmpString               BMPString (SIZE (1..MAX)) }
#endif
			ASN1_TYPE_OBJECT_TERMINATOR
		};

	if (get_object_count() == 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_index);
	}

	const asn1_der_type_c * const der_name_sequence = get_object(0ul)->get_sub_type(type_name_sequence);

	if (der_name_sequence == 0
		|| der_name_sequence->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_index);
	}

	// Second object (index 1) in SEQUENCE is AttributeValue.
	const asn1_der_type_c * const der_name = der_name_sequence->get_sub_types()->get_object(1ul);

	if (der_name == 0
		|| der_name->get_is_valid() == false
		|| (/* der_name->get_tag() != asn1_der_type_c::asn1_tag_teletex_string // This is not defined yet.
			&& */
			der_name->get_tag() != asn1_der_type_c::asn1_tag_printable_string
			&& der_name->get_tag() != asn1_der_type_c::asn1_tag_universal_string
			&& der_name->get_tag() != asn1_der_type_c::asn1_tag_utf8_string
			&& der_name->get_tag() != asn1_der_type_c::asn1_tag_bmp_string
			&& der_name->get_tag() != asn1_der_type_c::asn1_tag_t61_string))
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_index);
	}

    // Copy the decoded data into the returned parameter
    status = decoded_data->set_copy_of_buffer(
		der_name->get_content(), 
		der_name->get_content_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
    
    EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
    return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------------------------------------------------------

// End.
