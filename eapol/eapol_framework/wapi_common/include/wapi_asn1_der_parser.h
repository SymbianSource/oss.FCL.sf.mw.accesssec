/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/wapi_asn1_der_parser.h
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
* Template version: 4.2
*/



#if !defined(_WAPI_ASN1_DER_PARSER_H_)
#define _WAPI_ASN1_DER_PARSER_H_

#include "eap_variable_data.h"
#include "eap_am_export.h"
#include "eap_array.h"
#include "asn1_der_type.h"

//--------------------------------------------------

class EAP_EXPORT wapi_asn1_der_parser_c
{
	//--------------------------------------------------
public:
	//--------------------------------------------------

	EAP_FUNC_IMPORT virtual ~wapi_asn1_der_parser_c();

	EAP_FUNC_IMPORT wapi_asn1_der_parser_c(
		abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the wapi_asn1_der_parser_c object.
	 * @return True indicates the object is initialized.
	 */
	EAP_FUNC_IMPORT bool get_is_valid() const;

	EAP_FUNC_IMPORT u32_t get_index() const;

	/**
	 * The decode() function decodes ASN.1/DER data.
	 * Data can include many ASN.1/DER objects.
	 * @return eap_status_ok indicates successfull operation.
	 */
	EAP_FUNC_IMPORT eap_status_e decode(const eap_variable_data_c * const asn1_der_data);


	EAP_FUNC_IMPORT const asn1_der_type_c * get_object(const u32_t index) const;

	EAP_FUNC_IMPORT u32_t get_object_count() const;


	/**
	 * The get_wapi_identity() function copies the WAPI identity data.
	 * First you must call decode() function with the input data.
	 * @return eap_status_ok indicates successfull operation.
	 */
	EAP_FUNC_IMPORT eap_status_e get_wapi_identity(
		eap_variable_data_c * const subject_name,
		eap_variable_data_c * const issuer_name,
		eap_variable_data_c * const sequence_number);

	/**
	 * The get_wapi_identity() function copies the WAPI identity data.
	 * First you must call decode() function with the input data.
	 * @return eap_status_ok indicates successfull operation.
	 */
	EAP_FUNC_IMPORT eap_status_e get_wapi_identity(
		eap_variable_data_c * const wapi_identity);
	/**
	 * The get_decoded_subject_name() function parses and
	 * returns the certificate identity subject name
	 * @return eap_status_ok indicates successfull operation.
	 */
	EAP_FUNC_IMPORT eap_status_e get_decoded_subject_name(
	    eap_variable_data_c * const identity_data,
	    eap_variable_data_c * const decoded_data);
	    

	//--------------------------------------------------
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	bool m_is_valid;

	eap_array_c<asn1_der_type_c> m_objects;

	//--------------------------------------------------
};

//--------------------------------------------------------------------------------------------------

#endif //#if !defined(_WAPI_ASN1_DER_PARSER_H_)

//--------------------------------------------------------------------------------------------------

// End.
