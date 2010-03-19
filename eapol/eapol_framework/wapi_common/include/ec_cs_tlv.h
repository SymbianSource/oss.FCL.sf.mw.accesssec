/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/ec_cs_tlv.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 9 % << Don't touch! Updated by Synergy at check-out.
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



#if !defined(_EC_CS_TLV_H_)
#define _EC_CS_TLV_H_

#if defined(USE_WAPI_CORE)

#include "eap_am_export.h"
#include "eap_tools.h"
#include "ec_cs_tlv_header.h"
#include "ec_cs_types.h"


/** @file */

class ec_cs_variable_data_c;
class tls_extension_c;
class ec_cs_tlv_payloads_c;
class ec_cs_data_c;

//----------------------------------------------------------------------------


/// This class defines EC CS TLV.
/**
 * EC CS TLV is constructed with Attribute-Value Pairs.
 */
class EAP_EXPORT ec_cs_tlv_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	ec_cs_tlv_payloads_c * m_payloads;

	bool m_is_client;

	bool m_is_valid;

	//--------------------------------------------------

	eap_status_e create_MAC(
		eap_variable_data_c * const MAC,
		const eap_variable_data_c * const server_opaque_mac_key,
		const eap_variable_data_c * const protected_data);

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the ec_cs_tlv_c class does nothing.
	 */
	EAP_FUNC_IMPORT virtual ~ec_cs_tlv_c();

	/**
	 * The constructor of the ec_cs_tlv_c class simply initializes the attributes.
	 */
	EAP_FUNC_IMPORT ec_cs_tlv_c(
		abs_eap_am_tools_c * const tools,
		const bool true_when_is_client);


	EAP_FUNC_IMPORT const ec_cs_tlv_payloads_c * get_payloads() const;


	EAP_FUNC_IMPORT bool get_is_valid();

	EAP_FUNC_IMPORT eap_status_e reset();

	//--------------------------------------------------

	EAP_FUNC_IMPORT eap_status_e generate_data_key(
		const bool in_true_when_encryption_key,
		const ec_cs_data_type_e in_data_type,
		eap_variable_data_c * const out_MAC_key,
		const eap_variable_data_c * const in_base_key,
		const eap_variable_data_c * const in_data_reference,
		const eap_variable_data_c * const in_CS_store_device_seed);

	/**
	 * Function creates the Master key data block.
	 * Parameter in_CS_master_key_or_null is optional.
	 * Null parameter value generates a new Master key with random data.
	 */
	EAP_FUNC_IMPORT eap_status_e create_master_key_data(
		const eap_variable_data_c * const in_CS_password,
		const eap_variable_data_c * const in_CS_store_device_seed,
		const eap_variable_data_c * const in_CS_master_key_or_null,
		const eap_variable_data_c * const in_data_reference,
		eap_variable_data_c * const master_key_data);

	//--------------------------------------------------

	EAP_FUNC_IMPORT eap_status_e create_tlv(
		ec_cs_variable_data_c *const new_tlv,
		const ec_cs_tlv_type_e type,
		const eap_variable_data_c * const pac_attributes);


	EAP_FUNC_IMPORT eap_status_e create_generic_tlv(
		ec_cs_variable_data_c * const new_tlv,
		const ec_cs_tlv_type_e type,
		const eap_variable_data_c * const payload);

	EAP_FUNC_IMPORT eap_status_e create_u32_t_tlv(
		ec_cs_variable_data_c * const new_tlv,
		const ec_cs_tlv_type_e type,
		const u32_t value);

	EAP_FUNC_IMPORT eap_status_e create_u16_t_tlv(
		ec_cs_variable_data_c * const new_tlv,
		const ec_cs_tlv_type_e type,
		const u16_t value);

	//--------------------------------------------------

	EAP_FUNC_IMPORT eap_status_e read_generic_tlv(
		const ec_cs_variable_data_c * const tlv,
		const ec_cs_tlv_type_e type,
		eap_variable_data_c * const payload);

	EAP_FUNC_IMPORT eap_status_e read_u32_t_tlv(
		const ec_cs_variable_data_c * const tlv,
		const ec_cs_tlv_type_e type,
		u32_t * const value);

	EAP_FUNC_IMPORT eap_status_e read_u16_t_tlv(
		const ec_cs_variable_data_c * const tlv,
		const ec_cs_tlv_type_e type,
		u16_t * const value);

	//--------------------------------------------------

	EAP_FUNC_IMPORT eap_status_e create_encrypted_tlv(
		const ec_cs_tlv_type_e in_TLV_Type,
		const eap_variable_data_c * const in_encryption_key,
		const ec_cs_variable_data_c * const in_plaintext_data_TLV,
		ec_cs_variable_data_c * const out_new_tlv);

	EAP_FUNC_IMPORT eap_status_e parse_encrypted_tlv(
		const eap_variable_data_c * const in_decryption_key,
		const ec_cs_variable_data_c * const in_encrypted_block_tlv,
		ec_cs_variable_data_c * const out_plain_text_tlv);

	EAP_FUNC_IMPORT eap_status_e create_data_with_MAC(
		const eap_variable_data_c * const MAC_key,
		const eap_variable_data_c * const in_data,
		eap_variable_data_c * const out_data_tlv);

	EAP_FUNC_IMPORT eap_status_e verify_data_with_MAC(
		const eap_variable_data_c * const in_base_key,
		const eap_variable_data_c * const in_CS_store_device_seed,
		const ec_cs_data_c * const in_CS_data_with_MAC);

	EAP_FUNC_IMPORT eap_status_e parse_data_with_MAC(
		const eap_variable_data_c * const in_MAC_key,
		const eap_variable_data_c * const in_CS_data_with_MAC);

	EAP_FUNC_IMPORT eap_status_e parse_cs_tlv(
		const ec_cs_variable_data_c * const in_PAC_tlv);

	EAP_FUNC_IMPORT eap_status_e parse_encrypted_tlv_with_MAC(
		const ec_cs_data_type_e in_data_type,
		const eap_variable_data_c * const in_base_key,
		const eap_variable_data_c * const in_data_reference,
		const eap_variable_data_c * const in_CS_store_device_seed,
		const eap_variable_data_c * const in_data_tlv,
		ec_cs_variable_data_c * const out_plain_text_tlv);

	//--------------------------------------------------

	EAP_FUNC_IMPORT eap_status_e create_encrypted_certificate(
		const ec_cs_data_type_e in_data_type,
		const eap_variable_data_c * const in_base_key,
		const eap_variable_data_c * const in_data_reference,
		const eap_variable_data_c * const in_CS_store_device_seed,
		const eap_variable_data_c * const in_certificate_reference,
		const ec_cs_tlv_type_e in_certificate_tlv_type,
		const eap_variable_data_c * const in_certificate_data,
		eap_variable_data_c * const out_certificate_data_block);

	EAP_FUNC_IMPORT eap_status_e parse_encrypted_certificate(
		const ec_cs_data_type_e in_data_type,
		const eap_variable_data_c * const in_base_key,
		const eap_variable_data_c * const in_data_reference,
		const eap_variable_data_c * const in_CS_store_device_seed,
		const eap_variable_data_c * const in_certificate_data_block,
		eap_variable_data_c * const out_certificate_reference);

	//--------------------------------------------------

}; // class ec_cs_tlv_c


#endif //#if defined(USE_WAPI_CORE)

#endif //#if !defined(_EC_CS_TLV_H_)



// End.
