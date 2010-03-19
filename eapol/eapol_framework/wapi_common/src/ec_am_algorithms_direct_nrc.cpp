/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/ec_algorithms.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 28.1.2 % << Don't touch! Updated by Synergy at check-out.
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
#include "ec_am_algorithms_direct_nrc.h"
#include "ec_cs_types.h"
#include "ec_cs_strings.h"
#include "abs_ec_am_algorithms.h"
#include "abs_eap_am_file_input.h"
#include "asn1_der_type.h"
#include "abs_ec_am_algorithms.h"
#include "eap_crypto_api.h"

#if defined(USE_NRC_ECC_ALGORITHMS)
#include "nc_drmeccp256.h"
#include "nc_pkcs1_5.h"
#include "nc_hash.h"
#include "nc_rand.h"
#endif //#if defined(USE_NRC_ECC_ALGORITHMS)

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT ec_am_algorithms_direct_nrc_c::~ec_am_algorithms_direct_nrc_c()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_am_algorithms_direct_nrc_c::~ec_am_algorithms_direct_nrc_c():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_am_algorithms_direct_nrc_c::~ec_am_algorithms_direct_nrc_c()");

}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT ec_am_algorithms_direct_nrc_c::ec_am_algorithms_direct_nrc_c(
	abs_eap_am_tools_c * const tools,
	abs_ec_am_algorithms_c * const partner,
	const bool is_client_when_true)
	: m_am_tools(tools)
	, m_partner(partner)
	, m_e_curve(tools)
	, m_nc_rand_state(tools)
	, m_is_client(is_client_when_true)
	, m_is_valid(false)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_am_algorithms_direct_nrc_c::ec_am_algorithms_direct_nrc_c():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_am_algorithms_direct_nrc_c::ec_am_algorithms_direct_nrc_c()");

	m_is_valid = true;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT bool ec_am_algorithms_direct_nrc_c::get_is_valid() const
{
	return m_is_valid;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_am_algorithms_direct_nrc_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_am_algorithms_direct_nrc_c::configure():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_am_algorithms_direct_nrc_c::configure()");

	eap_status_e status(eap_status_ok);

	status = initialize_curve();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_am_algorithms_direct_nrc_c::create_signature_with_private_key(
	const eap_variable_data_c * const hash_of_message,
	const eap_variable_data_c * const private_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_am_algorithms_direct_nrc_c::create_signature_with_private_key():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_am_algorithms_direct_nrc_c::create_signature_with_private_key()");

	eap_status_e status(eap_status_not_supported);

	asn1_der_type_c asn1(m_am_tools);
	if (asn1.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = asn1.decode(private_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	static const asn1_type_const_c private_key_query[] =
	{
		ASN1_TYPE_OBJECT(
			asn1_der_type_c::asn1_class_universal,
			asn1_der_type_c::asn1_tag_sequence,
			0),                                       // ECPrivateKey{CURVES:IOSet} ::= SEQUENCE
		ASN1_TYPE_OBJECT(
			asn1_der_type_c::asn1_class_universal,
			asn1_der_type_c::asn1_tag_octet_string,
			1),                                       // privateKey OCTET STRING
		ASN1_TYPE_OBJECT_TERMINATOR
	};

	const asn1_der_type_c * const der_private_key = asn1.get_sub_type(private_key_query);

	if (der_private_key != 0)
	{

#if defined(USE_NRC_ECC_ALGORITHMS)

		gfp_coord private_key;

		OS2IP(
			private_key.a.d,
			der_private_key->get_content(),
			der_private_key->get_content_length());

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ECC Private key"),
			der_private_key->get_content(),
			der_private_key->get_content_length()));

		gfp_point sign_point1;
		gfp_point sign_point2;

		gfp_curve * const e_curve = reinterpret_cast<gfp_curve *>(m_e_curve.get_data());
		if (e_curve == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		struct nc_rand_state * const nc_rand_state = reinterpret_cast<struct nc_rand_state *>(m_nc_rand_state.get_data(sizeof(struct nc_rand_state)));
		if (e_curve == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("hash_of_message"),
			hash_of_message->get_data(),
			hash_of_message->get_data_length()));


		DRM_ECDSA_Sign_P256(
			nc_rand_state,
			sign_point1.x.a.d,
			sign_point2.x.a.d,
			hash_of_message->get_data(),
			hash_of_message->get_data_length(),
			private_key.a.d,
			e_curve,
			0);

		u32_t sign_len(0ul);
		u32_t sign_point_len((2ul * sign_point1.x.a.d[0]) + (2ul * sign_point2.x.a.d[0]));

		eap_variable_data_c signature(m_am_tools);

		if (signature.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = signature.set_buffer_length(sign_point_len);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = signature.set_data_length(sign_point_len);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


		/* Check the length of sign_point1.x.a.d and convert it to octet string. */
		if (sign_point1.x.a.d[0] != 0)
		{
			sign_point_len = 2ul * sign_point1.x.a.d[0];

			I2OSP(
				signature.get_data_offset(sign_len, sign_point_len),
				sign_point1.x.a.d,
				sign_point_len);

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("sign_point1"),
				signature.get_data_offset(sign_len, sign_point_len),
				sign_point_len));

			sign_len += sign_point_len;
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: WAPI_Core: this = 0x%08x, %s: ec_am_algorithms_direct_nrc_c::create_signature_with_private_key(): ECDSA sign point 1 generation failed\n"),
				 this,
				 (m_is_client == true ? "client": "server")));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		 /* Check the length of sign_point2.x.a.d and convert it to octet string. */
		if (sign_point2.x.a.d[0] != 0)
		{
			sign_point_len = 2ul * sign_point2.x.a.d[0];

			I2OSP(
				signature.get_data_offset(sign_len, sign_point_len),
				sign_point2.x.a.d,
				sign_point_len);

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("sign_point2"),
				signature.get_data_offset(sign_len, sign_point_len),
				sign_point_len));

			sign_len += sign_point_len;
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: WAPI_Core: this = 0x%08x, %s: ec_am_algorithms_direct_nrc_c::create_signature_with_private_key(): ECDSA sign point 2 generation failed\n"),
				 this,
				 (m_is_client == true ? "client": "server")));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		status = signature.set_data_length(sign_len);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("signature"),
			 signature.get_data(),
			 signature.get_data_length()));


		status = m_partner->complete_create_signature_with_private_key(&signature, eap_status_ok);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
#endif //#if defined(USE_NRC_ECC_ALGORITHMS)
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("# Private key not found.\n")));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_am_algorithms_direct_nrc_c::verify_signature_with_public_key(
	const eap_variable_data_c * const public_key,
	const eap_variable_data_c * const hash_of_message,
	const eap_variable_data_c * const signature)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_am_algorithms_direct_nrc_c::verify_signature_with_public_key():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_am_algorithms_direct_nrc_c::verify_signature_with_public_key()");

	eap_status_e status(eap_status_not_supported);

	asn1_der_type_c asn1(m_am_tools);
	if (asn1.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = asn1.decode(public_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	static const asn1_type_const_c public_key_query[] =
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
			6),                                       // subjectPublicKeyInfo SubjectPublicKeyInfo, SubjectPublicKeyInfo  ::=  SEQUENCE
		ASN1_TYPE_OBJECT(
			asn1_der_type_c::asn1_class_universal,
			asn1_der_type_c::asn1_tag_bit_string,
			1),                                       // subjectPublicKey     BIT STRING
		ASN1_TYPE_OBJECT_TERMINATOR
	};

	const asn1_der_type_c * const der_public_key = asn1.get_sub_type(public_key_query);

	if (der_public_key != 0)
	{

#if defined(USE_NRC_ECC_ALGORITHMS)

		gfp_point public_key;

		{
			const u8_t * const bit_string_public_key = der_public_key->get_content();
			const u32_t bit_string_public_key_length(der_public_key->get_content_length());

			if (bit_string_public_key != 0
				&& bit_string_public_key_length > 0ul)
			{
				// bit_string_public_key[0]: number of unused bits
				// bit_string_public_key[1]: format of bit string
				// bit_string_public_key[2]: the public key starts
				const u8_t * key = &(bit_string_public_key[2]);
				const u32_t key_length(bit_string_public_key_length - 2ul);

				const u32_t length = key_length / 2ul;

				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ECC Public key"),
					key,
					key_length));

				OS2IP(
					public_key.x.a.d,
					key,
					length);

				key += length;

				OS2IP(
					public_key.y.a.d,
					key,
					key_length - length);
			}
		}

		gfp_point sign_point1;
		gfp_point sign_point2;

		const u32_t length(signature->get_data_length() / 2ul);

		OS2IP(
			sign_point1.x.a.d,
			signature->get_data(length),
			length);

		const u32_t remaining_length(signature->get_data_length() - length);

		OS2IP(
			sign_point2.x.a.d,
			signature->get_data_offset(length, remaining_length),
			remaining_length);

		gfp_curve * const e_curve = reinterpret_cast<gfp_curve *>(m_e_curve.get_data());
		if (e_curve == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
		
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("hash_of_message"),
			hash_of_message->get_data(),
			hash_of_message->get_data_length()));

		u32_t verification_status = DRM_ECDSA_Verify_P256(
			hash_of_message->get_data(),
			hash_of_message->get_data_length(),
			sign_point1.x.a.d,
			sign_point2.x.a.d,
			&public_key,
			e_curve);

		if (verification_status)
		{
			// OK signature.

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: this = 0x%08x, %s: ec_am_algorithms_direct_nrc_c::verify_signature_with_public_key(): Signature OK, verification_status = %d .\n"),
				 this,
				 (m_is_client == true ? "client": "server"),
				 verification_status));

			status = m_partner->complete_verify_signature_with_public_key(eap_status_ok);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: WAPI_Core: this = 0x%08x, %s: ec_am_algorithms_direct_nrc_c::verify_signature_with_public_key(): Wrong signature.\n"),
				 this,
				 (m_is_client == true ? "client": "server")));

			status = m_partner->complete_verify_signature_with_public_key(eap_status_authentication_failure);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

#else

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);

#endif //#if defined(USE_NRC_ECC_ALGORITHMS)

	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("# Public key not found.\n")));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

eap_status_e ec_am_algorithms_direct_nrc_c::initialize_curve()
{

#if defined(USE_NRC_ECC_ALGORITHMS)

	const byte param_a192[24]=
	{
		0xBB, 0x8E, 0x5E, 0x8F, 0xBC, 0x11, 0x5E, 0x13,
		0x9F, 0xE6, 0xA8, 0x14, 0xFE, 0x48, 0xAA, 0xA6,
		0xF0, 0xAD, 0xA1, 0xAA, 0x5D, 0xF9, 0x19, 0x85
	};

	const byte param_b192[24]=
	{
		0x18, 0x54, 0xBE, 0xBD, 0xC3, 0x1B, 0x21, 0xB7,
		0xAE, 0xFC, 0x80, 0xAB, 0x0E, 0xCD, 0x10, 0xD5,
		0xB1, 0xB3, 0x30, 0x8E, 0x6D, 0xBF, 0x11, 0xC1
	};

	const byte param_p192[24]=
	{
		0xBD, 0xB6, 0xF4, 0xFE, 0x3E, 0x8B, 0x1D, 0x9E,
		0x0D, 0xA8, 0xC0, 0xD4, 0x6F, 0x4C, 0x31, 0x8C,
		0xEF, 0xE4, 0xAF, 0xE3, 0xB6, 0xB8, 0x55, 0x1F
	};

	const byte param_order192[24]=
	{
		0xBD, 0xB6, 0xF4, 0xFE, 0x3E, 0x8B, 0x1D, 0x9E,
		0x0D, 0xA8, 0xC0, 0xD4, 0x0F, 0xC9, 0x62, 0x19,
		0x5D, 0xFA, 0xE7, 0x6F, 0x56, 0x56, 0x46, 0x77
	};

	const byte param_gx192[24]=
	{
		0x4A, 0xD5, 0xF7, 0x04, 0x8D, 0xE7, 0x09, 0xAD,
		0x51, 0x23, 0x6D, 0xE6, 0x5E, 0x4D, 0x4B, 0x48,
		0x2C, 0x83, 0x6D, 0xC6, 0xE4, 0x10, 0x66, 0x40
	};

	const byte param_gy192[24]=
	{
		0x02, 0xBB, 0x3A, 0x02, 0xD4, 0xAA, 0xAD, 0xAC,
		0xAE, 0x24, 0x81, 0x7A, 0x4C, 0xA3, 0xA1, 0xB0,
		0x14, 0xB5, 0x27, 0x04, 0x32, 0xDB, 0x27, 0xD2
	};

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("Initialize 192 bits elliptic curve\n")));
	

	gfp_curve local_e_curve;

	OS2IP(local_e_curve.e.p.a.d,param_p192,24);
	OS2IP(local_e_curve.order.a.d,param_order192,24);

	OS2IP(local_e_curve.e.a.a.d,param_a192,24);
	OS2IP(local_e_curve.e.b.a.d,param_b192,24);

	OS2IP(local_e_curve.g.x.a.d,param_gx192,24);
	OS2IP(local_e_curve.g.y.a.d,param_gy192,24);

	eap_status_e status = m_e_curve.set_copy_of_buffer(&local_e_curve, sizeof(local_e_curve));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	{
		struct nc_rand_state local_state;

		m_am_tools->memset(&local_state, 0, sizeof(local_state));

		int i;
		byte ZIPSeed[16];
		byte random[20];

		status = m_am_tools->get_crypto()->get_rand_bytes(
			random,
			sizeof(random));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("random"),
			random,
			sizeof(random)));

		for(i=0;i<16;i++)
		{
			ZIPSeed[i]=i;
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ZIPSeed"),
			ZIPSeed,
			sizeof(ZIPSeed)));

		random_init(&local_state, ZIPSeed, random);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("local_state"),
			&local_state,
			sizeof(local_state)));

		status = m_nc_rand_state.set_copy_of_buffer(&local_state, sizeof(local_state));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);

#else

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);

#endif //#if defined(USE_NRC_ECC_ALGORITHMS)

}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_am_algorithms_direct_nrc_c::create_ecdh_temporary_keys()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_am_algorithms_direct_nrc_c::create_ecdh_temporary_keys():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_am_algorithms_direct_nrc_c::create_ecdh_temporary_keys()");

	eap_status_e status(eap_status_not_supported);

	eap_variable_data_c private_key_d(m_am_tools);
	eap_variable_data_c public_key_x(m_am_tools);
	eap_variable_data_c public_key_y(m_am_tools);

	if (private_key_d.get_is_valid() == false
		|| public_key_x.get_is_valid() == false
		|| public_key_y.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

#if defined(USE_NRC_ECC_ALGORITHMS)
	{
		gfp_coord tmp_user_priv_key;
		gfp_point tmp_user_public_key;

		gfp_curve * const e_curve = reinterpret_cast<gfp_curve *>(m_e_curve.get_data(sizeof(gfp_curve)));
		if (e_curve == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		struct nc_rand_state * const nc_rand_state = reinterpret_cast<struct nc_rand_state *>(m_nc_rand_state.get_data(sizeof(struct nc_rand_state)));
		if (nc_rand_state == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		DRM_ECC_GenKeyPair_P256(nc_rand_state, tmp_user_priv_key.a.d, &tmp_user_public_key, e_curve);

		if (tmp_user_priv_key.a.d[0] != 0u)
		{
			u32_t key_len = 2 * tmp_user_priv_key.a.d[0];

			status = private_key_d.set_buffer_length(key_len);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = private_key_d.set_data_length(key_len);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			I2OSP(
				private_key_d.get_data(key_len),
				tmp_user_priv_key.a.d,
				key_len);

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ECDH: private_key_d"),
				 private_key_d.get_data(),
				 private_key_d.get_data_length()));
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: WAPI_Core: this = 0x%08x, %s: ec_am_algorithms_direct_nrc_c::create_ecdh_temporary_keys(): ECDH private key generation failed\n"),
				 this,
				 (m_is_client == true ? "client": "server")));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		if (tmp_user_public_key.x.a.d[0] != 0u)
		{
			u32_t key_len = 2 * tmp_user_public_key.x.a.d[0];

			status = public_key_x.set_buffer_length(key_len);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = public_key_x.set_data_length(key_len);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			I2OSP(
				public_key_x.get_data(key_len),
				tmp_user_public_key.x.a.d,
				key_len);

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ECDH: public_key_x"),
				 public_key_x.get_data(),
				 public_key_x.get_data_length()));
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: WAPI_Core: this = 0x%08x, %s: ec_am_algorithms_direct_nrc_c::create_ecdh_temporary_keys(): ECDH public key x generation failed\n"),
				 this,
				 (m_is_client == true ? "client": "server")));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		if (tmp_user_public_key.y.a.d[0] != 0u)
		{
			u32_t key_len = 2 * tmp_user_public_key.y.a.d[0];

			status = public_key_y.set_buffer_length(key_len);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = public_key_y.set_data_length(key_len);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			I2OSP(
				public_key_y.get_data(key_len),
				tmp_user_public_key.y.a.d,
				key_len);

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ECDH: public_key_y"),
				 public_key_y.get_data(),
				 public_key_y.get_data_length()));
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: WAPI_Core: this = 0x%08x, %s: ec_am_algorithms_direct_nrc_c::create_ecdh_temporary_keys(): ECDH public key y generation failed\n"),
				 this,
				 (m_is_client == true ? "client": "server")));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}
	}

#else

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);

#endif //#if defined(USE_NRC_ECC_ALGORITHMS)

	status = m_partner->complete_create_ecdh_temporary_keys(
		&private_key_d,
		&public_key_x,
		&public_key_y);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_am_algorithms_direct_nrc_c::create_ecdh(
	const eap_variable_data_c * const own_private_key_d,
	const eap_variable_data_c * const peer_public_key_x,
	const eap_variable_data_c * const peer_public_key_y)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_am_algorithms_direct_nrc_c::create_ecdh():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_am_algorithms_direct_nrc_c::create_ecdh()");

	eap_status_e status(eap_status_not_supported);

	eap_variable_data_c K_AB_x4(m_am_tools);
	eap_variable_data_c K_AB_y4(m_am_tools);

	if (K_AB_x4.get_is_valid() == false
		|| K_AB_y4.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

#if defined(USE_NRC_ECC_ALGORITHMS)
	{
		gfp_point K_AB;
		gfp_point user_b_public;
		gfp_coord private_key;

		gfp_curve * const e_curve = reinterpret_cast<gfp_curve *>(m_e_curve.get_data());
		if (e_curve == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ECDH: own_private_key_d"),
			 own_private_key_d->get_data(),
			 own_private_key_d->get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ECDH: peer_public_key_x"),
			 peer_public_key_x->get_data(),
			 peer_public_key_x->get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ECDH: peer_public_key_y"),
			 peer_public_key_y->get_data(),
			 peer_public_key_y->get_data_length()));

		OS2IP(
			private_key.a.d,
			own_private_key_d->get_data(),
			own_private_key_d->get_data_length());

		OS2IP(
			user_b_public.x.a.d,
			peer_public_key_x->get_data(),
			peer_public_key_x->get_data_length());

		OS2IP(
			user_b_public.y.a.d,
			peer_public_key_y->get_data(),
			peer_public_key_y->get_data_length());


		gfp_ecc_dh(
			&K_AB,
			&user_b_public,
			private_key.a.d,
			e_curve);

		if (K_AB.x.a.d[0] != 0u)
		{
			u32_t key_len = 2 * K_AB.x.a.d[0];

			status = K_AB_x4.set_buffer_length(key_len);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = K_AB_x4.set_data_length(key_len);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			I2OSP(
				K_AB_x4.get_data(key_len),
				K_AB.x.a.d,
				key_len);

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ECDH: K_AB_x4"),
				 K_AB_x4.get_data(),
				 K_AB_x4.get_data_length()));
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: WAPI_Core: this = 0x%08x, %s: ec_am_algorithms_direct_nrc_c::create_ecdh(): ECDH shared key x generation failed\n"),
				 this,
				 (m_is_client == true ? "client": "server")));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		if (K_AB.y.a.d[0] != 0u)
		{
			u32_t key_len = 2 * K_AB.y.a.d[0];

			status = K_AB_y4.set_buffer_length(key_len);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = K_AB_y4.set_data_length(key_len);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			I2OSP(
				K_AB_y4.get_data(key_len),
				K_AB.y.a.d,
				key_len);

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ECDH: K_AB_y4"),
				 K_AB_y4.get_data(),
				 K_AB_y4.get_data_length()));
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: WAPI_Core: this = 0x%08x, %s: ec_am_algorithms_direct_nrc_c::create_ecdh(): ECDH shared key y generation failed\n"),
				 this,
				 (m_is_client == true ? "client": "server")));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}
	}
#endif //#if defined(USE_NRC_ECC_ALGORITHMS)

	status = m_partner->complete_create_ecdh(
		&K_AB_x4,
		&K_AB_y4);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT ec_am_base_algorithms_c * ec_am_base_algorithms_c::new_ec_base_algorithms_c(
	abs_eap_am_tools_c * const tools,
	abs_ec_am_algorithms_c * const partner,
	const bool is_client_when_true)
{
	ec_am_base_algorithms_c * store = new ec_am_algorithms_direct_nrc_c(
		tools,
		partner,
		is_client_when_true);

	if (store == 0)
	{
		return 0;
	}

	eap_status_e status(store->configure());

	if (status != eap_status_ok)
	{
		delete store;
		return 0;
	}

	return store;
}

//----------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

// End.
