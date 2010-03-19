/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/ec_cs_tlv.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 19 % << Don't touch! Updated by Synergy at check-out.
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
	#define EAP_FILE_NUMBER_ENUM 706 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#if defined(USE_WAPI_CORE)

#include "eap_am_memory.h"
#include "eap_crypto_api.h"
#include "ec_cs_tlv.h"
#include "eap_automatic_variable.h"
#include "ec_cs_tlv_payloads.h"
#include "ec_cs_strings.h"
#include "ec_cs_data.h"


/** @file */

//------------------------------------------------------------------------------

/**
 * The destructor of the ec_cs_tlv_c class does nothing.
 */
ec_cs_tlv_c::~ec_cs_tlv_c()
{
	delete m_payloads;
	m_payloads = 0;
}

//--------------------------------------------------

/**
 * The constructor of the ec_cs_tlv_c class simply initializes the attributes.
 */
ec_cs_tlv_c::ec_cs_tlv_c(
	abs_eap_am_tools_c * const tools,
	const bool true_when_is_client)
	: m_am_tools(tools)
	, m_payloads(0)
	, m_is_client(true_when_is_client)
	, m_is_valid(true)
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT const ec_cs_tlv_payloads_c * ec_cs_tlv_c::get_payloads() const
{
	return m_payloads;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool ec_cs_tlv_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ec_cs_tlv_c::reset()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_cs_tlv_c::reset()");

	if (m_payloads == 0)
	{
		m_payloads = new ec_cs_tlv_payloads_c(m_am_tools, m_is_client);

		if (m_payloads == 0
			|| m_payloads->get_is_valid() == false)
		{
			delete m_payloads;
			m_payloads = 0;

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
	}

	eap_status_e status = m_payloads->reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::generate_data_key(
	const bool in_true_when_encryption_key,
	const ec_cs_data_type_e in_data_type,
	eap_variable_data_c * const out_key,
	const eap_variable_data_c * const in_base_key,
	const eap_variable_data_c * const in_data_reference,
	const eap_variable_data_c * const in_CS_store_device_seed)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC-CS: ec_cs_tlv_c::generate_data_key()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_cs_tlv_c::generate_data_key()");

	eap_status_e status(eap_status_process_general_error);

	if (in_base_key == 0
		|| in_base_key->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (in_CS_store_device_seed->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (out_key == 0
		|| out_key->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c label(m_am_tools);
	if (label.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (in_true_when_encryption_key == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EC-CS: ec_cs_store_c::generate_data_key(): creates encyption key\n")));

		status = label.set_copy_of_buffer(EC_CS_ENCRYPTION_KEY_LABEL, EC_CS_ENCRYPTION_KEY_LABEL_SIZE);
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
			(EAPL("EC-CS: ec_cs_store_c::generate_data_key(): creates MAC key\n")));

		status = label.set_copy_of_buffer(EC_CS_MAC_KEY_LABEL, EC_CS_MAC_KEY_LABEL_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c seed(m_am_tools);
	if (seed.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = seed.set_copy_of_buffer(in_CS_store_device_seed);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = seed.add_data(EC_CS_SEED_SEPARATOR, EC_CS_SEED_SEPARATOR_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (in_data_type == ec_cs_data_type_master_key)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EC-CS: ec_cs_store_c::generate_data_key(): creates a key for master key :-)\n")));

		status = seed.add_data(EC_CS_MASTER_KEY_SEED, EC_CS_MASTER_KEY_SEED_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (in_data_type == ec_cs_data_type_reference_counter)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EC-CS: ec_cs_store_c::generate_data_key(): creates reference counter key\n")));

		status = seed.add_data(EC_CS_REFERENCE_COUNTER_SEED, EC_CS_REFERENCE_COUNTER_SEED_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (in_data_type == ec_cs_data_type_ca_certificate_data)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EC-CS: ec_cs_store_c::generate_data_key(): creates CA certificate data key\n")));

		status = seed.add_data(EC_CS_CA_CERTIFICATE_DATA_DATA_SEED, EC_CS_CA_CERTIFICATE_DATA_DATA_SEED_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (in_data_type == ec_cs_data_type_client_certificate_data)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EC-CS: ec_cs_store_c::generate_data_key(): creates client certificate data key\n")));

		status = seed.add_data(EC_CS_USER_CERTIFICATE_DATA_DATA_SEED, EC_CS_USER_CERTIFICATE_DATA_DATA_SEED_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (in_data_type == ec_cs_data_type_private_key_data)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EC-CS: ec_cs_store_c::generate_data_key(): creates private key data key\n")));

		status = seed.add_data(EC_CS_PRIVATE_KEY_DATA_SEED, EC_CS_PRIVATE_KEY_DATA_SEED_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (in_data_type == ec_cs_data_type_ca_asu_id)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EC-CS: ec_cs_store_c::generate_data_key(): creates CA ASU-ID data key\n")));

		status = seed.add_data(EC_CS_CA_ASU_ID_DATA_SEED, EC_CS_CA_ASU_ID_DATA_SEED_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (in_data_type == ec_cs_data_type_client_asu_id)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EC-CS: ec_cs_store_c::generate_data_key(): creates client ASU-ID data key\n")));

		status = seed.add_data(EC_CS_CLIENT_ASU_ID_DATA_SEED, EC_CS_CLIENT_ASU_ID_DATA_SEED_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	status = seed.add_data(in_data_reference);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	status = out_key->set_buffer_length(EC_CS_MAC_KEY_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = out_key->set_data_length(EC_CS_MAC_KEY_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	crypto_tls_prf_c t_prf(m_am_tools);

	if (t_prf.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC CS store base key"),
		 in_base_key->get_data(),
		 in_base_key->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC CS store device seed"),
		 in_CS_store_device_seed->get_data(),
		 in_CS_store_device_seed->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC CS store reference"),
		 in_data_reference->get_data(),
		 in_data_reference->get_data_length()));

	status = t_prf.tls_prf_init(
		in_base_key,
		&label,
		&seed);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = t_prf.tls_prf_output(
		out_key->get_data(),
		static_cast<u16_t>(out_key->get_data_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	EAP_ASSERT((EC_CS_MAC_KEY_SIZE >= EC_CS_ENCRYPTION_KEY_SIZE));

	if (in_true_when_encryption_key == true)
	{
		status = out_key->set_data_length(EC_CS_ENCRYPTION_KEY_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC CS store key"),
		 out_key->get_data(),
		 out_key->get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::create_tlv(
	ec_cs_variable_data_c * const new_tlv,
	const ec_cs_tlv_type_e type,
	const eap_variable_data_c * const pac_attributes)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ec_cs_tlv_c::create_tlv()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_cs_tlv_c::create_tlv()");

	if (new_tlv == 0
		|| new_tlv->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (pac_attributes == 0
		|| pac_attributes->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	/*  EC CS TLV
	 *  0                   1                   2                   3   
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |      TLV Type (AVP Type)      |            Length             |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |            EC CS Attributes ...                  
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	eap_status_e status = new_tlv->set_copy_of_buffer(
		type,
		pac_attributes->get_data(),
		pac_attributes->get_data_length());

	EC_CS_TLV_TRACE_PAYLOAD("Creates EC CS TLV", (new_tlv->get_header()), m_is_client);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::create_generic_tlv(
	ec_cs_variable_data_c * const new_tlv,
	const ec_cs_tlv_type_e type,
	const eap_variable_data_c * const payload)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ec_cs_tlv_c::create_generic_tlv()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_cs_tlv_c::create_generic_tlv()");

	if (new_tlv == 0
		|| new_tlv->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	/*  CS-generic TLV
	 *  0                   1                   2                   3   
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |      TLV Type (AVP Type)      |            Length             |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                                                               |
	 * |                            Payload                            |
	 * |                                                               |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	eap_status_e status(eap_status_ok);

	if (payload != 0
		&& payload->get_is_valid_data() == true)
	{
		status = new_tlv->set_copy_of_buffer(
			type,
			payload->get_data(),
			payload->get_data_length());
	}
	else
	{
		status = new_tlv->set_copy_of_buffer(
			type,
			0,
			0ul);
	}

	EC_CS_TLV_TRACE_PAYLOAD("Creates CS-generic TLV", (new_tlv->get_header()), m_is_client);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::create_u32_t_tlv(
	ec_cs_variable_data_c * const new_tlv,
	const ec_cs_tlv_type_e type,
	const u32_t value)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ec_cs_tlv_c::create_u32_t_tlv(%s)\n"),
		ec_cs_tlv_header_c::get_tlv_string(type)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_cs_tlv_c::create_u32_t_tlv()");

	if (new_tlv == 0
		|| new_tlv->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	/*  CS-u32_t TLV
	 *  0                   1                   2                   3   
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |      TLV Type (AVP Type)      |            Length             |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |       any 32-bit value                                        |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	u32_t network_order_value(eap_htonl(value));

	eap_status_e status = new_tlv->set_copy_of_buffer(
		type,
		&network_order_value,
		sizeof(network_order_value));

	EC_CS_TLV_TRACE_PAYLOAD("Creates CS-32-bit TLV", (new_tlv->get_header()), m_is_client);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::create_u16_t_tlv(
	ec_cs_variable_data_c * const new_tlv,
	const ec_cs_tlv_type_e type,
	const u16_t value)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ec_cs_tlv_c::create_u16_t_tlv(%s)\n"),
		ec_cs_tlv_header_c::get_tlv_string(type)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_cs_tlv_c::create_u16_t_tlv()");

	if (new_tlv == 0
		|| new_tlv->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	/*  CS-u16_t TLV
	 *  0                   1                   2                   3   
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |      TLV Type (AVP Type)      |            Length             |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |       any 16-bit value        |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	u16_t network_order_value(eap_htons(value));

	eap_status_e status = new_tlv->set_copy_of_buffer(
		type,
		&network_order_value,
		sizeof(network_order_value));

	EC_CS_TLV_TRACE_PAYLOAD("Creates CS-16-bit lifetime TLV", (new_tlv->get_header()), m_is_client);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::read_generic_tlv(
	const ec_cs_variable_data_c * const tlv,
	const ec_cs_tlv_type_e type,
	eap_variable_data_c * const payload)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ec_cs_tlv_c::read_generic_tlv()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_cs_tlv_c::read_generic_tlv()");

	if (tlv != 0
		&& tlv->get_type() == type
		&& payload != 0
		&& payload->get_is_valid() == true)
	{
		u8_t * type_data = tlv->get_data(sizeof(u16_t));
		if (type_data == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		eap_status_e status = payload->set_copy_of_buffer(type_data, tlv->get_data_length());

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::read_u32_t_tlv(
	const ec_cs_variable_data_c * const tlv,
	const ec_cs_tlv_type_e type,
	u32_t * const value)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ec_cs_tlv_c::read_u32_t_tlv()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_cs_tlv_c::read_u32_t_tlv()");

	if (tlv != 0
		&& tlv->get_type() == type
		&& value != 0)
	{
		u8_t * type_data = tlv->get_data(sizeof(u16_t));
		if (type_data == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		*value = eap_read_u16_t_network_order(
			type_data,
			sizeof(u32_t));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::read_u16_t_tlv(
	const ec_cs_variable_data_c * const tlv,
	const ec_cs_tlv_type_e type,
	u16_t * const value)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ec_cs_tlv_c::read_u16_t_tlv()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_cs_tlv_c::read_u16_t_tlv()");

	if (tlv != 0
		&& tlv->get_type() == type
		&& value != 0)
	{
		u8_t * type_data = tlv->get_data(sizeof(u16_t));
		if (type_data == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		*value = eap_read_u16_t_network_order(
			type_data,
			sizeof(u16_t));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::create_MAC(
	eap_variable_data_c * const MAC,
	const eap_variable_data_c * const server_opaque_mac_key,
	const eap_variable_data_c * const protected_data)
{
	crypto_sha_256_c sha256(m_am_tools);
	crypto_hmac_c hmac(m_am_tools, &sha256, false);

	eap_status_e status = hmac.hmac_set_key(
		server_opaque_mac_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC-CS Compound MAC over data"),
		protected_data->get_data(),
		protected_data->get_data_length()));

	status = hmac.hmac_update(
		protected_data->get_data(),
		protected_data->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (MAC == 0
		|| MAC->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = MAC->set_buffer_length(hmac.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = MAC->set_data_length(hmac.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t mac_length = hmac.get_digest_length();

	status = hmac.hmac_final(
		MAC->get_data(),
		&mac_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (mac_length != hmac.get_digest_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EC-CS Compound MAC"),
		 MAC->get_data(),
		 hmac.get_digest_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::create_encrypted_tlv(
	const ec_cs_tlv_type_e new_tlv_type,
	const eap_variable_data_c * const encryption_key,
	const ec_cs_variable_data_c * const plaintext_data_tlvs,
	ec_cs_variable_data_c * const new_tlv)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ec_cs_tlv_c::create_encrypted_tlv()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_cs_tlv_c::create_encrypted_tlv()");

	if (new_tlv == 0
		|| new_tlv->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	EC_CS_TLV_TRACE_PAYLOAD("Plain text TLV", (plaintext_data_tlvs->get_header()), m_is_client);

	eap_status_e status(eap_status_process_general_error);

	//----------------------------------------------------------------------

	/*
	 * EC CS Encrypted block TLV
	 *
 	 * 0                   1                   2                   3   
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    -+ -+
	 * | Type=CS-Encrypted block TLV   |    Length=4+16+4+n+4+m        |     |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+  |  |
	 * | Type=CS-Encryption IV TLV     |          Length=16            |  |  |  | plain text
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  |  |
	 * |                              IV (16 octets)                   |  |  |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+  |  |
	 * | Type=CS-Encrypted data TLV    |          Length=n+4+m         |  |  |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  | -+
	 * |                           data TLVs (n octets)                |  |  |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  |  | encrypted
	 * | Type=CS-padding TLV           |          Length=m             |  |  |  | multiple of
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  |  | 16 octets
	 * |                           padding (m octets)                  |  |  |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+ -+ -+
	 */

	//----------------------------------------------------------------------

	crypto_aes_c aes(m_am_tools);
	crypto_cbc_c aes_cbc(m_am_tools, &aes, false);

	if (aes.get_is_valid() == false
		|| aes_cbc.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	ec_cs_variable_data_c temporary_encrypt_tlv(m_am_tools);
	if (temporary_encrypt_tlv.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = temporary_encrypt_tlv.set_copy_of_buffer(plaintext_data_tlvs);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	//----------------------------------------------------------------------
	// Create IV.
	// IV will be added to the begin of the encypted data.

	ec_cs_variable_data_c  * const IV_tlv = new ec_cs_variable_data_c(m_am_tools);
	eap_automatic_variable_c<ec_cs_variable_data_c> automatic_IV_tlv(m_am_tools, IV_tlv);
	if (IV_tlv == 0
		|| IV_tlv->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		eap_variable_data_c IV(m_am_tools);
		if (IV.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = IV.set_buffer_length(aes_cbc.get_block_size());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = IV.set_data_length(aes_cbc.get_block_size());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		crypto_random_c rand(m_am_tools);
		if (rand.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = rand.get_rand_bytes(
			IV.get_data(),
			IV.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = create_generic_tlv(
			IV_tlv,
			ec_cs_tlv_type_CS_encryption_IV,
			&IV);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	//----------------------------------------------------------------------
	// Create padding.

	{
		u32_t padding_length(
			aes_cbc.get_block_size()
				- ((temporary_encrypt_tlv.get_data_length() + ec_cs_tlv_header_c::get_header_length())
					% aes_cbc.get_block_size()));

		u8_t max_padding[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, };

		eap_variable_data_c padding(m_am_tools);
		if (padding.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = padding.set_buffer(
			max_padding,
			padding_length,
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		ec_cs_variable_data_c  * const padding_tlv = new ec_cs_variable_data_c(m_am_tools);
		eap_automatic_variable_c<ec_cs_variable_data_c> automatic_padding_tlv(m_am_tools, padding_tlv);
		if (padding_tlv == 0
			|| padding_tlv->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = create_generic_tlv(
			padding_tlv,
			ec_cs_tlv_type_CS_padding,
			&padding);

		// Add padding TLV to plaintext data.
		status = temporary_encrypt_tlv.add_data(
			padding_tlv->get_full_tlv_buffer()->get_data(),
			padding_tlv->get_full_tlv_buffer()->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	//----------------------------------------------------------------------
	// Encrypt data.

	{
		status = aes_cbc.set_encryption_key(
			IV_tlv->get_data(IV_tlv->get_data_length()),
			IV_tlv->get_data_length(),
			encryption_key->get_data(),
			encryption_key->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// NOTE, only the data field including padding TLV is encrypted.
		status = aes_cbc.encrypt_data(
			temporary_encrypt_tlv.get_data(temporary_encrypt_tlv.get_data_length()),
			temporary_encrypt_tlv.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	//----------------------------------------------------------------------
	// Combine TLVs.

	{
		status = create_generic_tlv(
			new_tlv,
			new_tlv_type,
			IV_tlv->get_full_tlv_buffer());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = new_tlv->add_data(
			temporary_encrypt_tlv.get_full_tlv_buffer()->get_data(),
			temporary_encrypt_tlv.get_full_tlv_buffer()->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	//----------------------------------------------------------------------

	EC_CS_TLV_TRACE_PAYLOAD("EC CS Encrypted block TLV", (new_tlv->get_header()), m_is_client);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::parse_encrypted_tlv(
	const eap_variable_data_c * const in_decryption_key,
	const ec_cs_variable_data_c * const in_encrypted_block_tlv,
	ec_cs_variable_data_c * const plain_text_tlv)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ec_cs_tlv_c::parse_encrypted_tlv()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_cs_tlv_c::parse_encrypted_tlv()");

	if (plain_text_tlv == 0
		|| plain_text_tlv->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	//----------------------------------------------------------------------

	EC_CS_TLV_TRACE_PAYLOAD("EC CS Encrypted block TLV", (in_encrypted_block_tlv->get_header()), m_is_client);

	/*
	 * EC CS Encrypted block TLV
	 *
 	 * 0                   1                   2                   3   
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    -+ -+
	 * | Type=CS-Encrypted block TLV   |     Length=4+16+4+n+4+m       |     |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+  |  |
	 * | Type=CS-Encryption IV TLV     |           Length=16           |  |  |  | plain text
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  |  |
	 * |                              IV (16 octets)                   |  |  |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+  |  |
	 * | Type=CS-Encrypted data TLV    |           Length=n+4+m        |  |  |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  | -+
	 * |                           data TLVs (n octets)                |  |  |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  |  | encrypted
	 * | Type=CS-padding TLV           |           Length=m            |  |  |  | multiple of
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  |  | 16 octets
	 * |                           padding (m octets)                  |  |  |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+ -+ -+
	 */

	//----------------------------------------------------------------------

	eap_status_e status(eap_status_process_general_error);

	ec_cs_tlv_payloads_c * const CS_encrypted_block_payloads = new ec_cs_tlv_payloads_c(m_am_tools, m_is_client);
	eap_automatic_variable_c<ec_cs_tlv_payloads_c> automatic_CS_encrypted_block_payloads(m_am_tools, CS_encrypted_block_payloads);
	if (CS_encrypted_block_payloads == 0
		|| CS_encrypted_block_payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t encrypted_block_payloads_length(in_encrypted_block_tlv->get_data_length());
	u32_t encrypted_block_payloads_padding_length(0ul);

	status = CS_encrypted_block_payloads->parse_ec_cs_payloads(
		in_encrypted_block_tlv->get_data(in_encrypted_block_tlv->get_data_length()), ///< This is the start of the IV TLV and Encrypted data TLV.
		&encrypted_block_payloads_length, ///< This is the length of the buffer. This must match with the length of all payloads.
		&encrypted_block_payloads_padding_length ///< Length of possible padding is set to this variable.
		);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	ec_cs_variable_data_c * const IV_tlv = CS_encrypted_block_payloads->get_tlv_pointer(ec_cs_tlv_type_CS_encryption_IV);

	if (IV_tlv == 0
		|| IV_tlv->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
	}

	ec_cs_variable_data_c * const encrypted_data_tlv = CS_encrypted_block_payloads->get_tlv_pointer(ec_cs_tlv_type_CS_encrypted_data);

	if (encrypted_data_tlv == 0
		|| encrypted_data_tlv->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
	}

	// Decrypt EC CS Encrypted data TLV

	crypto_aes_c aes(m_am_tools);
	crypto_cbc_c aes_cbc(m_am_tools, &aes, false);

	if (aes.get_is_valid() == false
		|| aes_cbc.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = aes_cbc.set_decryption_key(
		IV_tlv->get_data(IV_tlv->get_data_length()),
		IV_tlv->get_data_length(),
		in_decryption_key->get_data(),
		in_decryption_key->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = aes_cbc.decrypt_data(
		encrypted_data_tlv->get_data(encrypted_data_tlv->get_data_length()),
		encrypted_data_tlv->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = plain_text_tlv->set_copy_of_buffer(
		encrypted_data_tlv->get_full_tlv_buffer()->get_data(),
		encrypted_data_tlv->get_full_tlv_buffer()->get_data_length());

	EC_CS_TLV_TRACE_PAYLOAD("EC CS plain text TLV", (plain_text_tlv->get_header()), m_is_client);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::create_data_with_MAC(
	const eap_variable_data_c * const MAC_key,
	const eap_variable_data_c * const in_data,
	eap_variable_data_c * const out_data_tlv)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ec_cs_tlv_c::create_data_with_MAC()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_cs_tlv_c::create_data_with_MAC()");

	if (out_data_tlv == 0
		|| out_data_tlv->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (in_data == 0
		|| in_data->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}


	eap_status_e status(eap_status_process_general_error);

	//----------------------------------------------------------------------

	/*
	 * data in EC CS store
	 *
	 *  0                   1                   2                   3   
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+
	 * | Type=data TLV                 |           Length              |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | protected
	 * |                             data (n octets)                   |  | by MAC
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+
	 * | Type=CS-MAC TLV               |           Length=32           |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |                              MAC (32 octets)                  |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+
	 */

	status = out_data_tlv->set_copy_of_buffer(in_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	//----------------------------------------------------------------------
	// Add MAC TLV.

	ec_cs_variable_data_c  * const MAC_tlv = new ec_cs_variable_data_c(m_am_tools);
	eap_automatic_variable_c<ec_cs_variable_data_c> automatic_MAC_tlv(m_am_tools, MAC_tlv);
	if (MAC_tlv == 0
		|| MAC_tlv->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		eap_variable_data_c MAC(m_am_tools);

		status = create_MAC(
			&MAC,
			MAC_key,
			out_data_tlv);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = create_generic_tlv(
			MAC_tlv,
			ec_cs_tlv_type_CS_MAC,
			&MAC);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EC_CS_TLV_TRACE_PAYLOAD("CS-MAC TLV", (MAC_tlv->get_header()), m_is_client);

		status = out_data_tlv->add_data(MAC_tlv->get_full_tlv_buffer());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::verify_data_with_MAC(
	const eap_variable_data_c * const in_base_key,
	const eap_variable_data_c * const in_CS_store_device_seed,
	const ec_cs_data_c * const in_CS_data_with_MAC)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ec_cs_tlv_c::verify_data_with_MAC()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_cs_tlv_c::verify_data_with_MAC()");

	eap_status_e status(eap_status_process_general_error);

	eap_variable_data_c MAC_key(m_am_tools);
	if (MAC_key.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = generate_data_key(
		false,
		in_CS_data_with_MAC->get_type(),
		&MAC_key,
		in_base_key,
		in_CS_data_with_MAC->get_reference(),
		in_CS_store_device_seed);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = parse_data_with_MAC(
		&MAC_key,
		in_CS_data_with_MAC->get_data());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::parse_data_with_MAC(
	const eap_variable_data_c * const MAC_key,
	const eap_variable_data_c * const CS_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ec_cs_tlv_c::parse_data_with_MAC()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_cs_tlv_c::parse_data_with_MAC()");

	if (CS_data == 0
		|| CS_data->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_process_general_error);

	//----------------------------------------------------------------------

	delete m_payloads;
	m_payloads = new ec_cs_tlv_payloads_c(m_am_tools, m_is_client);

	if (m_payloads == 0
		|| m_payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t encrypted_block_payloads_length(CS_data->get_data_length());
	u32_t encrypted_block_payloads_padding_length(0ul);

	status = m_payloads->parse_ec_cs_payloads(
		CS_data->get_data(CS_data->get_data_length()), ///< This is the start of TLVs, the last one must be MAC TLV.
		&encrypted_block_payloads_length, ///< This is the length of the buffer. This must match with the length of all payloads.
		&encrypted_block_payloads_padding_length ///< Length of possible padding is set to this variable.
		);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	ec_cs_variable_data_c * const CS_MAC_tlv = m_payloads->get_tlv_pointer(ec_cs_tlv_type_CS_MAC);

	if (CS_MAC_tlv == 0
		|| CS_MAC_tlv->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
	}

	{
		eap_variable_data_c MAC_data(m_am_tools);
		if (MAC_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// MAC data includes all data except MAC TLV.
		u32_t MAC_data_length
			= CS_data->get_data_length() - CS_MAC_tlv->get_full_tlv_buffer()->get_data_length();

		status = MAC_data.set_buffer(
			CS_data->get_data(),
			MAC_data_length,
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_variable_data_c MAC(m_am_tools);
		if (MAC.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = create_MAC(
			&MAC,
			MAC_key,
			&MAC_data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (MAC.compare(CS_MAC_tlv->get_data(CS_MAC_tlv->get_data_length()), CS_MAC_tlv->get_data_length()) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}
	}

	//----------------------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::create_master_key_data(
	const eap_variable_data_c * const in_CS_password,
	const eap_variable_data_c * const in_CS_store_device_seed,
	const eap_variable_data_c * const in_CS_master_key_or_null,
	const eap_variable_data_c * const in_data_reference,
	eap_variable_data_c * const master_key_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ec_cs_tlv_c::create_master_key_data()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_cs_tlv_c::create_master_key_data()");

	if (in_CS_password == 0
		|| in_CS_password->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (in_CS_store_device_seed == 0
		|| in_CS_store_device_seed->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (in_CS_master_key_or_null != 0
		&& in_CS_master_key_or_null->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (master_key_data == 0
		|| master_key_data->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	//----------------------------------------------------------------------

	eap_variable_data_c master_key_encryption_key(m_am_tools);
	if (master_key_encryption_key.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = generate_data_key(
		true,
		ec_cs_data_type_master_key,
		&master_key_encryption_key,
		in_CS_password,
		in_data_reference,
		in_CS_store_device_seed);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c master_key_MAC_key(m_am_tools);
	if (master_key_MAC_key.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = generate_data_key(
		false,
		ec_cs_data_type_master_key,
		&master_key_MAC_key,
		in_CS_password,
		in_data_reference,
		in_CS_store_device_seed);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	ec_cs_variable_data_c encrypted_data_tlv(m_am_tools);
	if (encrypted_data_tlv.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	ec_cs_variable_data_c master_key_tlv(m_am_tools);
	if (master_key_tlv.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c CS_master_key(m_am_tools);
	if (CS_master_key.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (in_CS_master_key_or_null == 0)
	{
		// Create a new EC CS Store Master Key.
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ec_cs_tlv_c::create_master_key_data(): Creates new master key.\n")));

		crypto_random_c rand(m_am_tools);

		if (rand.get_is_valid() == false)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = CS_master_key.set_buffer_length(EC_CS_MASTER_KEY_SIZE);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = CS_master_key.set_data_length(EC_CS_MASTER_KEY_SIZE);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = rand.get_rand_bytes(
			CS_master_key.get_data(
				CS_master_key.get_data_length()),
			CS_master_key.get_data_length());
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ec_cs_tlv_c::create_master_key_data(): Uses existing master key.\n")));

		status = CS_master_key.set_buffer(in_CS_master_key_or_null);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = create_generic_tlv(
		&master_key_tlv,
		ec_cs_tlv_type_CS_master_key,
		&CS_master_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = create_generic_tlv(
		&encrypted_data_tlv,
		ec_cs_tlv_type_CS_encrypted_data,
		master_key_tlv.get_full_tlv_buffer());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	ec_cs_variable_data_c CS_encrypted_block_tlv(m_am_tools);
	if (CS_encrypted_block_tlv.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = create_encrypted_tlv(
		ec_cs_tlv_type_CS_encrypted_block,
		&master_key_encryption_key,
		&encrypted_data_tlv,
		&CS_encrypted_block_tlv);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = create_data_with_MAC(
		&master_key_MAC_key,
		CS_encrypted_block_tlv.get_full_tlv_buffer(),
		master_key_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("New Master key data"),
		 master_key_data->get_data(),
		 master_key_data->get_data_length()));

	//----------------------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::parse_cs_tlv(
	const ec_cs_variable_data_c * const PAC_tlv)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ec_cs_tlv_c::parse_cs_tlv()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_cs_tlv_c::parse_cs_tlv()");

	if (PAC_tlv == 0
		|| PAC_tlv->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_process_general_error);

	status = PAC_tlv->get_header()->check_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if ((PAC_tlv->get_header()->get_header_length() + PAC_tlv->get_header()->get_data_length()) > PAC_tlv->get_header()->get_header_buffer_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EC_CS_TLV_TRACE_PAYLOAD("Parse CS TLV", (PAC_tlv->get_header()), m_is_client);


	{
		delete m_payloads;
		m_payloads = 0;
		m_payloads = new ec_cs_tlv_payloads_c(m_am_tools, m_is_client);

		if (m_payloads == 0
			|| m_payloads->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t buffer_length(PAC_tlv->get_data_length());
		u32_t padding_length(0ul);

		status = m_payloads->parse_ec_cs_payloads(
			PAC_tlv->get_data(PAC_tlv->get_data_length()), ///< This is the start of the message buffer.
			&buffer_length, ///< This is the length of the buffer. This must match with the length of all payloads.
			&padding_length ///< Length of possible padding is set to this variable.
			);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::parse_encrypted_tlv_with_MAC(
	const ec_cs_data_type_e in_data_type,
	const eap_variable_data_c * const in_base_key,
	const eap_variable_data_c * const in_data_reference,
	const eap_variable_data_c * const in_CS_store_device_seed,
	const eap_variable_data_c * const in_data_tlv,
	ec_cs_variable_data_c * const out_plain_text_tlv)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ec_cs_tlv_c::parse_encrypted_tlv_with_MAC()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_cs_tlv_c::parse_encrypted_tlv_with_MAC()");

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("parse_encrypted_tlv_with_MAC(): in_data_tlv"),
		 in_data_tlv->get_data(),
		 in_data_tlv->get_data_length()));

	/*
	 * Encrypted data with MAC.
	 *
 	 * 0                   1                   2                   3   
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+ -+ -+
	 * | Type=Any pre-selected TLVs    | Length=4+l+4+16+4+n+4+m       |  |  |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  |M |
	 * |                     Any pre-selected data (l octets)          |  |  |A |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+  |C |
	 * | Type=CS-Encrypted-Block TLV   |  Length=4+16+4+n+4+m          |  |  |  | plain text
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  |d |
	 * | Type=CS-Encryption IV TLV     |           Length=16           |  |  |a |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  |t |
	 * |                              IV (16 octets)                   |  |  |a |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  |  |
	 * | Type=CS-Encrypted data TLV    |           Length=n+4+m        |  |  |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  | -+
	 * |                          Master key TLV (n octets)            |  |  |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  |  | encrypted
	 * | Type=CS-padding TLV           |           Length=m            |  |  |  | multiple of
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  |  | 16 octets
	 * |                           padding (m octets)                  |  |  |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+ -+ -+
	 * | Type=CS-MAC TLV               |           Length=32           |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |                              MAC (32 octets)                  |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+
	 */

	eap_status_e status(eap_status_process_general_error);

	// First check the MAC is correct.

	{
		eap_variable_data_c MAC_key(m_am_tools);
		if (MAC_key.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = generate_data_key(
			false,
			in_data_type,
			&MAC_key,
			in_base_key,
			in_data_reference,
			in_CS_store_device_seed);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = parse_data_with_MAC(
			&MAC_key,
			in_data_tlv);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	const ec_cs_variable_data_c * const encrypted_block_tlv = get_payloads()->get_tlv_pointer(ec_cs_tlv_type_CS_encrypted_block);
	if (encrypted_block_tlv == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// Second, decrypt encrypted block.

	{
		eap_variable_data_c decryption_key(m_am_tools);
		if (decryption_key.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = generate_data_key(
			true,
			in_data_type,
			&decryption_key,
			in_base_key,
			in_data_reference,
			in_CS_store_device_seed);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = parse_encrypted_tlv(
			&decryption_key,
			encrypted_block_tlv,
			out_plain_text_tlv);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::create_encrypted_certificate(
	const ec_cs_data_type_e in_data_type,
	const eap_variable_data_c * const in_base_key,
	const eap_variable_data_c * const in_data_reference,
	const eap_variable_data_c * const in_CS_store_device_seed,
	const eap_variable_data_c * const in_certificate_reference,
	const ec_cs_tlv_type_e in_certificate_tlv_type,
	const eap_variable_data_c * const in_certificate_data,
	eap_variable_data_c * const out_certificate_data_block)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ec_cs_tlv_c::create_encrypted_certificate()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_cs_tlv_c::create_encrypted_certificate()");

	eap_status_e status(eap_status_process_general_error);

	/**
	 *  0                   1                   2                   3   
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+
	 * | Type=Certificate-ref. TLV     |           Length              |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | protected
	 * |                    Certificate-reference                      |  | by MAC
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * | Type=CS-Encrypted-Block TLV   |           Length              |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |      CS-Encrypted block TLVs (Certificate-Data TLV) ...          |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+
	 * | Type=CS-MAC TLV               |           Length=32           |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |                           CS MAC (32 octets)                  |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+
	 */

	ec_cs_variable_data_c encrypted_block_tlv(m_am_tools);

	if (encrypted_block_tlv.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		eap_variable_data_c encryption_key(m_am_tools);
		if (encryption_key.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = generate_data_key(
			true,
			in_data_type,
			&encryption_key,
			in_base_key,
			in_data_reference,
			in_CS_store_device_seed);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		ec_cs_variable_data_c certificate_data_tlv(m_am_tools);

		if (certificate_data_tlv.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = certificate_data_tlv.set_copy_of_buffer(
			in_certificate_tlv_type,
			in_certificate_data->get_data(),
			in_certificate_data->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		ec_cs_variable_data_c plain_text_block_tlv(m_am_tools);

		if (plain_text_block_tlv.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = plain_text_block_tlv.set_copy_of_buffer(
			ec_cs_tlv_type_CS_encrypted_data,
			certificate_data_tlv.get_full_tlv_buffer()->get_data(),
			certificate_data_tlv.get_full_tlv_buffer()->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = create_encrypted_tlv(
			ec_cs_tlv_type_CS_encrypted_block,
			&encryption_key,
			&plain_text_block_tlv,
			&encrypted_block_tlv);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	eap_variable_data_c MAC_data_buffer(m_am_tools);
	if (MAC_data_buffer.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		ec_cs_variable_data_c certificate_reference_tlv(m_am_tools);

		if (certificate_reference_tlv.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = certificate_reference_tlv.set_copy_of_buffer(
			ec_cs_tlv_type_CS_certificate_reference,
			in_certificate_reference->get_data(),
			in_certificate_reference->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = MAC_data_buffer.set_copy_of_buffer(certificate_reference_tlv.get_full_tlv_buffer());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = MAC_data_buffer.add_data(encrypted_block_tlv.get_full_tlv_buffer());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		eap_variable_data_c MAC_key(m_am_tools);
		if (MAC_key.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = generate_data_key(
			false,
			in_data_type,
			&MAC_key,
			in_base_key,
			in_data_reference,
			in_CS_store_device_seed);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = create_data_with_MAC(
			&MAC_key,
			&MAC_data_buffer,
			out_certificate_data_block);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("New encrypted certificate data"),
			 out_certificate_data_block->get_data(),
			 out_certificate_data_block->get_data_length()));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_c::parse_encrypted_certificate(
	const ec_cs_data_type_e in_data_type,
	const eap_variable_data_c * const in_base_key,
	const eap_variable_data_c * const in_data_reference,
	const eap_variable_data_c * const in_CS_store_device_seed,
	const eap_variable_data_c * const in_certificate_data_block,
	eap_variable_data_c * const out_certificate_reference)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ec_cs_tlv_c::parse_encrypted_certificate()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_cs_tlv_c::parse_encrypted_certificate()");

	eap_status_e status(eap_status_process_general_error);

	ec_cs_variable_data_c decrypted_block_tlv(m_am_tools);
	if (decrypted_block_tlv.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = parse_encrypted_tlv_with_MAC(
		in_data_type,
		in_base_key,
		in_data_reference,
		in_CS_store_device_seed,
		in_certificate_data_block,
		&decrypted_block_tlv);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const ec_cs_variable_data_c * const certificate_reference_tlv = get_payloads()->get_tlv_pointer(ec_cs_tlv_type_CS_certificate_reference);
	if (certificate_reference_tlv == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	status = out_certificate_reference->set_copy_of_buffer(certificate_reference_tlv->get_full_tlv_buffer());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = parse_cs_tlv(&decrypted_block_tlv);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//------------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

// End.
