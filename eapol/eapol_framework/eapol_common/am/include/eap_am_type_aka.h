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

#if !defined(_EAP_AM_TYPE_AKA_H_)
#define _EAP_AM_TYPE_AKA_H_

#include "eap_tools.h"
#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_TYPE_AKA_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_AKA_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_H 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_AKA_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_AKA_H 
#elif defined(EAP_EXPORT_EAP_AM_TYPE_AKA_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_AKA_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_AKA_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_AKA_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_AKA_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_AKA_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_AKA_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_am_type_aka.h"
#include "eap_sim_triplets.h"
#include "eap_am_network_id.h"

/// This class is interface to adaptation module of AKA.
class EAP_CLASS_VISIBILITY_EAP_AM_TYPE_AKA_H eap_am_type_aka_c
{
private:
	//--------------------------------------------------

	abs_eap_am_type_aka_c *m_am_partner;
	abs_eap_am_tools_c *m_am_tools;

	bool m_is_valid;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~eap_am_type_aka_c()
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}

	// 
	eap_am_type_aka_c(abs_eap_am_tools_c * const tools /*, abs_eap_am_type_aka_c * const partner */)
	: m_am_partner(0)
	, m_am_tools(tools)
	, m_is_valid(false)
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		set_is_valid();
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}

	/** Function returns partner object of adaptation module of AKA.
	 *  Partner object is the AKA object.
	 */
	abs_eap_am_type_aka_c * const get_am_partner()
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return m_am_partner;
	}

	/** Function sets partner object of adaptation module of AKA.
	 *  Partner object is the AKA object.
	 */
	void set_am_partner(abs_eap_am_type_aka_c * const partner)
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		m_am_partner = partner;
	}

	void set_is_valid()
	{
		m_is_valid = true;
	}

	bool get_is_valid()
	{
		return m_is_valid;
	}

	virtual eap_status_e configure() = 0;

	virtual eap_status_e reset() = 0;

	/**
	 * The shutdown() function is called before the destructor of the 
	 * object is executed. During the function call the object 
	 * could shutdown the operations, for example cancel timers.
	 * Each derived class must define this function.
	 */
	virtual eap_status_e shutdown() = 0;

	/** AKA client calls this function.
	 *  AKA AM could store copy of pseudonym identity to favourite place for future use.
	 *  If parameter pseudonym is NULL pointer, AM should reset the existing pseudonym.
	 */
	virtual eap_status_e store_pseudonym_id(
		const eap_am_network_id_c * const send_network_id,
		const eap_variable_data_c * const pseudonym) = 0;

	/** AKA client calls this function.
	 *  AKA AM could store copy of reauthentication identity to favourite place for future use.
	 *  If parameter reauthentication_identity is NULL pointer, AM should reset the existing reauthentication identity.
	 */
	virtual eap_status_e store_reauthentication_id(
		const eap_am_network_id_c * const send_network_id,
		const eap_variable_data_c * const reauthentication_identity) = 0;

	/** AKA server and client calls this function.
	 * In order to use re-authentication, the client and the server need to
	 * store the following values: original XKEY, K_aut, K_encr, latest
	 * counter value and the next re-authentication identity.
	 * This function stores original XKEY, K_aut, K_encr and latest
	 * counter value.
	 */
	virtual eap_status_e store_reauth_parameters(
		const eap_variable_data_c * const XKEY,
		const eap_variable_data_c * const K_aut,
		const eap_variable_data_c * const K_encr,
		const u32_t reauth_counter) = 0;

	/** AKA client calls this function.
	 *  AKA AM could do finishing operations to databases etc. based on authentication status and type.
	 */
	virtual eap_status_e authentication_finished(
		const bool true_when_successfull,
		const eap_aka_authentication_type_e authentication_type,
		const eap_type_aka_identity_type identity_type) = 0;

	/** AKA server and client calls this function.
	 * In order to use re-authentication, the client and the server need to
	 * store the following values: original XKEY, K_aut, K_encr, latest
	 * counter value and the next re-authentication identity.
	 */
	virtual eap_status_e query_reauth_parameters(
		eap_variable_data_c * const XKEY,
		eap_variable_data_c * const K_aut,
		eap_variable_data_c * const K_encr,
		u32_t * const reauth_counter) = 0;

	/** AKA server and client calls this function.
	 *  This function increases re-authentication counter after a successfull re-authentication.
	 */
	virtual eap_status_e increase_reauth_counter() = 0;

	/** AKA client calls this function.
	 *  AM could copy IMSI or pseudonym to output parameters.
	 *  AM must copy IMSI or pseudonym to output parameters.
	 *  This function could be completed asyncronously with abs_eap_am_type_aka_c::complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() function call.
	 */
	virtual eap_status_e query_AKA_IMSI_or_pseudonym_or_reauthentication_id(
		eap_variable_data_c * const IMSI,
		eap_variable_data_c * const pseudonym_identity,
		eap_variable_data_c * const reauthentication_identity,
		eap_variable_data_c * const automatic_realm, ///< If this is not used, do not add any data to this parameter.
		u32_t * const length_of_mnc,
		const aka_payload_AT_type_e required_identity, ///< This parameter indicated the type of identity required.
		const eap_type_aka_complete_e required_completion, ///< This parameter tells the required completion after this call is completed, if this is asyncronous. Use this value with abs_eap_am_type_aka_c::complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() function call.
		const u8_t received_eap_identifier ///< This is the EAP-identifier of the received EAP-request message. Use this value with abs_eap_am_type_aka_c::complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() function call.
		) = 0;

	/** AKA client calls this function.
	 *  This call cancels asyncronous query_AKA_IMSI_or_pseudonym_or_reauthentication_id() function call.
	 *  AM must not complete query_AKA_IMSI_or_pseudonym_or_reauthentication_id()
	 *  with abs_eap_am_type_aka_c::complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() after
	 *  cancel_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() call.
	 */
	virtual eap_status_e cancel_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() = 0;


	/** AKA client calls this function.
	 *  Input parameter RAND and AUTN as input to AKA algorithm.
	 *  AM could copy CK, IK and RES to output parameters.
	 *  This function could be completed asyncronously with abs_eap_am_type_aka_c::complete_AKA_RES_query() function call.
	 */
	virtual eap_status_e query_AKA_RES(
		eap_type_aka_authentication_vector_c * const authentication_vector) = 0;

	/** AKA client calls this function.
	 *  This call cancels asyncronous query_AKA_RES() function call.
	 *  AM must not complete query_AKA_RES()
	 *  with abs_eap_am_type_aka_c::complete_AKA_RES_query() after
	 *  cancel_AKA_RES_query() call.
	 */
	virtual eap_status_e cancel_AKA_RES_query() = 0;


	/** AKA client calls this function.
	 *  Received AT_NOTIFICATION is handled in AM of AKA.
	 *  AM could show localized message to user.
	 */
	virtual eap_status_e handle_aka_notification(eap_aka_notification_codes_e aka_notification_code) = 0;

	/** AKA server calls this function.
	 *  AM could copy triplets to output parameters.
	 *  This function could be completed asyncronously with abs_eap_am_type_aka_c::complete_AKA_authentication_vector_query() function call.
	 */
	virtual eap_status_e query_AKA_authentication_vector(
		const eap_variable_data_c * const username, ///< // This is payload AT_IDENTITY. If this is uninitialized then imsi must be initialized.
		const u8_t next_eap_identifier,
		eap_variable_data_c * const imsi, ///< This is the real IMSI. If this is uninitialized then username must be initialized and imsi will be initialized after this call.
		eap_type_aka_authentication_vector_c * const authentication_vector,
		eap_type_aka_identity_type * const type) = 0;

	/** AKA server calls this function.
	 *  This call cancels asyncronous query_AKA_authentication_vector() function call.
	 *  AM must not complete query_AKA_authentication_vector() with abs_eap_am_type_aka_c::complete_AKA_authentication_vector_query() after
	 *  cancel_AKA_authentication_vector_query() call.
	 */
	virtual eap_status_e cancel_AKA_authentication_vector_query() = 0;

	/** AKA server calls this function.
	 *  This function call generates with a good source of
	 *  randomness the initialization vector (AT_IV payload).
	 */
	virtual eap_status_e generate_encryption_IV(
		eap_variable_data_c * const encryption_IV,
		const u32_t IV_length) = 0;

	/** AKA server calls this function.
	 *  New pseudonym identity is generated for IMSI.
	 *  Algorithm is freely selected. Look at query_imsi_from_username().
	 *  Pseudonym identity is copied to pseudonym_identity parameter.
	 *  Maximum length of pseudonym is maximum_pseudonym_length bytes.
	 */
	virtual eap_status_e generate_pseudonym_id(
		const eap_am_network_id_c * const send_network_id,
		const eap_variable_data_c * const imsi,
		eap_variable_data_c * const pseudonym_identity,
		const u32_t maximum_pseudonym_length) = 0;

	/** AKA server calls this function.
	 *  New reauthentication identity is generated for IMSI.
	 *  Algorithm is freely selected. Look at query_imsi_from_username().
	 *  Reauthentication identity is copied to pseudonym parameter.
	 *  Maximum length of pseudonym is maximum_reauthentication_identity_length bytes.
	 */
	virtual eap_status_e generate_reauthentication_id(
		const eap_am_network_id_c * const send_network_id,
		const eap_variable_data_c * const imsi,
		eap_variable_data_c * const reauthentication_identity,
		const u32_t maximum_reauthentication_identity_length) = 0;


	/** AKA server calls this function.
	 *  Server queries IMSI with username.
	 *  Username could be IMSI, pseudonym or re-authentication identity.
	 *  Adaptation module must verify which username is.
	 *  Adaptation module could map IMSI and username as it wish.
	 *  It can select any algorithm. Look at generate_pseudonym_id() and generate_reauthentication_id().
	 *  Function must return IMSI and set the identity type of received username.
	 */
	virtual eap_status_e query_imsi_from_username(
		const u8_t next_eap_identifier,
		const eap_am_network_id_c * const send_network_id,
		const eap_variable_data_c * const username,
		eap_variable_data_c * const imsi,
		eap_type_aka_identity_type * const type,
		const eap_type_aka_complete_e completion_action) = 0;

	/** AKA server calls this function.
	 *  Server queries re-syncronization.
	 *  This function call is completed by complete_re_syncronization_query() function.
	 */
	virtual eap_status_e query_re_syncronization(
		const u8_t next_eap_identifier,
		eap_type_aka_authentication_vector_c * const authentication_vector
		) = 0;

	/** AKA server calls this function.
	 *  This call cancels asyncronous query_imsi_from_username() function call.
	 *  AM must not complete query_imsi_from_username()
	 *  with abs_eap_am_type_aka_c::complete_imsi_from_username() after
	 *  cancel_imsi_from_username_query() call.
	 */
	virtual eap_status_e cancel_imsi_from_username_query() = 0;

	/**
	 * The type_configure_read() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	virtual eap_status_e type_configure_read(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	/**
	 * The type_configure_write() function writes the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the action to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	virtual eap_status_e type_configure_write(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	//--------------------------------------------------
}; // class eap_am_type_aka_c


/** @file */ 

/**
 * This function creates a new instance of adaptation module of AKA EAP-type.
 * @param tools is pointer to the abs_eap_am_tools class created by the adaptation module.
 * AKA EAP-type will callback caller using the partner pointer.
 */
EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_H  eap_am_type_aka_c *new_eap_am_type_aka(
	abs_eap_am_tools_c * const tools,
	abs_eap_base_type_c * const partner,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id);


#endif //#if !defined(_EAP_AM_TYPE_AKA_H_)

//--------------------------------------------------



// End.
