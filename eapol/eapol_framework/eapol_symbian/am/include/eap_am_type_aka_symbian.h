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
* %version: 18.1.5 %
*/

#if !defined(_EAP_AM_TYPE_AKA_SYMBIAN_H_)
#define _EAP_AM_TYPE_AKA_SYMBIAN_H_


//  INCLUDES

#include <EapType.h>
#include <d32dbms.h>
#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_TYPE_AKA_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_AKA_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_AKA_SYMBIAN_H 
#elif defined(EAP_EXPORT_EAP_AM_TYPE_AKA_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_AKA_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_AKA_SYMBIAN_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_AKA_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_AKA_SYMBIAN_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_base_type.h"

#include "eap_am_type_aka.h"
#include "abs_eap_am_aka_algorithm.h"

// FORWARD DECLARATIONS
class eap_am_tools_symbian_c;
class CEapAkaInterface;

// For the server side.
const u32_t MAX_PSEUDONYM_USE_COUNT = 1;
const u32_t MAX_REAUTH_USE_COUNT = 3;


// CLASS DECLARATION

/**
* Class that implements the operating system dependent portion of 
* EAP AKA protocol for Symbian OS.
*/


class EAP_CLASS_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_am_type_aka_symbian_c
: public CBase, public eap_am_type_aka_c
{
public:
	//--------------------------------------------------
	
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H static eap_am_type_aka_symbian_c* NewL(
		abs_eap_am_tools_c * const aTools,
		abs_eap_base_type_c * const aPartner,
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const bool aIsClient,
		const eap_am_network_id_c * const receive_network_id);
		
	// 
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H virtual ~eap_am_type_aka_symbian_c();	
	
	
	/**  From the parent eap_am_type_aka_c **/

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e configure();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e reset();

	/**
	 * The shutdown() function is called before the destructor of the 
	 * object is executed. During the function call the object 
	 * could shutdown the operations, for example cancel timers.
	 * Each derived class must define this function.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e shutdown();

	/** AKA client calls this function.
	 *  AKA AM could store copy of pseudonym identity to favourite place for future use.
	 *  If parameter pseudonym is NULL pointer, AM should reset the existing pseudonym.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e store_pseudonym_id(
		const eap_am_network_id_c * const send_network_id,
		const eap_variable_data_c * const pseudonym);

	/** AKA client calls this function.
	 *  AKA AM could store copy of reauthentication identity to favourite place for future use.
	 *  If parameter reauthentication_identity is NULL pointer, AM should reset the existing reauthentication identity.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e store_reauthentication_id(
		const eap_am_network_id_c * const send_network_id,
		const eap_variable_data_c * const reauthentication_identity);

	/** AKA server and client calls this function.
	 * In order to use re-authentication, the client and the server need to
	 * store the following values: original XKEY, K_aut, K_encr, latest
	 * counter value and the next re-authentication identity.
	 * This function stores original XKEY, K_aut, K_encr and latest
	 * counter value.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e store_reauth_parameters(
		const eap_variable_data_c * const XKEY,
		const eap_variable_data_c * const K_aut,
		const eap_variable_data_c * const K_encr,
		const u32_t reauth_counter);

	/** AKA client calls this function.
	 *  AKA AM could do finishing operations to databases etc. based on authentication status and type.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e authentication_finished(
		const bool true_when_successfull,
		const eap_aka_authentication_type_e authentication_type,
		const eap_type_aka_identity_type identity_type);

	/** AKA server and client calls this function.
	 * In order to use re-authentication, the client and the server need to
	 * store the following values: original XKEY, K_aut, K_encr, latest
	 * counter value and the next re-authentication identity.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e query_reauth_parameters(
		eap_variable_data_c * const XKEY,
		eap_variable_data_c * const K_aut,
		eap_variable_data_c * const K_encr,
		u32_t * const reauth_counter);

	/** AKA server and client calls this function.
	 *  This function increases re-authentication counter after a successfull re-authentication.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e increase_reauth_counter();

	/** AKA client calls this function.
	 *  AM could copy IMSI or pseudonym to output parameters.
	 *  AM must copy IMSI or pseudonym to output parameters.
	 *  This function could be completed asyncronously with abs_eap_am_type_aka_c::complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() function call.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e query_AKA_IMSI_or_pseudonym_or_reauthentication_id(
		eap_variable_data_c * const IMSI,
		eap_variable_data_c * const pseudonym_identity,
		eap_variable_data_c * const reauthentication_identity,
		eap_variable_data_c * const automatic_realm, ///< If this is not used, do not add any data to this parameter.
		u32_t * const length_of_mnc,
		const aka_payload_AT_type_e required_identity, ///< This parameter indicated the type of identity required.
		const eap_type_aka_complete_e required_completion, ///< This parameter tells the required completion after this call is completed, if this is asyncronous. Use this value with abs_eap_am_type_aka_c::complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() function call.
		const u8_t received_eap_identifier ///< This is the EAP-identifier of the received EAP-request message. Use this value with abs_eap_am_type_aka_c::complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() function call.
		);

	/** AKA client calls this function.
	 *  This call cancels asyncronous query_AKA_IMSI_or_pseudonym_or_reauthentication_id() function call.
	 *  AM must not complete query_AKA_IMSI_or_pseudonym_or_reauthentication_id()
	 *  with abs_eap_am_type_aka_c::complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() after
	 *  cancel_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() call.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e cancel_AKA_IMSI_or_pseudonym_or_reauthentication_id_query();


	/** AKA client calls this function.
	 *  Input parameter RAND and AUTN as input to AKA algorithm.
	 *  AM could copy CK, IK and RES to output parameters.
	 *  This function could be completed asyncronously with abs_eap_am_type_aka_c::complete_AKA_RES_query() function call.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e query_AKA_RES(
		eap_type_aka_authentication_vector_c * const authentication_vector);

	/** AKA client calls this function.
	 *  This call cancels asyncronous query_AKA_RES() function call.
	 *  AM must not complete query_AKA_RES()
	 *  with abs_eap_am_type_aka_c::complete_AKA_RES_query() after
	 *  cancel_AKA_RES_query() call.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e cancel_AKA_RES_query();

	/** AKA client calls this function.
	 *  Received AT_NOTIFICATION is handled in AM of AKA.
	 *  AM could show localized message to user.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e handle_aka_notification(eap_aka_notification_codes_e aka_notification_code);

	/** AKA server calls this function.
	 *  AM could copy triplets to output parameters.
	 *  This function could be completed asyncronously with abs_eap_am_type_aka_c::complete_AKA_authentication_vector_query() function call.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e query_AKA_authentication_vector(
		const eap_variable_data_c * const username, ///< // This is payload AT_IDENTITY. If this is uninitialized then imsi must be initialized.
		const u8_t next_eap_identifier,
		eap_variable_data_c * const imsi, ///< This is the real IMSI. If this is uninitialized then username must be initialized and imsi will be initialized after this call.
		eap_type_aka_authentication_vector_c * const authentication_vector,
		eap_type_aka_identity_type * const type);

	/** AKA server calls this function.
	 *  This call cancels asyncronous query_AKA_authentication_vector() function call.
	 *  AM must not complete query_AKA_authentication_vector() with abs_eap_am_type_aka_c::complete_AKA_authentication_vector_query() after
	 *  cancel_AKA_authentication_vector_query() call.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e cancel_AKA_authentication_vector_query();

	/** AKA server/client calls this function.
	 *  This function call generates with a good source of
	 *  randomness the initialization vector (AT_IV payload).
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e generate_encryption_IV(
		eap_variable_data_c * const encryption_IV,
		const u32_t IV_length);

	/** AKA server calls this function.
	 *  New pseudonym identity is generated for IMSI.
	 *  Algorithm is freely selected. Look at query_imsi_from_username().
	 *  Pseudonym identity is copied to pseudonym_identity parameter.
	 *  Maximum length of pseudonym is maximum_pseudonym_length bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e generate_pseudonym_id(
		const eap_am_network_id_c * const send_network_id,
		const eap_variable_data_c * const imsi,
		eap_variable_data_c * const pseudonym_identity,
		const u32_t maximum_pseudonym_length);

	/** AKA server calls this function.
	 *  New reauthentication identity is generated for IMSI.
	 *  Algorithm is freely selected. Look at query_imsi_from_username().
	 *  Reauthentication identity is copied to pseudonym parameter.
	 *  Maximum length of pseudonym is maximum_reauthentication_identity_length bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e generate_reauthentication_id(
		const eap_am_network_id_c * const send_network_id,
		const eap_variable_data_c * const imsi,
		eap_variable_data_c * const reauthentication_identity,
		const u32_t maximum_reauthentication_identity_length);

	/** AKA server calls this function.
	 *  Server queries IMSI with username.
	 *  Username could be IMSI, pseudonym or re-authentication identity.
	 *  Adaptation module must verify which username is.
	 *  Adaptation module could map IMSI and username as it wish.
	 *  It can select any algorithm. Look at generate_pseudonym_id() and generate_reauthentication_id().
	 *  Function must return IMSI and set the identity type of received username.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e query_imsi_from_username(
		const u8_t next_eap_identifier,
		const eap_am_network_id_c * const send_network_id,
		const eap_variable_data_c * const username,
		eap_variable_data_c * const imsi,
		eap_type_aka_identity_type * const type,
		const eap_type_aka_complete_e completion_action);

	/** AKA server calls this function.
	 *  Server queries re-syncronization.
	 *  This function call is completed by complete_re_syncronization_query() function.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e query_re_syncronization(
		const u8_t next_eap_identifier,
		eap_type_aka_authentication_vector_c * const authentication_vector
		);

	/** AKA server calls this function.
	 *  This call cancels asyncronous query_imsi_from_username() function call.
	 *  AM must not complete query_imsi_from_username()
	 *  with abs_eap_am_type_aka_c::complete_imsi_from_username() after
	 *  cancel_imsi_from_username_query() call.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e cancel_imsi_from_username_query();

	/**
	 * The type_configure_read() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e type_configure_read(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	/**
	 * The type_configure_write() function writes the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the action to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e type_configure_write(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);		

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H void set_is_valid();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H bool get_is_valid();
	
#if defined(__WINS__)
	
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e query_SIM_imsi(
		u8_t * const imsi, const u32_t max_length, u32_t * const imsi_length);
		
#endif //#if defined(__WINS__)
	
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e complete_AKA_imsi_L(
		const eap_variable_data_c * const IMSI,
		const eap_status_e completion_status = eap_status_ok);
		
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H eap_status_e complete_AKA_RES_L(
		eap_variable_data_c * const aRES, 
		eap_variable_data_c * const aCK,
		eap_variable_data_c * const aIK,
		eap_variable_data_c * const aAUTS,
		eap_status_e authenticationStatus = eap_status_ok,
		const eap_status_e completion_status = eap_status_ok);
		
	/**
	 * Returns true if the full authenticated session is valid.
	 * It finds the difference between current time and the 
	 * last full authentication time. If the difference is less than the
	 * Maximum Session Validity Time, then session is valid, returns true.
	 * Otherwise returns false. 
	 * Full authentication should be done if the session is not valid.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_AKA_SYMBIAN_H bool is_session_valid();

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	eap_am_type_aka_symbian_c(
		abs_eap_am_tools_c * const tools,
		abs_eap_base_type_c * const partner,
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const bool aIsClient,
		const eap_am_network_id_c * const receive_network_id);
	

	void ConstructL();

	//--------------------------------------------------

private:

	void type_configure_readL(
		eap_config_string field,
		const u32_t field_length,
		eap_variable_data_c * const data);

	void store_reauth_parametersL(
		const eap_variable_data_c * const XKEY,
		const eap_variable_data_c * const K_aut,
		const eap_variable_data_c * const K_encr,
		const u32_t reauth_counter);
	
	void query_reauth_parametersL(
		eap_variable_data_c * const reauth_XKEY,
		eap_variable_data_c * const reauth_K_aut,
		eap_variable_data_c * const reauth_K_encr,
		u32_t * const reauth_counter);

	void increase_reauth_counterL();
	
	void query_AKA_IMSI_or_pseudonym_or_reauthentication_idL(
		eap_variable_data_c * const IMSI,
		eap_variable_data_c * const pseudonym_identity,
		eap_variable_data_c * const reauthentication_identity,
		eap_variable_data_c * const automatic_realm, ///< If this is not used, do not add any data to this parameter.
		const aka_payload_AT_type_e required_identity,
		const eap_type_aka_complete_e required_completion,
		const u8_t received_eap_identifier);	

	void store_pseudonym_idL(
		const eap_am_network_id_c * const /*network_id*/,
		const eap_variable_data_c * const pseudonym);

	void store_reauthentication_idL(
		const eap_am_network_id_c * const /*network_id*/,
		const eap_variable_data_c * const /* reauthentication_id */);

#if defined (USE_EAP_TYPE_SERVER_AKA)
	// These functions are used only for server side.
	
	eap_status_e generate_identity(
		const eap_type_aka_identity_type identity_type,
		const eap_variable_data_c * const imsi,
		eap_variable_data_c * const pseudonym,
		const u32_t maximum_pseudonym_length);
			
	eap_status_e query_imsi_from_username_syncronous(
		const u8_t next_eap_identifier,
		const eap_am_network_id_c * const network_id,
		const eap_variable_data_c * const username,
		eap_variable_data_c * const imsi,
		eap_type_aka_identity_type * const identity_type);		
		
#endif // #if defined (USE_EAP_TYPE_SERVER_AKA)		
	
	eap_status_e store_imsi(const eap_variable_data_c * const imsi);

	void store_imsiL(const eap_variable_data_c * const imsi);
			
	eap_status_e check_is_valid_imsi( const eap_variable_data_c * const username );		

	void send_error_notification(const eap_status_e error);
	
	/**
	 * Returns true if the full authenticated session is valid.
	 * It finds the difference between current time and the 
	 * last full authentication time. If the difference is less than the
	 * Maximum Session Validity Time, then session is valid, returns true.
	 * Otherwise returns false. 
	 * Full authentication should be done if the session is not valid.
	 */
	bool is_session_validL();
	
	/**
	 * Stores current universal time as the the full authentication time
	 * in the database. Returns KErrNone if storing succeeds.
	 */
	void store_authentication_timeL();

private:

	//--------------------------------------------------

	RFs m_session;
	
	RDbNamedDatabase m_database;	

	eap_am_tools_symbian_c * const m_am_tools;

	abs_eap_base_type_c * const m_partner;

	eap_variable_data_c m_nai_realm;

	TIndexType m_index_type;
	
	TInt m_index;

	eap_type_value_e m_tunneling_type;

	bool m_is_valid;

	bool m_is_client;

	eap_variable_data_c m_stored_reauth_id;
	
	eap_variable_data_c m_stored_pseudonym;
	
	eap_variable_data_c m_previous_imsi;

	eap_type_aka_complete_e m_stored_required_completion;
	
	u8_t m_stored_received_eap_identifier;

	bool m_shutdown_was_called;

	abs_eap_am_aka_algorithm_c *m_aka_algorithm;
	
	CEapAkaInterface* m_aka_if;	
	
	eap_variable_data_c m_simulator_aka_K;
	eap_variable_data_c m_simulator_aka_OP;
	eap_variable_data_c m_simulator_aka_AMF;
	
	eap_type_aka_authentication_vector_c * m_authentication_vector;
	
	eap_variable_data_c m_pseudonym_identity;
	eap_variable_data_c m_reauthentication_identity;
	eap_variable_data_c m_username;
	eap_am_network_id_c m_receive_network_id;

	eap_variable_data_c m_IMSI;

	aka_payload_AT_type_e m_required_identity;
	eap_type_aka_complete_e m_required_completion;
	eap_type_aka_identity_type m_identity_type;
	eap_type_aka_complete_e m_completion_action;
	u8_t m_next_eap_identifier;
		
	eap_aka_authentication_vector_status_e m_aka_authentication_vector_status;
	u32_t m_pseudonym_key_index;
	eap_variable_data_c m_pseudonym_key;
	eap_variable_data_c m_pseudonym_MAC_key;
	eap_variable_data_c m_prev_pseudonym_key;
	eap_variable_data_c m_prev_pseudonym_MAC_key;
	u32_t m_pseudonym_key_use_count;
	
	// These values are needed especially in the case of synchronization failure.
	eap_variable_data_c m_RAND;
	eap_variable_data_c m_AUTN;

	// This holds the max session time read from the configuration file.
	TInt64 m_max_session_time;
	
}; // class eap_am_type_aka_symbian_c


#endif //#if !defined(_EAP_AM_TYPE_AKA_SYMBIAN_H_)

//--------------------------------------------------



// End of file
