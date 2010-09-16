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
* %version: 19.1.5 %
*/

#if !defined(_EAP_AM_TYPE_GSMSIM_SYMBIAN_H_)
#define _EAP_AM_TYPE_GSMSIM_SYMBIAN_H_

//  INCLUDES
#include <EapType.h>
#include <d32dbms.h>
#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_TYPE_GSMSIM_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_GSMSIM_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_GSMSIM_SYMBIAN_H 
#elif defined(EAP_EXPORT_EAP_AM_TYPE_GSMSIM_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_GSMSIM_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_GSMSIM_SYMBIAN_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_GSMSIM_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_GSMSIM_SYMBIAN_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_base_type.h"
#include "eap_am_type_gsmsim.h"
#include "abs_eap_am_sim_algorithm.h"

#if !defined (USE_EAP_GSMSIM_INTERFACE)
// These are needed only for test environment ( Plugin tester).
// Comment out USE_EAP_GSMSIM_INTERFACE in eapol.mmh for building for the test environment.
#include "eap_am_sim_algorithm_nokia_test.h"
#endif // #if !defined (USE_EAP_GSMSIM_INTERFACE)

#include "eap_am_network_id.h"

// FORWARD DECLARATIONS

class CEapSimIsaInterface;
class eap_am_tools_symbian_c;

// CLASS DECLARATION

/**
* Class that implements the operating system dependent portion of EAP SIM protocol.
* For Symbian OS.
*/
class EAP_CLASS_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_am_type_gsmsim_symbian_c
: public CBase, public eap_am_type_gsmsim_c
{
public:
	//--------------------------------------------------

	static eap_am_type_gsmsim_symbian_c* NewL(
		abs_eap_am_tools_c * const aTools,
		abs_eap_base_type_c * const aPartner,
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const bool aIsClient,
		const eap_am_network_id_c * const receive_network_id);
	// 
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H virtual ~eap_am_type_gsmsim_symbian_c();

	// 
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e configure();

	// 
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e reset();

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e shutdown();

#if defined(__WINS__)
	// 
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e query_SIM_imsi(
		u8_t * const imsi, const u32_t max_length, u32_t * const imsi_length);

#endif //#if defined(__WINS__)

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e store_pseudonym_id(
		const eap_am_network_id_c * const network_id,
		const eap_variable_data_c * const pseudonym);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e store_reauthentication_id(
		const eap_am_network_id_c * const network_id,
		const eap_variable_data_c * const reauthentication_identity);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e query_SIM_IMSI_or_pseudonym_or_reauthentication_id(
		const bool must_be_synchronous,
		eap_variable_data_c * const IMSI,
		eap_variable_data_c * const pseudonym_identity,
		eap_variable_data_c * const reauthentication_identity,
		eap_variable_data_c * const automatic_realm, ///< If this is not used, do not add any data to this parameter.
		u32_t * const length_of_mnc,
		const gsmsim_payload_AT_type_e required_identity,
		const eap_type_gsmsim_complete_e required_completion,
		const u8_t received_eap_identifier
		);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e cancel_SIM_IMSI_or_pseudonym_or_reauthentication_id_query();

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e query_SIM_kc_and_sres(
		const u8_t * const rand,
		u8_t * const kc,
		u8_t * const sres);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e handle_gsmsim_notification(eap_gsmsim_notification_codes_e gsmsim_notification_code);


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e query_SIM_triplets(
		const bool must_be_synchronous,
		const eap_variable_data_c * const username,
		eap_variable_data_c * const imsi,
		eap_type_sim_triplet_array_c * const triplets,
		eap_type_gsmsim_identity_type * const type);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e cancel_SIM_triplets_query();
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e query_SIM_kc_sres(
		const bool must_be_synchronous,
		//const eap_variable_data_c * const imsi,
		const eap_variable_data_c * const n_rands,
		eap_variable_data_c * const n_kc,
		eap_variable_data_c * const n_sres);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e cancel_SIM_kc_sres_query();

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e generate_encryption_IV(
		eap_variable_data_c * const encryption_IV,
		const u32_t IV_length);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e generate_pseudonym_id(
		const eap_am_network_id_c * const network_id,
		const eap_variable_data_c * const imsi,
		eap_variable_data_c * const pseudonym,
		const u32_t maximum_pseudonym_length);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e generate_reauthentication_id(
		const eap_am_network_id_c * const network_id,
		const eap_variable_data_c * const imsi,
		eap_variable_data_c * const reauthentication_identity,
		const u32_t maximum_reauthentication_identity_length);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e store_reauth_parameters(
		const eap_variable_data_c * const XKEY,
		const eap_variable_data_c * const K_aut,
		const eap_variable_data_c * const K_encr,
		const u32_t reauth_counter);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e authentication_finished(
		const bool true_when_successfull,
		const eap_gsmsim_authentication_type_e authentication_type,
		const eap_type_gsmsim_identity_type identity_type);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e query_reauth_parameters(
		eap_variable_data_c * const XKEY,
		eap_variable_data_c * const K_aut,
		eap_variable_data_c * const K_encr,
		u32_t * const reauth_counter);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e increase_reauth_counter();


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e query_imsi_from_username(
		const bool must_be_synchronous,
		const u8_t next_eap_identifier,
		const eap_am_network_id_c * const network_id,
		const eap_variable_data_c * const username,
		eap_variable_data_c * const imsi,
		eap_type_gsmsim_identity_type * const type,
		const eap_type_gsmsim_complete_e completion_action);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e cancel_imsi_from_username_query();

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e check_is_rand_unused(const eap_variable_data_c * const n_rands);

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e set_rand_is_used(const eap_variable_data_c * const n_rands);

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H void set_is_valid();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H bool get_is_valid();

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e type_configure_read(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_H eap_status_e type_configure_write(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	eap_status_e complete_SIM_imsi_L(
		const eap_variable_data_c * const IMSI,
		const eap_status_e completion_status);

	eap_status_e complete_SIM_kc_and_sres_L(
		TDesC8& aKc,
		TDesC8& aSRES,
		const eap_status_e completion_status);
		
	/**
	 * Returns true if the full authenticated session is valid.
	 * It finds the difference between current time and the 
	 * last full authentication time. If the difference is less than the
	 * Maximum Session Validity Time, then session is valid, returns true.
	 * Otherwise returns false. 
	 * Full authentication should be done if the session is not valid.
	 */
	bool is_session_valid();
		

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	eap_am_type_gsmsim_symbian_c(
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

	void store_pseudonym_idL(
		const eap_am_network_id_c * const /*network_id*/,
		const eap_variable_data_c * const pseudonym);

	void store_reauthentication_idL(
		const eap_am_network_id_c * const /*network_id*/,
		const eap_variable_data_c * const /* reauthentication_id */);

	void query_SIM_IMSI_or_pseudonym_or_reauthentication_idL(
		const bool must_be_synchronous,
		eap_variable_data_c * const IMSI,
		eap_variable_data_c * const pseudonym_identity,
		eap_variable_data_c * const reauthentication_identity,
		eap_variable_data_c * const automatic_realm, ///< If this is not used, do not add any data to this parameter.
		u32_t * const length_of_mnc,
		const gsmsim_payload_AT_type_e required_identity,
		const eap_type_gsmsim_complete_e required_completion,
		const u8_t received_eap_identifier);

	eap_status_e generate_identity(
		const eap_am_network_id_c * const /* network_id */,
		const eap_variable_data_c * const imsi,
		eap_variable_data_c * const identity,
		const u32_t maximum_identity_length);

	eap_status_e store_imsi(const eap_variable_data_c * const imsi);
	
	void store_imsiL(const eap_variable_data_c * const imsi);

	void send_error_notification(const eap_status_e error);


#if defined(USE_EAP_SIM_RESET_RAND_DATABASES)

	eap_status_e reset_rand_check();

#endif //#if defined(USE_EAP_SIM_RESET_RAND_DATABASES)
	
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

	eap_variable_data_c m_triplet_file;

	eap_variable_data_c m_nai_realm;

	TIndexType m_index_type;
	
	TInt m_index;

	eap_type_value_e m_tunneling_type;

	bool m_is_valid;

	bool m_is_client;

	CEapSimIsaInterface* m_isa_if;
	
	eap_variable_data_c m_stored_reauth_id;
	
	eap_variable_data_c m_stored_pseudonym;
	
	eap_variable_data_c m_previous_imsi;

	eap_type_gsmsim_complete_e m_stored_required_completion;
	
	u8_t m_stored_received_eap_identifier;

	bool m_shutdown_was_called;
	
#if !defined (USE_EAP_GSMSIM_INTERFACE)
	eap_am_sim_algorithm_nokia_test_c m_sim_algorithm;
#endif //#if !defined (USE_EAP_GSMSIM_INTERFACE)
	
	sim_algorithm_e m_simulator_sim_algorithm;
	
	eap_variable_data_c m_simulator_sim_ki;

	eap_variable_data_c m_copy_of_n_rands;

	eap_variable_data_c m_n_kc;

	eap_variable_data_c m_n_sres;

	eap_variable_data_c m_uma_automatic_realm_prefix;

	eap_am_network_id_c m_receive_network_id;

	TInt m_rands_handled;

	/// This flag tells whether the client should check uniqueness of RANDs (true) or not (false).
	bool m_do_rand_uniqueness_check;
	
	// This holds the max session time read from the configuration file.
	TInt64 m_max_session_time;

	//--------------------------------------------------
}; // class eap_am_type_gsmsim_symbian_c


#endif //#if !defined(_EAP_AM_TYPE_GSMSIM_SYMBIAN_H_)

//--------------------------------------------------



// End of file
