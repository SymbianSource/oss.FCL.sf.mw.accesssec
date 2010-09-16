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
* %version: 120 %
*/

#if !defined(_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H_)
#define _EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H_

#include "eap_tools.h"
#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H 
#elif defined(EAP_EXPORT_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_am_type_tls_peap.h"
#include "eap_am_type_tls_peap.h"
#include "eap_am_network_id.h"
#include <d32dbms.h>
#include <EapType.h>
#include <unifiedcertstore.h>
#include <mctwritablecertstore.h>
#include <pkixcertchain.h>
#include "eap_auth_notifier.h"

#include "EapTlsPeapUtils.h"
#include <bigint.h>

#if defined(USE_FAST_EAP_TYPE)
#include "EapFastNotifierStruct.h"
#include <etelmm.h>
#endif

#include "EapTtlsPapDbInfoStruct.h"

class CX509Certificate;
class CEapTlsPeapCertInterface;
class eap_am_tools_symbian_c;
class abs_tls_am_application_eap_fast_c;



#ifdef USE_PAC_STORE
class CPacStoreDatabase;
class SInfoEntry;
#endif
#if defined(USE_EAP_CONFIGURATION_TO_SKIP_USER_INTERACTIONS)
class eap_file_config_c;
#endif

const TInt KMaxLabelLength = 64;
const TInt KMaxDatabaseTableName = 64;
const TInt KOffsetCorrection = 1;

#if defined(USE_FAST_EAP_TYPE)
const char KEapFastPacProvisResultKey[] = "eap_am_type_tls_peap_symbian_c prov. result";
const TInt KEapFastPacProvisResultType = 1;
const u32_t KEapFastPacProvisResultDefaultTimeout = 10000; // in milliseconds = 10 seconds
#endif

/// This class is interface to adaptation module of EAP/TLS and PEAP.
class EAP_CLASS_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_am_type_tls_peap_symbian_c
: public CActive
, public eap_am_type_tls_peap_c
, public abs_eap_base_timer_c
, public MNotificationCallback
{

public:

#if defined(USE_FAST_EAP_TYPE)
    enum TEapFastPacProvisResultValue
    {
    EEapFastPacProvisResultFailure, /* 0 */
    EEapFastPacProvisResultSuccess  /* 1 */  
    };
#endif

private: // data

	//--------------------------------------------------

	RFs m_session;

	RDbNamedDatabase m_database;

	enum TState 
	{
		EHandlingIdentityQuery,           /* 0 */
		EHandlingManualIdentityQuery,     /* 1 */
		EHandlingChainQuery,              /* 2 */
		EHandlingCipherSuiteQuery,        /* 3 */
    EHandlingDeviceSeedQuery,        /* 4 */
#if defined(USE_FAST_EAP_TYPE)            /* 5 */
		EHandlingNotifierQuery,           /* 6 */
		EPasswordQuery,                   /* 7 */
		EWrongPassword,                   /* 8 */
		EFilePasswordQuery,               /* 9 */
		EMasterkeyQuery,                  /* 10 */
		EPasswordCancel,                  /* 11 */
		EShowProvSuccesstNote,            /* 12 */
		EShowProvNotSuccesstNote,         /* 13 */
		ENotifierComplete,				/*14 */
#endif //#if defined(USE_FAST_EAP_TYPE)
		EPapUserNameAndPassword, /* 15 */
		EPapChallenge, /* 16 */
		ENone                             /* 17 */
		
	};
	
	TState m_state;
	TState m_prev_state;
	
	TIndexType m_index_type;

	TInt m_index;

	eap_type_value_e m_tunneling_type;

	abs_eap_base_type_c *m_partner;
	eap_am_tools_symbian_c *m_am_tools;

	abs_eap_am_type_tls_peap_c *m_am_partner;

	abs_tls_am_services_c * m_tls_am_partner;

#if defined(USE_FAST_EAP_TYPE)
	abs_tls_am_application_eap_fast_c * m_tls_application;

	enum TAlterTableCmd
	    {
	    EAddColumn,
	    ERemoveColumn
	    };

#endif //#if defined(USE_FAST_EAP_TYPE)

	bool m_is_valid;
	bool m_is_client;

	eap_type_value_e m_current_eap_type;

	TBufC<KMaxDatabaseTableName> m_db_table_name;
	TBufC<KMaxDatabaseTableName> m_db_user_cert_table_name;
	TBufC<KMaxDatabaseTableName> m_db_ca_cert_table_name;
	TBufC<KMaxDatabaseTableName> m_db_cipher_suite_table_name;
	TBufC<KMaxDatabaseTableName> m_db_name;

#if defined (USE_FAST_EAP_TYPE)	
	TBufC<KMaxDatabaseTableName> m_db_fast_special_table_name;
	RPointerArray<SInfoEntry> m_info_array;
#endif	

	u32_t m_max_count_of_session_resumes;
	
	tls_cipher_suites_e m_cipher_suite;

	CX509Certificate* m_ca_certificate;

	CX509Certificate* m_own_certificate;	
	
	CX509Certificate* m_peer_certificate;

	CEapTlsPeapCertInterface* m_cert_if;	

	EapCertificateEntry m_own_certificate_info;

	eap_am_network_id_c m_receive_network_id;

	u8_t m_eap_identifier;

	TKeyIdentifier m_subject_key_id;

	RPointerArray<EapCertificateEntry> m_allowed_ca_certs;

	RPointerArray<EapCertificateEntry> m_allowed_user_certs;
	
	RPointerArray<EapCertificateEntry> m_allowed_server_certs;

	RArray<TUint> m_allowed_cipher_suites;

	eap_variable_data_c m_peer_public_key;
	
	eap_variable_data_c m_param_p;
	eap_variable_data_c m_param_q;
	eap_variable_data_c m_param_g;
	
	bool m_shutdown_was_called;

	/// Tunneling EAP configuration data from EAP database.
	RPointerArray<TEapExpandedType> m_enabled_tunneling_exp_eap_array;
	RPointerArray<TEapExpandedType> m_disabled_tunneling_exp_eap_array;


	TBuf8<4> m_selector_output;

	eap_type_value_e m_tunneled_type;
	
	bool m_verify_certificate_realm;	
	
	bool m_allow_subdomain_matching;

	tls_alert_description_e m_latest_alert_description;

	bool m_use_manual_username;
	eap_variable_data_c m_manual_username;

	bool m_use_manual_realm;
	eap_variable_data_c m_manual_realm;
	
	bool m_tls_peap_server_authenticates_client_policy_flag;

	bool m_use_automatic_ca_certificate;

	/// This flag prevents double configuration. This can happen when 
	/// this class implements many interfaces.
	bool m_configured;

	// This holds the max session time read from the configuration file.
	TInt64 m_max_session_time;

#if defined(USE_EAP_TLS_SESSION_TICKET)
	/// This flag allows use of session ticket, see RFC 4507.
	bool m_use_session_ticket;
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)

#if defined(USE_FAST_EAP_TYPE)
	tls_extension_c * m_received_tunnel_pac_in_session_ticket;
	tls_extension_c * m_received_user_authorization_pac_in_session_ticket;
	eap_fast_pac_type_e m_saved_pac_type;
	eap_fast_completion_operation_e m_completion_operation;
	eap_status_e m_verification_status;
	eap_fast_pac_type_e m_pac_type;
	eap_variable_data_c m_PAC_store_password;
	eap_variable_data_c m_imported_PAC_data_password;
	eap_variable_data_c m_PAC_store_path;
	eap_variable_data_c m_EAP_FAST_IAP_reference;
	eap_variable_data_c m_EAP_FAST_Group_reference;
	eap_variable_data_c m_EAP_FAST_import_path;

	eap_status_e m_eap_fast_completion_status;
	eap_fast_pac_store_pending_operation_e m_eap_fast_pac_store_pending_operation;
	eap_array_c<eap_fast_pac_store_data_c> m_references_and_data_blocks;
	eap_array_c<eap_fast_pac_store_data_c> m_new_references_and_data_blocks;
	eap_array_c<eap_fast_pac_store_data_c> m_ready_references_and_data_blocks;
	
	bool m_serv_unauth_prov_mode;
	bool m_serv_auth_prov_mode;

	// This flag indicates object is used only for PAC-store initialization.
	bool m_is_pac_store_initialization;

    /* For MMETEL */
	// ETel connection.
    RTelServer iServer;
    RMobilePhone iPhone;
    
    // Stores the last queried Phone identities like manufacturer, model, 
    // revision and serial number
    RMobilePhone::TMobilePhoneIdentityV1 iDeviceId; 
    	
    // Tells if MMETEL is connected already or not.
    TBool iMMETELConnectionStatus;    

    TBool m_completed_with_zero;   
	TBool m_verificationStatus;

	HBufC8* m_pacStorePWBuf8;
	EEapFastNotifierUserAction m_userAction;
	eap_pac_store_data_type_e m_pacStoreDataRefType;
	eap_fast_pac_store_data_c m_data_reference;
	eap_variable_data_c m_userResponse;
	eap_fast_pac_store_pending_operation_e m_pending_operation;
	TInt m_both_completed;
	TInt m_both_asked;
	TUint m_ready_references_array_index;
	eap_fast_completion_operation_e m_provisioning_mode;
	
	/**
	* This member is used to store completion operation value
	* in initialize_PAC_store() call from common side.
	* The value is given later in complete call.
	*/
	eap_fast_completion_operation_e iCompletionOperation;
	/**
	* This member is used to store initialize-pac-store-completion value
	* in initialize_PAC_store() call from common side.
	* The value is given later in complete call.
	*/
	eap_fast_initialize_pac_store_completion_e iCompletion;

#endif //#if defined(USE_FAST_EAP_TYPE)

	CEapAuthNotifier::TEapDialogInfo * m_notifier_data_to_user;

	TPckg<CEapAuthNotifier::TEapDialogInfo> * m_notifier_data_pckg_to_user;

#ifdef USE_PAC_STORE
	CPacStoreDatabase * iPacStoreDb;
#endif

#ifdef USE_EAP_CONFIGURATION_TO_SKIP_USER_INTERACTIONS
    TBool m_skip_user_interactions;
    /// This is object to handle file configuration.
    eap_file_config_c * m_fileconfig;
#endif

	
	
	/**
	* Maximum TTLS-PAP session time read from the configuration file.	
	*/
	TInt64 iEapTtlsPapMaxSessionConfigTime;

	/**
	* Provides asynch services used by the caller such as
    * query for TTLS-PAP user name and password.
    */

 //   eap_am_type_tls_peap_symbian_c* iCaller;
    
    eap_variable_data_c* iPacStoreDeviceSeed;

	CEapAuthNotifier* iEapAuthNotifier;


	
//--------------------------------------------------
private: // methods
//--------------------------------------------------


	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H abs_tls_am_services_c * get_tls_am_partner();

	abs_eap_am_type_tls_peap_c * get_am_partner();
	
	void type_configure_readL(
		eap_config_string field,
		const u32_t field_length,
		eap_variable_data_c * const data);

	void verify_certificate_chainL(
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_chain,
		const tls_cipher_suites_e required_cipher_suite);

	void WriteBinaryParamL(
		eap_config_string field,
		const u32_t field_length,
		const eap_variable_data_c * const data);

	void WriteIntParamL(
		eap_config_string field,
		const u32_t field_length,
		eap_variable_data_c * const data);

	void WriteIntParamL(
		eap_config_string field,
		const u32_t field_length,
		const u32_t value);

	void get_identity_from_alternative_nameL(
		const CX509Certificate * const aCertificate, 
		eap_variable_data_c * const aIdentity);

	void get_identities_from_distinguished_namesL(
		const CX509Certificate * const aCertificate, 
		eap_variable_data_c * const aSubjectIdentity,
		eap_variable_data_c * const aIssuerIdentity);

	eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e /* tunneling_type */,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id);

	eap_status_e check_is_valid_eap_type(const eap_type_value_e eap_type);

	eap_status_e get_eap_type_list(
		eap_array_c<eap_type_value_e> * const eap_type_list);

	eap_status_e unload_module(const eap_type_value_e type);

	void complete_signL(const RInteger& aR, const RInteger& aS, eap_status_e aStatus);

	eap_status_e get_realms_from_certificate(
		CX509Certificate* certificate,
		eap_variable_data_c * const subject_realm,
		eap_variable_data_c * const issuer_realm);

	void authentication_finishedL(
		const bool true_when_successful,
		const tls_session_type_e tls_session_type);

	void read_dsa_parametersL();

	eap_status_e SaveManualIdentityL( 
		const TBool use_manual_username,
		TDesC& manual_username,
		const TBool use_manual_realm,
		TDesC& manual_realm);

	void send_error_notification(const eap_status_e error);

	void ResetSessionIdL();
	
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
	
#ifdef USE_PAC_STORE
	
	void GetPacStoreDbDataL(
		const eap_pac_store_data_type_e aPacStoreDataType,
		eap_variable_data_c * aPacStoreData,
		const eap_variable_data_c * const aPacStoreReference = NULL);
	
#endif	// End: #ifdef USE_PAC_STORE	

#if defined(USE_FAST_EAP_TYPE)

	void ReadPACStoredataL(
		const eap_fast_pac_store_pending_operation_e in_pending_operation,
		EAP_TEMPLATE_CONST eap_array_c<eap_fast_pac_store_data_c> * const in_references);
	
	void WritePACStoreDataL(
		const eap_fast_pac_store_pending_operation_e in_pending_operation,
		EAP_TEMPLATE_CONST eap_array_c<eap_fast_pac_store_data_c> * const in_references_and_data_blocks);
		


	eap_status_e RemoveIAPReference();

	eap_status_e ImportFilesL();
	
	eap_status_e PasswordQueryL();
	
	eap_status_e CompletePasswordQueryL();
	
	eap_status_e CompleteFilePasswordQueryL();
	
	eap_status_e CompleteFilePasswordQuery();
	
	eap_status_e FinalCompleteReadPACStoreDataL(eap_status_e status);

	void ConvertUnicodeToAsciiL(const TDesC16& aFromUnicode, TDes8& aToAscii);
	
	eap_status_e ConfigureL();
	
	eap_status_e CreateMasterkeyL();
	
	eap_status_e QueryUserPermissionForAIDL(
			const eap_fast_variable_data_c * const in_pac_attribute_A_ID_info,
			const eap_fast_variable_data_c * const in_pac_attribute_A_ID);
	
	void CompleteAddImportedPACFileL(
			const eap_variable_data_c * const in_imported_PAC_filename,
			const eap_variable_data_c * const out_used_group_reference);
	
#endif //#if defined(USE_FAST_EAP_TYPE)		



    /**
    * Check whether password is older than allowed
    * by max TTLS-PAP session timeout.
    * 
    * @return ETrue - session is valid, EFalse - otherwise.
    */ 
	TBool IsTtlsPapSessionValidL();
	

	/**
	* Check TTLS-PAP session validity.
	* 
	* @return ETrue if currentTime < aInLastFullAuthTime + aInMaxSessionTime,
	*         EFalse - otherwise.
	*/ 
	TBool CheckTtlsPapSessionValidity(
		const TInt64& aInMaxSessionTime,
		const TInt64& aInLastFullAuthTime );
	
#ifdef USE_FAST_EAP_TYPE    
    TInt CreateMMETelConnectionL();

    void DisconnectMMETel();    

    eap_status_e CreateDeviceSeedAsync();
    
    void CompleteCreateDeviceSeedL( TInt aStatus );
#endif
	
	eap_status_e select_cipher_suite(
		const bool select_all_cipher_suites,
		const tls_cipher_suites_e test_cipher_suite,
		const TAlgorithmId testcertAlgorithm,
		const TAlgorithmId certAlgorithm,
		eap_array_c<u16_t> * cipher_suites);

//--------------------------------------------------
protected: // methods
//--------------------------------------------------


	eap_am_type_tls_peap_symbian_c(
		abs_eap_am_tools_c * const aTools,
		abs_eap_base_type_c * const aPartner,
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const eap_type_value_e aEapType,
		const bool aIsClient,
		const eap_am_network_id_c * const receive_network_id);

	void ConstructL();

	void RunL();
	
	void DoCancel();
	
	
//--------------------------------------------------
public: // methods
//--------------------------------------------------

	// 
	static eap_am_type_tls_peap_symbian_c* NewL(
		abs_eap_am_tools_c * const aTools,
		abs_eap_base_type_c * const aPartner,
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const eap_type_value_e aEapType,
		const bool aIsClient,
		const eap_am_network_id_c * const receive_network_id);

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H virtual ~eap_am_type_tls_peap_symbian_c();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e shutdown();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H void set_is_valid();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H bool get_is_valid();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H void set_tls_am_partner(abs_tls_am_services_c * const tls_am_partner);

#if defined(USE_FAST_EAP_TYPE)
	/// This function sets pointer to application of TLS. See abs_tls_am_application_eap_fast_c.
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H void set_tls_application(abs_tls_am_application_eap_fast_c * const tls_application);
	
 	
    /**
    * Check provisioning mode.
    * 
    * @return ETrue - authenticated provisioning mode,
    *         EFalse - unauthenticated provisioning mode.
    */
	TBool IsProvisioningMode();
	
    /**
    * Send error notification to common side.
    * 
    * @param aUserAction EEapFastNotifierUserActionOk or
    *                    EEapFastNotifierUserActionCancel.
    * @return EAP status.
    */
	eap_status_e CompleteQueryUserPermissionForAid(
		EEapFastNotifierUserAction aUserAction );
	
	
	void ContinueInitializePacStore();


	void set_is_pac_store_initialization();
	
#endif //#if defined(USE_FAST_EAP_TYPE)

   /**
    * Send error notification to common side.
    * 
    * @param aError EAP status.
    */
	void SendErrorNotification( const eap_status_e aError );

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H void notify_configuration_error(
		const eap_status_e configuration_status);

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e configure();

	void set_am_partner(abs_eap_am_type_tls_peap_c * const partner);
	
	/** Client calls this function.
	 *  EAP-TLS/PEAP AM could do finishing operations to databases etc. based on authentication status and type.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e reset();

	/** Client calls this function.
	 *  EAP-TLS/PEAP AM could make some fast operations here, heavy operations should be done in the reset() function.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e authentication_finished(
		const bool true_when_successfull,
		const tls_session_type_e tls_session_type);

	/** Client calls this function.
	 *  AM must copy identity to output parameters if call is syncronous.
	 *  This function could be completed asyncronously with abs_eap_am_type_tls_peap_c::complete_query_eap_identity_query() function call.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e query_eap_identity(
		eap_variable_data_c * const identity,
		const eap_am_network_id_c * const receive_network_id,
		const u8_t eap_identifier,
		bool * const use_manual_username,
		eap_variable_data_c * const manual_username,
		bool *const use_manual_realm,
		eap_variable_data_c * const manual_realm);

	/** Client calls this function.
	 *  This call cancels asyncronous query_SIM_IMSI_or_pseudonym_or_reauthentication_id() function call.
	 *  AM must not complete query_SIM_IMSI_or_pseudonym_or_reauthentication_id()
	 *  with abs_eap_am_type_gsmsim_c::complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query() after
	 *  cancel_SIM_IMSI_or_pseudonym_or_reauthentication_id_query() call.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e cancel_identity_query();

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e timer_expired(
		const u32_t id, void *data);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e timer_delete_data(
		const u32_t id, void *data);

	/**
	 * The type_configure_read() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e type_configure_read(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	/**
	 * The type_configure_write() function writes the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the action to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e type_configure_write(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e alert_received(
		const tls_alert_level_e alert_level,
		const tls_alert_description_e alert_description);

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e query_cipher_suites_and_previous_session();

#if defined(USE_EAP_TLS_SESSION_TICKET)
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e query_new_session_ticket();
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e select_cipher_suite_and_check_session_id(
		EAP_TEMPLATE_CONST eap_array_c<u16_t> * const cipher_suite_proposal,
		const eap_variable_data_c * const session_id
#if defined(USE_EAP_TLS_SESSION_TICKET)
		, const tls_extension_c * const session_ticket
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)
		); 


	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e verify_certificate_chain(
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_chain,
		const tls_cipher_suites_e required_cipher_suite);

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e query_certificate_chain(
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_authorities,
		EAP_TEMPLATE_CONST eap_array_c<u8_t> * const certificate_types,
		const tls_cipher_suites_e required_cipher_suite);

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e query_certificate_authorities_and_types();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e query_dh_parameters(
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_chain,
		const tls_cipher_suites_e required_cipher_suite);

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e query_realm(
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_chain);

	// This is always syncronous call.
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e save_tls_session(
		const eap_variable_data_c * const session_id,
		const eap_variable_data_c * const master_secret,
		const tls_cipher_suites_e used_cipher_suite
#if defined(USE_EAP_TLS_SESSION_TICKET)
		, const tls_extension_c * const new_session_ticket
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)
		);

		/// This is always syncronous call.
	/// Function encrypts data with own RSA private key.
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e rsa_encrypt_with_public_key(
		const eap_variable_data_c * const premaster_secret);

	/// This is always syncronous call.
	/// Function decrypts data with own RSA private key.
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e rsa_decrypt_with_private_key(
		const eap_variable_data_c * const encrypted_premaster_secret);

	/// Function signs data with own PKI private key.
	/// NOTE this is syncronous at moment. Asyncronous completion needs many changes.
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e sign_with_private_key(
		const eap_variable_data_c * const message_hash);

	/// Function verifies signed data with peer PKI public key.
	/// NOTE this is syncronous at moment. Asyncronous completion needs many changes.
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e verify_with_public_key(
		const eap_variable_data_c * const message_hash,
		const eap_variable_data_c * const signed_message_hash);


	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e cancel_query_cipher_suites_and_previous_session();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e cancel_select_cipher_suite_and_check_session_id();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e cancel_verify_certificate_chain();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e cancel_query_certificate_chain();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e cancel_query_certificate_authorities_and_types();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e cancel_query_dh_parameters();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e cancel_query_realm();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e cancel_query_dsa_parameters();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e cancel_rsa_encrypt_with_public_key();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e cancel_rsa_decrypt_with_private_key();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e cancel_sign_with_private_key();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e cancel_verify_with_public_key();


	eap_status_e complete_read_own_certificate(
		const RPointerArray<CX509Certificate>& aCertChain, eap_status_e aStatus);
		
	eap_status_e complete_read_ca_certificate(
		const RPointerArray<CX509Certificate>& aCertChain, eap_status_e aStatus);

	void complete_validate_chain(const CPKIXValidationResult * const aValidationResult, const eap_status_e aStatus);

	void complete_get_matching_certificates(RPointerArray<EapCertificateEntry>& aMatchingCerts, eap_status_e aStatus);

	void complete_sign(const RInteger& aR, const RInteger& aS, eap_status_e aStatus);

	void complete_decrypt(TDes8& aData, eap_status_e aStatus);
	
	/**
	 * Returns true if the full authenticated session is valid.
	 * It finds the difference between current time and the 
	 * last full authentication time. If the difference is less than the
	 * Maximum Session Validity Time, then session is valid, returns true.
	 * Otherwise returns false. 
	 * Full authentication should be done if the session is not valid.
	 */
	bool is_session_valid();
	
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H void set_peap_version(
		const peap_version_e peap_version,
		const bool use_tppd_tls_peap,
		const bool use_tppd_peapv1_acknowledge_hack);

#if defined(USE_FAST_EAP_TYPE)

	// This is commented in tls_am_application_eap_fast_c::read_authority_identity().
	// Parameter is the authority identity (A-ID).
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e read_authority_identity(eap_variable_data_c * const authority_identity);

	// This is commented in tls_am_application_eap_fast_c::query_pac_of_type().
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e query_pac_of_type(const eap_fast_pac_type_e pac_type);
	
#if defined(USE_EAP_CORE_SERVER)
	/**
	 * This function call is always asyncronous.
	 * It will be completed always with complete_verify_pac() function call.
	 * Function verifies the received PAC is valid.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e verify_pac(const eap_fast_variable_data_c * const tlv_pac);
#endif //#if defined(USE_EAP_CORE_SERVER)

	// This is commented in eap_am_fast_pac_store_services_c::query_user_permission_for_A_ID().
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e query_user_permission_for_A_ID(
		const eap_fast_pac_store_pending_operation_e in_pending_operation,
		const eap_fast_variable_data_c * const in_pac_attribute_A_ID_info,
		const eap_fast_variable_data_c * const in_pac_attribute_A_ID);

	// This is commented in eap_am_fast_pac_store_services_c::read_PAC_store_data().
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e read_PAC_store_data(
		const eap_fast_pac_store_pending_operation_e in_pending_operation,
		EAP_TEMPLATE_CONST eap_array_c<eap_fast_pac_store_data_c> * const in_references);

	// This is commented in eap_am_fast_pac_store_services_c::write_PAC_store_data().
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e write_PAC_store_data(
		const bool when_true_must_be_synchronous_operation,
		const eap_fast_pac_store_pending_operation_e in_pending_operation,
		EAP_TEMPLATE_CONST eap_array_c<eap_fast_pac_store_data_c> * const in_references_and_data_blocks);

	// This is commented in eap_am_fast_pac_store_services_c::complete_add_imported_PAC_file().
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e complete_add_imported_PAC_file(
		const eap_status_e in_completion_status,
		const eap_variable_data_c * const in_imported_PAC_filename,
		const eap_variable_data_c * const out_used_group_reference);
		
	// This is commented in eap_am_fast_pac_store_services_c::complete_remove_PAC().
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e complete_remove_PAC(
		const eap_status_e completion_status,
		const eap_variable_data_c * const out_used_group_reference);

	// This is commented in eap_am_fast_pac_store_services_c::complete_remove_IAP_reference().
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e complete_remove_IAP_reference(
		const eap_status_e completion_status);

	// This is commented in eap_am_fast_pac_store_services_c::cancel_PAC_store_operations().
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e cancel_PAC_store_operations();
	
	/**
	 * This function initializes PAC store.
	 * Imported PACs and other configuration can be done within this function call.
	 * If asyncronous operations are needed the operations must be completed
	 * by complete_initialize_PAC_store() function call.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e initialize_PAC_store(
	    const eap_fast_completion_operation_e aCompletionOperation,
	    const eap_fast_initialize_pac_store_completion_e aCompletion );

	
	/**
    * Indicate provisioning start.
    * 
    * Common side indicates that PAC provisioning started.
    * Waiting note is displayed.
    * 
    * @param provisioning_mode Authenticated or unauthenticated provisioning mode.
    * @param pac_type PAC type provisioned by server.
    */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e indicates_eap_fast_provisioning_starts(
		const eap_fast_completion_operation_e provisioning_mode,
		const eap_fast_pac_type_e pac_type );

	/**
	* Indicate provisioning end.
	* 
	* Common side indicates that PAC provisioning ended.
	* Waiting note is stopped. Provisioning result note is displayed.
	* 
	* @param provisioning_successfull True if provisioning is successful,
	*                                 false - otherwise.
	* @param provisioning_mode Authenticated or unauthenticated provisioning mode.
	* @param pac_type PAC type provisioned by server.
	*/
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e indicates_eap_fast_provisioning_ends(
		const bool provisioning_successfull,
		const eap_fast_completion_operation_e provisioning_mode,
		const eap_fast_pac_type_e pac_type );

#endif //#if defined(USE_FAST_EAP_TYPE)

    
	// from tls_am_services_c
	
	/**
	* Check whether the PAP password is still valid or
	* should we prompt user again to enter the password.
	* @return True - password is valid, false - otherwise.
	*/ 
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H bool is_ttls_pap_session_valid();

	/**
	* From interface tls_am_services_c.
	* 
	* The interface is defined in common part. Request asynchronously
	* user name and password for TTLS-PAP authentication.
	* Complete request with abs_tls_am_services_c::
	* complete_query_ttls_pap_username_and_password( ... ).
	* 	* 
	* @param aInSrvChallenge Server challenge. It could be empty.
    * @return EAP status.
	*/
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H eap_status_e query_ttls_pap_username_and_password(
		const eap_variable_data_c * const aInSrvChallenge );
	
	/**
	* The method has empty implementation which is defined for
	* compilation purpose.
	*/ 
	eap_status_e verify_ttls_pap_username_and_password(
		const eap_variable_data_c * const aUserName,
		const eap_variable_data_c * const aUserPassword);
	
	// new
	
    /**
    * Complete asynch query for TTLS-PAP user name and password.
    * 
    * @param aEapStatus Status of asynch. query completion.
    * @param aUserName PAP user name.
    * @param aPassword PAP password.
    * @return EAP status.
    */
	eap_status_e CompleteQueryTtlsPapUserNameAndPassword( 
		eap_status_e aEapStatus,
		const TDesC8& aUserNameUtf8,
		const TDesC8& aPasswordUtf8 );
	
	/**
	* Delegate the task to m_am_tools.
	* 
	* @param aErr Symbian general error.
	* @return Eapol error converted from aErr.
	*/ 
	eap_status_e ConvertAmErrorToEapolError( TInt aErr );	
	
    /**
     * Read TTLS-PAP database.
     * 
     * @param aOutDbInfo Reference to structure containing TTLS-PAP
     *                   database information.
     */
 	void ReadTtlsPapDbL( TTtlsPapDbInfo& aOutDbInfo );
 	
     /**
     * Update TTLS-PAP database.
     * 
     * @param aInDbInfo Reference to structure containing TTLS-PAP
     *                  database information.
     */
 	void WriteTtlsPapDbL( const TTtlsPapDbInfo& aInDbInfo );
 	
 	/**
 	* Set value of specified column to NULL.
 	* 
 	* @param aColName Reference to column name.
 	*/ 
 	void SetTtlsPapColumnToNullL( const TDesC& aColName );
	
#if defined(USE_FAST_EAP_TYPE)
#if defined(USE_EAP_CONFIGURATION_TO_SKIP_USER_INTERACTIONS)
 	eap_status_e ReadFileConfig();
#endif

#endif 

	/** These two are documented in MNotificationCallback class **/
	
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H void DlgComplete( TInt aStatus );

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H TBool IsMasterKeyAndPasswordMatchingL(
	      const TDesC16 & aPassword);
	      
}; // class eap_am_type_tls_peap_symbian_c


#endif //#if !defined(_EAP_AM_TYPE_TLS_PEAP_SYMBIAN_H_)

//--------------------------------------------------



// End.
