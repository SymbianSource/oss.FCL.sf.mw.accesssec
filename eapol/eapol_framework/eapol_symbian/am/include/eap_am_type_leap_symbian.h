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
* %version: 16.1.15 %
*/

#ifndef EAP_AM_TYPE_LEAP_SYMBIAN_H
#define EAP_AM_TYPE_LEAP_SYMBIAN_H

// This flag is for testing memory leaks that occurs in QT notifier.
#define USE_EAP_AUTH_NOTIFIER

// INCLUDES

#include "eap_am_tools_symbian.h"
#include "abs_eap_base_type.h"
#include "eap_am_type_leap.h"
#include "eap_am_network_id.h"

#if defined(USE_EAP_AUTH_NOTIFIER)
#include "eap_auth_notifier.h"
#endif //#if defined(USE_EAP_AUTH_NOTIFIER)

#include <EapType.h>
#include <d32dbms.h>
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_TYPE_LEAP_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_LEAP_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_LEAP_SYMBIAN_H 
#elif defined(EAP_EXPORT_EAP_AM_TYPE_LEAP_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_LEAP_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_LEAP_SYMBIAN_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_LEAP_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_LEAP_SYMBIAN_H 
#endif
// End: added by script change_export_macros.sh.


const TUint KDefaultTimeoutLEAP = 120000;

// CLASS DECLARATION

/**
* Class that implements the operating system dependent portion of EAP LEAP protocol.
* For Symbian OS.
*/
class EAP_CLASS_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H eap_am_type_leap_symbian_c
: public CActive, public eap_am_type_leap_c
#if defined(USE_EAP_AUTH_NOTIFIER)
	, public MNotificationCallback
#endif //#if defined(USE_EAP_AUTH_NOTIFIER)

{
private:
	//--------------------------------------------------

	eap_am_tools_symbian_c * const m_am_tools;

	abs_eap_base_type_c * const m_partner;

	RFs m_session;

	RDbNamedDatabase m_database;

#if defined(USE_EAP_AUTH_NOTIFIER)
	RNotifier m_notifier;

	CEapAuthNotifier::TEapDialogInfo * m_input_output_data_ptr;

	TPckg<CEapAuthNotifier::TEapDialogInfo> * m_input_output_pckg_ptr;
#endif //#if defined(USE_EAP_AUTH_NOTIFIER)

	eap_am_network_id_c m_receive_network_id;

	TIndexType m_index_type;
	
	TInt m_index;

	eap_type_value_e m_tunneling_type;

	bool m_is_client;

	bool m_is_valid;

	bool m_is_identity_query;

	bool * m_password_prompt_enabled;

	eap_variable_data_c * m_username_utf8;

	eap_variable_data_c * m_password_utf8;

	bool m_shutdown_was_called;
	

	// This holds the max session time read from the configuration file.
	TInt64 m_max_session_time;
	
	void send_error_notification(const eap_status_e error);

	/**
	 * Stores current universal time as the the full authentication time
	 * in the database. Leaves if storing fails.
	 */
	void store_authentication_timeL();
	 
	bool is_session_validL();	

#if defined(USE_EAP_AUTH_NOTIFIER)
	CEapAuthNotifier* iEapAuthNotifier;
#endif //#if defined(USE_EAP_AUTH_NOTIFIER)

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	eap_am_type_leap_symbian_c(
		abs_eap_am_tools_c * const m_am_tools,
		abs_eap_base_type_c * const partner,
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const bool aIsClient,
		const eap_am_network_id_c * const receive_network_id);

	void ConstructL();

	void RunL();
	
	void DoCancel();

	eap_status_e update_username_password();

	void eap_am_type_leap_symbian_c::type_configure_updateL();

	void type_configure_readL(
		eap_config_string field,
		const u32_t field_length,
		eap_variable_data_c * const data);

	//--------------------------------------------------
public:
	//--------------------------------------------------

	static eap_am_type_leap_symbian_c* NewL(
		abs_eap_am_tools_c * const aTools,
		abs_eap_base_type_c * const aPartner,
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const bool aIsClient,
		const eap_am_network_id_c * const receive_network_id);

	// 
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H virtual ~eap_am_type_leap_symbian_c();

	eap_status_e show_username_password_dialog(
		eap_variable_data_c &username,
		eap_variable_data_c &password,
		bool &password_prompt_enabled,
		bool is_identity_query);

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H eap_status_e configure();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H eap_status_e reset();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H void set_is_valid();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H bool get_is_valid();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H eap_status_e type_configure_read(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H eap_status_e type_configure_write(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H eap_status_e shutdown();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H eap_status_e read_auth_failure_string(
		eap_variable_data_c &string);

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_LEAP_SYMBIAN_H eap_status_e get_memory_store_key(
		eap_variable_data_c * const memory_store_key);

	/**
	 * Returns true if the full authenticated session is valid.
	 * It finds the difference between current time and the 
	 * last full authentication time. If the difference is less than the
	 * Maximum Session Validity Time, then session is valid, returns true.
	 * Otherwise returns false. 
	 * Full authentication (using pw query) should be done if the session is not valid.
	 */
	bool is_session_valid();
	
	/**
	 * Stores current universal time as the the full authentication time
	 * in the database by calling the leaving function store_authentication_time_L.
	 * Returns appropriate error if storing fails. eap_status_ok for successful storing.
	 */
	eap_status_e store_authentication_time();

	void DlgComplete( TInt aStatus );

	TBool IsMasterKeyAndPasswordMatchingL(
	      const TDesC16 & aPassword8);

	TInt IsDlgReadyToCompleteL();
	
}; // class eap_am_type_leap_symbian_c


#endif // EAP_AM_TYPE_LEAP_SYMBIAN_H

// End of File
