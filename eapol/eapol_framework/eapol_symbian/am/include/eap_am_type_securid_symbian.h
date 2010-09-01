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
* %version: 18 %
*/

#ifndef EAP_AM_TYPE_SECURID_SYMBIAN_H
#define EAP_AM_TYPE_SECURID_SYMBIAN_H

//  INCLUDES
#include "eap_am_tools.h"
#include "abs_eap_base_type.h"
#include "eap_am_type_securid.h"
#include "eap_am_network_id.h"
#include "EapSecurIDNotifierStructs.h"
#include <EapType.h>
#include <d32dbms.h>

const TUint KDefaultTimeoutEAPSecurId = 120000;

/**
* Class that implements the operating system dependent portion of EAP SecurID protocol.
* For Symbian OS.
*/
class EAP_EXPORT eap_am_type_securid_symbian_c
	: public CActive, public eap_am_type_securid_c
{
private:

	RDbs m_session;

	RDbNamedDatabase m_database;

	enum TState 
	{
		EHandlingIdentityQuery,
		EHandlingPasscodeQuery,
		EHandlingPincodeQuery,
		EHandlingGTCQuery
	};

	TState m_state;

	RNotifier m_notifier;

	TEapSecurIDStruct * m_dialog_data_ptr;
	TPckg<TEapSecurIDStruct> * m_dialog_data_pckg_ptr;

	abs_eap_am_tools_c * const m_am_tools;

	abs_eap_base_type_c * const m_partner;

	eap_am_network_id_c m_receive_network_id;

	TIndexType m_index_type;
	
	TInt m_index;

	eap_type_value_e m_tunneling_type;

	bool m_is_client;

	bool m_is_valid;

	bool m_shutdown_was_called;

	eap_type_value_e m_eap_type;

	HBufC8* m_message_buf;
	
	bool m_is_notifier_connected; // Tells if notifier server is connected.

	// This holds the max session time read from the configuration file.
	TInt64 m_max_session_time;
	
	// This is the vendor-type for tunneling EAP type.
	// Valid for both expanded and non-expanded EAP types.
	// This is used since m_tunneling_type can not be used in the same way 
	// in expanded and non-expanded cases. 
	// Unlike EAP type, Tunneling type is still non-expanded
	// for both cases especially for using in the EAP databases.
	u32_t m_tunneling_vendor_type;	

	u32_t m_eap_vendor_type; // This is needed in certain cases.
	
	void send_error_notification(const eap_status_e error);
	
	bool is_session_validL();	

protected:

	eap_am_type_securid_symbian_c(
		abs_eap_am_tools_c * const m_am_tools,
		abs_eap_base_type_c * const partner,
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const eap_type_value_e aEapType,
		const bool aIsClient,
		const eap_am_network_id_c * const receive_network_id);

	void ConstructL();

	void RunL();
	
	void DoCancel();

	void type_configure_readL(
		eap_config_string field,
		const u32_t field_length,
		eap_variable_data_c * const data);
		
	/**
	 * Stores current universal time as the the full authentication time
	 * in the database. Leaves if storing fails.
	 */
	void store_authentication_timeL();		

public:

	static eap_am_type_securid_symbian_c* NewL(
		abs_eap_am_tools_c * const aTools,
		abs_eap_base_type_c * const aPartner,
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const eap_type_value_e aEapType,
		const bool aIsClient,
		const eap_am_network_id_c * const receive_network_id);

	EAP_FUNC_IMPORT virtual ~eap_am_type_securid_symbian_c();

	eap_status_e show_identity_query_dialog(
		eap_type_value_e eap_type,
		eap_variable_data_c * const identity);

	eap_status_e show_passcode_query_dialog(
		eap_variable_data_c * const passcode,
		bool is_first_query);

	eap_status_e show_pincode_query_dialog(
		eap_variable_data_c * const passcode,
		eap_variable_data_c * const pincode,
		bool is_first_query);

	eap_status_e show_gtc_query_dialog(
		eap_variable_data_c * const passcode,
		const u8_t * const message,
		u32_t message_length,
		bool is_first_query);

	EAP_FUNC_IMPORT eap_status_e configure();

	EAP_FUNC_IMPORT eap_status_e reset();	

	EAP_FUNC_IMPORT void set_is_valid();

	EAP_FUNC_IMPORT bool get_is_valid();

	EAP_FUNC_IMPORT eap_status_e type_configure_read(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	EAP_FUNC_IMPORT eap_status_e type_configure_write(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	EAP_FUNC_IMPORT eap_status_e shutdown();

	EAP_FUNC_IMPORT eap_status_e read_auth_failure_string(
		eap_variable_data_c * const string);

	EAP_FUNC_IMPORT eap_status_e get_memory_store_key(
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

}; // class eap_am_type_securid_symbian_c


#endif // EAP_AM_TYPE_SECURID_SYMBIAN_H
