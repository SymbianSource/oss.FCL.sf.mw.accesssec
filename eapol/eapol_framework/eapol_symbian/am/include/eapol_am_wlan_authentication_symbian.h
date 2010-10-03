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
* %version: 46 %
*/

#if !defined(_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H_)
#define _EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H 
	#define EAP_FUNC_EXPORT_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H 
#elif defined(EAP_EXPORT_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H 
#endif
// End: added by script change_export_macros.sh.
#include "eapol_am_wlan_authentication.h"
#include "eapol_wlan_database_reference.h"
#include "eap_am_network_id.h"
#include "eap_array_algorithms.h"

#if defined(USE_EAP_SIMPLE_CONFIG)
#include "abs_eap_configuration_if.h"
#include "simple_config_credential.h"
#include "abs_eap_configuration_if.h"
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

#include <e32base.h>
#include <e32std.h>
#include <d32dbms.h>

//#include <wdbifwlansettings.h>

#include <EapType.h> // For TIndexType

class CEapType;
class abs_eapol_am_wlan_authentication_c;
class abs_eap_am_tools_c;
class eap_file_config_c;

const TInt KMaxWPAPSKPasswordLength = 64;
const TInt KWPAPSKLength = 32;
// Just to make this different of already existing constant.
const TUint K_Max_SSID_Length = 32;


/// This class declares the simulator adaptation module of eapol_am_wlan_authentication_c.
/// See comments of the functions from eapol_am_wlan_authentication_c.
class EAP_CLASS_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H eapol_am_wlan_authentication_symbian_c
: public eapol_am_wlan_authentication_c
#if defined(USE_EAP_SIMPLE_CONFIG)
, public abs_eap_configuration_if_c
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)
{
private:
	//--------------------------------------------------

	abs_eapol_am_wlan_authentication_c * m_am_partner;

#if defined(USE_EAP_SIMPLE_CONFIG)
	abs_eap_configuration_if_c * m_configuration_if;
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)
	
	abs_eap_am_tools_c * m_am_tools;

	/// This is object to handle file configuration.
	eap_file_config_c * m_fileconfig;

	/// SSID of current network.
	eap_variable_data_c m_SSID;

	/// WPA(2)-PSK
	eap_variable_data_c m_wpa_preshared_key;

	/// HAHS of WPA(2)-PSK 
	eap_variable_data_c m_wpa_preshared_key_hash;

	/// Database reference to EAPOL settings.
	eap_variable_data_c m_database_reference;

	/// Handle of database session.
	RFs m_session;

	/// Handle of database file.
	//RFs m_fs;

	/// Network identity of current connection.
	eap_am_network_id_c m_receive_network_id;

	/// WLAN authentication type.
	eapol_key_authentication_type_e m_selected_eapol_key_authentication_type;

	/// WPA(2)-PSK override.
	bool m_WPA_override_enabled;

	/// This object is client (true).
	bool m_is_client;

	/// This object is valid (true).
	bool m_is_valid;

	//--------------------------------------------------

	/// This struct is used in WPA(2)-PSK setting handling.
	struct TPSKEntry
	{
		TIndexType indexType;
		TUint index;
		TBuf8<K_Max_SSID_Length> ssid;
		TBuf8<KMaxWPAPSKPasswordLength> password;
		TBuf8<KWPAPSKLength> psk;
	};

	/// This function tries to initialize database.
	void TryInitDatabaseL();

	/// This function tries to initialize database or if it fails
	/// tries to create new database.
	void InitDatabaseL();

	/// Function reads one configuration value from database.
	void read_configureL(
		const TDesC& aDbName,
		const TDesC& aTableName,
		eap_config_string field,
		const u32_t /*field_length*/,
		eap_variable_data_c * const data);

	/// Control function of this active-object.
	void RunL();

	/// Cancel function for active-object.
	void DoCancel();

	/// This function reads WPA(2)-PSK from database.
	void RetrievePSKL(TPSKEntry& entry);

	/// This function saves WPA(2)-PSK to database.
	void SavePSKL(TPSKEntry& entry);

	/// This function reads WPA-settings from database.
	void ReadWPASettingsL();

	/// THis function reads the references to active Internet Access Point (IAP).
	eap_status_e read_database_reference_values(
		TIndexType * const type,
		TUint * const index);

	/// This function sends error notification to partner object.
	void send_error_notification(const eap_status_e error);

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H virtual ~eapol_am_wlan_authentication_symbian_c();

	// 
	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H eapol_am_wlan_authentication_symbian_c(
		abs_eap_am_tools_c * const tools,
		const bool is_client_when_true);


	/// See comments of the functions from eapol_am_wlan_authentication_c.

	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H bool get_is_valid();

	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H eap_status_e configure();

	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H eap_status_e shutdown();

	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H eap_status_e set_am_partner(
		abs_eapol_am_wlan_authentication_c * am_partner
#if defined(USE_EAP_SIMPLE_CONFIG)
		, abs_eap_configuration_if_c * const configuration_if
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)
		);

	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H eap_status_e reset_wpa_configuration();

	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H eap_status_e set_wlan_parameters(
		const eap_variable_data_c * const SSID,
		const bool WPA_override_enabled,
		const eap_variable_data_c * const wpa_preshared_key,
		const eapol_key_authentication_type_e selected_eapol_key_authentication_type);

	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H eap_status_e association(
		const eap_am_network_id_c * const receive_network_id);

	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H eap_status_e disassociation(
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		);

	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H eap_status_e get_wlan_configuration(
		eap_variable_data_c * const wpa_preshared_key_hash);

	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H eap_status_e authentication_finished(
		const bool when_true_successfull,
		const eap_type_value_e eap_type,
		const eapol_key_authentication_type_e authentication_type);

	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H eap_status_e set_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id, 
		void * const data,
		const u32_t p_time_ms);

	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H eap_status_e cancel_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id);

	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H eap_status_e cancel_all_timers();

	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H void state_notification(
		const abs_eap_state_notification_c * const state);

#if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H eap_status_e save_simple_config_session(
		const simple_config_state_e state,
		EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
		const eap_variable_data_c * const new_password,
		const simple_config_Device_Password_ID_e Device_Password_ID,
		const simple_config_payloads_c * const other_configuration);	

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_FUNC_VISIBILITY_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H eap_status_e set_eap_database_reference_values(
		const eap_variable_data_c * const reference);

	//--------------------------------------------------
}; // class eapol_am_wlan_authentication_symbian_c

#endif //#if !defined(_EAPOL_AM_WLAN_AUTHENTICATION_SYMBIAN_H_)

//--------------------------------------------------



// End.
