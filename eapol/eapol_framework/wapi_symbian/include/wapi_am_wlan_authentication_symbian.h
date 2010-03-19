/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_symbian/include/wapi_am_wlan_authentication_symbian.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 13.1.1 % << Don't touch! Updated by Synergy at check-out.
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



#if !defined(_WAPI_AM_WLAN_AUTHENTICATION_SYMBIAN_H_)
#define _WAPI_AM_WLAN_AUTHENTICATION_SYMBIAN_H_

#include "eap_am_export.h"
#include "wapi_am_wlan_authentication.h"
#include "eapol_wlan_database_reference.h"
#include "eap_am_network_id.h"
#include "eap_array_algorithms.h"

#include <e32base.h>
#include <e32std.h>
#include <d32dbms.h>

#include <wdbifwlansettings.h>

#include <EapType.h>


// Full path is not needed. The database wapi.dat will be saved in the 
// data cage path for DBMS. So it will be in "\private\100012a5\wapi.dat" in C: drive.
// The maximum length of database name is 0x40 (KDbMaxName) , which is defined in d32dbms.h.

_LIT(KWapiDatabaseName, "c:wapi.dat");


class CEapType;
class abs_wapi_am_wlan_authentication_c;
class abs_eap_am_tools_c;
class eap_file_config_c;

/// This class declares the adaptation module of wapi_am_wlan_authentication_c.
/// See comments of the functions from wapi_am_wlan_authentication_c.
class EAP_EXPORT wapi_am_wlan_authentication_symbian_c
: public CActive
, public wapi_am_wlan_authentication_c
{
private:
	//--------------------------------------------------

	abs_wapi_am_wlan_authentication_c * m_am_partner;

	abs_eap_am_tools_c * m_am_tools;

	/// This is object to handle file configuration.
	eap_file_config_c * m_fileconfig;

	/// SSID of current network.
	eap_variable_data_c m_SSID;

	/// This pointer is abstract interface to reference of WLAN database of the current connection.
	const abs_eapol_wlan_database_reference_if_c * m_wlan_database_reference;


	/// Network identity of current connection.
	eap_am_network_id_c m_receive_network_id;

	/// WLAN security mode as defined in Symbian platform.
	EWlanSecurityMode m_security_mode;

	/// WLAN authentication type.
	eapol_key_authentication_type_e m_selected_eapol_key_authentication_type;

	/// This object is client (true).
	bool m_is_client;

	/// This object is valid (true).
	bool m_is_valid;

	/// WPA(2)-PSK
	eap_variable_data_c m_wapi_preshared_key;

	/// HAHS of WPA(2)-PSK 
	eap_variable_data_c m_wapi_psk;
	
	// Iap Index, NULL if not initialized
	TUint iIapIndex;
	//--------------------------------------------------

	/// Function reads one configuration value from database.
	void ReadConfigureL(
		eap_config_string fieldx,
		const eap_configuration_field_c * const field,
		const u32_t /*field_length*/,
		eap_variable_data_c * const data);

	/// Control function of this active-object.
	void RunL();

	/// Cancel function for active-object.
	void DoCancel();

	/// THis function reads the references to active Internet Access Point (IAP).
	eap_status_e read_database_reference_values(
		TIndexType * const type,
		TUint * const index);


    // This function Gets Psk from commdbif
	eap_status_e GetWlanConfigurationL(eap_variable_data_c * const wapi_psk );
	
	/// This function sends error notification to partner object.
	void send_error_notification(const eap_status_e error);

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	EAP_FUNC_IMPORT virtual ~wapi_am_wlan_authentication_symbian_c();

	// 
	EAP_FUNC_IMPORT wapi_am_wlan_authentication_symbian_c(
		abs_eap_am_tools_c * const tools,
		const bool is_client_when_true,
		const abs_eapol_wlan_database_reference_if_c * const wlan_database_reference);


	/// See comments of the functions from wapi_am_wlan_authentication_c.

	EAP_FUNC_IMPORT bool get_is_valid();

	EAP_FUNC_IMPORT eap_status_e configure();

	EAP_FUNC_IMPORT eap_status_e shutdown();

	EAP_FUNC_IMPORT eap_status_e set_am_partner(
		abs_wapi_am_wlan_authentication_c * am_partner
		);

	EAP_FUNC_IMPORT eap_status_e reset_wapi_configuration();

	EAP_FUNC_IMPORT eap_status_e set_wlan_parameters(
		const eap_variable_data_c * const SSID,
		const bool WPA_override_enabled,
		const eap_variable_data_c * const wapi_preshared_key,
		const eapol_key_authentication_type_e selected_eapol_key_authentication_type);

	EAP_FUNC_IMPORT eap_status_e association(
		const eap_am_network_id_c * const receive_network_id);

	EAP_FUNC_IMPORT eap_status_e disassociation(
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		);

	EAP_FUNC_IMPORT eap_status_e get_wlan_configuration(
		eap_variable_data_c * const wapi_psk);

	/**
	 * This function indicates finish of the authentication to adatation module.
	 * @param when_true_successfull tells whether authentication was successfull (true) or not (false).
	 * @param authentication_type tells the used WLAN authentication type.
	 */
	EAP_FUNC_EXPORT eap_status_e authentication_finished(
		const bool when_true_successfull,
		const eapol_key_authentication_type_e authentication_type);

	EAP_FUNC_IMPORT eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	EAP_FUNC_IMPORT eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	EAP_FUNC_IMPORT eap_status_e set_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id, 
		void * const data,
		const u32_t p_time_ms);

	EAP_FUNC_IMPORT eap_status_e cancel_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id);

	EAP_FUNC_IMPORT eap_status_e cancel_all_timers();

	EAP_FUNC_IMPORT void state_notification(
		const abs_eap_state_notification_c * const state);

	//--------------------------------------------------
}; // class wapi_am_wlan_authentication_symbian_c

#endif //#if !defined(_WAPI_AM_WLAN_AUTHENTICATION_SYMBIAN_H_)

//--------------------------------------------------



// End.
