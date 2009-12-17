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





#if !defined(_EAPOL_AM_CORE_SYMBIAN_H_)
#define _EAPOL_AM_CORE_SYMBIAN_H_

// INCLUDES
#include <d32dbms.h>
#include <wlanmgmtpacket.h> // For MWlanMgmtPacket

#include <wdbifwlansettings.h>

#include "abs_ethernet_core.h"
#include "eapol_key_types.h"
#include <EapType.h> // For TIndexType
//#include "EapolTimer.h"

#include <Eapol.h>

// FORWARD DECLARATIONS
class MEapolToWlmIf;
class CEapType;
class ethernet_core_c;
class eap_am_tools_symbian_c;
class eap_file_config_c;

const TInt KMaxWPAPSKPasswordLength = 64;
const TInt KWPAPSKLength = 32;

// CLASS DECLARATION
class eapol_am_core_symbian_c
:  public CActive, public abs_ethernet_core_c,
	public abs_eap_base_timer_c

{
public:

	struct TPSKEntry {
		TIndexType indexType;
		TUint index;
		TBuf8<KMaxSSIDLength> ssid;
		TBuf8<KMaxWPAPSKPasswordLength> password;
		TBuf8<KWPAPSKLength> psk;
	};

	virtual ~eapol_am_core_symbian_c();	
	
	///////////////////////////////////////////////////////////////
	/* These are called from WLM via CEapol */

	static eapol_am_core_symbian_c * NewL(
		MEapolToWlmIf* const aPartner,
		const bool aIsClient = ETrue,
		const TUint aServerIndex = 0);


	TInt Start( 
		const TIndexType aIndexType, 
		const TUint aIndex,
		const TSSID& aSSID,
		const TBool aWPAOverrideEnabled,
		const TUint8* aWPAPSK,
		const TUint aWPAPSKLength
		);

	TInt CompleteAssociation(
		const TInt aResult,
		const TMacAddress& aLocalAddress, 
		const TMacAddress& aRemoteAddress,
		const TUint8* const aReceivedWPAIE, // WLM must give only the WPA IE to EAPOL									        
		const TUint aReceivedWPAIELength,
		const TUint8* const aSentWPAIE,
		const TUint aSentWPAIELength,
		const TWPACipherSuite aGroupKeyCipherSuite,
		const TWPACipherSuite aPairwiseKeyCipherSuite
		);		

	
	TInt Disassociated(); 
		
	TInt ReceivePacket(
		const TUint aLength, 
		const TUint8* const aData);

	TInt SendWPAMICFailureReport(
		TBool aFatalMICFailure,
		const TMICFailureType aMICFailureType); 	

	/////////////////////////////////////////
	/* These are called from ethernet_core */
	
	/**
	* Sends packet to lower layers
	*/
	eap_status_e packet_send(
		const eap_am_network_id_c * const send_network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length); 

	u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length);

	eap_status_e eap_acknowledge(const eap_am_network_id_c * const receive_network_id); 

	eap_status_e reassociate(
			const eap_am_network_id_c * const send_network_id,
			const eapol_key_authentication_type_e authentication_type,
			const eap_variable_data_c * const PMKID,
			const eap_variable_data_c * const WPXM_WPXK1,
			const eap_variable_data_c * const WPXM_WPXK2);

	/**
	* Loads an EAP type plug-in.
	* @param type Type to be loaded.
	* @param partner Pointer to the partner class for the EAP type.
	* @param eap_type The pointer for the loaded type should be set here.
	* @param is_client_when_true Indicates whether the loaded EAP type should be client or server.
	* @param receive_network_id Network address.
	*/
	eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e /* tunneling_type */,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id);

	eap_status_e unload_module(const eap_type_value_e type); 	

	void set_is_valid();

	bool get_is_valid();

	void increment_authentication_counter();

	u32_t get_authentication_counter();

	bool get_is_client();

	/**
	* This does the initial configuration of the class.
	*/
	eap_status_e configure();

	eap_status_e shutdown();

	/**
	* Reads a configuration parameter value from the database. 
	* In Symbian this function is only a TRAP wrapper for read_configure_L.
	*/
	eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	eap_status_e write_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	// See abs_eap_base_type_c::state_notification().
	void state_notification(const abs_eap_state_notification_c * const state);
	
	eap_status_e set_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id, 
		void * const p_data,
		const u32_t p_time_ms);

	eap_status_e cancel_timer(
		abs_eap_base_timer_c * const p_initializer, 
		const u32_t p_id);

	eap_status_e cancel_all_timers();

	eap_status_e check_is_valid_eap_type(const eap_type_value_e eap_type);
	
	eap_status_e packet_data_crypto_keys(
		const eap_am_network_id_c * const send_network_id,
		const eap_variable_data_c * const master_session_key);

	/**
	* Forwards the keys to lower layer (= WLM).
	*/
	eap_status_e packet_data_session_key(
		const eap_am_network_id_c * const send_network_id,
		const eapol_session_key_c * const key);

	/**
	* Packet mangling routine for testing.
	*/
	
	eap_status_e timer_expired(const u32_t id, void *data);

	eap_status_e timer_delete_data(const u32_t id, void *data);

	eap_status_e get_eap_type_list(
		eap_array_c<eap_type_value_e> * const eap_type_list);

	eap_status_e add_rogue_ap(eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list);

protected:
	
	eapol_am_core_symbian_c(
		MEapolToWlmIf * const aPartner,
		const bool is_client_when_true,
		const TUint aServerIndex);
	
	void ConstructL();

	void RunL();
	
	void DoCancel();

private:

	eap_status_e random_error(
		eap_buf_chain_wr_c * const sent_packet,
		const bool forse_error,
		const u32_t packet_index);

	/**
	* Tries to open EAPOL parameter database.
	*/
	void TryOpenDatabaseL(RDbNamedDatabase& aDatabase, RDbs& aSession);

	/**
	* Opening function for EAPOL parameter database.
	*/
	void OpenDatabaseL(RDbNamedDatabase& aDatabase, RDbs& aSession);
	
	void read_configureL(eap_config_string field,
										const u32_t field_length,
										eap_variable_data_c * const data);	

	void ReadEAPSettingsL();

	void SetToTopPriorityL(const TEap* const aEapType);

	eap_status_e create_upper_stack();

	void RetrievePSKL(TPSKEntry& entry);

	void SavePSKL(TPSKEntry& entry);



private:

	RDbs m_session;
	RDbNamedDatabase m_database;

	/// Pointer to the lower layer in the stack
	MEapolToWlmIf* m_partner;

	/// Pointer to the upper layer in the stack
	ethernet_core_c* m_ethernet_core;

	/// Pointer to the tools class
	eap_am_tools_symbian_c* m_am_tools;

	bool m_enable_random_errors;

	u32_t m_error_probability;

	u32_t m_generate_multiple_error_packets;
	
	u32_t m_authentication_counter;

	u32_t m_successful_authentications;

	u32_t m_failed_authentications;

	bool m_is_valid;

	bool m_is_client;	

	/// Array for storing the loaded EAP types.
	RPointerArray<CEapType> m_plugin_if_array;
	/// Array which corresponds with m_plugin_if_array and indicates the types of the loaded EAP types.
	RArray<eap_type_value_e> m_eap_type_array;

	/// EAP configuration data from CommDb
	TEapArray m_iap_eap_array;
	TUint m_eap_index;
	/// Indicates the bearer type
	TIndexType m_index_type;
	/// Indicates the service index in CommDb
	TUint m_index;

	u32_t m_packet_index;

	bool m_manipulate_ethernet_header;

	bool m_send_original_packet_first;

	bool m_authentication_indication_sent;

	bool m_unicast_wep_key_received;

	bool m_broadcast_wep_key_received;

	bool m_block_packet_sends_and_notifications;

	bool m_success_indication_sent;

	bool m_first_authentication;

	bool m_self_disassociated;

	TAuthenticationMode m_802_11_authentication_mode;

	EWlanSecurityMode m_security_mode;

	eap_variable_data_c * m_wpa_preshared_key;

	eap_variable_data_c * m_ssid;

	eap_am_network_id_c* m_receive_network_id;
	
	eap_variable_data_c * m_wpa_psk_password_override;

	bool m_wpa_override_enabled;

	bool m_wpa_psk_mode_allowed;

	bool m_wpa_psk_mode_active;	

	bool m_stack_marked_to_be_deleted;

	TMacAddress m_local_address;

	TMacAddress m_remote_address;

	const TUint8* m_received_wpa_ie;

	TUint m_received_wpa_ie_length;

	const TUint8* m_sent_wpa_ie;

	TUint m_sent_wpa_ie_length;

	TWPACipherSuite m_group_key_cipher_suite;

	TWPACipherSuite m_pairwise_key_cipher_suite;

	bool m_active_type_is_leap;

	eap_file_config_c* m_fileconfig;

	//--------------------------------------------------
}; // class eapol_am_core_symbian_c

#endif //#if !defined(_EAPOL_AM_CORE_SYMBIAN_H_)

//--------------------------------------------------



// End of file
