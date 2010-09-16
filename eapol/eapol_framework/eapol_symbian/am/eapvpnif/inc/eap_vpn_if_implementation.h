/*
* Copyright (c) 2005-2006 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  CEapVpnInterfaceImplementation
*
*/

/*
* %version: 19.1.15 %
*/

#ifndef __EAPPLUGIN_H__
#define __EAPPLUGIN_H__

// INCLUDES
#include <d32dbms.h>

#include <wdbifwlansettings.h>
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_VPN_IF_IMPLEMENTATION_H)
	#define EAP_CLASS_VISIBILITY_EAP_VPN_IF_IMPLEMENTATION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_VPN_IF_IMPLEMENTATION_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_VPN_IF_IMPLEMENTATION_H 
	#define EAP_FUNC_EXPORT_EAP_VPN_IF_IMPLEMENTATION_H 
	#define EAP_C_FUNC_EXPORT_EAP_VPN_IF_IMPLEMENTATION_H 
#elif defined(EAP_EXPORT_EAP_VPN_IF_IMPLEMENTATION_H)
	#define EAP_CLASS_VISIBILITY_EAP_VPN_IF_IMPLEMENTATION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_VPN_IF_IMPLEMENTATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_VPN_IF_IMPLEMENTATION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_VPN_IF_IMPLEMENTATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_VPN_IF_IMPLEMENTATION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_VPN_IF_IMPLEMENTATION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_VPN_IF_IMPLEMENTATION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_VPN_IF_IMPLEMENTATION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_VPN_IF_IMPLEMENTATION_H 
	#define EAP_C_FUNC_EXPORT_EAP_VPN_IF_IMPLEMENTATION_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_vpn_if.h"
//#include "abs_eap_core.h"
#include "eapol_session_key.h"
#include "eap_am_tools_symbian.h"
#include "EapType.h"
#include "EapolTimer.h"
#include "abs_eap_session_core.h"

// FORWARD DECLARATIONS
class CEapType;
class CEapTypePlugin;
class eap_am_tools_symbian_c;
class eap_file_config_c;
class eap_session_core_base_c;
class eap_process_tlv_message_data_c;

/**
 * Class:       CEapVpnInterfaceImplementation
 *
 * Description: Implements the EAP over IKEv2 adaptation
 *              This is concrete class, instance of which
 *              ECOM framework gives to ECOM clients.
 */
class EAP_CLASS_VISIBILITY_EAP_VPN_IF_IMPLEMENTATION_H CEapVpnInterfaceImplementation
	: public CEapVpnInterface
	, public abs_eap_session_core_c
	, public abs_eap_base_timer_c
{
public:
	/**
     * Function:    NewL
     *
     * Description: Create instance of concrete implementation. Note that ECOM
     *              interface implementations can only have two signatures for
     *              NewL:
     *               - NewL without parameters (used here)
     *               - NewL with TAny* pointer, which may provide some client
     *                 data
     *
     * @return     Instance of this class.
     *
     * Note:       The interface, which is abstract base class of this
     *             implementation, also provides NewL method. Normally abstract
     *             classes do not provide NewL, because they cannot create
     *             instances of themselves.
     */
	static CEapVpnInterfaceImplementation* NewL(TAbsEapVpnInterfaceParams* aParams);

    virtual ~CEapVpnInterfaceImplementation();
    // Virtual functions from CEapVpnInterface
    /**
     * Function:    StartL
     *
     * Description: Initializes the eap plugin
	 *
     * @param       aType name of requested eap type implementation.
     *
     */
    virtual TInt StartL(const TUint8 aEapType);
    /**
     * Function:    EapConfigure
     *
     * Description: Configures the eap plugin
	 *
     * @param       aManualUsername The username, if not zero
     * @param       aManualRealm The realm, if not zero
     * @param       aManualRealmPrefix The realm prefix, if not zero
     * @param       aHideInitialIdentity Scramble username, if true
     *
     */
    virtual TInt EapConfigure(TDesC8& aManualUsername, TDesC8& aManualRealm, TDesC8& aRealmPrefix, TBool aHideInitialIdentity);

    /**
	 * Function:    QueryIdentity
	 *
	 * Description: Ask the identity
     */
    virtual TInt QueryIdentity();

    /**
	 * Function:    EapInbound
	 *
	 * Description: Handle incoming Eap message
	 *
     * @param       aMessage incoming eap message.
     *              
     */
    virtual TInt EapInbound(const TDesC8& aMessage);

// Virtual callback functions, called by the eap_core

    /**
	 * The derived class could send packets to partner class with this function.
	 * @see abs_eap_base_type_c::packet_send().
	 */
    virtual eap_status_e packet_send(
                                           const eap_am_network_id_c * const network_id,
                                           eap_buf_chain_wr_c * const sent_packet,
                                           const u32_t header_offset,
                                           const u32_t data_length,
                                           const u32_t buffer_length);

    /**
	 * The get_header_offset() function obtains the header offset of EAP-packet.
	 * @see abs_eap_base_type_c::get_header_offset().
	 */
    virtual u32_t get_header_offset(
                                          u32_t * const MTU,
                                          u32_t * const trailer_length);

    /**
	 * The load_module() function function indicates the lower level to
	 * load new module of EAP-type.
	 * @param type is the requested EAP-type.
	 * @param partner is pointer to the caller object.
	 * The partner of the new created EAP-type object is the caller object.
	 * @param eap_type is a pointer to a pointer of EAP-type object.
	 * Adaptation module sets eap_type pointer to created EAP-type object.
	 * @param is_client_when_true parameter indicates whether the network entity should
	 * act as a client (true) or server (false), in terms of EAP-protocol whether
	 * this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	 * @param receive_network_id includes the addresses (network identity) and packet type.
	 */
    virtual eap_status_e load_module(
                                           const eap_type_value_e type,
                                           const eap_type_value_e /* tunneling_type */,
                                           abs_eap_base_type_c * const partner,
                                           eap_base_type_c ** const eap_type,
                                           const bool is_client_when_true,
                                           const eap_am_network_id_c * const receive_network_id);

    /**
	 * The unload_module() function unloads the module of a EAP-type. 
	 * @param eap_type is the requested EAP-type.
	 */
    virtual eap_status_e unload_module(const eap_type_value_e eap_type);
    
    void set_is_valid();

    bool get_is_valid();

    void increment_authentication_counter();

    u32_t get_authentication_counter();

    bool get_is_client();
    
    eap_status_e configure();

    eap_status_e shutdown();

    /**
	 * Note this function is just an example. Parameters will change later.
	 * The packet_data_crypto_keys() function gives the generated keys to lower level.
	 * After EAP-authentication has generated the keys it calls this function
	 * to offer the keys to lower level.
	 * @see abs_eap_base_type_c::packet_data_crypto_keys().
	 */
    virtual eap_status_e packet_data_crypto_keys(
        const eap_am_network_id_c * const send_network_id,
        const eap_master_session_key_c * const master_session_key
        );

    /**
	 * The packet_data_session_key() function passes one traffic encryption key to 
	 * the lower layers. Ultimately the key can end up to the WLAN hardware.
	 * @param send_network_id carries the addresses (network identity) and type of the packet.
	 * @param key is the encryption key
	 * @param key_length is the length of the key
	 * @param key_type describes the type of the key (WEP or something else...)
	 * @param key_index is the index of the encryption key (there can be four broadcast keys in WEP for example)
	 */
    virtual eap_status_e packet_data_session_key(
        const eap_am_network_id_c * const send_network_id,
        const eapol_session_key_c * const key
        );

    /**
	 * The read_configure() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @see abs_eap_base_type_c::read_configure().
	 */
    virtual eap_status_e read_configure(
                                              const eap_configuration_field_c * const field,
                                              eap_variable_data_c * const data);

    /**
	 * The write_configure() function writes the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the action to some persistent store.
	 * @see abs_eap_base_type_c::write_configure().
	 */
    virtual eap_status_e write_configure(
                                               const eap_configuration_field_c * const field,
                                               eap_variable_data_c * const data);

    /**
	 * This is notification of internal state transition.
	 * This is used for notifications, debugging and protocol testing.
	 * The primal notifications are eap_state_variable_e::eap_state_authentication_finished_successfully
	 * and eap_state_variable_e::eap_state_authentication_terminated_unsuccessfully.
	 * These two notifications are sent from EAP-protocol layer (eap_protocol_layer_e::eap_protocol_layer_eap).
	 * These two notifications tells the end state of authentication session. These are the only
	 * reliable indications of the final status of authentication session.
	 * You MUST NOT make decision based on the return value of abs_eap_stack_interface_c::packet_process().
	 */
    virtual void state_notification(
                                    const abs_eap_state_notification_c * const state);

    /**
	 * The set_timer() function initializes timer to be elapsed after time_ms milliseconds.
	 * @param initializer is pointer to object which timer_expired() function will
	 * be called after timer elapses.
	 * @param id is identifier which will be returned in timer_expired() function.
	 * The user selects and interprets the id for this timer.
	 * @param data is pointer to any user selected data which will be returned in timer_expired() function.
	 * @param time_ms is the time of timer in milli seconds.
	 *
	 * Adaptation module internally implements the timer.
	 */
    virtual eap_status_e set_timer(
                                         abs_eap_base_timer_c * const initializer, 
                                         const u32_t id, 
                                         void * const data,
                                         const u32_t time_ms);

    /**
	 * The cancel_timer() function cancels the timer id initiated by initializer.
	 * @param initializer is pointer to object which set the cancelled timer.
	 * @param id is identifier which will be returned in timer_expired() function.
	 * The user selects and interprets the id for this timer.
	 *
	 * Adaptation module internally implements the timer.
	 */
    virtual eap_status_e cancel_timer(
                                            abs_eap_base_timer_c * const initializer, 
                                            const u32_t id);

    /**
	 * The cancel_all_timers() function cancels all timers.
	 * User should use this in termination of the stack before
	 * the adaptation module of tools is deleted.
	 * Preferred mode is to cancel each timer directly
	 * using cancel_timer() function.
	 *
	 * Adaptation module internally implements the timer.
	 */
    virtual eap_status_e cancel_all_timers();

    /**
	 * This function queries the validity of EAP-type.
	 * Lower layer should return eap_status_ok if this EAP-type is supported.
	 * @param eap_type is the requested EAP-type.
	 */
    virtual eap_status_e check_is_valid_eap_type(const eap_type_value_e eap_type);

    /**
	 * This function queries the list of supported EAP-types.
	 * Lower layer should return eap_status_ok if this call succeeds.
	 * @param eap_type_list will include the list of supported EAP-types. Each value in list
	 * is type of u32_t and represent one supported EAP-type. List consists of subsequent u32_t type values.
	 */
    virtual eap_status_e get_eap_type_list(eap_array_c<eap_type_value_e> * const eap_type_list);

    virtual eap_status_e add_rogue_ap(eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list);

    /**
	 * The adaptation module calls the restart_authentication() function
	 * when EAP-authentication is needed with another peer.
	 * @see abs_eap_core_c::restart_authentication().
	 */
    eap_status_e restart_authentication(
        const eap_am_network_id_c * const receive_network_id,
        const bool is_client_when_true,
        const bool force_clean_restart,
        const bool from_timer = false);

    /**
	 * This function tells lower layer to remove EAP session object asyncronously.
	 * @param send_network_id is pointer to network id that identifies the removed EAP session.
	 */
    eap_status_e asynchronous_init_remove_eap_session(
        const eap_am_network_id_c * const send_network_id);

    // This is documented in abs_eap_core_c::set_session_timeout().
    eap_status_e set_session_timeout(
        const u32_t session_timeout_ms);
    
    // See abs_eap_base_timer_c::timer_expired().
    eap_status_e timer_expired(
        const u32_t id, void *data);

    // See abs_eap_base_timer_c::timer_delete_data().
    eap_status_e timer_delete_data(
        const u32_t id, void *data);

	eap_status_e complete_get_802_11_authentication_mode(
		const eap_status_e completion_status,
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_802_11_authentication_mode_e mode);

	eap_status_e complete_remove_eap_session(
		const bool complete_to_lower_layer,
		const eap_am_network_id_c * const receive_network_id);

#if defined(USE_EAP_SIMPLE_CONFIG)
	/**
	 * This function tells AM to save SIMPLE_CONFIG configuration parameters.
	 * This is always syncronous call.
	 */
	eap_status_e save_simple_config_session(
		const simple_config_state_e state,
		EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
		const eap_variable_data_c * const new_password,
		const simple_config_Device_Password_ID_e Device_Password_ID,
		const simple_config_payloads_c * const other_configuration
		);
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

	static eap_session_core_base_c * new_eap_core_client_message_if_c(
		abs_eap_am_tools_c * const tools,
		abs_eap_session_core_c * const partner,
		const bool is_client_when_true,
		const u32_t MTU);

private:

    TInt CompleteAssociation(const TInt aResult);
    eap_status_e send_eap_identity_request();
    
    eap_status_e create_upper_stack();

	eap_status_e add_configuration_data(
		eap_process_tlv_message_data_c * const message,
		const eap_configuration_field_c * field,
		const eap_configure_type_e type,
		const eap_variable_data_c * const value_data
		);

	eap_status_e wait_complete_get_802_11_authentication_mode();

protected:

	/**
     * Function:   CEapVpnInterfaceImplementation
     *
     * Discussion: Perform the first phase of two phase construction
     */
	CEapVpnInterfaceImplementation();
	
	/**
     * Function:   ConstructL
     *
     * Discussion: Perform the second phase construction
     */
	void ConstructL(MAbsEapVpnInterface* aCaller, TBool aClient);
    
    void RunL();
    void DoCancel();

private: // implementation    
    static void CleanupImplArray( TAny* aAny );
    
private:
    // From eapol_am_core_symbian.h

    TBool iQueryIdentity;

    /// Pointer to the lower layer in the stack
    MAbsEapVpnInterface * iCaller;

    /// Pointer to the upper layer in the stack
    eap_session_core_base_c * iEapCore;

    eap_type_value_e iRequestedEapType;

    /// Pointer to the tools class
    eap_am_tools_symbian_c * m_am_tools;

    eap_am_network_id_c * m_receive_network_id;

	eap_variable_data_c * m_trace_log_file_name;
    
    u32_t m_authentication_counter;

    u32_t m_successful_authentications;

    u32_t m_failed_authentications;

    bool m_is_valid;

    bool m_is_client;	

    /// Array for storing the loaded EAP types.
    RPointerArray<CEapType> m_eap_if_array;

    /// Array for storing the loaded EAP types.
    RPointerArray<CEapTypePlugin> m_eap_plugin_if_array;

	/// Enabled expanded EAP configuration data from CommsDat
	// This is for the outer most EAP (not tunneled)
	RExpandedEapTypeArray m_enabled_expanded_eap_array;

	/// Disabled expanded EAP configuration data from CommsDat
	// This is for the outer most EAP (not tunneled)
	RExpandedEapTypeArray m_disabled_expanded_eap_array;
	
	/// Array which corresponds with m_plugin_if_array and indicates the types of the loaded EAP types.	
	eap_array_c<eap_type_value_e> * m_eap_type_array;

    /// Indicates the bearer type
    TIndexType m_index_type;

    /// Indicates the service index in CommDb
    TInt m_index;

    eap_file_config_c * m_fileconfig;

    u32_t m_packet_index;

    bool m_block_packet_sends_and_notifications;

    bool m_stack_marked_to_be_deleted;

    HBufC8 * iManualUsername;
    HBufC8 * iManualRealm;
    HBufC8 * iRealmPrefix;
    TBool iHideInitialIdentity;

	CActiveSchedulerWait iWait;

	eap_status_e m_completion_status;
};

#endif //#ifndef __EAPPLUGIN_H__

// End.
