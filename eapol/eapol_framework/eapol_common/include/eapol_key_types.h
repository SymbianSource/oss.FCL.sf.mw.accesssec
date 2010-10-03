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
* %version: 17.1.4 %
*/

#if !defined(_EAPOL_KEY_TYPES_H_)
#define _EAPOL_KEY_TYPES_H_

#include "eap_configuration_field.h"

//--------------------------------------------------------------------------------------------------

enum eapol_wpa_psk_constants_e
{
	EAPOL_WPA_PSK_LENGTH_BYTES = 32ul,
};

/**
 * Enumeration of EAPOL ethernet type.
 */
enum eapol_ethernet_type_e
{
	eapol_ethernet_type_none              = 0,
	eapol_ethernet_type_pae               = 0x888e, ///< Ethernet type Port Access Entity (PAE)
	eapol_ethernet_type_preauthentication = 0x88c7, ///< Ethernet type Preauthentication
#if defined(USE_WAPI_CORE)
	eapol_ethernet_type_wapi              = 0x88b4, ///< Ethernet type WAPI
#endif //#if defined(USE_WAPI_CORE)
};

/**
 * This is enumeration of key types.
 * NOTE, do not change the values, these are used in interface.
 * These values are used in for loop.
 */
enum eapol_key_type_e
{
	eapol_key_type_broadcast = 0,
	eapol_key_type_unicast = 1,
#if defined(EAP_USE_WPXM)
	eapol_key_type_wpxm_wpxk1 = 2,
	eapol_key_type_wpxm_wpxk2 = 3,
#endif //#if defined(EAP_USE_WPXM)
	eapol_key_type_pmkid = 4,
	eapol_key_type_last_type, ///< Keep this the last one.
};

/// Enumeration of RC4 Key flag field.
/// NOTE, do not change the values, these are used in interface.
enum eapol_RC4_key_flags_e
{
	eapol_RC4_key_flag_broadcast = 0,
	eapol_RC4_key_flag_unicast = 1,
	eapol_RC4_key_flag_none = 0xff
};


/// NOTE, do not change the values, these are used in interface.
enum eapol_wlan_authentication_state_e
{
	eapol_wlan_authentication_state_none = 0, ///< Initial value.
	eapol_wlan_authentication_state_association_ok = 1, ///< Successfull association.
	eapol_wlan_authentication_state_this_ap_failed = 2, ///< Still other authentication could be tested.
	eapol_wlan_authentication_state_failed_completely = 3, ///< No more options to try.
	eapol_wlan_authentication_state_802_11_auth_algorithm_not_supported = 4,
	eapol_wlan_authentication_state_authenticating = 5, ///< This is temporary build fix, do not use this anymore. Instead use eapol_wlan_authentication_state_eap_authentication_running or eapol_wlan_authentication_state_4_way_handshake_running. @{ remove after integrated with WLAN engine.}
	eapol_wlan_authentication_state_eap_authentication_running = 6,
	eapol_wlan_authentication_state_no_response = 7,
	eapol_wlan_authentication_state_4_way_handshake_running = 8,
	eapol_wlan_authentication_state_authentication_successfull = 9,
	eapol_wlan_authentication_state_authentication_cancelled = 10, // When user cancels the password prompt.
	eapol_wlan_authentication_state_immediate_reconnect = 11, ///< This was a provisioning of credentials. Immediately reconnect so the credentials can be used.
#if defined(USE_WAPI_CORE)
	eapol_wlan_authentication_state_wapi_authentication_running = 12,
#endif //#if defined(USE_WAPI_CORE)
};

/**
 * This is enumeration of authentication types.
 * NOTE, do not change the values, these are used in interface.
 */
enum eapol_key_authentication_type_e
{
	eapol_key_authentication_type_none = 0,
	eapol_key_authentication_type_RSNA_EAP = 1,   ///< Authentication is RSNA 802.11i EAP-authentication, 4-Way, Group Key and STAKey Handshakes.
	eapol_key_authentication_type_RSNA_PSK = 2,    ///< Authentication is RNSA 802.11i PSK (pre shared key), 4-Way and Group Key Handshakes.
	eapol_key_authentication_type_WPA_EAP = 3,    ///< Authentication is WPA EAP-authentication, 4-Way and Group Key Handshakes.
	eapol_key_authentication_type_WPA_PSK = 4,    ///< Authentication is WPA PSK (pre shared key), 4-Way and Group Key Handshakes.
	eapol_key_authentication_type_dynamic_WEP = 5, ///< Authentication is dynamic WEP (802.1X). EAP-authentication with simple EAPOL RC4 key message.
	eapol_key_authentication_type_WPXM = 6,    ///< Authentication is WPXM.
	eapol_key_authentication_type_WPS = 7,  ///< Authentication is Wi-Fi Alliance Protected Setup (Simple Configure).
#if defined(USE_WAPI_CORE)
	eapol_key_authentication_type_WAI_PSK = 8,  ///< Authentication is WAI PSK.
	eapol_key_authentication_type_WAI_certificate = 9,  ///< Authentication is WAI certificate.
#endif //#if defined(USE_WAPI_CORE)
	eapol_key_authentication_type_EAP_authentication_no_encryption = 10, ///< Authentication is EAP-authentication without EAPOL RC4 key message. WLAN data will be plain text.
};

/**
 * This is enumeration of 802.11 authentication modes.
 * NOTE, do not change the values, these are used in interface.
 */
enum eapol_key_802_11_authentication_mode_e
{
	eapol_key_802_11_authentication_mode_none = 0,
	eapol_key_802_11_authentication_mode_open = 1,   ///< Authentication is 802.11 open authentication.
	eapol_key_802_11_authentication_mode_shared = 2,    ///< Authentication is 802.11 shared authentication.
	eapol_key_802_11_authentication_mode_leap = 3,    ///< Authentication is LEAP-authentication.
};

/**
 * This is enumeration of EAPOL handshake types.
 * NOTE, do not change the values, these are used in interface.
 */
enum eapol_key_handshake_type_e
{
	eapol_key_handshake_type_none = 0,
	eapol_key_handshake_type_4_way_handshake = 1,
	eapol_key_handshake_type_group_key_handshake = 2,
	eapol_key_handshake_type_STAKey_handshake = 3,
	eapol_key_handshake_type_802_11i_handshake = 4,
	eapol_key_handshake_type_dynamic_WEP = 5,
#if defined(EAP_USE_WPXM)
	eapol_key_handshake_type_WPXM_reassociation = 6,
#endif //#if defined(EAP_USE_WPXM)
#if defined(USE_WAPI_CORE)
	eapol_key_handshake_type_wai_handshake = 7,
#endif //#if defined(USE_WAPI_CORE)
	eapol_key_handshake_type_EAP_authentication_no_encryption = 8,
	eapol_key_handshake_type_authenticated = 9,
};

/**
 * This is enumeration of EAPOL states.
 * NOTE, do not change the values, these are used in interface.
 */
enum eapol_key_state_e
{
	eapol_key_state_none = 0,
	
	eapol_key_state_preauthenticated = 1,

	eapol_key_state_eap_authentication_running = 2,

	eapol_key_state_wait_4_way_handshake_start = 3,
	eapol_key_state_wait_4_way_handshake_message_1 = 4,
	eapol_key_state_wait_4_way_handshake_message_2 = 5,
	eapol_key_state_wait_4_way_handshake_message_3 = 6,
	eapol_key_state_wait_4_way_handshake_message_4 = 7,
	eapol_key_state_4_way_handshake_running = 8,
	eapol_key_state_4_way_handshake_failed = 9,
	eapol_key_state_4_way_handshake_successfull = 10,

	eapol_key_state_wait_group_key_handshake_message_1 = 11,
	eapol_key_state_wait_group_key_handshake_message_2 = 12,
	eapol_key_state_group_key_handshake_failed = 13,
	eapol_key_state_group_key_handshake_successfull = 14,

	eapol_key_state_wait_rc4_key_message = 15,

	eapol_key_state_802_11i_authentication_terminated_unsuccessfull = 16,
	eapol_key_state_802_11i_authentication_finished_successfull = 17,

	eapol_key_state_reassociation_failed = 18,

#if defined(EAP_USE_WPXM)
	eapol_key_state_wpxm_reassociation_finished_successfull = 19,
#endif //#if defined(EAP_USE_WPXM)

#if defined(USE_WAPI_CORE)
	eapol_key_state_wapi_authentication_terminated_unsuccessfull = 20,
	eapol_key_state_wapi_authentication_finished_successfull = 21,
	eapol_key_state_wapi_authentication_running = 22,
	eapol_key_state_wapi_authentication_running_waits_message = 23,
#endif //#if defined(USE_WAPI_CORE)

};

/**
 * This is enumeration of authentication server.
 * NOTE, do not change the values, these are used in interface.
 */
enum eapol_authentication_server_state_e
{
	eapol_authentication_server_state_none = 0,
	eapol_authentication_server_state_authentication_successfull = 1,
};

//--------------------------------------------------------------------------------------------------

/**
 *  @defgroup EAPOL_key_state_config_options Configuration options of EAPOL Key State.
 *  The following configuration options are read through abs_eap_base_type_c::read_configure() function.
 *  @{
 */

/**
 *  This is u32_t configuration option.
 *  This is the maximum count EAPOL key state Authenticator resents EAPOL-Key message again.
 *  This is used in simulator testing.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_state_retransmission_counter,
	"EAPOL_key_state_retransmission_counter",
	eap_configure_type_u32_t,
	false);

/**
 *  This is u32_t configuration option.
 *  This is the time after EAPOL ket state Authenticator resents message again.
 *  Time is in milli seconds.
 *  This is used in simulator testing.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_state_retransmission_time,
	"EAPOL_key_state_retransmission_time",
	eap_configure_type_u32_t,
	false);

/**
 *  This is u32_t configuration option.
 *  This is the maximum time EAPOL-Key Handshake could succeed.
 *  EAPOL-Key Handshake is terminated after this time elapses.
 *  Time is in milli seconds.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_state_handshake_timeout,
	"EAPOL_key_state_handshake_timeout",
	eap_configure_type_u32_t,
	false);

#if defined(EAP_USE_WPXM)
/**
 *  This is u32_t configuration option.
 *  This is the maximum time WPXM reassociation could succeed.
 *  WPXM reassociation is terminated after this time elapses.
 *  Time is in milli seconds.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_state_wpxm_reassociate_timeout,
	"EAPOL_key_state_wpxm_reassociate_timeout",
	eap_configure_type_u32_t,
	false);
#endif //#if defined(EAP_USE_WPXM)

/**
 *  This is u32_t configuration option.
 *  This is the maximum time EAPOL-Key PMKSA is cached.
 *  Time is in milli seconds.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_state_pmksa_caching_timeout,
	"EAPOL_key_state_pmksa_caching_timeout",
	eap_configure_type_u32_t,
	false);

/**
 *  This string configuration option value selects the test authentication and key management.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_authentication_type,
	"EAPOL_key_authentication_type",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_authentication_type_config_value_RSNA_EAP,
	"RSNA_EAP",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_authentication_type_config_value_RSNA_PSK,
	"RSNA_PSK",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_authentication_type_config_value_WPA_EAP,
	"WPA_EAP",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_authentication_type_config_value_WPA_PSK,
	"WPA_PSK",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_authentication_type_config_value_dynamic_WEP,
	"dynamic_WEP",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_authentication_type_config_value_EAP_authentication_no_encryption,
	"EAP_authentication_no_encryption",
	eap_configure_type_string,
	false);


#if defined(EAP_USE_WPXM)
EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_authentication_type_config_value_WPXM,
	"WPXM",
	eap_configure_type_string,
	false);
#endif //#if defined(EAP_USE_WPXM)

#if defined(EAP_USE_WPXM)
EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_WPXM_type,
	"EAPOL_WPXM_type",
	eap_configure_type_string,
	false);
#endif //#if defined(EAP_USE_WPXM)

EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_authentication_type_config_value_WPS,
	"WPS",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_authentication_type_config_value_WAI_PSK,
	"WAI_PSK",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_authentication_type_config_value_WAI_certificate,
	"WAI_certificate",
	eap_configure_type_string,
	false);


/**
 *  This string configuration option value selects the test pairwise cipher.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_pairwise_cipher,
	"EAPOL_key_pairwise_cipher",
	eap_configure_type_string,
	false);

/**
 *  This string configuration option value selects the test group cipher.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_group_cipher,
	"EAPOL_key_group_cipher",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_cipher_CCMP,
	"CCMP",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_cipher_TKIP,
	"TKIP",
	eap_configure_type_string,
	false);


/**
 *  This is boolean configuration option.
 *  This flag tells whether broken 4-Way Handshake message 1 without PMKID is allowed (true) or dropped (false).
 *  Default value id false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_state_allow_missing_PMKID_in_message_1,
	"EAPOL_key_state_allow_missing_PMKID_in_message_1",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  This flag tells whether broken 4-Way Handshake message 1 without PMKID is created (true) or not (false).
 *  Default value id false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_state_skip_PMKID_key_data_in_message_1,
	"EAPOL_key_state_skip_PMKID_key_data_in_message_1",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  This flag activates group key update test (true) or not (false).
 *  Default value id false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_state_TEST_group_key_update,
	"EAPOL_key_state_TEST_group_key_update",
	eap_configure_type_boolean,
	false);


/**
 *  This is boolean configuration option.
 *  This flag tells whether broken 4-Way Handshake message 1 with non zero MIC is allowed (true) or dropped (false).
 *  Default value id false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_state_allow_non_zero_mic_in_message_1,
	"EAPOL_key_state_allow_non_zero_mic_in_message_1",
	eap_configure_type_boolean,
	false);

/**
 *  This is boolean configuration option.
 *  This flag tells the EAPOL must indicate PMKID to lower layers (true) or not (false).
 *  Default value id false.
 */
EAP_CONFIGURATION_FIELD(
	cf_str_EAPOL_key_state_indicate_pmkid_to_lower_layer,
	"EAPOL_key_state_indicate_pmkid_to_lower_layer",
	eap_configure_type_boolean,
	false);

/** @} */ // End of group EAPOK_key_state_config_options.

//--------------------------------------------------------------------------------------------------

#endif //#if !defined(_EAPOL_KEY_TYPES_)
