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
* %version: %
*/

#if !defined(_EAP_PROTOCOL_LAYER_H_)
#define _EAP_PROTOCOL_LAYER_H_

/** @file */ 

#define USE_EAP_PEAPV1_EXTENSIONS

/**
  * A EAP Core protocol layer enumeration.
  * NOTE, do not change the values, these are used in interface.
  */
enum eap_protocol_layer_e
{
	eap_protocol_layer_none = 0,
	eap_protocol_layer_general = 1,               ///< This is general protocol layer, eap_general_state_variable_e uses this.
	eap_protocol_layer_internal_type = 2,         ///< This is any internal authentication type used by EAP-type. For example TLS.
	eap_protocol_layer_am_eap_type = 3,           ///< Adaptation module of EAP type.
	eap_protocol_layer_radius = 4,                ///< RADIUS protocol
	eap_protocol_layer_eap_type = 5,              ///< EAP type.
	eap_protocol_layer_eap = 6,                   ///< EAP protocol, eap_state_variable_e uses this.
	eap_protocol_layer_eapol = 7,                 ///< EAPOL protocol, eapol_state_variable_e uses this.
	eap_protocol_layer_eapol_key = 8,             ///< EAPOL-Key protocol, eapol_key_state_e uses this.
	eap_protocol_layer_ethernet = 9,              ///< Ethernet protocol.
	eap_protocol_layer_wlan_authentication = 10,   ///< WLAN authentication uses this.
	eap_protocol_layer_authentication_server = 11, ///< authentication server uses this.
#if defined(USE_WAPI_CORE)
	eap_protocol_layer_wapi = 12,                  ///< WAPI authentication notification to WLAN engine uses this.
	eap_protocol_layer_wai = 13,                   ///< WAI authentication protocol uses this.
#endif
};


/**
  * A EAP state variable enumeration of eap_protocol_layer_e::eap_protocol_layer_general.
  * NOTE, do not change the values, these are used in interface.
  */
enum eap_general_state_variable_e
{
	eap_general_state_none = 0,
	eap_general_state_show_notification_string = 1, ///< Adaptation module should display notification string to user.
	eap_general_state_configuration_error = 2,      ///< Configuration was incorrect. Cannot continue.
	eap_general_state_authentication_cancelled = 3, ///< Authentication was cancelled. Cannot continue.
	eap_general_state_authentication_error = 4,     ///< Error on authentication, show appropriate error to user.
	eap_general_state_immediate_reconnect = 5,      ///< This was a provisioning of credentials. Immediately reconnect so the credentials can be used.
	eap_general_state_last_mark = 6,                ///< Keep this the last one.
};

/**
  * A EAP state variable enumeration of eap_protocol_layer_e::eap_protocol_layer_eap,
  * eap_protocol_layer_e::eap_protocol_layer_internal_type,
  * eap_protocol_layer_e::eap_protocol_layer_am_eap_type
  * and eap_protocol_layer_e::eap_protocol_layer_eap_type.
  * NOTE, do not change the values, these are used in interface.
  */
enum eap_state_variable_e
{
	eap_state_none = 0,
	eap_state_identity_request_sent = 1,                                                       ///< Server sent the EAP-Request/Identity.
	eap_state_identity_request_received = 2,                                                   ///< Client received the EAP-Request/Identity.
	eap_state_identity_response_received = 3,                                                  ///< Server received the EAP-Response/Identity.
	eap_state_eap_response_sent = 4,                                                           ///< Client sent the first EAP-Response.
	eap_state_tppd_peapv1_authentication_finished_successfully_with_tunneled_eap_success = 5,  ///< Client finished PEAP version 1 with tunneled EAP-Success.
	eap_state_authentication_finished_successfully = 6,                                        ///< Authentication was successfull and it is finished.
	eap_state_authentication_terminated_unsuccessfully = 7,                                    ///< Authentication was unsuccessfull and it is terminated.
	eap_state_authentication_wait_tppd_peapv1_empty_acknowledge = 8,                           ///< Server waits empty akcnowledge of PEAPv1.
	eap_state_use_eap_failure_in_termination = 9,                                              ///< Simple Config ends always with EAP-Failure message.
	eap_state_inner_eap_method_skipped = 10,                                                   ///< Inner EAP-method is not run.
	eap_state_authentication_wait_eap_fast_empty_acknowledge = 11,                             ///< Server waits empty akcnowledge of EAP-FAST.
	eap_state_wait_plain_eap_success = 12,                                                     ///< Client waits plain EAP-Success.
#if defined(USE_EAP_PEAPV1_EXTENSIONS)
	eap_state_authentication_finished_successfully_peapv1_extension = 13,                      ///< Client finished PEAP version 1 with tunneled Extension Response.
	eap_state_authentication_terminated_unsuccessfully_peapv1_extension = 14,                  ///< Client finished PEAP version 1 with tunneled Extension Response.
#endif //#if defined(USE_EAP_PEAPV1_EXTENSIONS)
	eap_state_last_mark = 15,                                                                  ///< Keep this the last one.
};

/**
  * NOTE, do not change the values, these are used in interface.
  */
enum eapol_state_variable_e
{
	eapol_state_none = 0,
	eapol_state_start_sent = 1,        ///< Client has sent EAPOL-Start
	eapol_state_no_start_response = 2, ///< Client did not receive response to EAPOL-Start
};

#endif //#if !defined(_EAP_PROTOCOL_LAYER_H_)

//--------------------------------------------------



// End.
