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

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 57 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include "eap_am_memory.h"

#include "eap_am_tools.h"
#include "eap_variable_data.h"
#include "eap_tools.h"
#include "eap_type_all.h"

#include "eapol_wlan_authentication.h"
#include "eapol_ethernet_header.h"
#include "ethernet_core.h"
#include "eap_crypto_api.h"
#include "eap_header_string.h"
#include "eap_rogue_ap_entry.h"
#include "abs_eap_state_notification.h"
#include "eapol_session_key.h"
#include "eap_buffer.h"
#include "eap_config.h"
#include "eap_array_algorithms.h"
#include "eap_state_notification.h"
#include "eap_automatic_variable.h"
#include "eapol_key_state_string.h"

// LOCAL CONSTANTS

enum eapol_am_core_timer_id_e
{
	EAPOL_WLAN_AUTHENTICATION_TIMER_FAILED_COMPLETELY_ID,
	EAPOL_WLAN_AUTHENTICATION_TIMER_THIS_AP_FAILED_ID,
	EAPOL_WLAN_AUTHENTICATION_TIMER_NO_RESPONSE_ID,
	EAPOL_WLAN_AUTHENTICATION_TIMER_AUTHENTICATION_CANCELLED_ID
};

#if defined(USE_EAPOL_WLAN_AUTHENTICATION_MUTEX)

	#if defined(USE_TEST_WLAN_AUTHENTICATION_MUTEX)
		#error "You cannot define both USE_EAPOL_WLAN_AUTHENTICATION_MUTEX and USE_TEST_WLAN_AUTHENTICATION_MUTEX."
	#endif

	#define WAUTH_ENTER_MUTEX(tools) { tools->enter_global_mutex(); }

	#define WAUTH_LEAVE_MUTEX(tools) { tools->leave_global_mutex(); }

#else

	#define WAUTH_ENTER_MUTEX(tools)

	#define WAUTH_LEAVE_MUTEX(tools)

#endif //#if defined(USE_EAPOL_WLAN_AUTHENTICATION_MUTEX)

// ================= MEMBER FUNCTIONS =======================

EAP_FUNC_EXPORT eapol_wlan_authentication_c * eapol_wlan_authentication_c::new_eapol_wlan_authentication(
	abs_eap_am_tools_c * const tools,
	abs_eapol_wlan_authentication_c * const partner,
	const bool is_client_when_true
	)
{
	EAP_TRACE_DEBUG(
		tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("partner calls: eapol_wlan_authentication_c::new_eapol_wlan_authentication()\n")));

	EAP_TRACE_RETURN_STRING(tools, "returns to partner: eapol_wlan_authentication_c::new_eapol_wlan_authentication()");

	eapol_am_wlan_authentication_c * m_am_wauth = eapol_am_wlan_authentication_c::new_eapol_am_wlan_authentication(
		tools,
		is_client_when_true);
	if (m_am_wauth == 0
		|| m_am_wauth->get_is_valid() == false)
	{
		// ERROR.
		if (m_am_wauth != 0)
		{
			EAP_TRACE_DEBUG(
				tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("calls: eapol_wlan_authentication_c::new_eapol_wlan_authentication(): m_am_wauth->shutdown(): %s.\n"),
				(is_client_when_true == true) ? "client": "server"));

			m_am_wauth->shutdown();
			delete m_am_wauth;
			m_am_wauth = 0;
		}
		return 0;
	}

	eapol_wlan_authentication_c * wauth = new eapol_wlan_authentication_c(tools, partner, m_am_wauth, is_client_when_true);
	if (wauth == 0
		|| wauth->get_is_valid() == false)
	{
		// ERROR.
		if (wauth != 0)
		{
			wauth->shutdown();
			delete wauth;
		}
		return 0;
	}

	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eapol_wlan_authentication_c::new_eapol_wlan_authentication(): m_am_wauth->set_am_partner(): %s.\n"),
		(is_client_when_true == true) ? "client": "server"));

	m_am_wauth->set_am_partner(
		wauth
#if defined(USE_EAP_SIMPLE_CONFIG)
		, wauth
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)
		);

	return wauth;
}	

//--------------------------------------------------

EAP_FUNC_EXPORT eapol_wlan_authentication_c::eapol_wlan_authentication_c(
	abs_eap_am_tools_c * const tools,
	abs_eapol_wlan_authentication_c * const partner,
	eapol_am_wlan_authentication_c * const am_wauth, ///< eapol_wlan_authentication_c must always delete the am_wauth object.
	const bool is_client_when_true)
: m_partner(partner)
, m_am_wauth(am_wauth)
, m_ethernet_core(0)
, m_am_tools(tools)
//, m_selected_eap_types(tools)
, m_wpa_preshared_key_hash(tools)
, m_authentication_type(eapol_key_authentication_type_none)
, m_802_11_authentication_mode(eapol_key_802_11_authentication_mode_none)
, m_received_WPA_IE(tools) // WLM must give only the WPA IE to EAPOL
, m_sent_WPA_IE(tools)
, m_group_key_cipher_suite(eapol_RSNA_key_header_c::eapol_RSNA_cipher_none)
, m_pairwise_key_cipher_suite(eapol_RSNA_key_header_c::eapol_RSNA_cipher_none)
, m_current_eap_index(0ul)
, m_authentication_counter(0u)
, m_successful_authentications(0u)
, m_failed_authentications(0u)
, m_is_valid(false)
, m_is_client(is_client_when_true)
, m_shutdown_was_called(false)
#if defined(USE_EAP_ERROR_TESTS)
, m_randomly_drop_packets(false)
, m_randomly_drop_packets_probability(0u)
, m_error_probability(0u)
, m_generate_multiple_error_packets(0u)
, m_packet_index(0u)
, m_enable_random_errors(false)
, m_manipulate_ethernet_header(false)
, m_send_original_packet_first(false)
#endif //#if defined(USE_EAP_ERROR_TESTS)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("starts: eapol_wlan_authentication_c::eapol_wlan_authentication_c(): %s, this = 0x%08x => 0x%08x, compiled %s %s.\n"),
		(m_is_client == true) ? "client": "server",
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this),
		__DATE__,
		__TIME__));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_wlan_authentication_c::eapol_wlan_authentication_c()");

	if (m_am_wauth == 0
		|| m_am_wauth->get_is_valid() == false)
	{
		// ERROR.
		if (m_am_wauth != 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("calls: eapol_wlan_authentication_c::eapol_wlan_authentication_c(): m_am_wauth->shutdown(): %s.\n"),
				(is_client_when_true == true) ? "client": "server"));

			m_am_wauth->shutdown();
			delete am_wauth;
		}
		return;
	}

	if (m_am_tools == 0
		|| m_am_tools->get_is_valid() == false)
	{
		// ERROR.
		if (m_am_wauth != 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("calls: eapol_wlan_authentication_c::eapol_wlan_authentication_c(): m_am_wauth->shutdown(): %s.\n"),
				(is_client_when_true == true) ? "client": "server"));

			m_am_wauth->shutdown();
			delete am_wauth;
		}
		return;
	}

	m_is_valid = true;
}	

//--------------------------------------------------

// Something in RVCT 2 forces this function cannot be exported.
eapol_wlan_authentication_c::~eapol_wlan_authentication_c()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("partner calls: eapol_wlan_authentication_c::~eapol_wlan_authentication_c(): this = 0x%08x\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to partner: eapol_wlan_authentication_c::~eapol_wlan_authentication_c()");

	EAP_ASSERT(m_shutdown_was_called == true);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("partner calls: eapol_wlan_authentication_c::shutdown(); %s, m_shutdown_was_called=%d\n"),
		(m_is_client == true) ? "client": "server",
		m_shutdown_was_called));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to partner: eapol_wlan_authentication_c::shutdown()");

	if (m_shutdown_was_called == true)
	{
		// Shutdown was already called once.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_shutdown_was_called = true;
	
	// Cancel timer	
	cancel_all_timers();

	// Delete upper stack if it still exists
	if (m_ethernet_core != 0)
	{
		WAUTH_ENTER_MUTEX(m_am_tools);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls eapol: eapol_wlan_authentication_c::shutdown(): m_ethernet_core->shutdown(): %s.\n"),
			(m_is_client == true) ? "client": "server"));

		eap_status_e status = m_ethernet_core->shutdown();
		EAP_UNREFERENCED_PARAMETER(status);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("returns from eapol: eapol_wlan_authentication_c::shutdown(): m_ethernet_core->shutdown(): %s, status = %s.\n"),
			(m_is_client == true) ? "client": "server",
			eap_status_string_c::get_status_string(status)));

		WAUTH_LEAVE_MUTEX(m_am_tools);

		delete m_ethernet_core;
		m_ethernet_core = 0;
	}
	
	// Print some statistics
	if (m_is_client)
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_TEST_VECTORS,
			(EAPL("eapol_wlan_authentication_c::shutdown(): client authentication SUCCESS %d, FAILED %d, count %d\n"),
			m_successful_authentications,
			m_failed_authentications,
			m_authentication_counter));	
	}
	else
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_TEST_VECTORS,
			(EAPL("eapol_wlan_authentication_c::shutdown(): server authentication SUCCESS %d, FAILED %d, count %d\n"),
			m_successful_authentications,
			m_failed_authentications,
			m_authentication_counter));
	}


	if (m_am_wauth != 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls: eapol_wlan_authentication_c::shutdown(): m_am_wauth->shutdown(): %s.\n"),
			(m_is_client == true) ? "client": "server"));

		m_am_wauth->shutdown();
		delete m_am_wauth;
		m_am_wauth = 0;
	}
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAUTH EXITING.\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

//--------------------------------------------------

//
eap_status_e eapol_wlan_authentication_c::cancel_all_authentication_sessions()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_wlan_authentication_c::cancel_all_authentication_sessions(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	eap_status_e status(eap_status_process_general_error);

	if (m_ethernet_core != 0)
	{
		WAUTH_ENTER_MUTEX(m_am_tools);
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls eapol: eapol_wlan_authentication_c::cancel_all_authentication_sessions(): m_ethernet_core->cancel_all_authentication_sessions(): %s.\n"),
			(m_is_client == true) ? "client": "server"));
		status = m_ethernet_core->cancel_all_authentication_sessions();
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("returns from eapol: eapol_wlan_authentication_c::cancel_all_authentication_sessions(): m_ethernet_core->cancel_all_authentication_sessions(): %s, status = %s.\n"),
			(m_is_client == true) ? "client": "server",
			eap_status_string_c::get_status_string(status)));
		WAUTH_LEAVE_MUTEX(m_am_tools);
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eapol_wlan_authentication_c::cancel_all_authentication_sessions(): Stack did not exists.\n")));
		status = eap_status_process_general_error;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::start_authentication(
	const eap_variable_data_c * const SSID,
	const eapol_key_authentication_type_e selected_eapol_key_authentication_type,
	const eap_variable_data_c * const preshared_key, // This does include WPA pre-shared key or WPS PIN.
	const bool WPA_override_enabled,
	const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("partner calls: eapol_wlan_authentication_c::start_authentication(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("Starting authentication, selected_eapol_key_authentication_type=%d=%s.\n"),
		selected_eapol_key_authentication_type,
		eapol_key_state_string_c::get_eapol_key_authentication_type_string(selected_eapol_key_authentication_type)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to partner: eapol_wlan_authentication_c::start_authentication()");

    EAP_TRACE_DATA_DEBUG(
        m_am_tools,
        TRACE_FLAGS_DEFAULT,
        (EAPL("new SSID"),
        SSID->get_data(),
        SSID->get_data_length()));

    EAP_TRACE_DATA_DEBUG(
        m_am_tools,
        TRACE_FLAGS_DEFAULT,
        (EAPL("new preshared_key"),
        preshared_key->get_data(),
        preshared_key->get_data_length()));

	eap_status_e status(eap_status_ok);

	status = cancel_all_authentication_sessions();
	if (status != eap_status_ok)
	{
		(void) EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_authentication_type = selected_eapol_key_authentication_type;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eapol_wlan_authentication_c::start_authentication(): m_am_wauth->set_wlan_parameters(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	status = m_am_wauth->set_wlan_parameters(
		SSID,
		WPA_override_enabled,
		preshared_key,
		selected_eapol_key_authentication_type);
	if (status != eap_status_ok)
	{
		(void) internal_disassociation(false, 0); // Note we have no addresses yet.

		(void) eapol_indication(
			0, // Note we have no addresses yet.
			eapol_wlan_authentication_state_failed_completely);

		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eapol_wlan_authentication_c::start_authentication(): m_am_wauth->reset_wpa_configuration(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	status = m_am_wauth->reset_wpa_configuration();
	if (status != eap_status_ok)
	{
		(void) internal_disassociation(false, 0); // Note we have no addresses yet.

		(void) eapol_indication(
			0, // Note we have no addresses yet.
			eapol_wlan_authentication_state_failed_completely);

		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eapol_wlan_authentication_c::start_authentication(): m_am_wauth->get_selected_eap_types(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eapol_wlan_authentication_c::start_authentication(): m_am_wauth->get_wlan_configuration(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	// Normally here is HASH of WPA pre-shared key, but when connection is Wi-fi Protected setup here is PIN or push button (00000000) key.
	status = m_am_wauth->get_wlan_configuration(
		&m_wpa_preshared_key_hash);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Start new authentication from scratch.
	
	WAUTH_ENTER_MUTEX(m_am_tools);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls eapol: eapol_wlan_authentication_c::start_authentication(): m_ethernet_core->create_state(): %s.\n"),
		(m_is_client == true) ? "client": "server"));
	status = m_ethernet_core->create_state(
		receive_network_id,
		m_authentication_type
		);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from eapol: eapol_wlan_authentication_c::start_authentication(): m_ethernet_core->create_state(): %s, status = %s.\n"),
		(m_is_client == true) ? "client": "server",
		eap_status_string_c::get_status_string(status)));
	WAUTH_LEAVE_MUTEX(m_am_tools);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (m_authentication_type == eapol_key_authentication_type_RSNA_PSK
		|| m_authentication_type == eapol_key_authentication_type_WPA_PSK)
	{
		// WPA Pre-shared key mode
		m_802_11_authentication_mode = eapol_key_802_11_authentication_mode_open;

		if (m_authentication_type == eapol_key_authentication_type_RSNA_PSK)
		{
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("start_authentication(): Trying auth mode OPEN and WPA2-PSK.\n")));
		}
		else
		{
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("start_authentication(): Trying auth mode OPEN and WPA-PSK.\n")));
		}

		status = complete_get_802_11_authentication_mode(
			eap_status_ok,
			receive_network_id,
			m_802_11_authentication_mode);
	}
	else //if (preshared_key == 0
		//|| preshared_key->get_is_valid_data() == false
		//|| WPA_override_enabled == false)
	{
		WAUTH_ENTER_MUTEX(m_am_tools);
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls eapol: eapol_wlan_authentication_c::start_authentication(): m_ethernet_core->get_802_11_authentication_mode(): %s.\n"),
			(m_is_client == true) ? "client": "server"));
		status = m_ethernet_core->get_802_11_authentication_mode(
			receive_network_id,
			m_authentication_type,
			SSID,
			preshared_key);
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("returns from eapol: eapol_wlan_authentication_c::start_authentication(): m_ethernet_core->get_802_11_authentication_mode(): %s, status = %s.\n"),
			(m_is_client == true) ? "client": "server",
			eap_status_string_c::get_status_string(status)));
		WAUTH_LEAVE_MUTEX(m_am_tools);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::complete_association(
	const eapol_wlan_authentication_state_e association_result,
	const eap_am_network_id_c * const receive_network_id, ///< source includes remote address, destination includes local address.
	const eap_variable_data_c * const received_WPA_IE, ///< WLM must give only the WPA IE to EAPOL
	const eap_variable_data_c * const sent_WPA_IE,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
		(EAPL("partner calls: eapol_wlan_authentication_c::complete_association(): %s: association_result=%d\n"),
		(m_is_client == true) ? "client": "server",
		association_result));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to partner: eapol_wlan_authentication_c::complete_association()");

	eap_status_e status(eap_status_ok);

	// ASSOCIATION UNSUCCESSFUL
	if (association_result != eapol_wlan_authentication_state_association_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("complete_association: Unsuccessful.\n")));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("Got AP MAC address"),
			receive_network_id->get_source(),
			receive_network_id->get_source_length()));

		// Report rogue AP if we tried LEAP and it failed
		if (m_802_11_authentication_mode == eapol_key_802_11_authentication_mode_leap)
		{
			// Only add rogue AP if the error code is correct
			if (association_result == eapol_wlan_authentication_state_802_11_auth_algorithm_not_supported)
			{
				eap_rogue_ap_entry_c rogue_entry(m_am_tools);
			
				rogue_entry.set_mac_address(receive_network_id->get_source());
				rogue_entry.set_rogue_reason(rogue_ap_association_failed);

				eap_array_c<eap_rogue_ap_entry_c> rogue_list(m_am_tools);
				status = rogue_list.add_object(&rogue_entry, false);
				if (status == eap_status_ok)
				{	
					status = add_rogue_ap(rogue_list);
					// Ignore return value on purpose - it's not fatal if this fails
				}
			}			
		}

		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("Could not associate to the AP.\n")));

		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
			(EAPL("Indication sent to WLM: eap_status_this_ap_failed.\n")));

		(void) internal_disassociation(false, receive_network_id);

		status = eapol_indication(
			receive_network_id,
			eapol_wlan_authentication_state_this_ap_failed);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);

	}
	
	// ASSOCIATION SUCCESSFUL
	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
		(EAPL("complete_association: Successful.\n")));

	// Store parameters

	if (m_authentication_type == eapol_key_authentication_type_RSNA_EAP
		|| m_authentication_type == eapol_key_authentication_type_RSNA_PSK
		|| m_authentication_type == eapol_key_authentication_type_WPA_EAP
		|| m_authentication_type == eapol_key_authentication_type_WPA_PSK
#if defined(EAP_USE_WPXM)
		|| m_authentication_type == eapol_key_authentication_type_WPXM
#endif //#if defined(EAP_USE_WPXM)
		)
	{
		status = m_received_WPA_IE.set_copy_of_buffer(received_WPA_IE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_sent_WPA_IE.set_copy_of_buffer(sent_WPA_IE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	m_group_key_cipher_suite = group_key_cipher_suite;

	m_pairwise_key_cipher_suite = pairwise_key_cipher_suite;

	eap_variable_data_c * wpa_preshared_key = 0;

	if (m_authentication_type == eapol_key_authentication_type_RSNA_PSK
		|| m_authentication_type == eapol_key_authentication_type_WPA_PSK)
	{
		wpa_preshared_key = &m_wpa_preshared_key_hash;
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eapol_wlan_authentication_c::complete_association(): m_am_wauth->association(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	status = m_am_wauth->association(receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	WAUTH_ENTER_MUTEX(m_am_tools);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls eapol: eapol_wlan_authentication_c::complete_association(): m_ethernet_core->association(): %s.\n"),
		(m_is_client == true) ? "client": "server"));
	status = m_ethernet_core->association(
		receive_network_id,
		m_authentication_type,
		&m_received_WPA_IE,
		&m_sent_WPA_IE,
		pairwise_key_cipher_suite,
		group_key_cipher_suite,
		wpa_preshared_key);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from eapol: eapol_wlan_authentication_c::complete_association(): m_ethernet_core->association(): %s, status = %s.\n"),
		(m_is_client == true) ? "client": "server",
		eap_status_string_c::get_status_string(status)));
	WAUTH_LEAVE_MUTEX(m_am_tools);

	if (status != eap_status_ok)
	{

		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
			(EAPL("m_ethernet_core->association call failed.\n")));

		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
			(EAPL("Indication sent to WLM: eap_status_failed_completely.\n")));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls: eapol_wlan_authentication_c::complete_association(): this->disassociation(): %s.\n"),
			(m_is_client == true) ? "client": "server"));

		(void) internal_disassociation(false, receive_network_id);

		status = eapol_indication(
			receive_network_id,
			eapol_wlan_authentication_state_failed_completely);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (m_authentication_type == eapol_key_authentication_type_RSNA_EAP
		|| m_authentication_type == eapol_key_authentication_type_WPA_EAP
		|| m_authentication_type == eapol_key_authentication_type_dynamic_WEP
		|| m_authentication_type == eapol_key_authentication_type_WPS
#if defined(EAP_USE_WPXM)
		|| m_authentication_type == eapol_key_authentication_type_WPXM
#endif //#if defined(EAP_USE_WPXM)
		|| m_authentication_type == eapol_key_authentication_type_EAP_authentication_no_encryption
		)
	{
		// Start authentication if mode is not pre-shared key. If mode is pre-shared key then
		// just wait for EAPOL-Key frames.
		WAUTH_ENTER_MUTEX(m_am_tools);
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls eapol: eapol_wlan_authentication_c::complete_association(): m_ethernet_core->start_authentication(): %s.\n"),
			(m_is_client == true) ? "client": "server"));
		status = m_ethernet_core->start_authentication(receive_network_id, m_is_client);
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("returns from eapol: eapol_wlan_authentication_c::complete_association(): m_ethernet_core->start_authentication(): %s, status = %s.\n"),
			(m_is_client == true) ? "client": "server",
			eap_status_string_c::get_status_string(status)));
		WAUTH_LEAVE_MUTEX(m_am_tools);
	}
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::start_preauthentication(
	const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("partner calls: eapol_wlan_authentication_c::start_preauthentication(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to partner: eapol_wlan_authentication_c::start_preauthentication()");

	WAUTH_ENTER_MUTEX(m_am_tools);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls eapol: eapol_wlan_authentication_c::start_preauthentication(): m_ethernet_core->start_preauthentication(): %s.\n"),
		(m_is_client == true) ? "client": "server"));
	eap_status_e status = m_ethernet_core->start_preauthentication(
		receive_network_id,
		m_authentication_type);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from eapol: eapol_wlan_authentication_c::start_preauthentication(): m_ethernet_core->start_preauthentication(): %s, status = %s.\n"),
		(m_is_client == true) ? "client": "server",
		eap_status_string_c::get_status_string(status)));
	WAUTH_LEAVE_MUTEX(m_am_tools);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::check_pmksa_cache(
	eap_array_c<eap_am_network_id_c> * const bssid_sta_receive_network_ids,
	const eapol_key_authentication_type_e selected_eapol_key_authentication_type,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("partner calls: eapol_wlan_authentication_c::check_pmksa_cache(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to partner: eapol_wlan_authentication_c::check_pmksa_cache()");

	WAUTH_ENTER_MUTEX(m_am_tools);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls eapol: eapol_wlan_authentication_c::check_pmksa_cache(): m_ethernet_core->check_pmksa_cache(): %s.\n"),
		(m_is_client == true) ? "client": "server"));
	eap_status_e status = m_ethernet_core->check_pmksa_cache(
		bssid_sta_receive_network_ids,
		selected_eapol_key_authentication_type,
		pairwise_key_cipher_suite,
		group_key_cipher_suite);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from eapol: eapol_wlan_authentication_c::check_pmksa_cache(): m_ethernet_core->check_pmksa_cache(): %s, status = %s.\n"),
		(m_is_client == true) ? "client": "server",
		eap_status_string_c::get_status_string(status)));
	WAUTH_LEAVE_MUTEX(m_am_tools);

	if (bssid_sta_receive_network_ids->get_object_count() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: eapol_wlan_authentication_c::check_pmksa_cache(): %s: No PMKSA:s found in cache.\n"),
			(m_is_client == true) ? "client": "server"));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::start_reassociation(
	const eap_am_network_id_c * const old_receive_network_id, ///< source includes remote address, destination includes local address.
	const eap_am_network_id_c * const new_receive_network_id, ///< source includes remote address, destination includes local address.
	const eapol_key_authentication_type_e selected_eapol_key_authentication_type ///< In WPXM this must be the same in old and new APs, other connections can change authentication type.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("partner calls: eapol_wlan_authentication_c::start_reassociation(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to partner: eapol_wlan_authentication_c::start_reassociation()");

	{
		EAP_TRACE_DATA_DEBUG(m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("old_receive_network_id source:"),
			old_receive_network_id->get_source_id()->get_data(),
			old_receive_network_id->get_source_id()->get_data_length()));

		EAP_TRACE_DATA_DEBUG(m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("old_receive_network_id destination:"),
			old_receive_network_id->get_destination_id()->get_data(),
			old_receive_network_id->get_destination_id()->get_data_length()));

		EAP_TRACE_DATA_DEBUG(m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("new_receive_network_id source:"),
			new_receive_network_id->get_source_id()->get_data(),
			new_receive_network_id->get_source_id()->get_data_length()));

		EAP_TRACE_DATA_DEBUG(m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("new_receive_network_id destination:"),
			new_receive_network_id->get_destination_id()->get_data(),
			new_receive_network_id->get_destination_id()->get_data_length()));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status = cancel_all_authentication_sessions();
	if (status != eap_status_ok)
	{
		(void) EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eapol_wlan_authentication_c::start_reassociation(): m_am_wauth->reset_wpa_configuration(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	status = m_am_wauth->reset_wpa_configuration();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c reassociation_PMKID(m_am_tools);

	WAUTH_ENTER_MUTEX(m_am_tools);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls eapol: eapol_wlan_authentication_c::start_reassociation(): m_ethernet_core->read_reassociation_parameters(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	status = m_ethernet_core->read_reassociation_parameters(
		old_receive_network_id,
		new_receive_network_id,
		selected_eapol_key_authentication_type,
		&reassociation_PMKID,
		0,
		0);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from eapol: eapol_wlan_authentication_c::start_reassociation(): m_ethernet_core->read_reassociation_parameters(): %s, status = %s.\n"),
		(m_is_client == true) ? "client": "server",
		eap_status_string_c::get_status_string(status)));
	WAUTH_LEAVE_MUTEX(m_am_tools);

	if (status == eap_status_ok)
	{
		// Here we swap the addresses.
		eap_am_network_id_c send_network_id(
			m_am_tools,
			new_receive_network_id->get_destination_id(),
			new_receive_network_id->get_source_id(),
			new_receive_network_id->get_type());
		if (send_network_id.get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		m_authentication_type = selected_eapol_key_authentication_type;

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls partner: eapol_wlan_authentication_c::start_reassociation(): %s: m_partner->reassociate(): m_authentication_type=%d=%s.\n"),
			 (m_is_client == true) ? "client": "server",
			 m_authentication_type,
			 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type)));

		status = m_partner->reassociate(
			&send_network_id,
			m_authentication_type,
			&reassociation_PMKID);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("returns from partner: eapol_wlan_authentication_c::start_reassociation(): %s: m_partner->reassociate(): status = %s\n"),
			 (m_is_client == true) ? "client": "server",
			 eap_status_string_c::get_status_string(status)));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::complete_reassociation(
	const eapol_wlan_authentication_state_e reassociation_result,
	const eap_am_network_id_c * const receive_network_id,
	const eap_variable_data_c * const received_WPA_IE, // WLM must give only the WPA IE to EAPOL
	const eap_variable_data_c * const sent_WPA_IE,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("partner calls: eapol_wlan_authentication_c::complete_reassociation(): %s, reassociation_result=%d\n"),
		(m_is_client == true) ? "client": "server",
		reassociation_result));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to partner: eapol_wlan_authentication_c::complete_reassociation()");

	eap_status_e status(eap_status_process_general_error);

	if (reassociation_result != eapol_wlan_authentication_state_association_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("complete_reassociation: Unsuccessful.\n")));

		WAUTH_ENTER_MUTEX(m_am_tools);
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls eapol: eapol_wlan_authentication_c::complete_reassociation(): m_ethernet_core->remove_pmksa_from_cache(): %s.\n"),
			(m_is_client == true) ? "client": "server"));
		status = m_ethernet_core->remove_pmksa_from_cache(
			receive_network_id);
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("returns from eapol: eapol_wlan_authentication_c::complete_reassociation(): m_ethernet_core->remove_pmksa_from_cache(): %s, status = %s.\n"),
			(m_is_client == true) ? "client": "server",
			eap_status_string_c::get_status_string(status)));
		WAUTH_LEAVE_MUTEX(m_am_tools);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("complete_reassociation: Successful.\n")));

		WAUTH_ENTER_MUTEX(m_am_tools);
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls eapol: eapol_wlan_authentication_c::complete_reassociation(): m_ethernet_core->complete_reassociation(): %s.\n"),
			(m_is_client == true) ? "client": "server"));
		status = m_ethernet_core->complete_reassociation(
			reassociation_result,
			receive_network_id,
			m_authentication_type,
			received_WPA_IE,
			sent_WPA_IE,
			pairwise_key_cipher_suite,
			group_key_cipher_suite);
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("returns from eapol: eapol_wlan_authentication_c::complete_reassociation(): m_ethernet_core->complete_reassociation(): %s, status = %s.\n"),
			(m_is_client == true) ? "client": "server",
			eap_status_string_c::get_status_string(status)));
		WAUTH_LEAVE_MUTEX(m_am_tools);

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::packet_process(
	const eap_am_network_id_c * const receive_network_id, ///< source includes remote address, destination includes local address.
	eap_general_header_base_c * const packet_data,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("partner calls: eapol_wlan_authentication_c::packet_process(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to partner: eapol_wlan_authentication_c::packet_process()");

#if !defined(EAPOL_SKIP_ETHERNET_HEADER)

	if (packet_length < eapol_ethernet_header_wr_c::get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

#endif //#if !defined(EAPOL_SKIP_ETHERNET_HEADER)

	eapol_ethernet_header_wr_c eth_header(
		m_am_tools,
		packet_data->get_header_buffer(packet_length),
		packet_length);

	eap_status_e status(eap_status_process_general_error);

#if !defined(EAPOL_SKIP_ETHERNET_HEADER)
	if (eth_header.get_type() == eapol_ethernet_type_pae
		|| eth_header.get_type() == eapol_ethernet_type_preauthentication)
#endif //#if !defined(EAPOL_SKIP_ETHERNET_HEADER)

	{
		// Forward the packet to the Ethernet layer of the EAPOL stack.
		// Ignore return value. Failure is signalled using state_notification.
		WAUTH_ENTER_MUTEX(m_am_tools);
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls eapol: eapol_wlan_authentication_c::packet_process(): m_ethernet_core->packet_process(): %s.\n"),
			(m_is_client == true) ? "client": "server"));
		status = m_ethernet_core->packet_process(
			receive_network_id,
			&eth_header,
			packet_length);
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("returns from eapol: eapol_wlan_authentication_c::packet_process(): m_ethernet_core->packet_process(): %s, status = %s.\n"),
			(m_is_client == true) ? "client": "server",
			eap_status_string_c::get_status_string(status)));
		WAUTH_LEAVE_MUTEX(m_am_tools);

		EAP_GENERAL_HEADER_COPY_ERROR_PARAMETERS(packet_data, &eth_header);
	} 
#if !defined(EAPOL_SKIP_ETHERNET_HEADER)
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Not supported ethernet type 0x%04x\n"), eth_header.get_type()));
		status = eap_status_ethernet_type_not_supported;
	}
#endif //#if !defined(EAPOL_SKIP_ETHERNET_HEADER)
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eapol_wlan_authentication_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eapol_wlan_authentication_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eapol_wlan_authentication_c::increment_authentication_counter()
{
	++m_authentication_counter;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eapol_wlan_authentication_c::get_authentication_counter()
{
	return m_authentication_counter;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eapol_wlan_authentication_c::get_is_client()
{
	return m_is_client;
}
	
//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::packet_data_session_key(
	const eap_am_network_id_c * const send_network_id,
	const eapol_session_key_c * const key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status(eap_status_ok);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::packet_data_session_key(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::packet_data_session_key()");

	const eap_variable_data_c * const key_data = key->get_key();
	if (key_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	EAP_TRACE_DEBUG(m_am_tools,
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_wlan_authentication_c::packet_data_session_key(): %s: key_type 0x%02x=%s, key_index %d\n"),
		(m_is_client == true) ? "client": "server",
		key->get_key_type(),
		eapol_session_key_c::get_eapol_key_type_string(key->get_key_type()),
		key->get_key_index()));
	
	EAP_TRACE_DATA_DEBUG(m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("packet_data_session_key:"),
		key_data->get_data(key_data->get_data_length()),
		key_data->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("packet_data_session_key      send source"), 
		 send_network_id->get_source(),
		 send_network_id->get_source_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("packet_data_session_key send destination"), 
		 send_network_id->get_destination(),
		 send_network_id->get_destination_length()));

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls partner: eapol_wlan_authentication_c::packet_data_session_key(): %s: m_partner->packet_data_session_key()\n"),
		 (m_is_client == true) ? "client": "server"));

	status = m_partner->packet_data_session_key(send_network_id, key);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from partner: eapol_wlan_authentication_c::packet_data_session_key(): %s: m_partner->packet_data_session_key(): status = %s\n"),
		 (m_is_client == true) ? "client": "server",
		 eap_status_string_c::get_status_string(status)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::packet_send(
	const eap_am_network_id_c * const send_network_id,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const u32_t buffer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::packet_send(data_length=%d): %s.\n"),
		data_length,
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::packet_send()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	if (header_offset != 0u)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet_send: packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}
	else if (header_offset+data_length != sent_packet->get_data_length())
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: packet_send: packet buffer corrupted (data_length != sent_packet->get_data_length()).\n")));
		EAP_ASSERT(data_length == sent_packet->get_buffer_length());
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}	

	eap_status_e status(eap_status_ok);


#if defined(USE_EAP_ERROR_TESTS)

	sent_packet->set_is_client(true);

	if (m_randomly_drop_packets == true)
	{
		u32_t random_guard;
		crypto_random_c rand(m_am_tools);
		status = rand.get_rand_bytes(
			reinterpret_cast<u8_t *>(&random_guard),
			sizeof(random_guard));
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// This is simple limiter to the probability of a packet drop.
		// probability = m_randomly_drop_packets_probability / (2^32)
		if (random_guard < m_randomly_drop_packets_probability)
		{
			// Drops this packet.

			if (sent_packet->get_stack_address() == 0)
			{
				// Initialize error testing data.
				sent_packet->set_stack_address(this);
				m_am_tools->increase_packet_index();
				sent_packet->set_send_packet_index(++m_packet_index);
			}

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("TEST: random_error(): packet_index 0x%08x:%lu, Send packet dropped\n"),
				sent_packet->get_stack_address(),
				sent_packet->get_send_packet_index()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return eap_status_ok;
		}
	}

	if (m_send_original_packet_first == true)
	{
		if (sent_packet->get_stack_address() == 0)
		{
			// Initialize error testing data.
			sent_packet->set_stack_address(this);
			sent_packet->set_send_packet_index(++m_packet_index);
		}

		if (m_enable_random_errors == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TEST: random_error(): packet_index 0x%08x:%lu, Send original packet\n"),
				sent_packet->get_stack_address(),
				sent_packet->get_send_packet_index()));
		}

		u8_t * const packet_data = sent_packet->get_data_offset(header_offset, data_length);
		if (packet_data == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls partner: eapol_wlan_authentication_c::packet_send(): %s: m_partner->packet_send()\n"),
			 (m_is_client == true) ? "client": "server"));

		// Here we send the original packet.
		status = m_partner->packet_send(
			send_network_id,
			sent_packet,
			header_offset,
			data_length,
			buffer_length);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("returns from partner: eapol_wlan_authentication_c::packet_send(): %s: m_partner->packet_send(): status = %s\n"),
			 (m_is_client == true) ? "client": "server",
			 eap_status_string_c::get_status_string(status)));
	}

	if (m_enable_random_errors == true
		&& status == eap_status_ok)
	{
		if (m_generate_multiple_error_packets > 0ul)
		{
			// First create a copy of sent packet. Original correct packet will will be sent last.
			for (u32_t ind = 0ul; ind < m_generate_multiple_error_packets; ind++)
			{
				eap_buf_chain_wr_c *copy_packet = sent_packet->copy();

				if (copy_packet != 0
					&& copy_packet->get_is_valid_data() == true)
				{
					copy_packet->set_send_packet_index(++m_packet_index);

					// Make a random error to the copy message.
					m_am_tools->generate_random_error(
						copy_packet,
						true,
						copy_packet->get_send_packet_index(),
						0UL,
						m_error_probability,
						eapol_ethernet_header_wr_c::get_header_length());

					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("TEST: random_error(): packet_index 0x%08x:%lu, Send error packet\n"),
						copy_packet->get_stack_address(),
						copy_packet->get_send_packet_index()));
					
					u8_t * const packet_data = copy_packet->get_data_offset(header_offset, data_length);
					if (packet_data == 0)
					{
						delete copy_packet;
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
					}

					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
						(EAPL("calls partner: eapol_wlan_authentication_c::packet_send(): %s: m_partner->packet_send()\n"),
						 (m_is_client == true) ? "client": "server"));

					// Here we send the copied and manipulated packet.
					status = m_partner->packet_send(
						send_network_id,
						copy_packet,
						header_offset,
						data_length,
						buffer_length);

					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
						(EAPL("returns from partner: eapol_wlan_authentication_c::packet_send(): %s: m_partner->packet_send(): status = %s\n"),
						 (m_is_client == true) ? "client": "server",
						 eap_status_string_c::get_status_string(status)));
				}

				delete copy_packet;
			} // for()
		}
		else
		{
			if (sent_packet->get_stack_address() == 0)
			{
				// Initialize error testing data.
				sent_packet->set_stack_address(this);
				sent_packet->set_send_packet_index(++m_packet_index);
			}

			eap_buf_chain_wr_c *copy_packet = sent_packet->copy();

			if (copy_packet != 0
				&& copy_packet->get_is_valid_data() == true)
			{
				copy_packet->set_send_packet_index(++m_packet_index);

				// Make a random error to the copy message.
				m_am_tools->generate_random_error(
					copy_packet,
					false,
					copy_packet->get_send_packet_index(),
					0UL,
					m_error_probability,
					eapol_ethernet_header_wr_c::get_header_length());

				if (copy_packet->get_is_manipulated() == true)
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("TEST: random_error(): packet_index 0x%08x:%lu, Send error packet\n"),
						copy_packet->get_stack_address(),
						copy_packet->get_send_packet_index()));

					u8_t * const packet_data = copy_packet->get_data_offset(header_offset, data_length);
					if (packet_data == 0)
					{
						delete copy_packet;
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
					}

					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
						(EAPL("calls partner: eapol_wlan_authentication_c::packet_send(): %s: m_partner->packet_send()\n"),
						 (m_is_client == true) ? "client": "server"));

					// Here we send the copied and manipulated packet.
					status = m_partner->packet_send(
						send_network_id,
						copy_packet,
						header_offset,
						data_length,
						buffer_length);

					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
						(EAPL("returns from partner: eapol_wlan_authentication_c::packet_send(): %s: m_partner->packet_send(): status = %s\n"),
						 (m_is_client == true) ? "client": "server",
						 eap_status_string_c::get_status_string(status)));
				}
			}

			delete copy_packet;
		}
	}


	if (m_send_original_packet_first == false
		&& status == eap_status_ok)
	{
		if (sent_packet->get_stack_address() == 0)
		{
			// Initialize error testing data.
			sent_packet->set_stack_address(this);
			sent_packet->set_send_packet_index(++m_packet_index);
		}

		if (m_enable_random_errors == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TEST: random_error(): packet_index 0x%08x:%lu, Send original packet\n"),
				sent_packet->get_stack_address(),
				sent_packet->get_send_packet_index()));
		}

		u8_t * const packet_data = sent_packet->get_data_offset(header_offset, data_length);
		if (packet_data == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
		}

#endif //#if defined(USE_EAP_ERROR_TESTS)


		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls partner: eapol_wlan_authentication_c::packet_send(): %s: m_partner->packet_send()\n"),
			 (m_is_client == true) ? "client": "server"));

		// Here we send the original packet.
		status = m_partner->packet_send(
			send_network_id,
			sent_packet,
			header_offset,
			data_length,
			buffer_length);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("returns from partner: eapol_wlan_authentication_c::packet_send(): %s: m_partner->packet_send(): status = %s\n"),
			 (m_is_client == true) ? "client": "server",
			 eap_status_string_c::get_status_string(status)));

#if defined(USE_EAP_ERROR_TESTS)
	}
#endif //#if defined(USE_EAP_ERROR_TESTS)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e eapol_wlan_authentication_c::cancel_timer_this_ap_failed()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = cancel_timer(
		this,
		EAPOL_WLAN_AUTHENTICATION_TIMER_THIS_AP_FAILED_ID);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_wlan_authentication_c::cancel_timer_this_ap_failed(): Cancels timer EAPOL_WLAN_AUTHENTICATION_TIMER_THIS_AP_FAILED_ID.\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e eapol_wlan_authentication_c::cancel_timer_failed_completely()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = cancel_timer(
		this,
		EAPOL_WLAN_AUTHENTICATION_TIMER_FAILED_COMPLETELY_ID);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_wlan_authentication_c::cancel_timer_failed_completely(): Cancels timer EAPOL_WLAN_AUTHENTICATION_TIMER_FAILED_COMPLETELY_ID.\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e eapol_wlan_authentication_c::cancel_timer_no_response()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = cancel_timer(
		this,
		EAPOL_WLAN_AUTHENTICATION_TIMER_NO_RESPONSE_ID);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_wlan_authentication_c::cancel_timer_no_response(): Cancels timer EAPOL_WLAN_AUTHENTICATION_TIMER_NO_RESPONSE_ID.\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e eapol_wlan_authentication_c::cancel_timer_authentication_cancelled()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = cancel_timer(
		this,
		EAPOL_WLAN_AUTHENTICATION_TIMER_AUTHENTICATION_CANCELLED_ID);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_wlan_authentication_c::cancel_timer_authentication_cancelled(): Cancels timer EAPOL_WLAN_AUTHENTICATION_TIMER_AUTHENTICATION_CANCELLED_ID.\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eapol_wlan_authentication_c::state_notification(
	const abs_eap_state_notification_c * const state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::state_notification()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::state_notification()");

	if (state == 0 
		|| state->get_send_network_id() == 0
		|| state->get_send_network_id()->get_is_valid_data() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: Illegal state notification state=0x%08x, state->get_send_network_id()=0x%08x.\n"),
			state,
			((state != 0) ? state->get_send_network_id() : 0)));
		(void)EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		return;
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("    send source"),
		 state->get_send_network_id()->get_source(),
		 state->get_send_network_id()->get_source_length()));
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("send destination"),
		 state->get_send_network_id()->get_destination(),
		 state->get_send_network_id()->get_destination_length()));

	// Here we swap the addresses.
	eap_am_network_id_c receive_network_id(m_am_tools,
		state->get_send_network_id()->get_destination_id(),
		state->get_send_network_id()->get_source_id(),
		state->get_send_network_id()->get_type());

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_am_network_id_c* send_network_id = new eap_am_network_id_c(
		m_am_tools,
		state->get_send_network_id());

	eap_automatic_variable_c<eap_am_network_id_c>
		automatic_send_network_id(m_am_tools, send_network_id);

	if (send_network_id == 0 
		|| send_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: No network identity: Indication sent to WLM: eap_status_failed_completely.\n")));

		(void) cancel_timer_failed_completely();

		set_timer(
			this,
			EAPOL_WLAN_AUTHENTICATION_TIMER_FAILED_COMPLETELY_ID,
			send_network_id,
			0);
		
		automatic_send_network_id.do_not_free_variable();

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Sets timer ")
			 EAPL("EAPOL_WLAN_AUTHENTICATION_TIMER_FAILED_COMPLETELY_ID.\n")));
	}


	{
		eap_status_string_c status_string;
		eap_header_string_c eap_string;

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eapol_wlan_authentication_c::state_notification() %s: protocol layer %d=%s, protocol %d=%s, EAP-type 0xfe%06x%08x=%s\n"),
			(state->get_is_client() == true ? "client": "server"),
			state->get_protocol_layer(),
			state->get_protocol_layer_string(),
			state->get_protocol(),
			state->get_protocol_string(),
			state->get_eap_type().get_vendor_id(),
			state->get_eap_type().get_vendor_type(),
			eap_header_string_c::get_eap_type_string(state->get_eap_type())));

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eapol_wlan_authentication_c::state_notification() %s: current state %d=%s, error %d=%s\n"),
			(state->get_is_client() == true ? "client": "server"),
			state->get_current_state(),
			state->get_current_state_string(),
			state->get_authentication_error(),
			status_string.get_status_string(state->get_authentication_error())));
	}


	if(state->get_protocol_layer() == eap_protocol_layer_general)
	{
		if (state->get_current_state() == eap_general_state_authentication_cancelled)
		{
			// Authentication was cancelled. Cannot continue.
			cancel_timer_authentication_cancelled();

			set_timer(this, EAPOL_WLAN_AUTHENTICATION_TIMER_AUTHENTICATION_CANCELLED_ID, send_network_id, 0);
			automatic_send_network_id.do_not_free_variable();

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Authentication was cancelled. Sets timer ")
				 EAPL("EAPOL_WLAN_AUTHENTICATION_TIMER_AUTHENTICATION_CANCELLED_ID.\n")));

			// This indication is sent synchronously to WLAN engine. That prevent other indications to bypass this indication.
			eap_status_e status = eapol_indication(
				&receive_network_id,
				eapol_wlan_authentication_state_authentication_cancelled);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				(void)EAP_STATUS_RETURN(m_am_tools, status);
				return;
			}
		}
		else if (state->get_current_state() == eap_general_state_configuration_error)
		{
			// Configuration error. Cannot continue.
			(void) cancel_timer_failed_completely();

			set_timer(this, EAPOL_WLAN_AUTHENTICATION_TIMER_FAILED_COMPLETELY_ID, send_network_id, 0);
			automatic_send_network_id.do_not_free_variable();

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Configuration error. Sets timer ")
				 EAPL("EAPOL_WLAN_AUTHENTICATION_TIMER_FAILED_COMPLETELY_ID.\n")));
		}
		else if (state->get_current_state() == eap_general_state_authentication_error)
		{
			// An authentication error from EAPOL-stack.

			eap_status_string_c status_string;
			eap_header_string_c eap_string;

			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: eapol_wlan_authentication_c::state_notification() %s: protocol layer %d=%s, protocol %d=%s, EAP-type 0xfe%06x%08x=%s\n"),
				(state->get_is_client() == true ? "client": "server"),
				state->get_protocol_layer(),
				state->get_protocol_layer_string(),
				state->get_protocol(),
				state->get_protocol_string(),
				state->get_eap_type().get_vendor_id(),
				state->get_eap_type().get_vendor_type(),
				eap_header_string_c::get_eap_type_string(state->get_eap_type())));

			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: eapol_wlan_authentication_c::state_notification() %s: current state %d=%s, error %d=%s\n"),
				(state->get_is_client() == true ? "client": "server"),
				state->get_current_state(),
				state->get_current_state_string(),
				state->get_authentication_error(),
				status_string.get_status_string(state->get_authentication_error())));

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("calls partner: eapol_wlan_authentication_c::state_notification(): %s: m_partner->state_notification()\n"),
				 (m_is_client == true) ? "client": "server"));

			// Calls lower layer.
			// Note the optimization prevents most of the state notifications to lower layer.
			m_partner->state_notification(state);

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("returns from partner: eapol_wlan_authentication_c::state_notification(): %s: m_partner->state_notification()\n"),
				 (m_is_client == true) ? "client": "server"));

			(void) cancel_timer_this_ap_failed();

			set_timer(
				this,
				EAPOL_WLAN_AUTHENTICATION_TIMER_THIS_AP_FAILED_ID,
				send_network_id,
				0);
			automatic_send_network_id.do_not_free_variable();

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Sets timer EAPOL_WLAN_AUTHENTICATION_TIMER_THIS_AP_FAILED_ID.\n")));
		}
		else if (state->get_current_state() == eap_general_state_immediate_reconnect)
		{
			// An provision protocol ready. Do immediate reconnect to use the new credentials.

			eap_status_string_c status_string;
			eap_header_string_c eap_string;

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eapol_wlan_authentication_c::state_notification() %s: protocol layer %d=%s, protocol %d=%s, EAP-type 0xfe%06x%08x=%s\n"),
				(state->get_is_client() == true ? "client": "server"),
				state->get_protocol_layer(),
				state->get_protocol_layer_string(),
				state->get_protocol(),
				state->get_protocol_string(),
				state->get_eap_type().get_vendor_id(),
				state->get_eap_type().get_vendor_type(),
				eap_header_string_c::get_eap_type_string(state->get_eap_type())));

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eapol_wlan_authentication_c::state_notification() %s: current state %d=%s, error %d=%s\n"),
				(state->get_is_client() == true ? "client": "server"),
				state->get_current_state(),
				state->get_current_state_string(),
				state->get_authentication_error(),
				status_string.get_status_string(state->get_authentication_error())));

				eap_status_e status = eapol_indication(
					&receive_network_id,
					eapol_wlan_authentication_state_immediate_reconnect);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return;
				}

		}
	}
	else if(state->get_protocol_layer() == eap_protocol_layer_eap) // Check if this is EAP layer notification
	{
		switch (state->get_current_state())
		{
		case eap_state_none:
			break;
		case eap_state_identity_request_sent:
			// This is for server only so no need to notify WLM.
			break;
		case eap_state_identity_request_received:
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("EAP authentication running...\n")));
			}
			break;
		case eap_state_identity_response_received:
			// This is for server only so no need to notify WLM.
			break;
		case eap_state_authentication_finished_successfully:
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("calls: eapol_wlan_authentication_c::state_notification(): m_am_wauth->authentication_finished(): %s.\n"),
					(m_is_client == true) ? "client": "server"));

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("calls partner: eapol_wlan_authentication_c::state_notification(): %s: m_partner->state_notification()\n"),
					 (m_is_client == true) ? "client": "server"));

				// Calls lower layer.
				// Note the optimization prevents most of the state notifications to lower layer.
				m_partner->state_notification(state);

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("returns from partner: eapol_wlan_authentication_c::state_notification(): %s: m_partner->state_notification()\n"),
					 (m_is_client == true) ? "client": "server"));

				m_am_wauth->authentication_finished(
					true,
					state->get_eap_type(),
					m_authentication_type);

				if (state->get_eap_type() == eap_expanded_type_simple_config.get_type())
				{
					increment_authentication_counter();
					m_successful_authentications++;

					EAP_TRACE_ALWAYS(
						m_am_tools,
						TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
						(EAPL("EAPOL_KEY: %s: EAP WFA Protected Setup SUCCESS\n"),
						(m_is_client == true ? "client": "server")));

					eap_status_e status = eapol_indication(
						&receive_network_id,
						eapol_wlan_authentication_state_authentication_successfull);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return;
					}
				}
			}
			break;
		case eap_state_authentication_terminated_unsuccessfully:
			{
				increment_authentication_counter();
				m_failed_authentications++;

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("calls partner: eapol_wlan_authentication_c::state_notification(): %s: m_partner->state_notification()\n"),
					 (m_is_client == true) ? "client": "server"));

				// Calls lower layer.
				// Note the optimization prevents most of the state notifications to lower layer.
				m_partner->state_notification(state);

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("returns from partner: eapol_wlan_authentication_c::state_notification(): %s: m_partner->state_notification()\n"),
					 (m_is_client == true) ? "client": "server"));

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("calls: eapol_wlan_authentication_c::state_notification(): m_am_wauth->authentication_finished(): %s.\n"),
					(m_is_client == true) ? "client": "server"));

				m_am_wauth->authentication_finished(
					false,
					state->get_eap_type(),
					m_authentication_type);

				(void) cancel_timer_this_ap_failed();

				set_timer(
					this,
					EAPOL_WLAN_AUTHENTICATION_TIMER_THIS_AP_FAILED_ID,
					send_network_id,
					0);
				automatic_send_network_id.do_not_free_variable();

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("Sets timer EAPOL_WLAN_AUTHENTICATION_TIMER_THIS_AP_FAILED_ID.\n")));
			}
			break;
		default:
			break;
		}
	}
	else if(state->get_protocol_layer() == eap_protocol_layer_eapol)
	{
		switch (state->get_current_state())
		{
		case eapol_state_no_start_response:
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: Indication sent to WLM: ENoResponse.\n")));

			{
				(void) cancel_timer_no_response();

				set_timer(
					this,
					EAPOL_WLAN_AUTHENTICATION_TIMER_NO_RESPONSE_ID,
					send_network_id,
					0);
				automatic_send_network_id.do_not_free_variable();

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("Sets timer ")
					 EAPL("EAPOL_WLAN_AUTHENTICATION_TIMER_NO_RESPONSE_ID.\n")));
			}
			break;
		default:
			break;
		}
	}
	else if(state->get_protocol_layer() == eap_protocol_layer_eapol_key)
	{
		switch (state->get_current_state())
		{

		case eapol_key_state_eap_authentication_running:
			{
				EAP_TRACE_ALWAYS(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
					(EAPL("EAPOL_KEY: %s: EAP authentication RUNNING\n"),
					(m_is_client == true ? "client": "server")));

				eap_status_e status = eapol_indication(
					&receive_network_id,
					eapol_wlan_authentication_state_eap_authentication_running);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return;
				}
			}
			break;

		case eapol_key_state_4_way_handshake_running:
			{
				EAP_TRACE_ALWAYS(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
					(EAPL("EAPOL_KEY: %s: 4-Way Handshake RUNNING\n"),
					(m_is_client == true ? "client": "server")));

				eap_status_e status = eapol_indication(
					&receive_network_id,
					eapol_wlan_authentication_state_4_way_handshake_running);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return;
				}
			}
			break;

		case eapol_key_state_802_11i_authentication_terminated_unsuccessfull:
		case eapol_key_state_reassociation_failed:
			{					
				increment_authentication_counter();
				m_failed_authentications++;

				// Consider EAPOL layer failures fatal.
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: Unsuccessful authentication on EAPOL level.\n")));

				(void) cancel_timer_this_ap_failed();

				set_timer(
					this,
					EAPOL_WLAN_AUTHENTICATION_TIMER_THIS_AP_FAILED_ID,
					send_network_id,
					0);
				automatic_send_network_id.do_not_free_variable();

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("Sets timer EAPOL_WLAN_AUTHENTICATION_TIMER_THIS_AP_FAILED_ID.\n")));
			}
			break;

		case eapol_key_state_802_11i_authentication_finished_successfull:
#if defined(EAP_USE_WPXM)
		case eapol_key_state_wpxm_reassociation_finished_successfull:
#endif //#if defined(EAP_USE_WPXM)
			{
				// This is used in dynamic WEP (802.1x), WPA and WPA2 (RNS) authentications.
				increment_authentication_counter();
				m_successful_authentications++;

				EAP_TRACE_ALWAYS(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
					(EAPL("EAPOL_KEY: %s: Authentication SUCCESS\n"),
					(m_is_client == true ? "client": "server")));

				eap_status_e status = eapol_indication(
					&receive_network_id,
					eapol_wlan_authentication_state_authentication_successfull);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return;
				}
			}
			break;

		default:
			break;
		}
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eapol_wlan_authentication_c::state_notification(): m_am_wauth->state_notification(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	// AM could have to show some notification to user.
	m_am_wauth->state_notification(state);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::timer_expired(
	const u32_t id,
	void * data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::timer_expired(): id = %d, data = 0x%08x.\n"),
		id,
		data));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::timer_expired()");

	eap_am_network_id_c * const send_network_id = static_cast<eap_am_network_id_c *>(data);
	if (send_network_id == 0 
		|| send_network_id->get_is_valid_data() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// Here we swap the addresses.
	eap_am_network_id_c receive_network_id(m_am_tools,
		send_network_id->get_destination_id(),
		send_network_id->get_source_id(),
		send_network_id->get_type());


	switch (id)
	{
	case EAPOL_WLAN_AUTHENTICATION_TIMER_FAILED_COMPLETELY_ID:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL_WLAN_AUTHENTICATION_TIMER_FAILED_COMPLETELY_ID elapsed: ")
				 EAPL("Indication sent to WLM: eap_status_failed_completely.\n")));

			(void) disassociation_mutex_must_be_reserved(false, &receive_network_id);

			eap_status_e status = eapol_indication(
				&receive_network_id,
				eapol_wlan_authentication_state_failed_completely);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		break;
	
	case EAPOL_WLAN_AUTHENTICATION_TIMER_THIS_AP_FAILED_ID:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL_WLAN_AUTHENTICATION_TIMER_THIS_AP_FAILED_ID elapsed: ")
				 EAPL("Indication sent to WLM: eap_status_this_ap_failed.\n")));

			(void) disassociation_mutex_must_be_reserved(false, &receive_network_id);

			eap_status_e status = eapol_indication(
				&receive_network_id,
				eapol_wlan_authentication_state_this_ap_failed);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		break;

	case EAPOL_WLAN_AUTHENTICATION_TIMER_NO_RESPONSE_ID:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL_WLAN_AUTHENTICATION_TIMER_NO_RESPONSE_ID elapsed: ")
				 EAPL("Indication sent to WLM: eap_status_no_response.\n")));

			(void) disassociation_mutex_must_be_reserved(false, &receive_network_id);

			eap_status_e status = eapol_indication(
				&receive_network_id,
				eapol_wlan_authentication_state_no_response);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		break;
		
	case EAPOL_WLAN_AUTHENTICATION_TIMER_AUTHENTICATION_CANCELLED_ID:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL_WLAN_AUTHENTICATION_TIMER_AUTHENTICATION_CANCELLED_ID elapsed: ")
				 EAPL("Indication sent to WLM: eapol_wlan_authentication_state_authentication_cancelled.\n")));

			(void) disassociation_mutex_must_be_reserved(false, &receive_network_id);
		}
		break;

	default:
		break;
	}
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::timer_delete_data(
	const u32_t id,
	void *data)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::timer_delete_data(): id = %d, data = 0x%08x.\n"),
		id,
		data));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::timer_delete_data()");

	eap_am_network_id_c * const send_network_id = static_cast<eap_am_network_id_c *>(data);
	if (send_network_id == 0 
		|| send_network_id->get_is_valid_data() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	switch (id)
	{
	//case EAPOL_WLAN_AUTHENTICATION_TIMER_RESTART_AUTHENTICATION_ID:
	//case EAPOL_WLAN_AUTHENTICATION_TIMER_DELETE_STACK_ID:
	case EAPOL_WLAN_AUTHENTICATION_TIMER_FAILED_COMPLETELY_ID:
	case EAPOL_WLAN_AUTHENTICATION_TIMER_THIS_AP_FAILED_ID:
	case EAPOL_WLAN_AUTHENTICATION_TIMER_NO_RESPONSE_ID:
	case EAPOL_WLAN_AUTHENTICATION_TIMER_AUTHENTICATION_CANCELLED_ID:
		delete send_network_id;
		break;
	default:
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eapol_wlan_authentication_c::timer_delete_data: deleted unknown timer.\n")));
			(void)EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
		}
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u32_t eapol_wlan_authentication_c::get_header_offset(
	u32_t * const MTU,
	u32_t * const trailer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::get_header_offset()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::get_header_offset()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls partner: eapol_wlan_authentication_c::get_header_offset(): %s: m_partner->get_header_offset()\n"),
		 (m_is_client == true) ? "client": "server"));
	
	const u32_t offset = m_partner->get_header_offset(MTU, trailer_length);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from partner: eapol_wlan_authentication_c::get_header_offset(): %s: m_partner->get_header_offset(): offset = %d\n"),
		 (m_is_client == true) ? "client": "server",
		 offset));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return offset;

}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::unload_module(
	const eap_type_value_e type)
{
	EAP_UNREFERENCED_PARAMETER(type);
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::unload_module(type 0x%08x=%s): \n"),
		convert_eap_type_to_u32_t(type),
		eap_header_string_c::get_eap_type_string(type)
		));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::unload_module()");

	eap_status_e status(eap_status_type_does_not_exists_error);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eapol_wlan_authentication_c::unload_module(): m_am_wauth->unload_module(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

#if 0

	status = m_am_wauth->unload_module(type);

#else

	status = eap_status_not_supported;

#endif


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::eap_acknowledge(
	const eap_am_network_id_c * const receive_network_id)
{
	// Any Network Protocol packet is accepted as a success indication.
	// This is described in RFC 2284 "PPP Extensible Authentication Protocol (EAP)".

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("partner calls: eapol_wlan_authentication_c::eap_acknowledge()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to partner: eapol_wlan_authentication_c::eap_acknowledge()");

	WAUTH_ENTER_MUTEX(m_am_tools);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls eapol: eapol_wlan_authentication_c::eap_acknowledge(): m_ethernet_core->eap_acknowledge(): %s.\n"),
		(m_is_client == true) ? "client": "server"));
	eap_status_e status = m_ethernet_core->eap_acknowledge(receive_network_id);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from eapol: eapol_wlan_authentication_c::eap_acknowledge(): m_ethernet_core->eap_acknowledge(): %s, status = %s.\n"),
		 (m_is_client == true) ? "client": "server",
		 eap_status_string_c::get_status_string(status)));
	WAUTH_LEAVE_MUTEX(m_am_tools);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::set_eap_database_reference_values(
	const eap_variable_data_c * const reference)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("partner calls: eapol_wlan_authentication_c::set_eap_database_reference_values()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to partner: eapol_wlan_authentication_c::set_eap_database_reference_values()");

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_wlan_authentication_c::set_eap_database_reference_values(): reference"),
		 reference->get_data(),
		 reference->get_data_length()));

	WAUTH_ENTER_MUTEX(m_am_tools);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls eapol: eapol_wlan_authentication_c::set_eap_database_reference_values(): m_ethernet_core->set_eap_database_reference_values(): %s.\n"),
		(m_is_client == true) ? "client": "server"));
	eap_status_e status = m_ethernet_core->set_eap_database_reference_values(reference);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from eapol: eapol_wlan_authentication_c::set_eap_database_reference_values(): m_ethernet_core->set_eap_database_reference_values(): %s, status = %s.\n"),
		 (m_is_client == true) ? "client": "server",
		 eap_status_string_c::get_status_string(status)));
	WAUTH_LEAVE_MUTEX(m_am_tools);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	WAUTH_ENTER_MUTEX(m_am_tools);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls eapol: eapol_wlan_authentication_c::set_eap_database_reference_values(): m_am_wauth->set_eap_database_reference_values(): %s.\n"),
		(m_is_client == true) ? "client": "server"));
	status = m_am_wauth->set_eap_database_reference_values(reference);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from eapol: eapol_wlan_authentication_c::set_eap_database_reference_values(): m_am_wauth->set_eap_database_reference_values(): %s, status = %s.\n"),
		 (m_is_client == true) ? "client": "server",
		 eap_status_string_c::get_status_string(status)));
	WAUTH_LEAVE_MUTEX(m_am_tools);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::load_module(
		const eap_type_value_e type,
		const eap_type_value_e tunneling_type,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type_if,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id)
{	
	EAP_UNREFERENCED_PARAMETER(type);
	EAP_UNREFERENCED_PARAMETER(tunneling_type);
	EAP_UNREFERENCED_PARAMETER(eap_type_if);
	EAP_UNREFERENCED_PARAMETER(receive_network_id);
	EAP_UNREFERENCED_PARAMETER(partner);
	EAP_UNREFERENCED_PARAMETER(is_client_when_true);
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::load_module(type 0x%08x=%s, tunneling_type 0x%08x=%s), %s\n"),
		convert_eap_type_to_u32_t(type),
		eap_header_string_c::get_eap_type_string(type),
		convert_eap_type_to_u32_t(tunneling_type),
		eap_header_string_c::get_eap_type_string(tunneling_type),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::load_module()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eapol_wlan_authentication_c::load_module(): m_am_wauth->load_module(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

#if 0

	eap_status_e status = m_am_wauth->load_module(
		type,
		tunneling_type,
		partner,
		eap_type_if,
		is_client_when_true,
		receive_network_id);

#else

	eap_status_e status = eap_status_not_supported;

#endif

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e eapol_wlan_authentication_c::disassociation_mutex_must_be_reserved(
	const bool complete_to_lower_layer,
	const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::disassociation_mutex_must_be_reserved(): %s, complete_to_lower_layer=%s\n"),
		 (m_is_client == true) ? "client": "server",
		 (complete_to_lower_layer == true) ? "true": "false"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::disassociation_mutex_must_be_reserved()");

	// reset index
	m_current_eap_index = 0UL;

	eap_status_e status(eap_status_process_general_error);

	if (m_ethernet_core != 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls eapol: eapol_wlan_authentication_c::disassociation_mutex_must_be_reserved(): m_ethernet_core->disassociation(): %s.\n"),
			(m_is_client == true) ? "client": "server"));

		status = m_ethernet_core->disassociation(
			complete_to_lower_layer,
			receive_network_id);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("returns from eapol: eapol_wlan_authentication_c::disassociation_mutex_must_be_reserved(): m_ethernet_core->disassociation(): %s, status = %s.\n"),
			 (m_is_client == true) ? "client": "server",
			 eap_status_string_c::get_status_string(status)));

		if (status == eap_status_handler_does_not_exists_error)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eapol_wlan_authentication_c::disassociation_mutex_must_be_reserved(): Association did not exists.\n")));
			status = eap_status_ok;
		}
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eapol_wlan_authentication_c::disassociation_mutex_must_be_reserved(): Stack did not exists.\n")));
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eapol_wlan_authentication_c::disassociation_mutex_must_be_reserved(): m_am_wauth->disassociation(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	// This call indicates the disassociation to adaptation.
	status = m_am_wauth->disassociation(receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eapol_wlan_authentication_c::disassociation_mutex_must_be_reserved(): m_am_wauth->disassociation() failed.\n")));
		(void) EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e eapol_wlan_authentication_c::internal_disassociation(
	const bool complete_to_lower_layer,
	const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::internal_disassociation(): %s, complete_to_lower_layer=%s\n"),
		 (m_is_client == true) ? "client": "server",
		 (complete_to_lower_layer == true) ? "true": "false"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: : eapol_wlan_authentication_c::internal_disassociation()");

	eap_status_e status(eap_status_ok);

	WAUTH_ENTER_MUTEX(m_am_tools);
	status = disassociation_mutex_must_be_reserved(
		complete_to_lower_layer,
		receive_network_id);
	WAUTH_LEAVE_MUTEX(m_am_tools);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::disassociation(
	const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("partner calls: eapol_wlan_authentication_c::disassociation(): %s\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to partner: eapol_wlan_authentication_c::disassociation()");

	eap_status_e status(eap_status_ok);

	status = internal_disassociation(
		true,
		receive_network_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::tkip_mic_failure(
	const eap_am_network_id_c * const receive_network_id,
	const bool fatal_failure_when_true,
	const eapol_RSNA_key_header_c::eapol_tkip_mic_failure_type_e tkip_mic_failure_type)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
		(EAPL("partner calls: eapol_wlan_authentication_c::tkip_mic_failure(%d, %d).\n"),
		fatal_failure_when_true,
		tkip_mic_failure_type));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to partner: eapol_wlan_authentication_c::tkip_mic_failure()");

	WAUTH_ENTER_MUTEX(m_am_tools);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls eapol: eapol_wlan_authentication_c::tkip_mic_failure(): m_ethernet_core->tkip_mic_failure(): %s.\n"),
		(m_is_client == true) ? "client": "server"));
	const eap_status_e status = m_ethernet_core->tkip_mic_failure(
		receive_network_id,
		fatal_failure_when_true,
		tkip_mic_failure_type);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from eapol: eapol_wlan_authentication_c::tkip_mic_failure(): m_ethernet_core->tkip_mic_failure(): %s, status = %s.\n"),
		 (m_is_client == true) ? "client": "server",
		 eap_status_string_c::get_status_string(status)));
	WAUTH_LEAVE_MUTEX(m_am_tools);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::configure()
{	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("partner calls: eapol_wlan_authentication_c::configure(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to partner: eapol_wlan_authentication_c::configure()");

	//----------------------------------------------------------

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eapol_wlan_authentication_c::configure(): m_am_wauth->configure(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	eap_status_e status = m_am_wauth->configure();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	//----------------------------------------------------------

#if defined(USE_EAP_ERROR_TESTS)

	{
		eap_variable_data_c EAP_ERROR_TEST_randomly_drop_packets(m_am_tools);
		
		status = read_configure(
			cf_str_EAP_ERROR_TEST_randomly_drop_packets.get_field(),
			&EAP_ERROR_TEST_randomly_drop_packets);
		if (status == eap_status_ok
			&& EAP_ERROR_TEST_randomly_drop_packets.get_is_valid_data() == true)
		{
			u32_t *randomly_drop_packets = reinterpret_cast<u32_t *>(
				EAP_ERROR_TEST_randomly_drop_packets.get_data(sizeof(u32_t)));
			if (randomly_drop_packets != 0
				&& *randomly_drop_packets != 0)
			{
				m_randomly_drop_packets = true;
			}
		}
	}
		
	{
		eap_variable_data_c EAP_ERROR_TEST_randomly_drop_packets_probability(m_am_tools);

		status = read_configure(
			cf_str_EAP_ERROR_TEST_randomly_drop_packets_probability.get_field(),
			&EAP_ERROR_TEST_randomly_drop_packets_probability);
		if (status == eap_status_ok
			&& EAP_ERROR_TEST_randomly_drop_packets_probability.get_is_valid_data() == true)
		{
			u32_t *randomly_drop_packets_probability = reinterpret_cast<u32_t *>(
				EAP_ERROR_TEST_randomly_drop_packets_probability.get_data(sizeof(u32_t)));
			if (randomly_drop_packets_probability != 0)
			{
				m_randomly_drop_packets_probability = *randomly_drop_packets_probability;
			}
		}
	}
		
	{
		eap_variable_data_c EAP_ERROR_TEST_enable_random_errors(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_ERROR_TEST_enable_random_errors.get_field(),
			&EAP_ERROR_TEST_enable_random_errors);
		if (status == eap_status_ok
			&& EAP_ERROR_TEST_enable_random_errors.get_is_valid_data() == true)
		{
			u32_t *enable_random_errors = reinterpret_cast<u32_t *>(
				EAP_ERROR_TEST_enable_random_errors.get_data(sizeof(u32_t)));
			if (enable_random_errors != 0
				&& *enable_random_errors != 0)
			{
				m_enable_random_errors = true;
			}
		}
	}

	{
		eap_variable_data_c EAP_ERROR_TEST_send_original_packet_first(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_ERROR_TEST_send_original_packet_first.get_field(),
			&EAP_ERROR_TEST_send_original_packet_first);
		if (status == eap_status_ok
			&& EAP_ERROR_TEST_send_original_packet_first.get_is_valid_data() == true)
		{
			u32_t *send_original_packet_first = reinterpret_cast<u32_t *>(
				EAP_ERROR_TEST_send_original_packet_first.get_data(sizeof(u32_t)));
			if (send_original_packet_first != 0
				&& *send_original_packet_first != 0)
			{
				m_send_original_packet_first = true;
			}
		}
	}

	{
		eap_variable_data_c EAP_ERROR_TEST_generate_multiple_error_packets(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_ERROR_TEST_generate_multiple_error_packets.get_field(),
			&EAP_ERROR_TEST_generate_multiple_error_packets);
		if (status == eap_status_ok
			&& EAP_ERROR_TEST_generate_multiple_error_packets.get_is_valid_data() == true)
		{
			u32_t *generate_multiple_error_packets = reinterpret_cast<u32_t *>(
				EAP_ERROR_TEST_generate_multiple_error_packets.get_data(sizeof(u32_t)));
			if (generate_multiple_error_packets != 0
				&& *generate_multiple_error_packets != 0)
			{
				m_generate_multiple_error_packets = *generate_multiple_error_packets;
			}
		}
	}


	{
		eap_variable_data_c EAP_ERROR_TEST_manipulate_ethernet_header(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_ERROR_TEST_manipulate_ethernet_header.get_field(),
			&EAP_ERROR_TEST_manipulate_ethernet_header);
		if (status == eap_status_ok
			&& EAP_ERROR_TEST_manipulate_ethernet_header.get_is_valid_data() == true)
		{
			u32_t *manipulate_ethernet_header = reinterpret_cast<u32_t *>(
				EAP_ERROR_TEST_manipulate_ethernet_header.get_data(sizeof(u32_t)));
			if (manipulate_ethernet_header != 0
				&& *manipulate_ethernet_header != 0)
			{
				m_manipulate_ethernet_header = true;
			}
		}
	}

	{
		eap_variable_data_c EAP_ERROR_TEST_error_probability(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_ERROR_TEST_error_probability.get_field(),
			&EAP_ERROR_TEST_error_probability);
		if (status == eap_status_ok
			&& EAP_ERROR_TEST_error_probability.get_is_valid_data() == true)
		{
			u32_t *error_probability = reinterpret_cast<u32_t *>(
				EAP_ERROR_TEST_error_probability.get_data(sizeof(u32_t)));
			if (error_probability != 0)
			{
				m_error_probability = *error_probability;
			}
		}
	}	

	{
		eap_variable_data_c EAP_disable_function_traces(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_TRACE_enable_function_traces.get_field(),
			&EAP_disable_function_traces);
		if (status == eap_status_ok
			&& EAP_disable_function_traces.get_is_valid_data() == true)
		{
			u32_t *disable_function_traces = reinterpret_cast<u32_t *>(
				EAP_disable_function_traces.get_data(sizeof(u32_t)));
			if (disable_function_traces != 0
				&& *disable_function_traces != 0)
			{
				m_am_tools->set_trace_mask(
					m_am_tools->get_trace_mask()
					| eap_am_tools_c::eap_trace_mask_functions
					);
			}
		}
	}

#endif //#if defined(USE_EAP_ERROR_TESTS)


	//----------------------------------------------------------

	{		
		eap_variable_data_c EAP_TRACE_disable_traces(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_TRACE_disable_traces.get_field(),
			&EAP_TRACE_disable_traces);
		if (status == eap_status_ok
			&& EAP_TRACE_disable_traces.get_is_valid_data() == true)
		{
			u32_t *disable_traces = reinterpret_cast<u32_t *>(
				EAP_TRACE_disable_traces.get_data(sizeof(u32_t)));
			if (disable_traces != 0
				&& *disable_traces != 0)
			{
				m_am_tools->set_trace_mask(eap_am_tools_c::eap_trace_mask_none);
			}
		}
	}

	//----------------------------------------------------------

	{		
		eap_variable_data_c EAP_TRACE_activate_only_trace_masks_always_and_error(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_TRACE_activate_only_trace_masks_always_and_error.get_field(),
			&EAP_TRACE_activate_only_trace_masks_always_and_error);
		if (status == eap_status_ok
			&& EAP_TRACE_activate_only_trace_masks_always_and_error.get_is_valid_data() == true)
		{
			u32_t *activate_trace_mask_always = reinterpret_cast<u32_t *>(
				EAP_TRACE_activate_only_trace_masks_always_and_error.get_data(sizeof(u32_t)));
			if (activate_trace_mask_always != 0
				&& *activate_trace_mask_always != 0)
			{
				m_am_tools->set_trace_mask(
					eap_am_tools_c::eap_trace_mask_always
					| eap_am_tools_c::eap_trace_mask_error
					);
			}
		}
	}

	//----------------------------------------------------------

	{		
		eap_variable_data_c EAP_TRACE_activate_trace_on_error(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_TRACE_activate_trace_on_error.get_field(),
			&EAP_TRACE_activate_trace_on_error);
		if (status == eap_status_ok
			&& EAP_TRACE_activate_trace_on_error.get_is_valid_data() == true)
		{
			u32_t *activate_trace_on_error = reinterpret_cast<u32_t *>(
				EAP_TRACE_activate_trace_on_error.get_data(sizeof(u32_t)));
			if (activate_trace_on_error != 0
				&& *activate_trace_on_error != 0)
			{
				m_am_tools->set_activate_trace_on_error();
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c EAP_TRACE_enable_timer_traces(m_am_tools);

		status = read_configure(
			cf_str_EAP_TRACE_enable_timer_traces.get_field(),
			&EAP_TRACE_enable_timer_traces);
		if (status == eap_status_ok
			&& EAP_TRACE_enable_timer_traces.get_is_valid_data() == true)
		{
			u32_t *enable_timer_traces = reinterpret_cast<u32_t *>(
				EAP_TRACE_enable_timer_traces.get_data(sizeof(u32_t)));
			if (enable_timer_traces != 0
				&& *enable_timer_traces != 0)
			{
				m_am_tools->set_trace_mask(
					m_am_tools->get_trace_mask()
					| TRACE_FLAGS_TIMER
					);
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c EAP_TRACE_enable_timer_queue_traces(m_am_tools);

		status = read_configure(
			cf_str_EAP_TRACE_enable_timer_queue_traces.get_field(),
			&EAP_TRACE_enable_timer_queue_traces);
		if (status == eap_status_ok
			&& EAP_TRACE_enable_timer_queue_traces.get_is_valid_data() == true)
		{
			u32_t *enable_timer_queue_traces = reinterpret_cast<u32_t *>(
				EAP_TRACE_enable_timer_queue_traces.get_data(sizeof(u32_t)));
			if (enable_timer_queue_traces != 0
				&& *enable_timer_queue_traces != 0)
			{
				m_am_tools->set_trace_mask(
					m_am_tools->get_trace_mask()
					| TRACE_FLAGS_TIMER_QUEUE
					);
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c EAP_TRACE_enable_ok_return_traces(m_am_tools);

		status = read_configure(
			cf_str_EAP_TRACE_enable_ok_return_traces.get_field(),
			&EAP_TRACE_enable_ok_return_traces);
		if (status == eap_status_ok
			&& EAP_TRACE_enable_ok_return_traces.get_is_valid_data() == true)
		{
			u32_t *enable_ok_return_traces = reinterpret_cast<u32_t *>(
				EAP_TRACE_enable_ok_return_traces.get_data(sizeof(u32_t)));
			if (enable_ok_return_traces != 0
				&& *enable_ok_return_traces != 0)
			{
				m_am_tools->set_trace_mask(
					m_am_tools->get_trace_mask()
					| TRACE_FLAGS_OK_RETURNS
					);
			}
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c EAP_TRACE_enable_message_data_traces(m_am_tools);

		status = read_configure(
			cf_str_EAP_TRACE_enable_message_data_traces.get_field(),
			&EAP_TRACE_enable_message_data_traces);
		if (status == eap_status_ok
			&& EAP_TRACE_enable_message_data_traces.get_is_valid_data() == true)
		{
			u32_t *enable_message_data_traces = reinterpret_cast<u32_t *>(
				EAP_TRACE_enable_message_data_traces.get_data(sizeof(u32_t)));
			if (enable_message_data_traces != 0
				&& *enable_message_data_traces != 0)
			{
				m_am_tools->set_trace_mask(
					m_am_tools->get_trace_mask()
					| EAP_TRACE_FLAGS_MESSAGE_DATA
					);
			}
		}
	}

	//----------------------------------------------------------

	// Create stack if it does not already exist. 
	status = create_upper_stack();

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// All of the configuration options are optional.
	// So we return OK.
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::read_configure(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::read_configure()");

	EAP_ASSERT_ALWAYS(data != 0);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eapol_wlan_authentication_c::read_configure(): m_am_wauth->read_configure(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	eap_status_e status = m_am_wauth->read_configure(field, data);

	m_am_tools->trace_configuration(
		status,
		field,
		data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::write_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::write_configure(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::write_configure()");

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eapol_wlan_authentication_c::write_configure(): m_am_wauth->write_configure(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	eap_status_e status = m_am_wauth->write_configure(field, data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::set_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id, 
	void * const p_data,
	const u32_t p_time_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::set_timer(): id = %d, data = 0x%08x, time = %d\n"),
		p_id,
		p_data,
		p_time_ms));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::set_timer()");

	const eap_status_e status = m_am_tools->am_set_timer(
		p_initializer, 
		p_id, 
		p_data,
		p_time_ms);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::cancel_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::cancel_timer(): initializer = 0x%08x, id = %d\n"),
		p_initializer,
		p_id));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::cancel_timer()");

	const eap_status_e status = m_am_tools->am_cancel_timer(
		p_initializer, 
		p_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::cancel_all_timers()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::cancel_all_timers()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::cancel_all_timers()");

	eap_status_e status = eap_status_ok;
	
	if (m_am_tools != 0)
	{
		WAUTH_ENTER_MUTEX(m_am_tools);
		status = m_am_tools->am_cancel_all_timers();
		WAUTH_LEAVE_MUTEX(m_am_tools);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::check_is_valid_eap_type(
	const eap_type_value_e /* eap_type */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::check_is_valid_eap_type()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::check_is_valid_eap_type()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eapol_wlan_authentication_c::check_is_valid_eap_type(): m_am_wauth->check_is_valid_eap_type(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

#if 0

	eap_status_e status = m_am_wauth->check_is_valid_eap_type(eap_type);
	
#else

	eap_status_e status = eap_status_not_supported;

#endif


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::get_eap_type_list(
	eap_array_c<eap_type_value_e> * const /* eap_type_list */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::get_eap_type_list()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::get_eap_type_list()");

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eapol_wlan_authentication_c::get_eap_type_list(): m_am_wauth->get_eap_type_list(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

#if 0

	eap_status_e status = m_am_wauth->get_eap_type_list(eap_type_list);

#else

	eap_status_e status = eap_status_not_supported;

#endif

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eapol_wlan_authentication_c::eapol_indication(
	const eap_am_network_id_c * const receive_network_id, ///< source includes remote address, destination includes local address.
	const eapol_wlan_authentication_state_e wlan_authentication_state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::eapol_indication()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::eapol_indication()");

	eap_status_e status(eap_status_ok);

	eap_am_network_id_c send_network_id(m_am_tools);

	if (receive_network_id != 0)
	{
		// Here we swap the addresses.
		eap_am_network_id_c tmp_network_id(m_am_tools,
			receive_network_id->get_destination_id(),
			receive_network_id->get_source_id(),
			receive_network_id->get_type());

		status = send_network_id.set_copy_of_network_id(&tmp_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		const u8_t no_address[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00,};

		eap_am_network_id_c tmp_network_id(
			m_am_tools,
			no_address,
			sizeof(no_address),
			no_address,
			sizeof(no_address),
			eapol_ethernet_type_pae,
			false,
			false);

		status = send_network_id.set_copy_of_network_id(&tmp_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	eap_state_notification_c notification(
		m_am_tools,
		&send_network_id,
		m_is_client,
		eap_state_notification_generic,
		eap_protocol_layer_wlan_authentication,
		eap_type_none, // EAP-type is unknown.
		eapol_wlan_authentication_state_none, // Previous state is unknown.
		wlan_authentication_state, // The current indicated state.
		0UL, // EAP-identifier is unknown.
		false // This is not applicable here.
		);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_wlan_authentication_c::eapol_indication(): Sending state notification to Engine. state=%s=%d\n"),
		 notification.get_state_string( notification.get_protocol_layer() ,wlan_authentication_state ),
		 wlan_authentication_state));	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("    send source"),
		 send_network_id.get_source(),
		 send_network_id.get_source_length()));
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("send destination"),
		 send_network_id.get_destination(),
		 send_network_id.get_destination_length()));
		
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls partner: eapol_wlan_authentication_c::eapol_indication(): %s: m_partner->state_notification()\n"),
		 (m_is_client == true) ? "client": "server"));
	
	m_partner->state_notification(&notification);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from partner: eapol_wlan_authentication_c::eapol_indication(): %s: m_partner->state_notification(): status = %s\n"),
		 (m_is_client == true) ? "client": "server",
		 eap_status_string_c::get_status_string(status)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eapol_wlan_authentication_c::create_upper_stack()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::create_upper_stack()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::create_upper_stack()");

	eap_status_e status(eap_status_ok);

	if (m_ethernet_core == 0)
	{        
		m_ethernet_core = new ethernet_core_c(m_am_tools, this, m_is_client);
		if (m_ethernet_core == 0
			|| m_ethernet_core->get_is_valid() != true)
		{
			if (m_ethernet_core != 0)
			{
				WAUTH_ENTER_MUTEX(m_am_tools);
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("calls eapol: eapol_wlan_authentication_c::create_upper_stack(): m_ethernet_core->shutdown(): %s.\n"),
					(m_is_client == true) ? "client": "server"));
				status = m_ethernet_core->shutdown();
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("returns from eapol: eapol_wlan_authentication_c::create_upper_stack(): m_ethernet_core->shutdown(): %s, status = %s.\n"),
					 (m_is_client == true) ? "client": "server",
					 eap_status_string_c::get_status_string(status)));
				WAUTH_LEAVE_MUTEX(m_am_tools);

				delete m_ethernet_core;
				m_ethernet_core = 0;							
			}			
			EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Stack creation failed.\n")));			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);	
		}

		// Initialise upper stack
		WAUTH_ENTER_MUTEX(m_am_tools);
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls eapol: eapol_wlan_authentication_c::create_upper_stack(): m_ethernet_core->configure(): %s.\n"),
			(m_is_client == true) ? "client": "server"));
		status = m_ethernet_core->configure();
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("returns from eapol: eapol_wlan_authentication_c::create_upper_stack(): m_ethernet_core->configure(): %s, status = %s.\n"),
			 (m_is_client == true) ? "client": "server",
			 eap_status_string_c::get_status_string(status)));
		WAUTH_LEAVE_MUTEX(m_am_tools);
		
		if (status != eap_status_ok)
		{
			WAUTH_ENTER_MUTEX(m_am_tools);
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("calls eapol: eapol_wlan_authentication_c::create_upper_stack(): m_ethernet_core->shutdown(): %s.\n"),
				(m_is_client == true) ? "client": "server"));
			status = m_ethernet_core->shutdown();
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("returns from eapol: eapol_wlan_authentication_c::create_upper_stack(): m_ethernet_core->shutdown(): %s, status = %s.\n"),
				 (m_is_client == true) ? "client": "server",
				 eap_status_string_c::get_status_string(status)));
			WAUTH_LEAVE_MUTEX(m_am_tools);

			delete m_ethernet_core;
			m_ethernet_core = 0;							

			EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Stack creation failed.\n")));			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);	
		}
	}
	else
	{			
		status = eap_status_already_exists;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::add_rogue_ap(
	eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::add_rogue_ap()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::add_rogue_ap()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status(eap_status_ok);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls partner: eapol_wlan_authentication_c::add_rogue_ap(): %s: m_partner->add_rogue_ap()\n"),
		 (m_is_client == true) ? "client": "server"));
	
	status = m_partner->add_rogue_ap(rogue_ap_list);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from partner: eapol_wlan_authentication_c::add_rogue_ap(): %s: m_partner->add_rogue_ap(): status = %s\n"),
		 (m_is_client == true) ? "client": "server",
		 eap_status_string_c::get_status_string(status)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eapol_wlan_authentication_c::get_current_eap_index()
{
	return m_current_eap_index;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eapol_wlan_authentication_c::set_current_eap_index(u32_t eap_index)
{
	m_current_eap_index = eap_index;
}

//--------------------------------------------------

#if defined(USE_TEST_EAPOL_WLAN_AUTHENTICATION)

EAP_FUNC_EXPORT u32_t eapol_wlan_authentication_c::get_wrong_send_packet_index()
{
	return 0ul;
}

#endif //#if defined(USE_TEST_EAPOL_WLAN_AUTHENTICATION)

//--------------------------------------------------

#if defined(USE_TEST_EAPOL_WLAN_AUTHENTICATION)

EAP_FUNC_EXPORT void eapol_wlan_authentication_c::reset_authentication_can_succeed()
{
}

#endif //#if defined(USE_TEST_EAPOL_WLAN_AUTHENTICATION)

//--------------------------------------------------

#if defined(USE_TEST_EAPOL_WLAN_AUTHENTICATION)

EAP_FUNC_EXPORT void eapol_wlan_authentication_c::set_authentication_can_succeed()
{
}

#endif //#if defined(USE_TEST_EAPOL_WLAN_AUTHENTICATION)

//--------------------------------------------------

#if defined(USE_TEST_EAPOL_WLAN_AUTHENTICATION)

EAP_FUNC_EXPORT void eapol_wlan_authentication_c::restore_authentication_can_succeed()
{
}

#endif //#if defined(USE_TEST_EAPOL_WLAN_AUTHENTICATION)

//--------------------------------------------------

#if defined(USE_TEST_EAPOL_WLAN_AUTHENTICATION)

EAP_FUNC_EXPORT void eapol_wlan_authentication_c::set_authentication_must_not_succeed(
	const u32_t /* wrong_packet_index */,
	const u32_t /* packet_index */,
	const void * const /* wrong_packet_stack */)
{
}

#endif //#if defined(USE_TEST_EAPOL_WLAN_AUTHENTICATION)

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::start_WPXM_reassociation(
	const eap_am_network_id_c * const old_receive_network_id, ///< source includes remote address, destination includes local address.
	const eap_am_network_id_c * const new_receive_network_id, ///< source includes remote address, destination includes local address.
	eap_variable_data_c * const send_reassociation_request_ie,
	const eap_variable_data_c * const received_WPA_ie,
	const eap_variable_data_c * const sent_WPA_ie
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("partner calls: eapol_wlan_authentication_c::start_WPXM_reassociation(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	{
		EAP_TRACE_DATA_DEBUG(m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("old_receive_network_id source:"),
			old_receive_network_id->get_source_id()->get_data(),
			old_receive_network_id->get_source_id()->get_data_length()));

		EAP_TRACE_DATA_DEBUG(m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("old_receive_network_id destination:"),
			old_receive_network_id->get_destination_id()->get_data(),
			old_receive_network_id->get_destination_id()->get_data_length()));

		EAP_TRACE_DATA_DEBUG(m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("new_receive_network_id source:"),
			new_receive_network_id->get_source_id()->get_data(),
			new_receive_network_id->get_source_id()->get_data_length()));

		EAP_TRACE_DATA_DEBUG(m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("new_receive_network_id destination:"),
			new_receive_network_id->get_destination_id()->get_data(),
			new_receive_network_id->get_destination_id()->get_data_length()));
	}

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to partner: eapol_wlan_authentication_c::start_WPXM_reassociation()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status = cancel_all_authentication_sessions();
	if (status != eap_status_ok)
	{
		(void) EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c reassociation_PMKID(m_am_tools);

	WAUTH_ENTER_MUTEX(m_am_tools);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls eapol: eapol_wlan_authentication_c::start_reassociation(): m_ethernet_core->read_reassociation_parameters(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	status = m_ethernet_core->read_reassociation_parameters(
		old_receive_network_id,
		new_receive_network_id,
		m_authentication_type,
		&reassociation_PMKID,
		received_WPA_ie,
		sent_WPA_ie);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from eapol: eapol_wlan_authentication_c::start_reassociation(): m_ethernet_core->read_reassociation_parameters(): %s, status = %s.\n"),
		(m_is_client == true) ? "client": "server",
		eap_status_string_c::get_status_string(status)));
	WAUTH_LEAVE_MUTEX(m_am_tools);

	if (status == eap_status_ok)
	{
		WAUTH_ENTER_MUTEX(m_am_tools);
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls eapol: eapol_wlan_authentication_c::start_WPXM_reassociation(): m_ethernet_core->start_WPXM_reassociation(): %s.\n"),
			(m_is_client == true) ? "client": "server"));

		status = m_ethernet_core->start_WPXM_reassociation(
			new_receive_network_id,
			m_authentication_type,
			send_reassociation_request_ie);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("returns from eapol: eapol_wlan_authentication_c::start_WPXM_reassociation(): m_ethernet_core->start_WPXM_reassociation(): %s, status = %s.\n"),
			 (m_is_client == true) ? "client": "server",
			 eap_status_string_c::get_status_string(status)));
		WAUTH_LEAVE_MUTEX(m_am_tools);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::complete_WPXM_reassociation(
	const eapol_wlan_authentication_state_e reassociation_result,
	const eap_am_network_id_c * const receive_network_id,
	const eap_variable_data_c * const received_reassociation_ie
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("partner calls: eapol_wlan_authentication_c::complete_WPXM_reassociation(): %s, reassociation_result=%d\n"),
		(m_is_client == true) ? "client": "server",
		reassociation_result));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to partner: eapol_wlan_authentication_c::complete_WPXM_reassociation()");

	eap_status_e status(eap_status_process_general_error);

	if (reassociation_result != eapol_wlan_authentication_state_association_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("complete_WPXM_reassociation: Unsuccessful.\n")));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("complete_WPXM_reassociation: Successful.\n")));

		WAUTH_ENTER_MUTEX(m_am_tools);
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls eapol: eapol_wlan_authentication_c::complete_WPXM_reassociation(): m_ethernet_core->complete_WPXM_reassociation(): %s.\n"),
			(m_is_client == true) ? "client": "server"));
		status = m_ethernet_core->complete_WPXM_reassociation(
			reassociation_result,
			receive_network_id,
			m_authentication_type,
			received_reassociation_ie);
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("returns from eapol: eapol_wlan_authentication_c::complete_WPXM_reassociation(): m_ethernet_core->complete_WPXM_reassociation(): %s, status = %s.\n"),
			 (m_is_client == true) ? "client": "server",
			 eap_status_string_c::get_status_string(status)));
		WAUTH_LEAVE_MUTEX(m_am_tools);

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::save_simple_config_session(
	const simple_config_state_e state,
	EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
	const eap_variable_data_c * const new_password,
	const simple_config_Device_Password_ID_e Device_Password_ID,
	const simple_config_payloads_c * const other_configuration)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::save_simple_config_session(): %s\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::save_simple_config_session()");

	for (u32_t ind = 0ul; ind < credential_array->get_object_count(); ind++)
	{
		simple_config_credential_c * const credential = credential_array->get_object(ind);

		if (credential != 0
			&& credential->get_is_valid() == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("SIMPLE_CONFIG: network_index=%d\n"),
				credential->get_network_index()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("SIMPLE_CONFIG: SSID"),
				credential->get_SSID()->get_data(),
				credential->get_SSID()->get_data_length()));

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("SIMPLE_CONFIG: Authentication_Type=%d\n"),
				credential->get_Authentication_Type()));

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("SIMPLE_CONFIG: Encryption_Type=%d\n"),
				credential->get_Encryption_Type()));

			for (u32_t ind = 0ul; ind < credential->get_network_keys()->get_object_count(); ++ind)
			{
				network_key_and_index_c * const key = credential->get_network_keys()->get_object(ind);
				if (key != 0)
				{

					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("SIMPLE_CONFIG: network_key_index=%d\n"),
						key->get_network_key_index()));

					EAP_TRACE_DATA_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("SIMPLE_CONFIG: Key"),
						key->get_network_key()->get_data(),
						key->get_network_key()->get_data_length()));
				}
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("SIMPLE_CONFIG: MAC_address"),
				credential->get_MAC_address()->get_data(),
				credential->get_MAC_address()->get_data_length()));
		}
	}

	if (new_password != 0)
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("SIMPLE_CONFIG: new_password"),
			new_password->get_data(),
			new_password->get_data_length()));
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: Device_Password_ID=%d\n"),
		Device_Password_ID));

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls partner: eapol_wlan_authentication_c::save_simple_config_session(): %s: m_partner->save_simple_config_session()\n"),
		 (m_is_client == true) ? "client": "server"));
	
	eap_status_e status = m_partner->save_simple_config_session(
		state,
		credential_array,
		new_password,
		Device_Password_ID,
		other_configuration);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from partner: eapol_wlan_authentication_c::save_simple_config_session(): %s: m_partner->save_simple_config_session(): status = %s\n"),
		 (m_is_client == true) ? "client": "server",
		 eap_status_string_c::get_status_string(status)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

eap_status_e eapol_wlan_authentication_c::complete_check_pmksa_cache(
	EAP_TEMPLATE_CONST eap_array_c<eap_am_network_id_c> * const bssid_sta_receive_network_ids)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls partner: eapol_wlan_authentication_c::complete_check_pmksa_cache(): %s: m_partner->complete_check_pmksa_cache().\n"),
		(m_is_client == true) ? "client": "server"));

	const eap_status_e status = m_partner->complete_check_pmksa_cache(
		bssid_sta_receive_network_ids);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from partner: eapol_wlan_authentication_c::complete_check_pmksa_cache(): %s: m_partner->complete_check_pmksa_cache(): status = %s\n"),
		 (m_is_client == true) ? "client": "server",
		 eap_status_string_c::get_status_string(status)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::complete_get_802_11_authentication_mode(
		const eap_status_e completion_status,
		const eap_am_network_id_c * const /* receive_network_id */,
		const eapol_key_802_11_authentication_mode_e mode)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eapol_wlan_authentication_c::complete_get_802_11_authentication_mode(): completion_status=%d=%s, mode=%d\n"),
		completion_status,
		eap_status_string_c::get_status_string(completion_status),
		mode));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::complete_get_802_11_authentication_mode()");

	eap_status_e status(eap_status_ok);

	if (completion_status != eap_status_ok
		|| mode == eapol_key_802_11_authentication_mode_none)
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
			(EAPL("No enabled EAP types.\n")));
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
			(EAPL("Indication sent to WLM: eap_status_failed_completely.\n")));

		(void) internal_disassociation(false, 0); // Note we have no addresses yet.

		status = eapol_indication(
			0, // Note we have no addresses yet.
			eapol_wlan_authentication_state_failed_completely);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	m_802_11_authentication_mode = mode;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls partner: eapol_wlan_authentication_c::complete_get_802_11_authentication_mode(): m_partner->associate(%d).\n"),
		m_802_11_authentication_mode));

	status = m_partner->associate(m_802_11_authentication_mode);
	(void)EAP_STATUS_RETURN(m_am_tools, status);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from partner: eapol_wlan_authentication_c::complete_get_802_11_authentication_mode(): %s: m_partner->associate(): status = %s\n"),
		 (m_is_client == true) ? "client": "server",
		 eap_status_string_c::get_status_string(status)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_wlan_authentication_c::complete_disassociation(
	const bool complete_to_lower_layer,
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol calls: eapol_wlan_authentication_c::complete_disassociation(): %s: m_partner->complete_disassociation(), complete_to_lower_layer=%s.\n"),
		 (m_is_client == true) ? "client": "server",
		 (complete_to_lower_layer == true) ? "true": "false"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eapol: eapol_wlan_authentication_c::complete_disassociation()");

	eap_status_e status(eap_status_ok);

	if (complete_to_lower_layer == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls partner: eapol_wlan_authentication_c::complete_disassociation(): %s: m_partner->complete_disassociation(), complete_to_lower_layer=%s.\n"),
			 (m_is_client == true) ? "client": "server",
			 (complete_to_lower_layer == true) ? "true": "false"));

		status = m_partner->complete_disassociation(
			receive_network_id);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("returns from partner: eapol_wlan_authentication_c::complete_disassociation(): %s: m_partner->complete_disassociation(): status = %s\n"),
			 (m_is_client == true) ? "client": "server",
			 eap_status_string_c::get_status_string(status)));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------
// End of file
