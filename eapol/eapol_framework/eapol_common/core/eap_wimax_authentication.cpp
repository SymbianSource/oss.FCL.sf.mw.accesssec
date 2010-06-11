/*
* Copyright (c) 2007 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  EAP stack interface for Wimax.
*
*/

/*
* %version: %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 1001 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES
#include <eap_am_memory.h>

#include <eap_am_tools.h>
#include <eap_variable_data.h>
#include <eap_tools.h>
#include "eap_type_all.h"

#include "eap_wimax_authentication.h"
#include "eap_session_core.h"
#include <eap_header_string.h>
#include <eap_rogue_ap_entry.h>
#include <abs_eap_state_notification.h>
#include <eap_config.h>
#include <eap_buffer.h>
#include <eap_state_notification.h>
#include "eap_automatic_variable.h"
#include <eap_am_network_id.h>

#include <eap_master_session_key.h>
#include <abs_eap_am_mutex.h>


#if defined(USE_EAP_WIMAX_AUTHENTICATION_MUTEX)

	#if defined(USE_TEST_WIMAX_AUTHENTICATION_MUTEX)
		#error "You cannot define both USE_EAP_WIMAX_AUTHENTICATION_MUTEX and USE_TEST_WIMAX_AUTHENTICATION_MUTEX."
	#endif

	#define WAUTH_ENTER_MUTEX(tools) { tools->enter_global_mutex(); }

	#define WAUTH_LEAVE_MUTEX(tools) { tools->leave_global_mutex(); }

#else

	#define WAUTH_ENTER_MUTEX(tools)

	#define WAUTH_LEAVE_MUTEX(tools)

#endif //#if defined(USE_EAP_WIMAX_AUTHENTICATION_MUTEX)



// ================= MEMBER FUNCTIONS =======================

EAP_FUNC_EXPORT eap_wimax_authentication_c::~eap_wimax_authentication_c()
{
  EAP_TRACE_DEBUG
    (m_am_tools,
     TRACE_FLAGS_DEFAULT, 
     (EAPL("partner calls: eap_wimax_authentication_c::~eap_wimax_authentication_c(): this = 0x%08x\n"),
      this));
  
  EAP_TRACE_RETURN_STRING(m_am_tools, "returns to partner: eap_wimax_authentication_c::~eap_wimax_authentication_c()\n");
  
  EAP_ASSERT(m_shutdown_was_called == true);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_wimax_authentication_c::eap_wimax_authentication_c
(abs_eap_am_tools_c* const tools, 
 abs_eap_wimax_authentication_c* const partner,
 // eap_wimax_authentication_c must always delete the am_wauth object
 eap_am_wimax_authentication_c* const am_wauth,
 const bool is_client_when_true)
  : m_am_tools(tools), 
    m_partner(partner),
    m_am_wauth(am_wauth),
    m_eap_core(0), // created in configure
    m_is_valid(false),
    m_is_client(is_client_when_true),
    m_shutdown_was_called(false),
    m_block_state_notifications(false)    
{
  EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
  
  EAP_TRACE_DEBUG
    (m_am_tools, 
     TRACE_FLAGS_DEFAULT, 
     (EAPL("starts: eap_wimax_authentication_c::eap_wimax_authentication_c(): %s, this = 0x%08x.\n"),
      (m_is_client == true) ? "client": "server",
      this));
  
  EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_wimax_authentication_c::eap_wimax_authentication_c()\n");
  
  if (m_am_wauth == 0
      || m_am_wauth->get_is_valid() == false)
    {
      // ERROR.
      if (m_am_wauth != 0)
	{
	  EAP_TRACE_DEBUG
	    (m_am_tools,
	     TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
	     (EAPL("calls: eap_wimax_authentication_c::eap_wimax_authentication_c(): m_am_wauth->shutdown(): %s.\n"),
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
	  EAP_TRACE_DEBUG
	    (m_am_tools,
	     TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
	     (EAPL("calls: eap_wimax_authentication_c::eap_wimax_authentication_c(): m_am_wauth->shutdown(): %s.\n"),
	      (is_client_when_true == true) ? "client": "server"));
	  
	  m_am_wauth->shutdown();
	  delete am_wauth;
	}
      return;
    }
  
  m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_wimax_authentication_c* eap_wimax_authentication_c::new_eap_wimax_authentication_c
(abs_eap_am_tools_c* const tools,
 abs_eap_wimax_authentication_c* const partner,
 const bool is_client_when_true)
{
  EAP_TRACE_DEBUG
    (tools, 
     TRACE_FLAGS_DEFAULT, 
     (EAPL("partner calls: eap_wimax_authentication_c::new_eap_wimax_authentication_c()\n")));

  EAP_TRACE_RETURN_STRING(tools, "returns to partner: eap_wimax_authentication_c::new_eap_wimax_authentication_c()\n");

  eap_am_wimax_authentication_c* m_am_wauth = eap_am_wimax_authentication_c::new_eap_am_wimax_authentication
    (tools,
     is_client_when_true,
     wimax_database_reference);

  if (m_am_wauth == 0
      || m_am_wauth->get_is_valid() == false)
    {
      // ERROR.
      if (m_am_wauth != 0)
	{
	  EAP_TRACE_DEBUG
	    (tools,
	     TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
	     (EAPL("calls: eap_wimax_authentication_c::new_eap_wimax_authentication_c(): m_am_wauth->shutdown(): %s.\n"),
	      (is_client_when_true == true) ? "client": "server"));
	  
	  m_am_wauth->shutdown();
	  delete m_am_wauth;
	  m_am_wauth = 0;
	}
      return 0;
    }

  eap_wimax_authentication_c* wauth = new eap_wimax_authentication_c(tools, partner, m_am_wauth, is_client_when_true);
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
  
  EAP_TRACE_DEBUG
    (tools,
     TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
     (EAPL("calls: eap_wimax_authentication_c::new_eap_wimax_authentication_c(): m_am_wauth->set_am_partner(): %s.\n"),
      (is_client_when_true == true) ? "client": "server"));
  
  m_am_wauth->set_am_partner(wauth);
  
  return wauth;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::shutdown()
{
  EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
  
  EAP_TRACE_DEBUG
    (m_am_tools,
     TRACE_FLAGS_DEFAULT,
     (EAPL("partner calls: eap_wimax_authentication_c::shutdown(); %s, m_shutdown_was_called=%d\n"),
      (m_is_client == true) ? "client": "server",
      m_shutdown_was_called));

  EAP_TRACE_RETURN_STRING(m_am_tools, "returns to partner: eap_wimax_authentication_c::shutdown()\n");

  if (m_shutdown_was_called == true)
    {
      // Shutdown was already called once.
      return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
    }

  m_shutdown_was_called = true;
	
  // Cancel timers	
  cancel_all_timers();

  // Delete upper stack if it still exists
  if (m_eap_core != 0)
    {
      WAUTH_ENTER_MUTEX(m_am_tools);
      
      EAP_TRACE_DEBUG
	(m_am_tools,
	 TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
	 (EAPL("calls eap: eap_wimax_authentication_c::shutdown(): m_eap_core->shutdown(): %s.\n"),
	  (m_is_client == true) ? "client": "server"));
      
      eap_status_e status = m_eap_core->shutdown();

      EAP_TRACE_DEBUG
	(m_am_tools,
	 TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
	 (EAPL("returns from eap: eap_wimax_authentication_c::shutdown(): m_eap_core->shutdown(): %s, status = %s.\n"),
	  (m_is_client == true) ? "client": "server",
	  eap_status_string_c::get_status_string(status)));
      
      EAP_UNREFERENCED_PARAMETER(status); // in release
      
      WAUTH_LEAVE_MUTEX(m_am_tools);
      
      delete m_eap_core;
      m_eap_core = 0;
    }
	
  if (m_am_wauth != 0)
    {
      EAP_TRACE_DEBUG
		(m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eap_wimax_authentication_c::shutdown(): m_am_wauth->shutdown(): %s.\n"),
		(m_is_client == true) ? "client": "server"));
      
      m_am_wauth->shutdown();
      delete m_am_wauth;
      m_am_wauth = 0;
    }
  
  EAP_TRACE_DEBUG
    (m_am_tools,
	TRACE_FLAGS_DEFAULT,
    (EAPL("WAUTH EXITING.\n")));
  
  EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
  return eap_status_ok;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::cancel_all_authentication_sessions()
{
  EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
  
  EAP_TRACE_DEBUG
    (m_am_tools, 
     TRACE_FLAGS_DEFAULT, 
     (EAPL("eap_wimax_authentication_c::cancel_all_authentication_sessions(): this = 0x%08x.\n"),
      this));
  
  eap_status_e status(eap_status_ok);
  
  bool previous_block = m_block_state_notifications;
  m_block_state_notifications = true;
  
  if (m_eap_core != 0)
    {

      WAUTH_ENTER_MUTEX(m_am_tools);

      EAP_TRACE_DEBUG
		(m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls eap: eap_wimax_authentication_c:cancel_all_authentication_sessions(): m_eap_core->cancel_all_eap_sessions(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

      status = m_eap_core->cancel_all_eap_sessions();

      EAP_TRACE_DEBUG
		(m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from eap: eap_wimax_authentication_c:cancel_all_authentication_sessions(): m_eap_core->cancel_all_eap_sessions(): %s, status = %s.\n"),
		(m_is_client == true) ? "client": "server",
		eap_status_string_c::get_status_string(status)));

      WAUTH_LEAVE_MUTEX(m_am_tools); 
    }
  
  m_block_state_notifications = previous_block;
  
  EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
  return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_wimax_authentication_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_wimax_authentication_c::get_is_client()
{
	return m_is_client;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::packet_data_crypto_keys(
	const eap_am_network_id_c * const send_network_id,
	const eap_master_session_key_c * const master_session_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eap_wimax_authentication_c::packet_data_crypto_keys()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	if (master_session_key->get_is_valid() == true)
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("master session key"),
			 master_session_key->get_data(master_session_key->get_data_length()),
			 master_session_key->get_data_length()));
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls partner: eap_wimax_authentication_c::packet_data_crypto_keys(): %s: m_partner->packet_data_crypto_keys()\n"),
		 (m_is_client == true) ? "client": "server"));

	// Forward the keys to lower layers (defined in abs_eap_wimax_authentication_c)
	status = m_partner->packet_data_crypto_keys(send_network_id, master_session_key);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from partner: eap_wimax_authentication_c::packet_data_crypto_keys(): %s: m_partner->packet_data_crypto_keys(): status = %s\n"),
		 (m_is_client == true) ? "client": "server",
		 eap_status_string_c::get_status_string(status)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::packet_send(
	const eap_am_network_id_c * const network_id,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const u32_t buffer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eap_wimax_authentication_c::packet_send(data_length=%d): %s.\n"),
		data_length,
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eap: eap_wimax_authentication_c::packet_send()\n");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status(eap_status_ok);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls partner: eap_wimax_authentication_c::packet_send(): %s: m_partner->packet_send()\n"),
		 (m_is_client == true) ? "client": "server"));

	// Here we send the original packet.
	status = m_partner->packet_send(
		network_id,
		sent_packet,
		header_offset,
		data_length,
		buffer_length);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from partner: eap_wimax_authentication_c::packet_send(): %s: m_partner->packet_send(): status = %s\n"),
		 (m_is_client == true) ? "client": "server",
		 eap_status_string_c::get_status_string(status)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_wimax_authentication_c::get_header_offset(
	u32_t * const MTU, 
	u32_t * const trailer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eap_wimax_authentication_c::get_header_offset()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eap: eap_wimax_authentication_c::get_header_offset()\n");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls partner: eap_wimax_authentication_c::get_header_offset(): %s: m_partner->get_header_offset()\n"),
		 (m_is_client == true) ? "client": "server"));
	
	// we ask these from the partner in case it wants to leave some 
	// room for adding something (e.g. Ethernet header)
	const u32_t offset = m_partner->get_header_offset(MTU, trailer_length);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from partner: eap_wimax_authentication_c::get_header_offset(): %s: m_partner->get_header_offset(): offset = %d\n"),
		 (m_is_client == true) ? "client": "server",
		 offset));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return offset;

}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::load_module(
	const eap_type_value_e type,
	const eap_type_value_e tunneling_type,
	abs_eap_base_type_c * const partner,
	eap_base_type_c ** const eap_type,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id)
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eap_wimax_authentication_c::load_module(type 0x%08x=%s, tunneling_type 0x%08x=%s)\n"),
		convert_eap_type_to_u32_t(type),
		eap_header_string_c::get_eap_type_string(type),
		convert_eap_type_to_u32_t(tunneling_type),
		eap_header_string_c::get_eap_type_string(tunneling_type)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eap: eap_wimax_authentication_c::load_module()\n");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eap_wimax_authentication_c::load_module(): m_am_wauth->load_module(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	eap_status_e status = m_am_wauth->load_module(
		type,
		tunneling_type,
		partner,
		eap_type,
		is_client_when_true,
		receive_network_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::unload_module(const eap_type_value_e eap_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap calls: eap_wimax_authentication_c::unload_module(type 0x%08x=%s): \n"),
		convert_eap_type_to_u32_t(eap_type),
		eap_header_string_c::get_eap_type_string(eap_type)
		));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eap: eap_wimax_authentication_c::unload_module()\n");

	eap_status_e status(eap_status_type_does_not_exists_error);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eap_wimax_authentication_c::unload_module(): m_am_wauth->unload_module(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	status = m_am_wauth->unload_module(eap_type);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::restart_authentication(
	const eap_am_network_id_c * const receive_network_id,
	const bool is_client_when_true,
	const bool force_clean_restart,
	const bool from_timer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_not_supported);

#if defined(USE_EAP_CORE_SERVER)
	if(is_client_when_true == false)
	{
		// only the server can start authentication
		status = m_eap_core->send_eap_identity_request(receive_network_id);
	}
#endif

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eap_wimax_authentication_c::read_configure(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eap: eap_wimax_authentication_c::read_configure()\n");

	EAP_ASSERT_ALWAYS(data != 0);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eap_wimax_authentication_c::read_configure(): m_am_wauth->read_configure(): %s.\n"),
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

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::write_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: eap_wimax_authentication_c::write_configure(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eap: eap_wimax_authentication_c::write_configure()\n");

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eap_wimax_authentication_c::write_configure(): m_am_wauth->write_configure(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	eap_status_e status = m_am_wauth->write_configure(field, data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_wimax_authentication_c::state_notification(
	const abs_eap_state_notification_c * const state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap calls: eap_wimax_authentication_c::state_notification()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eap: eap_wimax_authentication_c::state_notification()\n");

	// Calls lower layer.
	m_partner->state_notification(state);

	// AM could have to show some notification to user.
	m_am_wauth->state_notification(state);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::asynchronous_init_remove_eap_session(
		const eap_am_network_id_c * const send_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	// not supported
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::set_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id, 
		void * const data,
		const u32_t time_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap calls: eap_wimax_authentication_c::set_timer(): id = %d, data = 0x%08x, time = %d\n"),
		id,
		data,
		time_ms));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eap: eap_wimax_authentication_c::set_timer()\n");

	const eap_status_e status = m_am_tools->am_set_timer(
		initializer, 
		id, 
		data,
		time_ms);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::cancel_timer(
		abs_eap_base_timer_c * const initializer, 
		const u32_t id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap calls: eap_wimax_authentication_c::cancel_timer(): initializer = 0x%08x, id = %d\n"),
		initializer,
		id));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eap: eap_wimax_authentication_c::cancel_timer()\n");

	const eap_status_e status = m_am_tools->am_cancel_timer(
		initializer, 
		id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::cancel_all_timers()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap calls: eap_wimax_authentication_c::cancel_all_timers()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eap: eap_wimax_authentication_c::cancel_all_timers()\n");

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

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::check_is_valid_eap_type(
	const eap_type_value_e eap_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap calls: eap_wimax_authentication_c::check_is_valid_eap_type()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eap: eap_wimax_authentication_c::check_is_valid_eap_type()\n");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eap_wimax_authentication_c::check_is_valid_eap_type(): m_am_wauth->check_is_valid_eap_type(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	eap_status_e status = m_am_wauth->check_is_valid_eap_type(eap_type);
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::get_eap_type_list(
		eap_array_c<eap_type_value_e> * const eap_type_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap calls: eap_wimax_authentication_c::get_eap_type_list()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eap: eap_wimax_authentication_c::get_eap_type_list()\n");

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eap_wimax_authentication_c::get_eap_type_list(): m_am_wauth->get_eap_type_list(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	eap_status_e status = m_am_wauth->get_eap_type_list(eap_type_list);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::add_rogue_ap(
	eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	// not used in Wimax
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::set_session_timeout(
		const u32_t /* session_timeout_ms */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	// not supported
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::packet_process(
	const eap_am_network_id_c * const receive_network_id,
	eap_general_header_base_c * const packet_data,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("partner calls: eap_wimax_authentication_c::packet_process(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	if (packet_data == 0
		|| packet_length < eap_header_base_c::get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_header_wr_c eap(
		m_am_tools,
		packet_data->get_header_buffer(packet_data->get_header_buffer_length()),
		packet_data->get_header_buffer_length());

	if (eap.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (packet_length < eap.get_data_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (m_eap_core == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	
	// Forward the packet to the EAP layer of the EAP stack.
	// Ignore return value. Failure is signalled using state_notification.
	WAUTH_ENTER_MUTEX(m_am_tools);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
		(EAPL("calls eapol: eap_wimax_authentication_c::packet_process(): m_eap_core->packet_process(): %s. %d %d\n"),
		(m_is_client == true) ? "client": "server", eap.get_data_length(), packet_length));

	eap_status_e status = m_eap_core->packet_process(
		receive_network_id,
		&eap,
                packet_length);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("returns from eapol: eap_wimax_authentication_c::packet_process(): m_eap_core->packet_process(): %s, status = %s.\n"),
		(m_is_client == true) ? "client": "server",
		eap_status_string_c::get_status_string(status)));

	EAP_UNREFERENCED_PARAMETER(status); // in release

	WAUTH_LEAVE_MUTEX(m_am_tools);

	EAP_GENERAL_HEADER_COPY_ERROR_PARAMETERS(packet_data, &eap);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::eap_acknowledge(
	const eap_am_network_id_c * const receive_network_id)
{
	// Any Network Protocol packet is accepted as a success indication.
	// This is described in RFC 2284 "PPP Extensible Authentication Protocol (EAP)".

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	if (m_eap_core == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	WAUTH_ENTER_MUTEX(m_am_tools);
	eap_status_e status = m_eap_core->eap_acknowledge(receive_network_id);
	WAUTH_LEAVE_MUTEX(m_am_tools);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return EAP_STATUS_RETURN(m_am_tools, status);
}


EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::configure()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("partner calls: eap_wimax_authentication_c::configure(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to partner: eap_wimax_authentication_c::configure()\n");

	//----------------------------------------------------------

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eap_wimax_authentication_c::configure(): m_am_wauth->configure(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	eap_status_e status = m_am_wauth->configure();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

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

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::set_wimax_parameters(
	eap_variable_data_c* const routing_info,
	eap_variable_data_c* const nai_decoration)
{

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("calls: eap_wimax_authentication_c::set_wimax_parameters(): m_am_wauth->reset_eap_configuration(): %s.\n"),
		(m_is_client == true) ? "client": "server"));

	eap_status_e status = m_am_wauth->reset_eap_configuration();

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_am_wauth->set_wimax_parameters(routing_info, nai_decoration);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_wimax_authentication_c::create_upper_stack()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap calls: eap_wimax_authentication_c::create_upper_stack()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns to eap: eap_wimax_authentication_c::create_upper_stack()\n");

	eap_status_e status(eap_status_ok);

	if (m_eap_core == 0)
	{        
		// we use session always
		m_eap_core = new eap_session_core_c(m_am_tools, this, m_is_client);
		if (m_eap_core == 0
			|| m_eap_core->get_is_valid() != true)
		{
			if (m_eap_core != 0)
			{
				WAUTH_ENTER_MUTEX(m_am_tools);

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("calls eap: eap_wimax_authentication_c::create_upper_stack(): m_eap_core->shutdown(): %s.\n"),
					(m_is_client == true) ? "client": "server"));

				status = m_eap_core->shutdown();

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("returns from eap: eap_wimax_authentication_c::create_upper_stack(): m_eap_core->shutdown(): %s, status = %s.\n"),
					 (m_is_client == true) ? "client": "server",
					 eap_status_string_c::get_status_string(status)));

				WAUTH_LEAVE_MUTEX(m_am_tools);

				delete m_eap_core;
				m_eap_core = 0;							
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
			(EAPL("calls eapol: eap_wimax_authentication_c::create_upper_stack(): m_eap_core->configure(): %s.\n"),
			(m_is_client == true) ? "client": "server"));

		status = m_eap_core->configure();

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("returns from eapol: eap_wimax_authentication_c::create_upper_stack(): m_eap_core->configure(): %s, status = %s.\n"),
			 (m_is_client == true) ? "client": "server",
			 eap_status_string_c::get_status_string(status)));

		WAUTH_LEAVE_MUTEX(m_am_tools);
		
		if (status != eap_status_ok)
		{
			WAUTH_ENTER_MUTEX(m_am_tools);

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("calls eap: eap_wimax_authentication_c::create_upper_stack(): m_eap_core->shutdown(): %s.\n"),
				(m_is_client == true) ? "client": "server"));

			status = m_eap_core->shutdown();

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("returns from eap: eapol_wlan_authentication_c::create_upper_stack(): m_eap_core->shutdown(): %s, status = %s.\n"),
				 (m_is_client == true) ? "client": "server",
				 eap_status_string_c::get_status_string(status)));

			WAUTH_LEAVE_MUTEX(m_am_tools);

			delete m_eap_core;
			m_eap_core = 0;							

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


// End.
