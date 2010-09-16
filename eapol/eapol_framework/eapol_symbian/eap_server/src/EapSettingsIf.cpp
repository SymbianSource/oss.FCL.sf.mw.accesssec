/*
* Copyright (c) 2009-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  EAP-settings interface in EAP-server.
*
*/

/*
* %version: 19 %
*/


#include "eap_am_tools.h"
#include "eap_am_export.h"
#include "EapSettingsIf.h"
#include "eap_automatic_variable.h"
#include "eap_config.h"
#include "eap_file_config.h"
#include "abs_eap_am_mutex.h"
#include "eap_am_general_settings.h"
#include "eap_am_general_settings_symbian.h"
#include "eap_general_settings_server_message_if.h"
#include "EapServerClientDef.h"

/** @file */

//--------------------------------------------------

CEapSettingsIf::CEapSettingsIf(
	abs_eap_am_tools_c * const tools,
	eap_am_message_if_c * const server)
	: m_am_tools(tools)
	, m_client_if(0)
	, m_server_if(server)
	, m_use_asyncronous_test(false)
	, m_is_valid(false)
{
	if (m_am_tools == 0 || m_am_tools->get_is_valid() == false)
	{
		return;
	}

	if (m_server_if == 0 || m_server_if->get_is_valid() == false)
	{
		return;
	}

	m_is_valid = true;
}

//--------------------------------------------------

CEapSettingsIf::~CEapSettingsIf()
{
	if (m_server_if != 0)
	{
		m_server_if->shutdown();
	}
    delete m_server_if;
    m_server_if = 0;
}

//--------------------------------------------------

bool CEapSettingsIf::get_is_valid()
{
    return m_is_valid;
}

//--------------------------------------------------

eap_status_e CEapSettingsIf::configure(
	const eap_variable_data_c * const client_configuration)
{
	return EAP_STATUS_RETURN(m_am_tools, m_server_if->configure(client_configuration));
}

//--------------------------------------------------

void CEapSettingsIf::set_partner(AbsEapSendInterface * const client)
{
    m_client_if = client;
}

// ----------------------------------------------------------------

eap_status_e CEapSettingsIf::send_data(const void * const data, const u32_t length)
{
	return EAP_STATUS_RETURN(m_am_tools, m_client_if->SendData(data, length, EEapSettingsSendData));
}

// ----------------------------------------------------------------

eap_status_e CEapSettingsIf::process_data(const void * const data, const u32_t length)
{
	return EAP_STATUS_RETURN(m_am_tools, m_server_if->process_data(data, length));
}

//--------------------------------------------------

//
eap_status_e CEapSettingsIf::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("CEapSettingsIf::shutdown(): this = 0x%08x.\n"),
		this));

	eap_status_e status(eap_status_ok);

	if (m_server_if != 0)
	{
		status = m_server_if->shutdown();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_am_general_settings_c * new_eap_am_general_settings_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_am_general_settings_c * const partner)
{
	eap_am_general_settings_c * const plugin = new eap_am_general_settings_symbian_c(tools, partner);

	// This will delete the plugin memory automatically.
	eap_automatic_variable_c<eap_am_general_settings_c> automatic_plugin(
		tools,
		plugin);

	if (plugin == 0
	|| plugin->get_is_valid() == false)
	{
		// ERROR.
		if (plugin != 0)
		{
			EAP_TRACE_DEBUG(
			tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls: new_eap_am_general_settings_c(): plugin->shutdown()\n")));

			(void) plugin->shutdown();
		}
		return 0;
	}

	eap_status_e status = plugin->configure();
	if (status != eap_status_ok)
	{
		(void) plugin->shutdown();
		return 0;
	}

	// This will prevent automatic deletion of the plugin memory.
	automatic_plugin.do_not_free_variable();

	return plugin;
}

//--------------------------------------------------

eap_am_message_if_c * eap_am_message_if_c::new_eap_general_settings_server_message_if_c(
	abs_eap_am_tools_c * const tools)
{
	eap_am_message_if_c * const server = new eap_general_settings_server_message_if_c(
		tools);

	// This will delete the server memory automatically.
	eap_automatic_variable_c<eap_am_message_if_c> automatic_server(
		tools,
		server);

	if (server == 0
	|| server->get_is_valid() == false)
	{
		// ERROR.
		if (server != 0)
		{
			EAP_TRACE_DEBUG(
			tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls: eap_am_message_if_c::new_eap_general_settings_server_message_if_c(): server->shutdown()\n")));

			(void) server->shutdown();
		}
		return 0;
	}

	eap_status_e status = server->configure(0);
	if (status != eap_status_ok)
	{
		(void) server->shutdown();
		return 0;
	}

	// This will prevent automatic deletion of the server memory.
	automatic_server.do_not_free_variable();

	return server;
}

//--------------------------------------------------

CEapSettingsIf* CEapSettingsIf::new_CEapSettingsIf(
    abs_eap_am_tools_c * const tools)
{
	eap_am_message_if_c * const server = eap_am_message_if_c::new_eap_general_settings_server_message_if_c(
		tools);

	// This will delete the server memory automatically.
	eap_automatic_variable_c<eap_am_message_if_c> automatic_server(
		tools,
		server);

	if (server == 0
	|| server->get_is_valid() == false)
	{
		// ERROR.
		if (server != 0)
		{
			EAP_TRACE_DEBUG(
			tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls: CEapSettingsIf::new_CEapPluginIf(): server->shutdown()\n")));

			(void) server->shutdown();
		}
		return 0;
	}

	CEapSettingsIf * const settings_if = new CEapSettingsIf(
		tools,
		server);

	// This will delete the settings_if memory automatically.
	eap_automatic_variable_c<CEapSettingsIf> automatic_settings_if(
		tools,
		settings_if);

	if (settings_if == 0
	|| settings_if->get_is_valid() == false)
	{
		// ERROR.
		if (settings_if != 0)
		{
			EAP_TRACE_DEBUG(
			tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls: CEapSettingsIf::new_CEapPluginIf(): settings_if->shutdown()\n")));

			// This will prevent automatic deletion of the server memory.
			// automatic_settings_if will delete settings_if and server too.
			automatic_server.do_not_free_variable();

			(void) settings_if->shutdown();
		}
		return 0;
	}

	server->set_partner(settings_if);

	// This will prevent automatic deletion of the server memory.
	automatic_server.do_not_free_variable();
	// This will prevent automatic deletion of the settings_if memory.
	automatic_settings_if.do_not_free_variable();

	return settings_if;
}

//--------------------------------------------------
// End
