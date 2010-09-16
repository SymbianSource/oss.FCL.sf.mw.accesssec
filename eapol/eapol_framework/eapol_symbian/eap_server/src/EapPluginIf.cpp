/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  EAP-plugin interface.
*
*/

/*
* %version: 18 %
*/

#include "eap_am_tools.h"
#include "eap_am_export.h"
#include "EapPluginIf.h"
#include "eap_automatic_variable.h"
#include "eap_config.h"
#include "eap_file_config.h"
#include "abs_eap_am_mutex.h"
#include "eap_am_plugin.h"
#include "eap_am_plugin_symbian.h"
#include "eap_plugin_server_message_if.h"

/** @file */

//--------------------------------------------------

CEapPluginIf::CEapPluginIf(
    abs_eap_am_tools_c * const tools,
    eap_am_message_if_c * const server)
    : m_am_tools(tools)
    , m_client_if(0)
    , m_server_if(server)
    , m_use_asyncronous_test(false)
		, m_is_valid(false)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapPluginIf::CEapPluginIf()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapPluginIf::CEapPluginIf()");

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

CEapPluginIf::~CEapPluginIf()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapPluginIf::~CEapPluginIf()\n")));

	if (m_server_if != 0)
	{
		m_server_if->shutdown();
	}
    delete m_server_if;
    m_server_if = 0;
}

//--------------------------------------------------

bool CEapPluginIf::get_is_valid()
{
    return m_is_valid;
}

//--------------------------------------------------

eap_status_e CEapPluginIf::configure(
	const eap_variable_data_c * const client_configuration)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapPluginIf::configure()\n")));

	return EAP_STATUS_RETURN(m_am_tools, m_server_if->configure(client_configuration));
}

//--------------------------------------------------

void CEapPluginIf::set_partner(AbsEapSendInterface * const client)
{
    m_client_if = client;
}

// ----------------------------------------------------------------

eap_status_e CEapPluginIf::send_data(const void * const data, const u32_t length)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapPluginIf::send_data()\n")));

	return EAP_STATUS_RETURN(m_am_tools, m_client_if->SendData(data, length, EEapPluginSendData));
}

// ----------------------------------------------------------------

eap_status_e CEapPluginIf::process_data(const void * const data, const u32_t length)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapPluginIf::process_data()\n")));

	return EAP_STATUS_RETURN(m_am_tools, m_server_if->process_data(data, length));
}

//--------------------------------------------------

//
eap_status_e CEapPluginIf::shutdown()
{
    EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

    EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

    EAP_TRACE_DEBUG(
        m_am_tools, 
        EAP_TRACE_FLAGS_MESSAGE_DATA, 
        (EAPL("CEapPluginIf::shutdown(): this = 0x%08x.\n"),
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

eap_am_plugin_c * new_eap_am_plugin_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_am_plugin_c * const partner)
{
	eap_am_plugin_c * const plugin = new eap_am_plugin_symbian_c(tools, partner);

	eap_automatic_variable_c<eap_am_plugin_c> automatic_plugin(
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
			(EAPL("calls: new_eap_am_plugin_c(): plugin->shutdown()\n")));

			plugin->shutdown();
		}
		return 0;
	}

	eap_status_e status = plugin->configure();
	if (status != eap_status_ok)
	{
		plugin->shutdown();
		return 0;
	}

	automatic_plugin.do_not_free_variable();

	return plugin;
}

//--------------------------------------------------

eap_am_message_if_c * eap_am_message_if_c::new_eap_plugin_server_message_if_c(
	abs_eap_am_tools_c * const tools)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_message_if_c::new_eap_plugin_server_message_if_c()\n")));

	EAP_TRACE_RETURN_STRING(tools, "returns: eap_am_message_if_c::new_eap_plugin_server_message_if_c()");

	eap_am_message_if_c * const server = new eap_plugin_server_message_if_c(
		tools);

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
			(EAPL("calls: CEapPluginIf::new_CEapPluginIf(): server->shutdown()\n")));

			server->shutdown();
		}
		return 0;
	}

	eap_status_e status = server->configure(0);
	if (status != eap_status_ok)
	{
		server->shutdown();
		return 0;
	}

	automatic_server.do_not_free_variable();

	return server;
}

//--------------------------------------------------

CEapPluginIf* CEapPluginIf::new_CEapPluginIf(
    abs_eap_am_tools_c * const tools)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapPluginIf::new_CEapPluginIf()\n")));

	EAP_TRACE_RETURN_STRING(tools, "returns: CEapPluginIf::new_CEapPluginIf()");

	eap_am_message_if_c * const server = eap_am_message_if_c::new_eap_plugin_server_message_if_c(
		tools);

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
				(EAPL("calls: CEapPluginIf::new_CEapPluginIf(): server->shutdown()\n")));

			server->shutdown();
		}

		return 0;
	}

	CEapPluginIf * const plugin_if = new CEapPluginIf(
		tools,
		server);

	eap_automatic_variable_c<CEapPluginIf> automatic_plugin_if(
		tools,
		plugin_if);

	if (plugin_if == 0
	|| plugin_if->get_is_valid() == false)
	{
		// ERROR.
		if (plugin_if != 0)
		{
			EAP_TRACE_DEBUG(
			tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls: CEapPluginIf::new_CEapPluginIf(): plugin_if->shutdown()\n")));

			// automatic_plugin_if will delete plugin_if and plugin_if will delete server too.
			automatic_server.do_not_free_variable();
			plugin_if->shutdown();
		}

		return 0;
	}

	server->set_partner(plugin_if);

	automatic_server.do_not_free_variable();
	automatic_plugin_if.do_not_free_variable();

	return plugin_if;
}

//--------------------------------------------------
// End
