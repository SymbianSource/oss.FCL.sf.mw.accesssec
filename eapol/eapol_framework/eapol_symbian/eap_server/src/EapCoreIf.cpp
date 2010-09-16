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
* Description:  EAP and WLAN authentication protocols.
*
*/

/*
* %version: 18 %
*/


#include "eap_am_tools.h"
#include "eap_am_export.h"
#include "EapCoreIf.h"
#include "eap_automatic_variable.h"
#include "eap_config.h"
#include "eap_file_config.h"
#include "abs_eap_am_mutex.h"
#include "EapServerClientDef.h"

/** @file */

//--------------------------------------------------

/**
 * This is the timer ID used with abs_eap_am_tools_c::set_timer() and abs_eap_am_tools_c::cancel_timer().
 */
enum eap_am_core_message_if_timer_id
{
    EAP_AM_CORE_MESSAGE_IF_TIMER_PROCESS_DATA_ID,
    EAP_AM_CORE_MESSAGE_IF_TIMER_SEND_DATA_ID,
};

//--------------------------------------------------

CEapCoreIf::CEapCoreIf(
    abs_eap_am_tools_c * const tools,
    eap_am_message_if_c * const server,
    AbsEapSendInterface * client)
    : m_am_tools(tools)
    , m_client_if(client)
    , m_server_if(server)
    , m_fileconfig(0)
    , m_use_asyncronous_test(false)
    , iIsValid(false)
{
	if (m_am_tools == 0 || m_am_tools->get_is_valid() == false)
	{
		return;
	}

	if (m_client_if == 0)
	{
		return;
	}

	if (m_server_if == 0 || m_server_if->get_is_valid() == false)
	{
		return;
	}

	iIsValid = true;
}

//--------------------------------------------------

CEapCoreIf::~CEapCoreIf()
{
	if (m_server_if != 0)
	{
		m_server_if->shutdown();
	}
    delete m_server_if;
    m_server_if = 0;

    delete m_fileconfig;
    m_fileconfig = 0;
}

//--------------------------------------------------

bool CEapCoreIf::get_is_valid()
{
    return iIsValid;
}

//--------------------------------------------------

eap_status_e CEapCoreIf::configure(
	const eap_variable_data_c * const client_configuration)
{
	return EAP_STATUS_RETURN(m_am_tools, m_server_if->configure(client_configuration));
}

// ----------------------------------------------------------------

eap_status_e CEapCoreIf::send_data(const void * const data, const u32_t length)
{
	return EAP_STATUS_RETURN(m_am_tools, m_client_if->SendData(data, length, EEapCoreSendData));
}

// ----------------------------------------------------------------

eap_status_e CEapCoreIf::process_data(const void * const data, const u32_t length)
{
	return EAP_STATUS_RETURN(m_am_tools, m_server_if->process_data(data, length));
}

//--------------------------------------------------

//
eap_status_e CEapCoreIf::shutdown()
{
    EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

    EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

    EAP_TRACE_DEBUG(
        m_am_tools, 
        EAP_TRACE_FLAGS_MESSAGE_DATA, 
        (EAPL("CEapCoreIf::shutdown(): this = 0x%08x.\n"),
        this));

    eap_status_e status(eap_status_process_general_error);

    if (m_server_if != 0)
    {
        m_server_if->shutdown();
    }

    EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
    return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

CEapCoreIf* CEapCoreIf::new_CEapCoreIf(
    abs_eap_am_tools_c * const tools,
    const bool is_client_when_true,
    const u32_t MTU,
    AbsEapSendInterface * client)
{
	eap_am_message_if_c *server =  eap_am_message_if_c::new_eap_am_server_message_if_c(
		tools,
		is_client_when_true,
		MTU);

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
				(EAPL("calls: CEapCoreIf(): server->shutdown(): %s.\n"),
				(is_client_when_true == true) ? "client": "server"));

			server->shutdown();
		}

		return 0;
	}

	CEapCoreIf * core_if = new CEapCoreIf(
		tools,
		server,
		client);

	eap_automatic_variable_c<CEapCoreIf> automatic_core_if(
		tools,
		core_if);

	if (core_if == 0
		|| core_if->get_is_valid() == false)
	{
		// ERROR.
		if (core_if != 0)
		{
			EAP_TRACE_DEBUG(
				tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("calls: CEapCoreIf(): core_if->shutdown(): %s.\n"),
				(is_client_when_true == true) ? "client": "server"));

			// automatic_core_if will delete core_if and core_if will delete server too.
			automatic_server.do_not_free_variable();
			core_if->shutdown();
		}

		return 0;
	}

	server->set_partner(core_if);

	automatic_server.do_not_free_variable();
	automatic_core_if.do_not_free_variable();

	return core_if;
}

//--------------------------------------------------
// End
