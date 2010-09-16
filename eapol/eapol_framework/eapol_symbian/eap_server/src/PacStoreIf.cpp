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
* Description:  PAC-store interface inside the EAP-server.
*
*/

/*
* %version: 14 %
*/

#include "eap_am_tools.h"
#include "eap_am_export.h"
#include "PacStoreIf.h"
#include "eap_automatic_variable.h"
#include "eap_config.h"
#include "eap_file_config.h"
#include "abs_eap_am_mutex.h"
#include "eap_pac_store_server_message_if.h"


/** @file */

//--------------------------------------------------

/**
 * This is the timer ID used with abs_eap_am_tools_c::set_timer() and abs_eap_am_tools_c::cancel_timer().
 */
enum pac_store_message_if_timer_id
{
    pac_store_message_IF_TIMER_PROCESS_DATA_ID,
    pac_store_message_IF_TIMER_SEND_DATA_ID,
};

//--------------------------------------------------

EAP_FUNC_EXPORT CPacStoreIf::CPacStoreIf(
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

EAP_FUNC_EXPORT CPacStoreIf::~CPacStoreIf()
{
	if (m_server_if != 0)
	{
		m_server_if->shutdown();
    	delete m_server_if;
    	m_server_if = 0;
	}

    delete m_fileconfig;
    m_fileconfig = 0;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool CPacStoreIf::get_is_valid()
{
    return iIsValid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e CPacStoreIf::configure(
	const eap_variable_data_c * const client_configuration)
{
	return m_server_if->configure(client_configuration);
}

// ----------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e CPacStoreIf::send_data(const void * const data, const u32_t length)
    {
    return m_client_if->SendData(data, length, EEapPacStoreSendData);
    }

// ----------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e CPacStoreIf::process_data(const void * const data, const u32_t length)
    {
    return m_server_if->process_data(data, length);
    }

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e CPacStoreIf::shutdown()
{
    EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

    EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

    EAP_TRACE_DEBUG(
        m_am_tools, 
        EAP_TRACE_FLAGS_MESSAGE_DATA, 
        (EAPL("CPacStoreIf::shutdown(): this = 0x%08x.\n"),
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
//--------------------------------------------------

EAP_FUNC_EXPORT eap_pac_store_server_message_if_c * eap_pac_store_server_message_if_c::new_eap_pac_store_server_message_if_c(
    abs_eap_am_tools_c * const tools)
{
    EAP_TRACE_DEBUG(
        tools,
        TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
        (EAPL("eap_pac_store_server_message_if_c::new_eap_pac_store_server_message_if_c()\n")));

    EAP_TRACE_RETURN_STRING(tools, "returns: eap_pac_store_server_message_if_c::new_eap_pac_store_server_message_if_c()");

#if !defined(EAP_PAC_STORE_DUMMY)

    eap_pac_store_server_message_if_c * const server = new eap_pac_store_server_message_if_c(
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
            (EAPL("calls: CPacStoreIf::CPacStoreIf(): server->shutdown()\n")));

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

    automatic_server.do_not_free_variable();

    return server;

#else

	return 0;

#endif

}

//--------------------------------------------------

EAP_FUNC_EXPORT CPacStoreIf* CPacStoreIf::new_CPacStoreIf(
    abs_eap_am_tools_c * const tools,
    const bool is_client_when_true,
    const u32_t MTU,
    AbsEapSendInterface * client)
    {
    EAP_UNREFERENCED_PARAMETER(is_client_when_true);
    EAP_UNREFERENCED_PARAMETER(MTU);

#if !defined(EAP_PAC_STORE_DUMMY)

    eap_pac_store_server_message_if_c *server =  eap_pac_store_server_message_if_c::new_eap_pac_store_server_message_if_c(
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
                (EAPL("calls: CPacStoreIf(): server->shutdown(): %s.\n"),
                (is_client_when_true == true) ? "client": "server"));

            (void) server->shutdown();
            }
        return 0;
        }

    CPacStoreIf * pacstore_if = new CPacStoreIf(
        tools,
        server,
        client);

    eap_automatic_variable_c<CPacStoreIf> automatic_pacstore_if(
        tools,
        pacstore_if);

    if (pacstore_if == 0
        || pacstore_if->get_is_valid() == false)
        {
        // ERROR.
        if (pacstore_if != 0)
            {
            EAP_TRACE_DEBUG(
                tools,
                TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
                (EAPL("calls: CPacStoreIf(): pacstore_if->shutdown(): %s.\n"),
                (is_client_when_true == true) ? "client": "server"));

			// automatic_pacstore_if will delete pacstore_if and pacstore_if will delete server too.
			automatic_server.do_not_free_variable();

            (void) pacstore_if->shutdown();
            }
        return 0;
        }

    server->set_partner(pacstore_if);

    automatic_server.do_not_free_variable();
    automatic_pacstore_if.do_not_free_variable();
    
    return pacstore_if;

#else

	return 0;

#endif

    }

//--------------------------------------------------
// End
