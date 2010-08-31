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
* Description:  EAP-general-settings interface inside the EAP-server.
*
*/

/*
* %version: 10 %
*/

#ifndef _EAP_SETTINGS_IF_H_
#define _EAP_SETTINGS_IF_H_

#include "abs_eap_am_message_if.h"
#include "eap_am_message_if.h"
#include "abs_eap_am_plugin.h"
#include "eap_am_plugin.h"
#include "eap_tools.h"
#include "AbsEapSendInterface.h"

//--------------------------------------------------

/** @file */

/// This class is the EAP-general-settings interface inside the EAP-server.
class CEapSettingsIf
: public CBase
, public abs_eap_am_message_if_c
{

public:

    // ----------------------------------------------------------------------

    CEapSettingsIf(
        abs_eap_am_tools_c * const tools,
        eap_am_message_if_c * const server);

    virtual ~CEapSettingsIf();

    bool get_is_valid();

    eap_status_e configure(
		const eap_variable_data_c * const client_configuration);

    void set_partner(AbsEapSendInterface * const client);

    eap_status_e send_data(const void * const data, const u32_t length);

    eap_status_e process_data(const void * const data, const u32_t length);

    eap_status_e shutdown();

    // ------------------------------------------------------

    static CEapSettingsIf * new_CEapSettingsIf(
        abs_eap_am_tools_c * const tools);

    // ----------------------------------------------------------------------

private:

    // ----------------------------------------------------------------------

    /// This is pointer to the tools class.
    abs_eap_am_tools_c * const m_am_tools;

    // client interface
    AbsEapSendInterface * m_client_if;

    /// CEapSettingsIf deletes m_server_if in destructor.
    eap_am_message_if_c * m_server_if;

    bool m_use_asyncronous_test;

	bool m_is_valid;

    // ----------------------------------------------------------------------

};


#endif /* _EAP_PLUGIN_IF_H_ */
