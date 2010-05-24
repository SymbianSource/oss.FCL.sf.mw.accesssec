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
* Description:  EAP-authentication interface in EAP-server.
*
*/

/*
* %version: 12 %
*/


#ifndef EAPCOREIF_H_
#define EAPCOREIF_H_

#include "abs_eap_am_message_if.h"
#include "eap_am_message_if.h"
#include "eap_tools.h"
#include "AbsEapSendInterface.h"

class eap_file_config_c;

//--------------------------------------------------

/** @file */

/// This class is the EAP-authentication interface in EAP-server.
class CEapCoreIf
: public CBase
, public abs_eap_am_message_if_c
{

private:

    // ----------------------------------------------------------------------

    /// This is pointer to the tools class.
    abs_eap_am_tools_c * const m_am_tools;

    // client interface
    AbsEapSendInterface * m_client_if;

    /// CEapCoreIf deletes m_server_if in destructor.
    eap_am_message_if_c * m_server_if;

    eap_file_config_c * m_fileconfig;

    bool m_use_asyncronous_test;
    
    bool iIsValid;

    // ----------------------------------------------------------------------

public:

    // ----------------------------------------------------------------------

    CEapCoreIf(
        abs_eap_am_tools_c * const tools,
        eap_am_message_if_c * const server,
        AbsEapSendInterface * client);

    virtual ~CEapCoreIf();

    bool get_is_valid();

    eap_status_e configure(
		const eap_variable_data_c * const client_configuration);

    eap_status_e send_data(const void * const data, const u32_t length);

    eap_status_e process_data(const void * const data, const u32_t length);

    eap_status_e shutdown();

    // ------------------------------------------------------

    static CEapCoreIf * new_CEapCoreIf(
        abs_eap_am_tools_c * const tools,
        const bool is_client_when_true,
        const u32_t MTU,
        AbsEapSendInterface * client);

    // ----------------------------------------------------------------------
};

#endif /* EAPCOREIF_H_ */
