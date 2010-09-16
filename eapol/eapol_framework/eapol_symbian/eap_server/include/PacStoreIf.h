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
* %version: 13 %
*/


#ifndef PACSTOREIF_H_
#define PACSTOREIF_H_

#include "abs_eap_am_message_if.h"
#include "eap_am_message_if.h"
#include "eap_tools.h"
#include "AbsEapSendInterface.h"
//#include "eap_pac_store_server_message_if.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_PACSTOREIF_H)
	#define EAP_CLASS_VISIBILITY_PACSTOREIF_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_PACSTOREIF_H 
	#define EAP_C_FUNC_VISIBILITY_PACSTOREIF_H 
	#define EAP_FUNC_EXPORT_PACSTOREIF_H 
	#define EAP_C_FUNC_EXPORT_PACSTOREIF_H 
#elif defined(EAP_EXPORT_PACSTOREIF_H)
	#define EAP_CLASS_VISIBILITY_PACSTOREIF_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_PACSTOREIF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_PACSTOREIF_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_PACSTOREIF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_PACSTOREIF_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_PACSTOREIF_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_PACSTOREIF_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_PACSTOREIF_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_PACSTOREIF_H 
	#define EAP_C_FUNC_EXPORT_PACSTOREIF_H 
#endif
// End: added by script change_export_macros.sh.


class eap_file_config_c;

//--------------------------------------------------

/** @file */

/// This class is the PAC-store interface inside the EAP-server.
class EAP_CLASS_VISIBILITY_PACSTOREIF_H CPacStoreIf
: public CBase
, public abs_eap_am_message_if_c
{

public:

    // ----------------------------------------------------------------------

    EAP_FUNC_VISIBILITY_PACSTOREIF_H CPacStoreIf(
        abs_eap_am_tools_c * const tools,
        eap_am_message_if_c * const server,
        AbsEapSendInterface * client);

    EAP_FUNC_VISIBILITY_PACSTOREIF_H virtual ~CPacStoreIf();

    EAP_FUNC_VISIBILITY_PACSTOREIF_H bool get_is_valid();

    EAP_FUNC_VISIBILITY_PACSTOREIF_H eap_status_e configure(
		const eap_variable_data_c * const client_configuration);

    EAP_FUNC_VISIBILITY_PACSTOREIF_H eap_status_e send_data(const void * const data, const u32_t length);

    EAP_FUNC_VISIBILITY_PACSTOREIF_H eap_status_e process_data(const void * const data, const u32_t length);

    EAP_FUNC_VISIBILITY_PACSTOREIF_H eap_status_e shutdown();

    // ------------------------------------------------------

    EAP_FUNC_VISIBILITY_PACSTOREIF_H static CPacStoreIf * new_CPacStoreIf(
        abs_eap_am_tools_c * const tools,
        const bool is_client_when_true,
        const u32_t MTU,
        AbsEapSendInterface * client);

    // ----------------------------------------------------------------------

private:

    // ----------------------------------------------------------------------

    /// This is pointer to the tools class.
    abs_eap_am_tools_c * const m_am_tools;

    // client interface
    AbsEapSendInterface * m_client_if;

    /// CPacStoreIf deletes m_server_if in destructor.
    eap_am_message_if_c * m_server_if;

    eap_file_config_c * m_fileconfig;

    bool m_use_asyncronous_test;
    
    bool iIsValid;

    // ----------------------------------------------------------------------

};

#endif /* PACSTOREIF_H_ */
