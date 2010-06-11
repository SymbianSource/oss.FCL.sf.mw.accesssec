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
* Description:  interface to PAC-store.
*
*/

/*
* %version: 8 %
*/

#if !defined(_EAP_AM_PAC_STORE_SYMBIAN_H_)
#define _EAP_AM_PAC_STORE_SYMBIAN_H_

#include "eap_tools.h"
#include "eap_status.h"
#include "eap_am_export.h"
#include "eap_expanded_type.h"
#include "eap_array.h"
#include "eap_database_reference_if.h"
#include "eap_am_pac_store.h"
#include "eap_process_tlv_message_data.h"
#include "pac_store_db_symbian.h"
#include <d32dbms.h>

class eap_method_settings_c;
class abs_eap_am_pac_store_c;

/** @file */

/// This class is the interface to PAC-store.
class EAP_EXPORT eap_am_pac_store_symbian_c
: public eap_am_pac_store_c
{

private:

	// ----------------------------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	abs_eap_am_pac_store_c * m_partner;

	bool m_is_valid;

	/// Function shutdown() is called already.
	bool m_shutdown_was_called;

	TBool iClientCreated;
	TBool iPacStoreSessionOpened;
	
	CPacStoreDatabase* iClient;
	
	eap_variable_data_c m_PAC_store_password;

	// ----------------------------------------------------------------------

	// ----------------------------------------------------------------------

public:

	// ----------------------------------------------------------------------

    static eap_am_pac_store_c* new_eap_am_pac_store_symbian_c(
            abs_eap_am_tools_c * const tools,
            abs_eap_am_pac_store_c * const partner);
    
	eap_am_pac_store_symbian_c(
		abs_eap_am_tools_c * const tools,
		abs_eap_am_pac_store_c * const partner);

	virtual ~eap_am_pac_store_symbian_c();

	EAP_FUNC_IMPORT bool get_is_valid();

	// This is documented in abs_eap_stack_interface_c::configure().
	EAP_FUNC_IMPORT	eap_status_e configure();

	// This is documented in abs_eap_stack_interface_c::shutdown().
	EAP_FUNC_IMPORT eap_status_e shutdown();

	EAP_FUNC_IMPORT eap_status_e open_pac_store();

	EAP_FUNC_IMPORT eap_status_e create_device_seed();

	EAP_FUNC_IMPORT eap_status_e is_master_key_present();

	EAP_FUNC_IMPORT eap_status_e is_master_key_and_password_matching(
		const eap_variable_data_c * const pac_store_password);

	EAP_FUNC_IMPORT eap_status_e create_and_save_master_key(
		const eap_variable_data_c * const pac_store_password);

	EAP_FUNC_IMPORT eap_status_e compare_pac_store_password(
		eap_variable_data_c * const pac_store_password);

	EAP_FUNC_IMPORT eap_status_e is_pacstore_password_present();

	EAP_FUNC_IMPORT eap_status_e set_pac_store_password(
		const eap_variable_data_c * pac_store_password);

	EAP_FUNC_IMPORT eap_status_e destroy_pac_store();

	// ----------------------------------------------------------------------
};

#endif //#if !defined(_EAP_AM_PAC_STORE_SYMBIAN_H_)


//--------------------------------------------------
// End
