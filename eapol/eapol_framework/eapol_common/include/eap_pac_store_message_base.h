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
* %version: %
*/

#if !defined(_EAP_PAC_STORE_MESSAGE_BASE_H_)
#define _EAP_PAC_STORE_MESSAGE_BASE_H_

#include "eap_tools.h"
#include "eap_am_export.h"

class eap_method_settings_c;
class abs_eap_pac_store_message_c;

/// A eap_pac_store_message_base_c class implements mapping of EAP authentication sessions.
/// Network identity separates parallel EAP authentication sessions.
class EAP_EXPORT eap_pac_store_message_base_c
{
private:
	//--------------------------------------------------


	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the eap_core class does nothing special.
	 */
	EAP_FUNC_IMPORT virtual ~eap_pac_store_message_base_c();

	/**
	 * The constructor initializes member attributes using parameters passed to it.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 * @param partner is back pointer to object which created this object.
	 * @param is_client_when_true indicates whether the network entity should act
	 * as a client (true) or server (false), in terms of EAP-protocol
	 * whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	 */
	EAP_FUNC_IMPORT eap_pac_store_message_base_c();

	/**
	 * This function must reset the state of object to same as 
	 * state was after the configure() function call.
	 * If object reset succeeds this function must return eap_status_ok.
	 * If object reset fails this function must return corresponding error status.
	 * @return This function returns the status of reset operation.
	 */
	virtual eap_status_e reset() = 0;

	// This is documented in abs_eap_stack_interface_c::configure().
	virtual eap_status_e configure() = 0;

	// This is documented in abs_eap_stack_interface_c::shutdown().
	virtual eap_status_e shutdown() = 0;

	// This is documented in abs_eap_stack_interface_c::get_is_valid().
	virtual bool get_is_valid() = 0;

	virtual eap_status_e open_pac_store(
		const eap_status_e completion_status) = 0;

	virtual eap_status_e create_device_seed(
		const eap_status_e completion_status) = 0;

	virtual eap_status_e is_master_key_present(
		const eap_status_e completion_status) = 0;

	virtual eap_status_e is_master_key_and_password_matching(
		const eap_variable_data_c * const pac_store_password
		,const eap_status_e completion_status) = 0;

	virtual eap_status_e create_and_save_master_key(
		const eap_variable_data_c * const pac_store_password
		,const eap_status_e completion_status) = 0;

	virtual eap_status_e compare_pac_store_password(
		eap_variable_data_c * const pac_store_password) = 0;

	virtual eap_status_e is_pacstore_password_present() = 0;

	virtual eap_status_e set_pac_store_password(
		const eap_variable_data_c * pac_store_password
		,const eap_status_e completion_status) = 0;

	virtual eap_status_e destroy_pac_store(
		const eap_status_e completion_status) = 0;

	//--------------------------------------------------

	static eap_pac_store_message_base_c * new_eap_pac_store_client_message_if_c(
		abs_eap_am_tools_c * const tools,
		abs_eap_pac_store_message_c * const partner);

	//--------------------------------------------------
}; // class eap_pac_store_message_base_c

//--------------------------------------------------

#endif //#if !defined(_EAP_PAC_STORE_MESSAGE_BASE_H_)

//--------------------------------------------------



// End.
