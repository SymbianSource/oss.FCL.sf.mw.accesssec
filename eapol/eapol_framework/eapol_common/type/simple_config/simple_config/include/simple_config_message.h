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




#if !defined(_SIMPLE_CONFIG_MESSAGE_H_)
#define _SIMPLE_CONFIG_MESSAGE_H_

#include "eap_tools.h"
#include "eap_array.h"
#include "abs_simple_config_apply_cipher_spec.h"

/** @file */


//----------------------------------------------------------------------------


/// This class defines one SIMPLE_CONFIG-message. One SIMPLE_CONFIG message could include many SIMPLE_CONFIG-records.
/**
 * This class defined one SIMPLE_CONFIG-message.
 * Parse and analyse of SIMPLE_CONFIG-message is asyncronous.
 * m_analyse_index tells the index of message where asyncronous
 * analyse of SIMPLE_CONFIG-message must continue.
 * Analysed messages are skipped during the asyncronous
 * analyse of messages. Asyncronous analyse is needed
 * because of the PKI functions are asyncronous in
 * Symbian.
 */
class EAP_EXPORT simple_config_message_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class. @see abs_eap_am_tools_c.
	abs_eap_am_tools_c * const m_am_tools;

	/// This buffer includes copy of the whole received SIMPLE_CONFIG-message data.
	eap_variable_data_c m_simple_config_message_data;

	/// This is EAP-identifier of the EAP-packet that includes SIMPLE_CONFIG-message. This is needed in XP-PEAP.
	u8_t m_received_eap_identifier;


	/// This indicates whether this object is client (true) or server (false). This is mostly for traces.
	const bool m_is_client;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the simple_config_message_c class does nothing special.
	 */
	EAP_FUNC_IMPORT virtual ~simple_config_message_c();

	/**
	 * The constructor of the simple_config_message_c class simply initializes the attributes.
	 */
	EAP_FUNC_IMPORT simple_config_message_c(
		abs_eap_am_tools_c * const tools,
		const bool is_client);

	/**
	 * This function resets this object.
	 */
	EAP_FUNC_IMPORT eap_status_e reset();

	/**
	 * This function copies the received SIMPLE_CONFIG-message data and EAP-identifier.
	 * EAP-identifier is needed in XP PEAPv0. That stupid version uses
	 * same EAP-identifier with PEAP header and tunneled EAP-header.
	 */
	EAP_FUNC_IMPORT eap_status_e set_simple_config_message_data(
		eap_variable_data_c * const simple_config_message_data,
		const u8_t received_eap_identifier);

	/**
	 * This function returns the SIMPLE_CONFIG-message data.
	 */
	EAP_FUNC_IMPORT eap_variable_data_c * get_simple_config_message_data();

	/**
	 * This function returns the EAP-identifier.
	 */
	EAP_FUNC_IMPORT u8_t get_received_eap_identifier();

	/**
	 * Function adds padding for block size if it is needed.
	 */
	EAP_FUNC_IMPORT eap_status_e add_padding(const u32_t block_size);

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	EAP_FUNC_IMPORT bool get_is_valid();
	// 
	//--------------------------------------------------
}; // class simple_config_message_c


//--------------------------------------------------

#endif //#if !defined(_SIMPLE_CONFIG_MESSAGE_H_)



// End.
