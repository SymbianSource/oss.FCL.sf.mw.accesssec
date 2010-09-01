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
* %version: 10 %
*/

#if !defined(_SIMPLE_CONFIG_BASE_RECORD_H_)
#define _SIMPLE_CONFIG_BASE_RECORD_H_


#include "simple_config_types.h"
#include "eap_array.h"
#include "eap_header.h"

class abs_simple_config_base_record_c;
class abs_eap_am_tools_c;
class eap_am_network_id_c;
class simple_config_record_header_c;
class eap_rogue_ap_entry_c;


/// The simple_config_base_record_c class declares pure virtual functions 
/// a user class of SIMPLE_CONFIG-record class could call.
class EAP_EXPORT simple_config_base_record_c
{
private:
	//--------------------------------------------------

	/// This is back pointer to object which created this object.
	/// The simple_config_base_record_c object sends packets to the network using m_type_partner object.
	/// @see abs_simple_config_base_record_c.
	abs_simple_config_base_record_c *m_type_partner;

	/// This is pointer to the tools class. @see abs_eap_am_tools_c.
	abs_eap_am_tools_c * const m_am_tools;

	/**
	 * The set_is_valid() function sets the state of the object valid.
	 * The creator of this object calls this function after it is initialized. 
	 */
	virtual void set_is_valid() = 0;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the simple_config_base_record_c class does nothing special.
	 */
	EAP_FUNC_IMPORT virtual ~simple_config_base_record_c();

	/**
	 * The constructor of the simple_config_base_record_c class simply initializes the attributes.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 * @param partner is back pointer to object which created this object.
	 * The simple_config_base_record_c object sends packets to the network using m_type_partner object.
	 */
	EAP_FUNC_IMPORT simple_config_base_record_c(
		abs_eap_am_tools_c * const tools);

	/**
	 * Type partner is object below the simple_config_base_record_c object.
	 * @return The get_type_partner() function returns the pointer to the partner class.
	 */
	EAP_FUNC_IMPORT abs_simple_config_base_record_c * get_type_partner();

	EAP_FUNC_IMPORT void set_type_partner(abs_simple_config_base_record_c * const partner);

	/**
	 * The configure() function is called after the constructor of the 
	 * object is successfully executed. During the function call the object 
	 * could query the configuration. Each derived class must define this function.
	 */
	virtual eap_status_e configure() = 0;

	/**
	 * The shutdown() function is called before the destructor of the 
	 * object is executed. During the function call the object 
	 * could shutdown the operations, for example cancel timers.
	 * Each derived class must define this function.
	 */
	virtual eap_status_e shutdown() = 0;

	/**
	 * This function sets the NAI realm.
	 */
	virtual eap_status_e set_nai_realm(const eap_variable_data_c * const NAI_realm) = 0;

	/**
	 * This function sends starts EAP-SIMPLE_CONFIG/PEAP after a start message is received.
	 */
	virtual eap_status_e start_simple_config_authentication(
		const eap_variable_data_c * const NAI ///< This is the full NAI of the client.
		) = 0;

	/**
	 * This function processes the received packet.
	 * @param simple_config_packet points to the buffer of the whole reassembled SIMPLE_CONFIG-packet.
	 */
	virtual eap_status_e packet_process(
		eap_variable_data_c * const simple_config_packet,
		const u8_t received_eap_identifier) = 0;

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	virtual bool get_is_valid() = 0;

	/**
	 * This function resets the reused simple_config_base_record_c object.
	 */
	virtual eap_status_e reset() = 0;

	//--------------------------------------------------
}; // class simple_config_base_record_c

#endif //#if !defined(_SIMPLE_CONFIG_BASE_RECORD_H_)

//--------------------------------------------------



// End.
