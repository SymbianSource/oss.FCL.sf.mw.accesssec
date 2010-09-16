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

#if !defined(_ABS_EAP_STACK_INTERFACE_H_)
#define _ABS_EAP_STACK_INTERFACE_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_STACK_INTERFACE_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_STACK_INTERFACE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_STACK_INTERFACE_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_STACK_INTERFACE_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_STACK_INTERFACE_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_STACK_INTERFACE_H 
#elif defined(EAP_EXPORT_ABS_EAP_STACK_INTERFACE_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_STACK_INTERFACE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_STACK_INTERFACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_STACK_INTERFACE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_STACK_INTERFACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_STACK_INTERFACE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_STACK_INTERFACE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_STACK_INTERFACE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_STACK_INTERFACE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_STACK_INTERFACE_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_STACK_INTERFACE_H 
#endif
// End: added by script change_export_macros.sh.

class eap_am_network_id_c;
class eap_general_header_base_c;


/// The abs_eap_stack_interface_c class declares common pure virtual functions 
/// a lower layer class of EAP-stack could call from upper layer class.
/// Main purpose of this interface is documenting those functions.
/// Note the each interface could include other functions too.
/// Those are defined in each individual interface.
class EAP_CLASS_VISIBILITY_ABS_EAP_STACK_INTERFACE_H abs_eap_stack_interface_c
{
private:
	//--------------------------------------------------

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
	 * The destructor of the abs_eap_stack_interface_c class does nothing special.
	 */
	virtual ~abs_eap_stack_interface_c()
	{
	}

	/**
	 * The constructor of the abs_eap_stack_interface_c does nothing special.
	 */
	abs_eap_stack_interface_c()
	{
	}

	/**
	 * The configure() function is called after the constructor of the 
	 * object is successfully executed. During the function call the object 
	 * could query the configuration. Each derived class must define this function.
	 * Needed configuration depends on the implementation.
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
	 * The packet_process() function processes the received packet.
	 * The return value of this function should be used only for traces
	 * and error counters. You MUST NOT make any decision of authentication session
	 * based on the return value. The stack calls abs_eap_core_c::state_notification()
	 * function when authentication session terminates unsuccessfully or ends successfully.
	 * You MUST make decision of authentication session based on the state_notification() call.
	 * See more abs_eap_core_c::state_notification().
	 * @param receive_network_id carries the addresses and type of the received packet.
	 * @param packet_data includes the buffer of the packet.
	 * @param packet_length is length in bytes of the EAP-packet.
	 */
	virtual eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id,
		eap_general_header_base_c * const packet_data,
		const u32_t packet_length) = 0;

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	virtual bool get_is_valid() = 0;

	//--------------------------------------------------
}; // class abs_eap_stack_interface_c

#endif //#if !defined(_ABS_EAP_STACK_INTERFACE_H_)

//--------------------------------------------------



// End.
