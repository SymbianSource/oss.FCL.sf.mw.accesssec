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

#if !defined(_EAP_BASE_TYPE_H_)
#define _EAP_BASE_TYPE_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_BASE_TYPE_H)
	#define EAP_CLASS_VISIBILITY_EAP_BASE_TYPE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_BASE_TYPE_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_BASE_TYPE_H 
	#define EAP_FUNC_EXPORT_EAP_BASE_TYPE_H 
	#define EAP_C_FUNC_EXPORT_EAP_BASE_TYPE_H 
#elif defined(EAP_EXPORT_EAP_BASE_TYPE_H)
	#define EAP_CLASS_VISIBILITY_EAP_BASE_TYPE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_BASE_TYPE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_BASE_TYPE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_BASE_TYPE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_BASE_TYPE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_BASE_TYPE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_BASE_TYPE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_BASE_TYPE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_BASE_TYPE_H 
	#define EAP_C_FUNC_EXPORT_EAP_BASE_TYPE_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_base_type.h"
#include "eap_header.h"


class abs_eap_base_type_c;
class eap_am_network_id_c;

/// The eap_base_type_c class declares pure virtual functions 
/// a user class of EAP-type class could call.
/// See also abs_eap_stack_interface_c. It includes
/// important functions too.
class EAP_CLASS_VISIBILITY_EAP_BASE_TYPE_H eap_base_type_c
//: public abs_eap_stack_interface_c This is not used here because packet_process() function differs.
{

private:
	//--------------------------------------------------

	/// This is back pointer to object which created this object.
	/// The eap_base_type_c object sends packets to the network using m_type_partner object.
	/// @see abs_eap_base_type_c.
	abs_eap_base_type_c *m_type_partner;

	/// This is pointer to the tools class. @see abs_eap_am_tools_c.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is count of references to this EAP-type.
	/// EAP-type is removed from eap_core_map_c after the reference count is zero.
	u32_t m_reference_count;

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
	 * The destructor of the eap_base_type class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_BASE_TYPE_H virtual ~eap_base_type_c();

	/**
	 * The constructor of the eap_base_type class simply initializes the attributes.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 * @param partner is back pointer to object which created this object.
	 * The eap_base_type_c object sends packets to the network using m_type_partner object.
	 */
	EAP_FUNC_VISIBILITY_EAP_BASE_TYPE_H eap_base_type_c(
		abs_eap_am_tools_c * const tools,
		abs_eap_base_type_c * const partner);

	/**
	 * The object_increase_reference_count() function increases the reference count.
	 */
	EAP_FUNC_VISIBILITY_EAP_BASE_TYPE_H void object_increase_reference_count();

	/**
	 * The object_decrease_reference_count () function decreases 
	 * the reference count and returns the remaining value.
	 * The EAP type is removed after there is no references to it.
	 */
	EAP_FUNC_VISIBILITY_EAP_BASE_TYPE_H u32_t object_decrease_reference_count();

	/**
	 * Type partner is object below the EAP-type object.
	 * @return The get_type_partner() function returns the pointer to the partner class.
	 */
	EAP_FUNC_VISIBILITY_EAP_BASE_TYPE_H abs_eap_base_type_c * get_type_partner();

	/**
	 * This function queries the identity of user using this type.
	 * @param must_be_synchronous tells whether this call must be synchronous.
	 * @param identity is buffer for queried identity in synchronous call.
	 * @param receive_network_id carries the addresses and type of the received packet.
	 * @param eap_identifier is EAP-Identifier for EAP-Response/Identity packet.
	 *
	 * Parameters receive_network_id and eap_identifier are used in asynchronous 
	 * completion of this call. See abs_eap_base_type_c::complete_eap_identity_query().
	 */
	virtual eap_status_e query_eap_identity(
		const bool must_be_synchronous,
		eap_variable_data_c * const identity,
		const eap_am_network_id_c * const receive_network_id,
		const u8_t eap_identifier) = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * The configure() function is called after the constructor of the 
	 * object is successfully executed. During the function call the object 
	 * could query the configuration. Each derived class must define this function.
	 * Needed configuration depends on the EAP-type.
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
	 * This function processes the received packet.
	 * The return value of this function should be used only for traces
	 * and error counters. You MUST NOT make any decision of authentication session
	 * based on the return value. The stack calls abs_eap_core_c::state_notification()
	 * function when authentication session terminates unsuccessfully or ends successfully.
	 * You MUST make decision of authentication session based on the state_notification() call.
	 * See more abs_eap_core_c::state_notification().
	 * @param receive_network_id carries the addresses and type of the received packet.
	 * @param eap includes the buffer of the packet.
	 * @param packet_length is length in bytes of the EAP-packet.
	 */
	virtual eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id,
		eap_header_wr_c * const eap,
		const u32_t packet_length) = 0;

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	virtual bool get_is_valid() = 0;

	/**
	 * This function resets the reused object.
	 */
	virtual eap_status_e reset() = 0;

	/**
	 * This function sets the initial EAP-Identifier to be used for the first sent packet.
	 * This function is only needed in Windows RAS.
	 */
	virtual eap_status_e set_initial_eap_identifier(
		const eap_am_network_id_c * const receive_network_id,
		const u8_t initial_identifier) = 0;

	/**
	 * The adaptation module calls the eap_acknowledge() function after
	 * any Network Protocol packet is received. This is used as a success indication.
	 * This is described in RFC 2284 "PPP Extensible Authentication Protocol (EAP)".
	 * Mostly there is only one session in the client.
	 * The server does not need eap_acknowledge() function because
	 * server (EAP-authenticator) sends the EAP-success message.
	 */
	virtual eap_status_e eap_acknowledge(
		const eap_am_network_id_c * const receive_network_id) = 0;

	//--------------------------------------------------
}; // class eap_base_type_c

#endif //#if !defined(_EAP_BASE_TYPE_H_)

//--------------------------------------------------



// End.
