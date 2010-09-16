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

#if !defined(_TLS_BASE_RECORD_H_)
#define _TLS_BASE_RECORD_H_


#include "tls_peap_types.h"
#include "eap_array.h"
#include "eap_header.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_TLS_BASE_RECORD_H)
	#define EAP_CLASS_VISIBILITY_TLS_BASE_RECORD_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_TLS_BASE_RECORD_H 
	#define EAP_C_FUNC_VISIBILITY_TLS_BASE_RECORD_H 
	#define EAP_FUNC_EXPORT_TLS_BASE_RECORD_H 
	#define EAP_C_FUNC_EXPORT_TLS_BASE_RECORD_H 
#elif defined(EAP_EXPORT_TLS_BASE_RECORD_H)
	#define EAP_CLASS_VISIBILITY_TLS_BASE_RECORD_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_TLS_BASE_RECORD_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_BASE_RECORD_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_TLS_BASE_RECORD_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_TLS_BASE_RECORD_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_TLS_BASE_RECORD_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_TLS_BASE_RECORD_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_BASE_RECORD_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_TLS_BASE_RECORD_H 
	#define EAP_C_FUNC_EXPORT_TLS_BASE_RECORD_H 
#endif
// End: added by script change_export_macros.sh.


class abs_tls_base_record_c;
class abs_eap_am_tools_c;
class eap_am_network_id_c;
class tls_record_header_c;
class eap_rogue_ap_entry_c;


/// The tls_base_record_c class declares pure virtual functions 
/// a user class of TLS-record class could call.
class EAP_CLASS_VISIBILITY_TLS_BASE_RECORD_H tls_base_record_c
{
private:
	//--------------------------------------------------

	/// This is back pointer to object which created this object.
	/// The tls_base_record_c object sends packets to the network using m_type_partner object.
	/// @see abs_tls_base_record_c.
	abs_tls_base_record_c *m_type_partner;

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
	 * The destructor of the tls_base_record_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_TLS_BASE_RECORD_H virtual ~tls_base_record_c();

	/**
	 * The constructor of the tls_base_record_c class simply initializes the attributes.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 * @param partner is back pointer to object which created this object.
	 * The tls_base_record_c object sends packets to the network using m_type_partner object.
	 */
	EAP_FUNC_VISIBILITY_TLS_BASE_RECORD_H tls_base_record_c(
		abs_eap_am_tools_c * const tools /*,
		abs_tls_base_record_c * const partner */);

	/**
	 * Type partner is object below the tls_base_record_c object.
	 * @return The get_type_partner() function returns the pointer to the partner class.
	 */
	EAP_FUNC_VISIBILITY_TLS_BASE_RECORD_H abs_tls_base_record_c * get_type_partner();

	EAP_FUNC_VISIBILITY_TLS_BASE_RECORD_H void set_type_partner(abs_tls_base_record_c * const partner);

	virtual void set_peap_version(
		const peap_version_e peap_version, ///< This is the PEAP version (PEAPv2, PEAPv1, XP PEAPv0), yes very nice to have many different versions.
		const bool use_tppd_tls_peap, ///< Of course some vendors have own TLS/PEAP quirks.
		const bool use_tppd_peapv1_acknowledge_hack) = 0;

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
	 * This function sends starts EAP-TLS/PEAP after a start message is received.
	 */
	virtual eap_status_e start_tls_peap_authentication(
		const eap_variable_data_c * const received_authority_identity_payload
		) = 0;

	/**
	 * This function starts the tunneled EAP-type within PEAP.
	 */
	virtual eap_status_e start_peap_tunneled_authentication(
		const eap_am_network_id_c * const receive_network_id,
		const u8_t received_eap_identifier,
		const tls_session_type_e tls_session_type) = 0;

	/**
	 * This function processes the received packet.
	 * @param tls_packet points to the buffer of the whole reassembled TLS-packet.
	 */
	virtual eap_status_e packet_process(
		eap_variable_data_c * const tls_packet,
		const u8_t received_eap_identifier) = 0;

	/**
	 * This function indicates the plain text EAP-Success or EAP-Failure packet is received.
	 * @param receive_network_id includes the addresses (network identity) and packet type.
	 * @param received_eap_identifier is the EAP-Identifier of the received EAP-Success packet.
	 */
	virtual eap_status_e plain_eap_success_failure_packet_received(
		const eap_am_network_id_c * const receive_network_id,
		const eap_code_value_e received_eap_code,
		const u8_t received_eap_identifier) = 0;

	/**
	 * This function indicates the empty Ack packet is received.
	 * This is used in TTLS.
	 * @param receive_network_id includes the addresses (network identity) and packet type.
	 * @param received_eap_identifier is the EAP-Identifier of the received EAP-Success packet.
	 */
	virtual eap_status_e empty_ack_packet_received(
		const eap_am_network_id_c * const receive_network_id,
		const u8_t received_eap_identifier) = 0;

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	virtual bool get_is_valid() = 0;

	/**
	 * This function resets the reused tls_base_record_c object.
	 */
	virtual eap_status_e reset() = 0;

	virtual eap_status_e add_rogue_ap(eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list) = 0;

	/**
	 * This function reads the authority identity (A-ID) of server.
	 * This is used in EAP-FAST.
	 */
	virtual eap_status_e read_authority_identity(eap_variable_data_c * const authority_identity_payload) = 0;

	//--------------------------------------------------
}; // class tls_base_record_c

#endif //#if !defined(_TLS_BASE_RECORD_H_)

//--------------------------------------------------



// End.
