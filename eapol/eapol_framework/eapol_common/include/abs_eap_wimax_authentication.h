/*
* Copyright (c) 2007 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  EAP stack interface for Wimax.
*
*/

/*
* %version: %
*/

#if !defined(_ABS_EAP_WIMAX_AUTHENTICATION_H_)
#define _ABS_EAP_WIMAX_AUTHENTICATION_H_

#include <eap_am_export.h>
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_WIMAX_AUTHENTICATION_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_WIMAX_AUTHENTICATION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_WIMAX_AUTHENTICATION_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_WIMAX_AUTHENTICATION_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_WIMAX_AUTHENTICATION_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_WIMAX_AUTHENTICATION_H 
#elif defined(EAP_EXPORT_ABS_EAP_WIMAX_AUTHENTICATION_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_WIMAX_AUTHENTICATION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_WIMAX_AUTHENTICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_WIMAX_AUTHENTICATION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_WIMAX_AUTHENTICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_WIMAX_AUTHENTICATION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_WIMAX_AUTHENTICATION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_WIMAX_AUTHENTICATION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_WIMAX_AUTHENTICATION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_WIMAX_AUTHENTICATION_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_WIMAX_AUTHENTICATION_H 
#endif
// End: added by script change_export_macros.sh.


/// This class defines the interface for 
/// the eap_wimax_authentication_c class towards the Wimax engine.

class EAP_CLASS_VISIBILITY_ABS_EAP_WIMAX_AUTHENTICATION_H abs_eap_wimax_authentication_c
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~abs_eap_wimax_authentication_c()
	{
	}

	// 
	abs_eap_wimax_authentication_c()
	{
	}

	// Look at abs_eap_base_type_c::packet_send().
	virtual eap_status_e packet_send(
		const eap_am_network_id_c * const send_network_id, ///< source includes local address, destination includes remote address.
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t buffer_length) = 0;

	// Look at abs_eap_base_type_c::get_header_offset().
	virtual u32_t get_header_offset(
		u32_t * const MTU,
		u32_t * const trailer_length) = 0;

	/**
	 * Look at abs_eap_base_type_c::packet_data_crypto_keys(). 
	 */
	virtual eap_status_e packet_data_crypto_keys(
		const eap_am_network_id_c * const send_network_id, ///< source includes local address, destination includes remote address.
		const eap_master_session_key_c * const master_session_key) = 0;

	/**
	 * This is notification of internal state transition.
	 * This is used for notifications, debugging and protocol testing.
	 * The primal notifications are eap_state_variable_e::eap_state_authentication_finished_successfully
	 * and eap_state_variable_e::eap_state_authentication_terminated_unsuccessfully.
	 * These two notifications are sent from EAP-protocol layer (eap_protocol_layer_e::eap_protocol_layer_eap).
	 */
	virtual void state_notification(
		const abs_eap_state_notification_c * const state) = 0;

	//--------------------------------------------------
}; // class abs_ea_wimax_authentication_c


#endif //#if !defined(_ABS_EAP_WIMAX_AUTHENTICATION_H_)

//--------------------------------------------------


// End of file

