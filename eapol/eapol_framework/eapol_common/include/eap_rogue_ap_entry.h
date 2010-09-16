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

#ifndef EAP_ROGUE_AP_ENTRY_H
#define EAP_ROGUE_AP_ENTRY_H

// INCLUDES
#include "eap_am_tools.h"
#include "eapol_ethernet_address.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_ROGUE_AP_ENTRY_H)
	#define EAP_CLASS_VISIBILITY_EAP_ROGUE_AP_ENTRY_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_ROGUE_AP_ENTRY_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_ROGUE_AP_ENTRY_H 
	#define EAP_FUNC_EXPORT_EAP_ROGUE_AP_ENTRY_H 
	#define EAP_C_FUNC_EXPORT_EAP_ROGUE_AP_ENTRY_H 
#elif defined(EAP_EXPORT_EAP_ROGUE_AP_ENTRY_H)
	#define EAP_CLASS_VISIBILITY_EAP_ROGUE_AP_ENTRY_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_ROGUE_AP_ENTRY_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_ROGUE_AP_ENTRY_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_ROGUE_AP_ENTRY_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_ROGUE_AP_ENTRY_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_ROGUE_AP_ENTRY_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_ROGUE_AP_ENTRY_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_ROGUE_AP_ENTRY_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_ROGUE_AP_ENTRY_H 
	#define EAP_C_FUNC_EXPORT_EAP_ROGUE_AP_ENTRY_H 
#endif
// End: added by script change_export_macros.sh.


enum eap_rogue_ap_reason_e
{
	rogue_ap_none,
	rogue_ap_association_failed,
	rogue_ap_timeout,
	rogue_ap_challenge_to_client_failed,
	rogue_ap_challenge_to_ap_failed
};

// CLASS DECLARATION

class EAP_CLASS_VISIBILITY_EAP_ROGUE_AP_ENTRY_H eap_rogue_ap_entry_c
{
	public:

		// Constructors and destructor

		/**
		* Constructor
		* @param tools Pointer to EAP tools class
		*/        
		EAP_FUNC_VISIBILITY_EAP_ROGUE_AP_ENTRY_H eap_rogue_ap_entry_c(
			abs_eap_am_tools_c * const tools);

		/**
		* Destructor
		*/
		EAP_FUNC_VISIBILITY_EAP_ROGUE_AP_ENTRY_H virtual ~eap_rogue_ap_entry_c();

		/**
		* Returns a copy of this object.
		*/
		EAP_FUNC_VISIBILITY_EAP_ROGUE_AP_ENTRY_H eap_rogue_ap_entry_c * copy() const;

		/**
		* Returns pointer to MAC address
		* @return Pointer to MAC address
		*/
		EAP_FUNC_VISIBILITY_EAP_ROGUE_AP_ENTRY_H u8_t * get_mac_address() const;

		/**
		* Returns pointer to MAC address and copies MAC address into given pointer
		* @param mac_address Copies MAC address into this
		* @return Pointer to MAC address
		*/
		EAP_FUNC_VISIBILITY_EAP_ROGUE_AP_ENTRY_H u8_t * get_mac_address(u8_t * const mac_address) const;

		/**
		* Sets MAC address
		* @param mac_address pointer to MAC address
		*/
		EAP_FUNC_VISIBILITY_EAP_ROGUE_AP_ENTRY_H void set_mac_address(const u8_t * const mac_address);

		/**
		* Sets Rogue reason code
		* @param reason Rogue reson code
		*/
		EAP_FUNC_VISIBILITY_EAP_ROGUE_AP_ENTRY_H void set_rogue_reason(const eap_rogue_ap_reason_e reason);

		/**
		* Returns reson code of Rogue AP entry
		* @return Rogue reson code
		*/
		EAP_FUNC_VISIBILITY_EAP_ROGUE_AP_ENTRY_H eap_rogue_ap_reason_e get_rogue_reason() const;

	private: // Data

		/// Pointer to EAP tools
		abs_eap_am_tools_c * const m_am_tools;

		eap_rogue_ap_reason_e m_rogue_ap_reason;

		u8_t m_rogue_ap_mac_address[EAPOL_ETHERNET_ADDRESS_LENGTH];

}; // class eap_rogue_ap_entry_c

#endif // EAP_ROGUE_AP_ENTRY_H

// End of File
