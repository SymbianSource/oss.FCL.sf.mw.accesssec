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

#if !defined(_EAPOL_RSNA_KEY_DATA_PAYLOADS_H_)
#define _EAPOL_RSNA_KEY_DATA_PAYLOADS_H_

#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPOL_RSNA_KEY_DATA_PAYLOADS_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H 
	#define EAP_FUNC_EXPORT_EAPOL_RSNA_KEY_DATA_PAYLOADS_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_RSNA_KEY_DATA_PAYLOADS_H 
#elif defined(EAP_EXPORT_EAPOL_RSNA_KEY_DATA_PAYLOADS_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPOL_RSNA_KEY_DATA_PAYLOADS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPOL_RSNA_KEY_DATA_PAYLOADS_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPOL_RSNA_KEY_DATA_PAYLOADS_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_RSNA_KEY_DATA_PAYLOADS_H 
#endif
// End: added by script change_export_macros.sh.
#include "eapol_rsna_key_data_header.h"
#include "eap_array.h"



class EAP_CLASS_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H eapol_rsna_variable_data_c
: public eap_variable_data_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	eapol_rsna_key_data_header_c m_original_header;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H virtual ~eapol_rsna_variable_data_c();

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H eapol_rsna_variable_data_c(
		abs_eap_am_tools_c * const tools,
		const bool is_RSNA_when_true,
		const bool is_WPXM_when_true);

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H const eapol_rsna_key_data_header_c * get_original_header() const;

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H eap_status_e set_buffer(
		const eapol_rsna_key_data_header_c * const original_header,
		u8_t *buffer,
		const u32_t buffer_length,
		const bool free_buffer,
		const bool is_writable);

	//--------------------------------------------------
}; // class eapol_rsna_variable_data_c


//--------------------------------------------------


// 
class EAP_CLASS_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H eapol_rsna_key_data_payloads_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;


	/// This includes reference to Group Transient Key (GTK) if such payloads is included to EAPOL Key Data.
	eapol_rsna_variable_data_c m_group_key;

	/// This is KeyID if such payloads is included to EAPOL Key Data.
	u8_t m_group_key_id;

	/// This is Tx bit if such payloads is included to EAPOL Key Data.
	bool m_group_key_tx_bit;


	/// This includes reference to STAKey if such payloads is included to EAPOL Key Data.
	eapol_rsna_variable_data_c m_STAKey;

	/// This includes reference to Pairwise Master Key ID (PMKID) if such payloads is included to EAPOL Key Data.
	eapol_rsna_variable_data_c m_PMKID;

	/// This plain reference to information elements if such payloads is included to EAPOL Key Data.
	/// Here could be included one or more RSN IEs.
	eap_array_c<eap_variable_data_c> m_RSN_IE;

	bool m_is_valid;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------


	enum eapol_rsna_key_data_payload_status_e
	{
		eapol_rsna_key_data_payload_status_optional,
		eapol_rsna_key_data_payload_status_must_be,
		eapol_rsna_key_data_payload_status_must_not_be
	};


	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H virtual ~eapol_rsna_key_data_payloads_c();

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H eapol_rsna_key_data_payloads_c(
		abs_eap_am_tools_c * const tools,
		const bool is_RSNA_when_true,
		const bool is_WPXM_when_true);

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H bool check_one_payload(
		const eapol_rsna_key_data_payload_status_e status,
		const eapol_rsna_variable_data_c * const payload);

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H bool check_one_payload(
		const eapol_rsna_key_data_payload_status_e status,
		const eap_array_c<eap_variable_data_c> * const payload);

	/** This function checks the correct set of payloads are included in the message.
	 *  NOTE do not change the order of parameters.
	 *  Add new payload type to the last of the parameter list.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_PAYLOADS_H bool check_payloads(
		const eapol_rsna_key_data_payload_status_e key_id_and_group_key,
		const eapol_rsna_key_data_payload_status_e sta_key,
		const eapol_rsna_key_data_payload_status_e pmkid,
		const eapol_rsna_key_data_payload_status_e one_or_more_RSN_IE
		);

	u8_t get_group_key_id();

	bool get_group_key_tx();

	eapol_rsna_variable_data_c * get_group_key();

	eapol_rsna_variable_data_c * get_STAKey();

	eapol_rsna_variable_data_c * get_PMKID();

	eap_array_c<eap_variable_data_c> * get_RSN_IE();

	bool get_is_valid() const;


	void set_group_key_id(const u8_t key_index);

	void set_group_key_tx(const bool key_tx_bit);

	//--------------------------------------------------
}; // class eapol_rsna_key_data_payloads_c


#endif //#if !defined(_EAPOL_RSNA_KEY_DATA_PAYLOADS_H_)

//--------------------------------------------------



// End.
