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
* %version: 7.1.2 %
*/

#if !defined(_PEAP_TLV_PAYLOADS_H_)
#define _PEAP_TLV_PAYLOADS_H_

#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_TLS_PEAP_TLV_PAYLOADS_H)
	#define EAP_CLASS_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H 
	#define EAP_C_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H 
	#define EAP_FUNC_EXPORT_TLS_PEAP_TLV_PAYLOADS_H 
	#define EAP_C_FUNC_EXPORT_TLS_PEAP_TLV_PAYLOADS_H 
#elif defined(EAP_EXPORT_TLS_PEAP_TLV_PAYLOADS_H)
	#define EAP_CLASS_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_TLS_PEAP_TLV_PAYLOADS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_TLS_PEAP_TLV_PAYLOADS_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_TLS_PEAP_TLV_PAYLOADS_H 
	#define EAP_C_FUNC_EXPORT_TLS_PEAP_TLV_PAYLOADS_H 
#endif
// End: added by script change_export_macros.sh.
#include "tls_peap_tlv_header.h"



class EAP_CLASS_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H peap_tlv_variable_data_c
: public eap_variable_data_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	tls_peap_tlv_header_c m_original_header;

	eap_variable_data_c m_header_copy;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H virtual ~peap_tlv_variable_data_c();

	EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H peap_tlv_variable_data_c(abs_eap_am_tools_c * const tools);

	EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H const tls_peap_tlv_header_c * get_original_header() const;

	EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H eap_status_e set_buffer(
		const tls_peap_tlv_header_c * const original_header,
		u8_t *data_buffer,
		const u32_t data_buffer_length,
		const bool free_buffer,
		const bool is_writable);

	EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H eap_status_e set_copy_of_buffer(
		const tls_peap_tlv_header_c * const original_header);

	//--------------------------------------------------
}; // class peap_tlv_variable_data_c


//--------------------------------------------------


// 
class EAP_CLASS_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H peap_tlv_payloads_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	peap_tlv_variable_data_c m_result_tlv;

	peap_tlv_variable_data_c m_nak_tlv;

	peap_tlv_variable_data_c m_crypto_binding_tlv;

	peap_tlv_variable_data_c m_eap_payload_tlv;

	peap_tlv_variable_data_c m_intermediate_result_tlv;

	bool m_is_valid;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------


	enum peap_tlv_payload_status_e
	{
		peap_tlv_payload_status_optional,
		peap_tlv_payload_status_must_be,
		peap_tlv_payload_status_must_not_be
	};


	EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H virtual ~peap_tlv_payloads_c();

	EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H peap_tlv_payloads_c(
		abs_eap_am_tools_c * const tools);

	EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H bool check_one_payload(
		const peap_tlv_payload_status_e status,
		const peap_tlv_variable_data_c * const payload);

	/** This function checks the correct set of payloads are included in the message.
	 *  NOTE do not change the order of parameters.
	 *  Add new payload type to the last of the parameter list.
	 */
	EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H bool check_payloads(
		const peap_tlv_payload_status_e result_tlv,
		const peap_tlv_payload_status_e nak_tlv,
		const peap_tlv_payload_status_e crypto_binding_tlv,
		const peap_tlv_payload_status_e eap_payload_tlv,
		const peap_tlv_payload_status_e intermediate_result_tlv
		);

	EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H peap_tlv_variable_data_c * get_result_tlv();

	EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H peap_tlv_variable_data_c * get_nak_tlv();

	EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H peap_tlv_variable_data_c * get_crypto_binding_tlv();

	EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H peap_tlv_variable_data_c * get_eap_payload_tlv();

	EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H peap_tlv_variable_data_c * get_intermediate_result_tlv();

	EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H void reset();

	EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_PAYLOADS_H bool get_is_valid() const;

	//--------------------------------------------------
}; // class peap_tlv_payloads_c


#endif //#if !defined(_PEAP_TLV_PAYLOADS_H_)

//--------------------------------------------------



// End.
