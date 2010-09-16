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
* %version: 3.1.2 %
*/

#if !defined(_GSMSIM_RESULT_H_)
#define _GSMSIM_RESULT_H_

#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TYPE_GSMSIM_PAYLOADS_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H 
	#define EAP_FUNC_EXPORT_EAP_TYPE_GSMSIM_PAYLOADS_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_GSMSIM_PAYLOADS_H 
#elif defined(EAP_EXPORT_EAP_TYPE_GSMSIM_PAYLOADS_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_GSMSIM_PAYLOADS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_GSMSIM_PAYLOADS_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_GSMSIM_PAYLOADS_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_GSMSIM_PAYLOADS_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_type_gsmsim_header.h"



class EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_fixed_data_c
{
private:
	//--------------------------------------------------

	bool m_is_valid;
	gsmsim_payload_AT_header_c m_original_header;
	u16_t m_type;
	u16_t m_data;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H virtual ~gsmsim_fixed_data_c();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_fixed_data_c(
		abs_eap_am_tools_c * const tools);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H bool get_is_valid() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H const gsmsim_payload_AT_header_c * get_original_header();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H u16_t get_type(abs_eap_am_tools_c * const m_am_tools) const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H u16_t get_data(abs_eap_am_tools_c * const m_am_tools) const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H void set_data(
		const gsmsim_payload_AT_header_c * const original_header,
		const u16_t type, const u16_t data);

	//--------------------------------------------------
}; // class gsmsim_fixed_data_c


class EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	eap_variable_data_c m_data;

	gsmsim_payload_AT_header_c m_original_header;

	bool m_payload_included;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H virtual ~gsmsim_variable_data_c();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c(abs_eap_am_tools_c * const tools);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H const gsmsim_payload_AT_header_c * get_original_header() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H eap_status_e set_buffer(
		const gsmsim_payload_AT_header_c * const original_header,
		u8_t *buffer,
		const u32_t buffer_length,
		const bool free_buffer,
		const bool is_writable);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H bool get_payload_included() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H u32_t get_data_length() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H u8_t * get_data(const u32_t data_length) const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H eap_variable_data_c * get_payload_buffer();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H eap_status_e reset();

	//--------------------------------------------------
}; // class gsmsim_variable_data_c


//--------------------------------------------------


// 
class EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_payloads_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	gsmsim_variable_data_c m_nonce_mt;

	gsmsim_variable_data_c m_nonce_s;

	gsmsim_variable_data_c m_MAC;

	gsmsim_variable_data_c m_ENCR_DATA;

	gsmsim_variable_data_c m_IDENTITY_payload;

	gsmsim_variable_data_c m_padding_payload;

	gsmsim_variable_data_c m_n_RANDs;

	gsmsim_variable_data_c m_PERMANENT_ID_REQ;

	gsmsim_variable_data_c m_FULLAUTH_ID_REQ;

	gsmsim_variable_data_c m_ANY_ID_REQ;

	gsmsim_variable_data_c m_IV;

	gsmsim_variable_data_c m_NEXT_PSEUDONYM;

	gsmsim_variable_data_c m_NEXT_REAUTH_ID;

	gsmsim_variable_data_c m_NOTIFICATION;

	gsmsim_variable_data_c m_VERSION_LIST;

	gsmsim_variable_data_c m_SELECTED_VERSION;

	gsmsim_variable_data_c m_COUNTER;

	gsmsim_variable_data_c m_COUNTER_TOO_SMALL;

	gsmsim_variable_data_c m_CLIENT_ERROR_CODE;

	gsmsim_variable_data_c m_RESULT_IND;

	gsmsim_payload_AT_type_e m_unknown_payload;

	bool m_includes_other_version_than_1;

	bool m_is_valid;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------


	enum eap_gsmsim_payload_status_e
	{
		eap_gsmsim_payload_status_optional,
		eap_gsmsim_payload_status_must_be,
		eap_gsmsim_payload_status_must_not_be
	};


	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H virtual ~gsmsim_payloads_c();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_payloads_c(
		abs_eap_am_tools_c * const tools);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H bool check_one_payload(
		const eap_gsmsim_payload_status_e status,
		const gsmsim_variable_data_c * const payload);

	/** This function checks the correct set of payloads are included in the message.
	 *  NOTE do not change the order of parameters.
	 *  Add new payload type to the last of the parameter list.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H bool check_payloads(
		const eap_gsmsim_payload_status_e nonce_mt,
		const eap_gsmsim_payload_status_e nonce_s,
		const eap_gsmsim_payload_status_e MAC,
		const eap_gsmsim_payload_status_e ENCR_DATA,
		const eap_gsmsim_payload_status_e IDENTITY,
		const eap_gsmsim_payload_status_e padding,
		const eap_gsmsim_payload_status_e n_RANDs,
		const eap_gsmsim_payload_status_e PERMANENT_ID_REQ,
		const eap_gsmsim_payload_status_e FULLAUTH_ID_REQ,
		const eap_gsmsim_payload_status_e ANY_ID_REQ,
		const eap_gsmsim_payload_status_e IV,
		const eap_gsmsim_payload_status_e NEXT_PSEUDONYM,
		const eap_gsmsim_payload_status_e NEXT_REAUTH_ID,
		const eap_gsmsim_payload_status_e NOTIFICATION,
		const eap_gsmsim_payload_status_e VERSION_LIST,
		const eap_gsmsim_payload_status_e SELECTED_VERSION,
		const eap_gsmsim_payload_status_e COUNTER,
		const eap_gsmsim_payload_status_e COUNTER_TOO_SMALL,
		const eap_gsmsim_payload_status_e CLIENT_ERROR_CODE,
		const eap_gsmsim_payload_status_e RESULT_IND
		);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_NONCE_MT();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_NONCE_S();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_MAC();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_ENCR_DATA();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_IDENTITY_payload();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_padding_payload();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_n_RANDs();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_PERMANENT_ID_REQ();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_FULLAUTH_ID_REQ();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_ANY_ID_REQ();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_IV();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_NEXT_PSEUDONYM();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_NEXT_REAUTH_ID();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_NOTIFICATION();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_RESULT_IND();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_VERSION_LIST();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_SELECTED_VERSION();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_CLIENT_ERROR_CODE();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_COUNTER();

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_variable_data_c * get_counter_too_small();


	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H void set_includes_unknown_attribute(const gsmsim_payload_AT_type_e unknown_payload);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H gsmsim_payload_AT_type_e get_includes_unknown_attribute();


	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H void set_includes_other_version_than_1(const bool includes_other_version_than_1);

	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H bool get_includes_other_version_than_1();


	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_PAYLOADS_H bool get_is_valid() const;

	//--------------------------------------------------
}; // class gsmsim_payloads_c


#endif //#if !defined(_GSMSIM_RESULT_H_)

//--------------------------------------------------



// End.
